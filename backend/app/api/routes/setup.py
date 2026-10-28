"""First-time Authentik configuration (only available until setup completes)."""

import hmac

from fastapi import APIRouter, Header, HTTPException, Request, status
from pydantic import BaseModel, Field

from app.core.config import settings
from app.services.authentik_oidc import fetch_discovery, normalize_issuer_url

router = APIRouter()


class SetupStatusResponse(BaseModel):
    setup_pending: bool
    requires_setup_secret: bool = False
    issuer_url_hint: str = ""
    client_id_hint: str = ""
    redirect_uri_hint: str = ""
    public_app_hint: str = ""


class CompleteSetupPayload(BaseModel):
    authentik_issuer_url: str = Field(..., min_length=8)
    authentik_client_id: str = Field(..., min_length=1)
    authentik_client_secret: str = Field(..., min_length=1)
    authentik_redirect_uri: str = Field(..., min_length=8)
    public_app_url: str = Field(..., min_length=8)


def _suggest_urls(request: Request) -> tuple[str, str]:
    scheme_raw = (request.headers.get("x-forwarded-proto") or "http").split(",")[0].strip()
    raw_host = (request.headers.get("x-forwarded-host") or request.headers.get("host") or "").split(",")[0].strip()
    scheme = scheme_raw
    host = raw_host
    if scheme == "https" and host.endswith(":443"):
        host = host[:-4]
    if scheme == "http" and host.endswith(":80"):
        host = host[:-3]
    if not host:
        return "", ""
    base = f"{scheme}://{host}".rstrip("/")
    redirect_uri = f"{base}/api/v1/auth/oidc/callback"
    return redirect_uri, base


@router.get("/status", response_model=SetupStatusResponse)
async def setup_status(request: Request) -> SetupStatusResponse:
    if settings.setup_complete:
        return SetupStatusResponse(setup_pending=False)

    redirect_hint, pub_hint = _suggest_urls(request)
    secret_required = bool(settings.homelabable_setup_secret.strip())
    return SetupStatusResponse(
        setup_pending=True,
        requires_setup_secret=secret_required,
        issuer_url_hint=settings.authentik_issuer_url.strip(),
        client_id_hint=settings.authentik_client_id.strip(),
        redirect_uri_hint=redirect_hint,
        public_app_hint=(settings.public_app_url.strip() or pub_hint),
    )


@router.post("/complete")
async def complete_setup(
    body: CompleteSetupPayload,
    x_homelabable_setup_secret: str | None = Header(default=None, alias="X-Homelabable-Setup-Secret"),
) -> dict[str, str]:
    """Persists SSO config and marks setup finished. Forbidden after setup completes."""
    if settings.setup_complete:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Setup already completed")

    expected = settings.homelabable_setup_secret.strip()
    if expected:
        provided = x_homelabable_setup_secret or ""
        if not hmac.compare_digest(provided.encode(), expected.encode()):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid setup secret")

    issuer = normalize_issuer_url(body.authentik_issuer_url.strip())
    try:
        discovery = await fetch_discovery(issuer)
        if not discovery.get("authorization_endpoint"):
            raise ValueError("invalid discovery document")
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot reach OpenID discovery for this issuer: {exc}",
        ) from exc

    data = {
        "setup_complete": True,
        "allow_local_login": False,
        "authentik_oidc_enabled": True,
        "authentik_issuer_url": body.authentik_issuer_url.strip(),
        "authentik_client_id": body.authentik_client_id.strip(),
        "authentik_client_secret": body.authentik_client_secret,
        "authentik_redirect_uri": body.authentik_redirect_uri.strip(),
        "public_app_url": body.public_app_url.strip().rstrip("/"),
    }
    try:
        settings.save_auth_settings_to_disk(data)
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"Cannot save setup: {exc}") from exc

    return {"status": "ok"}
