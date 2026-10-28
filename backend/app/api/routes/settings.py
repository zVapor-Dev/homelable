"""App-level settings (status checker interval, SSO, etc.)."""
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.api.deps import get_current_principal
from app.api.principal import Principal
from app.core.config import settings
from app.services.authentik_oidc import fetch_discovery, normalize_issuer_url

router = APIRouter()


class AppSettings(BaseModel):
    interval_seconds: int


@router.get("", response_model=AppSettings)
async def get_settings(_: Principal = Depends(get_current_principal)) -> AppSettings:
    return AppSettings(interval_seconds=settings.status_checker_interval)


@router.post("", response_model=AppSettings)
async def update_settings(
    payload: AppSettings, _: Principal = Depends(get_current_principal)
) -> AppSettings:
    try:
        settings.status_checker_interval = payload.interval_seconds
        settings.save_overrides()
        return payload
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


class AuthSettingsRead(BaseModel):
    allow_local_login: bool
    authentik_oidc_enabled: bool
    authentik_issuer_url: str
    authentik_client_id: str
    authentik_redirect_uri: str
    public_app_url: str
    client_secret_configured: bool


class AuthSettingsWrite(BaseModel):
    allow_local_login: bool | None = None
    authentik_oidc_enabled: bool | None = None
    authentik_issuer_url: str | None = None
    authentik_client_id: str | None = None
    authentik_client_secret: str | None = Field(default=None, description="Omit or empty to leave unchanged.")
    authentik_redirect_uri: str | None = None
    public_app_url: str | None = None


def _serialize_auth_disk() -> dict[str, Any]:
    return {
        "setup_complete": True,
        "allow_local_login": settings.allow_local_login,
        "authentik_oidc_enabled": settings.authentik_oidc_enabled,
        "authentik_issuer_url": settings.authentik_issuer_url,
        "authentik_client_id": settings.authentik_client_id,
        "authentik_client_secret": settings.authentik_client_secret,
        "authentik_redirect_uri": settings.authentik_redirect_uri,
        "public_app_url": settings.public_app_url,
    }


@router.get("/auth", response_model=AuthSettingsRead)
async def read_auth_settings(_: Principal = Depends(get_current_principal)) -> AuthSettingsRead:
    return AuthSettingsRead(
        allow_local_login=settings.allow_local_login,
        authentik_oidc_enabled=settings.authentik_oidc_enabled,
        authentik_issuer_url=settings.authentik_issuer_url.strip(),
        authentik_client_id=settings.authentik_client_id.strip(),
        authentik_redirect_uri=settings.authentik_redirect_uri.strip(),
        public_app_url=settings.public_app_url.strip(),
        client_secret_configured=bool(settings.authentik_client_secret.strip()),
    )


@router.put("/auth")
async def update_auth_settings(
    body: AuthSettingsWrite, _: Principal = Depends(get_current_principal)
) -> dict[str, str]:
    if body.allow_local_login is not None:
        settings.allow_local_login = body.allow_local_login
    if body.authentik_oidc_enabled is not None:
        settings.authentik_oidc_enabled = body.authentik_oidc_enabled
    if body.authentik_issuer_url is not None:
        settings.authentik_issuer_url = body.authentik_issuer_url.strip()
    if body.authentik_client_id is not None:
        settings.authentik_client_id = body.authentik_client_id.strip()
    if body.authentik_redirect_uri is not None:
        settings.authentik_redirect_uri = body.authentik_redirect_uri.strip()
    if body.public_app_url is not None:
        settings.public_app_url = body.public_app_url.strip().rstrip("/")

    new_secret = (body.authentik_client_secret or "").strip()
    if new_secret:
        settings.authentik_client_secret = new_secret

    if not settings.authentik_oidc_enabled:
        pass
    elif not (
        settings.authentik_issuer_url.strip()
        and settings.authentik_client_id.strip()
        and settings.authentik_client_secret.strip()
        and settings.authentik_redirect_uri.strip()
    ):
        raise HTTPException(
            status_code=400,
            detail="When SSO is enabled, issuer, client id, secret, and redirect URI are required",
        )

    if settings.authentik_oidc_enabled:
        issuer = normalize_issuer_url(settings.authentik_issuer_url)
        try:
            disco = await fetch_discovery(issuer)
            if not disco.get("authorization_endpoint"):
                raise ValueError("invalid discovery")
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"OpenID issuer check failed: {exc}") from exc

    disk = _serialize_auth_disk()
    disk["setup_complete"] = True
    try:
        settings.save_auth_settings_to_disk(disk)
    except OSError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return {"status": "ok"}