import hmac
from typing import Literal
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel

from app.api.deps import get_current_principal
from app.api.principal import Principal
from app.core.config import settings
from app.core.security import create_access_token, verify_password
from app.services.authentik_oidc import (
    build_authorize_url,
    fetch_discovery,
    finish_oidc_login,
    mint_oidc_state_jwt,
    normalize_issuer_url,
)

router = APIRouter()


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class AuthConfigResponse(BaseModel):
    authentik_oidc_enabled: bool
    allow_local_login: bool
    setup_pending: bool


class MeResponse(BaseModel):
    username: str
    groups: list[str]
    permissions: list[str]
    auth_source: Literal["local", "oidc", "mcp"]


def _redirect_base_public_app(request: Request) -> str:
    if settings.public_app_url.strip():
        return settings.public_app_url.strip().rstrip("/")
    scheme_raw = request.headers.get("x-forwarded-proto") or "http"
    scheme = scheme_raw.split(",")[0].strip()
    raw_host = request.headers.get("x-forwarded-host") or request.headers.get("host") or ""
    host = raw_host.split(",")[0].strip()
    if not host:
        return ""
    if scheme == "https" and host.endswith(":443"):
        host = host[:-4]
    if scheme == "http" and host.endswith(":80"):
        host = host[:-3]
    return f"{scheme}://{host}"


@router.get("/me", response_model=MeResponse)
async def auth_me(principal: Principal = Depends(get_current_principal)) -> MeResponse:
    return MeResponse(
        username=principal.username,
        groups=list(principal.groups),
        permissions=list(principal.permissions),
        auth_source=principal.auth_source,
    )


@router.get("/config", response_model=AuthConfigResponse)
async def auth_public_config() -> AuthConfigResponse:
    return AuthConfigResponse(
        authentik_oidc_enabled=settings.authentik_oidc_enabled,
        allow_local_login=settings.allow_local_login,
        setup_pending=(not settings.setup_complete),
    )


@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest) -> TokenResponse:
    if not settings.allow_local_login:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Local login is disabled — use SSO or enable it under Settings.",
        )
    username_ok = hmac.compare_digest(body.username, settings.auth_username)
    password_ok = verify_password(body.password, settings.auth_password_hash)
    if not username_ok or not password_ok:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    token = create_access_token(body.username, auth_source="local")
    return TokenResponse(access_token=token)


@router.get("/oidc/login")
async def oidc_login() -> RedirectResponse:
    if not settings.setup_complete:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Complete first-time Authentik setup before signing in.",
        )
    if not settings.authentik_oidc_enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="OIDC login not enabled")

    issuer = normalize_issuer_url(settings.authentik_issuer_url)
    if len(issuer) <= 1:
        raise HTTPException(status_code=500, detail="AUTENTIK_ISSUER_URL not configured")

    cid = settings.authentik_client_id.strip()
    csec = settings.authentik_client_secret.strip()
    redirect_uri = settings.authentik_redirect_uri.strip()

    if not cid or not csec or not redirect_uri:
        raise HTTPException(
            status_code=500,
            detail="AUTENTIK_CLIENT_ID, AUTENTIK_CLIENT_SECRET, or AUTENTIK_REDIRECT_URI not configured",
        )

    discovery = await fetch_discovery(issuer)
    state = mint_oidc_state_jwt()
    url = build_authorize_url(state, discovery, redirect_uri)
    return RedirectResponse(url=url, status_code=302)


@router.get("/oidc/callback")
async def oidc_callback(
    request: Request,
    code: str | None = Query(None),
    state: str | None = Query(None),
    error: str | None = Query(None),
    error_description: str | None = Query(None),
) -> RedirectResponse:
    if not settings.setup_complete:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Complete first-time Authentik setup before signing in.",
        )
    if not settings.authentik_oidc_enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="OIDC login not enabled")

    base = _redirect_base_public_app(request)
    if not base:
        raise HTTPException(status_code=500, detail="PUBLIC_APP_URL is not set (and Host could not be derived)")

    if error:
        msg = quote(error_description or error, safe="")
        return RedirectResponse(url=f"{base}/oauth/callback#error={msg}", status_code=302)

    if not code or not state:
        return RedirectResponse(url=f"{base}/oauth/callback#error=missing_code_or_state", status_code=302)

    token = await finish_oidc_login(code=code, state=state)
    frag = quote(token, safe="")
    return RedirectResponse(url=f"{base}/oauth/callback#access_token={frag}", status_code=302)
