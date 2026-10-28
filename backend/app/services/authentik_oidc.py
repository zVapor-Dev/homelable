"""Authentik (OpenID Connect) authorization-code flow — token exchange and id_token validation."""

from __future__ import annotations

import asyncio
import logging
import secrets
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

import httpx
import jwt as pyjwt
from fastapi import HTTPException, status
from jose import JWTError
from jose import jwt as jose_jwt

from app.core.config import settings
from app.core.security import create_access_token

logger = logging.getLogger(__name__)

_DISCOVERY_TTL_S = 3600
_discovery_cache: dict[str, Any] | None = None
_discovery_fetched_at: float = 0.0
_cached_issuer_prefix: str | None = None

# Cloudflare / WAF often block non-browser-looking clients. JWKS must use the same fingerprint as token
# discovery/exchange (httpx). If the public JWKS URL still returns 403, set AUTHENTIK_JWKS_URI to an
# internal / alternate URL that serves the same JWKS JSON.
_OIDC_HTTP_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    ),
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.9",
}


@dataclass(frozen=True, slots=True)
class OidcIdentity:
    username: str
    groups: tuple[str, ...]
    permissions: tuple[str, ...]


def normalize_issuer_url(url: str) -> str:
    return url.strip().rstrip("/") + "/"


async def fetch_discovery(issuer_normalized: str) -> dict[str, Any]:
    global _discovery_cache, _discovery_fetched_at, _cached_issuer_prefix
    now = time.monotonic()
    if (
        _discovery_cache is not None
        and _cached_issuer_prefix == issuer_normalized
        and now - _discovery_fetched_at < _DISCOVERY_TTL_S
    ):
        return _discovery_cache

    well_known = f"{issuer_normalized}.well-known/openid-configuration"
    async with httpx.AsyncClient(timeout=30.0, headers=_OIDC_HTTP_HEADERS) as client:
        r = await client.get(well_known)
        r.raise_for_status()
        data = r.json()

    _discovery_cache = data
    _discovery_fetched_at = now
    _cached_issuer_prefix = issuer_normalized
    return data


def mint_oidc_state_jwt() -> str:
    from datetime import datetime, timedelta, timezone

    exp = datetime.now(timezone.utc) + timedelta(minutes=15)
    return str(
        jose_jwt.encode(
            {"s": secrets.token_hex(24), "exp": int(exp.timestamp())},
            settings.secret_key,
            algorithm="HS256",
        )
    )


def verify_oidc_state_jwt(token: str) -> None:
    try:
        jose_jwt.decode(token, settings.secret_key, algorithms=["HS256"])
    except JWTError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired OAuth state") from e


def build_authorize_url(state: str, discovery: dict[str, Any], redirect_uri: str) -> str:
    authorize = discovery["authorization_endpoint"]
    # "groups" is not standard OIDC scope text; Authentik accepts it when a scope/group mapping emits `groups`.
    q = urlencode({
        "client_id": settings.authentik_client_id,
        "response_type": "code",
        "scope": "openid profile email groups",
        "redirect_uri": redirect_uri,
        "state": state,
    })
    return f"{authorize}?{q}"


async def exchange_code_for_tokens(
    *,
    discovery: dict[str, Any],
    code: str,
    redirect_uri: str,
) -> dict[str, Any]:
    token_url = discovery["token_endpoint"]
    payload = {
        "grant_type": "authorization_code",
        "client_id": settings.authentik_client_id,
        "client_secret": settings.authentik_client_secret,
        "code": code,
        "redirect_uri": redirect_uri,
    }
    async with httpx.AsyncClient(timeout=30.0, headers=_OIDC_HTTP_HEADERS) as client:
        r = await client.post(
            token_url,
            data=payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
    if r.status_code >= 400:
        logger.warning("Authentik token exchange failed: %s %s", r.status_code, r.text[:500])
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="OAuth token exchange failed")
    body = r.json()
    id_token = body.get("id_token")
    if not id_token:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="OAuth response missing id_token")
    return body


def _flatten_claim_to_strs(val: Any) -> list[str]:
    if val is None:
        return []
    if isinstance(val, str):
        s = val.strip()
        return [s] if s else []
    if isinstance(val, dict) and "name" in val and isinstance(val.get("name"), str):
        # Authentik may emit group-like objects { "pk": ..., "name": "foo" }
        n = val["name"].strip()
        return [n] if n else []
    if isinstance(val, (list, tuple)):
        out: list[str] = []
        for item in val:
            out.extend(_flatten_claim_to_strs(item))
        return out
    s = str(val).strip()
    return [s] if s else []


def _oidc_group_tuple(claims: dict[str, Any]) -> tuple[str, ...]:
    names: list[str] = []
    for key in ("groups", "roles", "group_names"):
        names.extend(_flatten_claim_to_strs(claims.get(key)))
    for k, v in claims.items():
        if not isinstance(k, str):
            continue
        lk = k.lower()
        if "claims/groups" in lk or lk.endswith("/groups"):
            names.extend(_flatten_claim_to_strs(v))
    seen: set[str] = set()
    ordered: list[str] = []
    for n in names:
        if n not in seen:
            seen.add(n)
            ordered.append(n)
    return tuple(ordered)


def _oidc_permissions_tuple(claims: dict[str, Any]) -> tuple[str, ...]:
    names: list[str] = []
    for key in ("permissions", "perms"):
        names.extend(_flatten_claim_to_strs(claims.get(key)))
    for k, v in claims.items():
        if isinstance(k, str) and "claims/permissions" in k.lower():
            names.extend(_flatten_claim_to_strs(v))
    seen: set[str] = set()
    ordered: list[str] = []
    for n in names:
        if n not in seen:
            seen.add(n)
            ordered.append(n)
    return tuple(ordered)


def _resolve_jwks_signing_key(*, id_token: str, jwks_uri: str) -> Any:
    try:
        r = httpx.get(
            jwks_uri,
            headers=_OIDC_HTTP_HEADERS,
            timeout=30.0,
            follow_redirects=True,
        )
        r.raise_for_status()
    except httpx.HTTPStatusError as e:
        resp = e.response
        snippet = (resp.text[:400] if resp is not None else "") or ""
        code = resp.status_code if resp is not None else "?"
        logger.warning("JWKS HTTP %s from %s: %s", code, jwks_uri, snippet)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Could not fetch signing keys from the identity provider (JWKS)",
        ) from e
    except httpx.RequestError as e:
        logger.warning("JWKS request failed for %s: %s", jwks_uri, e)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Could not reach the identity provider JWKS endpoint",
        ) from e

    try:
        jwks = pyjwt.PyJWKSet.from_json(r.text)
    except pyjwt.PyJWTError as e:
        logger.warning("Invalid JWKS JSON from %s: %s", jwks_uri, e)
        raise HTTPException(status_code=500, detail="Invalid JWKS document from identity provider") from e

    try:
        header = pyjwt.get_unverified_header(id_token)
    except pyjwt.PyJWTError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Malformed id_token header") from e

    kid = header.get("kid")
    if not kid:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="id_token missing kid in header")

    try:
        jwk = jwks[str(kid)]
    except KeyError as e:
        logger.warning("No JWK for kid=%s", kid)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="id_token signing key not found in provider JWKS",
        ) from e
    return jwk.key


def verify_oidc_identity_sync(*, id_token: str, discovery: dict[str, Any]) -> OidcIdentity:
    jwks_uri = settings.authentik_jwks_uri.strip() or discovery.get("jwks_uri")
    if not jwks_uri:
        raise HTTPException(status_code=500, detail="OpenID discovery missing jwks_uri")

    issuer = discovery.get("issuer")
    if not isinstance(issuer, str) or not issuer.strip():
        raise HTTPException(status_code=500, detail="OpenID discovery missing issuer")

    signing_key = _resolve_jwks_signing_key(id_token=id_token, jwks_uri=str(jwks_uri))
    try:
        claims = pyjwt.decode(
            id_token,
            signing_key,
            algorithms=["RS256"],
            audience=settings.authentik_client_id,
            issuer=str(issuer),
        )
    except pyjwt.PyJWTError as e:
        logger.warning("id_token validation failed: %s", e)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid id_token") from e

    preferred = claims.get("preferred_username")
    if isinstance(preferred, str) and preferred.strip():
        username = preferred.strip()
    else:
        email = claims.get("email")
        if isinstance(email, str) and "@" in email:
            username = email.split("@", 1)[0].strip() or email.strip()
        else:
            sub = claims.get("sub")
            if isinstance(sub, str) and sub.strip():
                username = sub.strip()
            else:
                raise HTTPException(status_code=400, detail="id_token missing usable identity claims")

    return OidcIdentity(
        username=username,
        groups=_oidc_group_tuple(claims),
        permissions=_oidc_permissions_tuple(claims),
    )


async def finish_oidc_login(*, code: str, state: str) -> str:
    verify_oidc_state_jwt(state)
    issuer_normalized = normalize_issuer_url(settings.authentik_issuer_url)
    discovery = await fetch_discovery(issuer_normalized)

    redirect_uri = settings.authentik_redirect_uri.strip()
    if not redirect_uri:
        raise HTTPException(status_code=500, detail="AUTENTIK_REDIRECT_URI not configured")

    tokens = await exchange_code_for_tokens(discovery=discovery, code=code, redirect_uri=redirect_uri)
    id_token_str = str(tokens["id_token"])

    identity = await asyncio.to_thread(verify_oidc_identity_sync, id_token=id_token_str, discovery=discovery)
    return str(
        create_access_token(
            identity.username,
            groups=list(identity.groups),
            permissions=list(identity.permissions),
            auth_source="oidc",
        )
    )
