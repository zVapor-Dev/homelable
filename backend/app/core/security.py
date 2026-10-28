from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.api.principal import AuthSource, Principal
from app.core.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def _coerce_str_tuple(val: Any) -> tuple[str, ...]:
    if val is None:
        return ()
    if isinstance(val, str):
        s = val.strip()
        return (s,) if s else ()
    if isinstance(val, (list, tuple)):
        return tuple(str(x).strip() for x in val if str(x).strip())
    return ()


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bool(pwd_context.verify(plain, hashed))
    except ValueError:
        return False


def hash_password(password: str) -> str:
    return str(pwd_context.hash(password))


def create_access_token(
    subject: str,
    *,
    groups: list[str] | None = None,
    permissions: list[str] | None = None,
    auth_source: Literal["local", "oidc"] = "local",
) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.access_token_expire_minutes)
    payload: dict[str, Any] = {"sub": subject, "exp": expire, "auth": auth_source}
    if groups:
        payload["groups"] = list(groups)
    if permissions:
        payload["permissions"] = list(permissions)
    return str(jwt.encode(payload, settings.secret_key, algorithm=settings.algorithm))


def decode_principal(token: str) -> Principal | None:
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
    except JWTError:
        return None
    sub = payload.get("sub")
    if sub is None:
        return None
    auth_raw = payload.get("auth")
    if auth_raw == "oidc":
        auth_source: AuthSource = "oidc"
    elif auth_raw == "local":
        auth_source = "local"
    else:
        auth_source = "local"
    return Principal(
        username=str(sub),
        groups=_coerce_str_tuple(payload.get("groups")),
        permissions=_coerce_str_tuple(payload.get("permissions")),
        auth_source=auth_source,
    )


def decode_token(token: str) -> str | None:
    p = decode_principal(token)
    return p.username if p else None
