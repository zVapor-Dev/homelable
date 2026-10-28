import hmac

from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.api.principal import AuthSource, Principal
from app.core.config import settings
from app.core.security import decode_principal

bearer = HTTPBearer(auto_error=False)


def get_current_principal(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    x_mcp_service_key: str | None = Header(default=None),
) -> Principal:
    # 1. MCP service key (Docker-internal only — backend port is not externally exposed)
    if x_mcp_service_key is not None:
        if not settings.mcp_service_key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="MCP service key not configured")
        if not hmac.compare_digest(x_mcp_service_key.encode(), settings.mcp_service_key.encode()):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid MCP service key")
        mcp: AuthSource = "mcp"
        return Principal(username="__mcp_service__", groups=(), permissions=("*",), auth_source=mcp)

    # 2. Standard JWT bearer token
    if credentials is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    principal = decode_principal(credentials.credentials)
    if principal is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    required = settings.access_required_group_names
    if principal.auth_source == "oidc" and required and not principal.has_any_group(required):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not a member of any group allowed to use this application",
        )

    return principal
