import json
import logging
from pathlib import Path
from typing import Any

from pydantic import PrivateAttr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)

def _read_version() -> str:
    for candidate in [
        Path(__file__).parent.parent.parent.parent / "VERSION",  # repo root (dev)
        Path("/app/VERSION"),                                      # Docker image
    ]:
        if candidate.exists():
            return candidate.read_text().strip()
    return "unknown"

APP_VERSION = _read_version()


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    secret_key: str  # Required — set SECRET_KEY in .env
    sqlite_path: str = "./data/homelab.db"
    cors_origins: list[str] = ["http://localhost:5173", "http://localhost:3000"]

    # JWT
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 1440  # 24h

    # Auth — legacy local login (disabled by default once auth_config.json exists).
    auth_username: str = "admin"
    auth_password_hash: str = ""

    @model_validator(mode="after")
    def check_password_hash(self) -> "Settings":
        h = self.auth_password_hash
        if h and not h.startswith("$2"):
            logger.error(
                "AUTH_PASSWORD_HASH looks invalid (does not start with '$2b$'). "
                "bcrypt hashes contain '$' signs — wrap the value in single quotes "
                "in your .env file: AUTH_PASSWORD_HASH='$2b$12$...'"
            )
        return self

    # Local password login (emergency). Prefer false; can be toggled in Settings after OIDC works.
    allow_local_login: bool = False

    # Comma-separated Authentik group names. If non-empty, users who signed in via OIDC must be in
    # at least one listed group. Local login and the MCP service key are not subject to this check.
    access_required_groups: str = ""

    # If set, POST /api/v1/setup/complete must send header X-Homelabable-Setup-Secret matching this value.
    homelabable_setup_secret: str = ""

    # Scanner
    scanner_ranges: list[str] = ["192.168.1.0/24"]

    # Status checker
    status_checker_interval: int = 60

    # MCP service key — set MCP_SERVICE_KEY in .env
    mcp_service_key: str = ""

    # Authentik OpenID Connect — env defaults; overridden by data/auth_config.json when present.
    authentik_oidc_enabled: bool = False
    authentik_issuer_url: str = ""
    authentik_client_id: str = ""
    authentik_client_secret: str = ""
    authentik_redirect_uri: str = ""
    public_app_url: str = ""
    # Full JWKS URL; use when discovery `jwks_uri` is unreachable from Docker (CDN 403).
    # Must return the same key set as issuer metadata. Env: AUTHENTIK_JWKS_URI.
    authentik_jwks_uri: str = ""

    # Live view — optional read-only public canvas endpoint.
    liveview_key: str | None = None

    _setup_complete_from_file: bool = PrivateAttr(default=False)

    @property
    def setup_complete(self) -> bool:
        """Ready for normal app use: auth_config.json marked complete, or fully configured via env."""
        if self._setup_complete_from_file:
            return True
        return self._env_oidc_fully_configured()

    def _env_oidc_fully_configured(self) -> bool:
        return bool(
            self.authentik_oidc_enabled
            and self.authentik_issuer_url.strip()
            and self.authentik_client_id.strip()
            and self.authentik_client_secret.strip()
            and self.authentik_redirect_uri.strip()
        )

    @property
    def access_required_group_names(self) -> frozenset[str]:
        return frozenset(x.strip() for x in self.access_required_groups.split(",") if x.strip())

    def _auth_config_path(self) -> Path:
        return Path(self.sqlite_path).parent / "auth_config.json"

    def reload_auth_from_disk(self) -> None:
        """Load SSO + setup flags from auth_config.json when it exists."""
        path = self._auth_config_path()
        if not path.exists():
            self._setup_complete_from_file = False
            return

        try:
            data = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError) as exc:
            logger.error("Cannot read auth_config.json: %s", exc)
            self._setup_complete_from_file = False
            return

        self._setup_complete_from_file = bool(data.get("setup_complete", False))
        self.allow_local_login = bool(data.get("allow_local_login", False))
        self.authentik_oidc_enabled = bool(data.get("authentik_oidc_enabled", True))
        self.authentik_issuer_url = str(data.get("authentik_issuer_url") or "").strip()
        self.authentik_client_id = str(data.get("authentik_client_id") or "").strip()
        self.authentik_client_secret = str(data.get("authentik_client_secret") or "").strip()
        self.authentik_redirect_uri = str(data.get("authentik_redirect_uri") or "").strip()
        self.public_app_url = str(data.get("public_app_url") or "").strip()

    def save_auth_settings_to_disk(self, data: dict[str, Any]) -> None:
        """Persist SSO settings file (typically from authenticated Settings PUT). Keeps setup_complete=true."""
        path = self._auth_config_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2))
        self.reload_auth_from_disk()

    def _override_path(self) -> Path:
        return Path(self.sqlite_path).parent / "scan_config.json"

    def load_overrides(self) -> None:
        """Load runtime scan config overrides written by the API."""
        try:
            data = json.loads(self._override_path().read_text())
            if "scanner_ranges" in data:
                self.scanner_ranges = data["scanner_ranges"]
            if "status_checker_interval" in data:
                self.status_checker_interval = int(data["status_checker_interval"])
        except Exception:
            pass

    def save_overrides(self) -> None:
        """Persist scan config so it survives container restarts."""
        self._override_path().parent.mkdir(parents=True, exist_ok=True)
        self._override_path().write_text(json.dumps({
            "scanner_ranges": self.scanner_ranges,
            "status_checker_interval": self.status_checker_interval,
        }))


settings = Settings()  # type: ignore[call-arg]

settings.reload_auth_from_disk()
