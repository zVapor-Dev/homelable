"""Authenticated principal (API user) including optional OIDC groups and permissions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

AuthSource = Literal["local", "oidc", "mcp"]


@dataclass(frozen=True, slots=True)
class Principal:
    username: str
    groups: tuple[str, ...] = ()
    permissions: tuple[str, ...] = ()
    auth_source: AuthSource = "local"

    def has_any_group(self, names: frozenset[str]) -> bool:
        if not names:
            return True
        return bool(names & frozenset(self.groups))

    def has_permission(self, perm: str) -> bool:
        if "*" in self.permissions:
            return True
        return perm in self.permissions
