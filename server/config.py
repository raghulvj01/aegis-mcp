from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover - dependency may be unavailable in restricted envs
    yaml = None


@dataclass(frozen=True)
class Settings:
    """Runtime configuration for the MCP service."""

    service_name: str = "devsecops"
    environment: str = "dev"
    policy_roles_path: Path = Path("policies/roles.yaml")
    policy_scopes_path: Path = Path("policies/scope_rules.yaml")
    oidc_issuer: str | None = None
    oidc_audience: str | None = None



def _parse_simple_yaml(raw: str) -> dict[str, Any]:
    """Fallback parser for simple mappings of key -> list[str]."""
    root: dict[str, Any] = {}
    current_section: dict[str, list[str]] | None = None
    current_key: str | None = None

    for line in raw.splitlines():
        stripped = line.rstrip()
        if not stripped or stripped.lstrip().startswith("#"):
            continue
        if not line.startswith(" ") and stripped.endswith(":"):
            section = stripped[:-1]
            root[section] = {}
            current_section = root[section]
            current_key = None
        elif current_section is not None and line.startswith("  ") and stripped.endswith(":"):
            current_key = stripped.strip()[:-1]
            current_section[current_key] = []
        elif current_section is not None and current_key and stripped.strip().startswith("-"):
            current_section[current_key].append(stripped.split("-", maxsplit=1)[1].strip().strip('"'))

    return root



def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}

    with path.open("r", encoding="utf-8") as handle:
        content = handle.read()

    if yaml is not None:
        return yaml.safe_load(content) or {}
    return _parse_simple_yaml(content)



def load_settings() -> Settings:
    return Settings(
        service_name=os.getenv("MCP_SERVICE_NAME", "devsecops"),
        environment=os.getenv("MCP_ENV", "dev"),
        policy_roles_path=Path(os.getenv("MCP_ROLES_FILE", "policies/roles.yaml")),
        policy_scopes_path=Path(os.getenv("MCP_SCOPES_FILE", "policies/scope_rules.yaml")),
        oidc_issuer=os.getenv("OIDC_ISSUER"),
        oidc_audience=os.getenv("OIDC_AUDIENCE"),
    )



def load_role_policies(settings: Settings) -> dict[str, list[str]]:
    raw = _load_yaml(settings.policy_roles_path)
    roles = raw.get("roles", {})
    return {str(k): [str(v) for v in values] for k, values in roles.items()}



def load_scope_policies(settings: Settings) -> dict[str, list[str]]:
    raw = _load_yaml(settings.policy_scopes_path)
    scopes = raw.get("scopes", {})
    return {str(k): [str(v) for v in values] for k, values in scopes.items()}
