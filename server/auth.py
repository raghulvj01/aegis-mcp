from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any

from server.config import Settings

try:
    import jwt  # type: ignore
except Exception:  # pragma: no cover - dependency may be unavailable in restricted envs
    jwt = None


@dataclass(frozen=True)
class Principal:
    subject: str
    role: str
    scopes: list[str]


class AuthorizationError(PermissionError):
    pass



def _decode_payload_without_verification(token: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) < 2:
        raise AuthorizationError("invalid token format")

    payload = parts[1]
    payload += "=" * (-len(payload) % 4)
    try:
        decoded = base64.urlsafe_b64decode(payload.encode("utf-8")).decode("utf-8")
        return json.loads(decoded)
    except Exception as exc:  # noqa: BLE001
        raise AuthorizationError("invalid token payload") from exc



def decode_bearer_token(token: str, settings: Settings) -> Principal:
    """Decode token claims.

    NOTE: this scaffold only verifies issuer/audience constraints. Replace with JWKS
    signature verification in production.
    """
    if jwt is not None:
        options: dict[str, Any] = {
            "verify_signature": False,
            "verify_exp": True,
        }

        try:
            claims = jwt.decode(  # type: ignore[union-attr]
                token,
                options=options,
                algorithms=["RS256", "HS256"],
                audience=settings.oidc_audience,
                issuer=settings.oidc_issuer,
            )
        except Exception as exc:  # noqa: BLE001
            raise AuthorizationError(f"invalid token: {exc}") from exc
    else:
        claims = _decode_payload_without_verification(token)
        if settings.oidc_issuer and claims.get("iss") != settings.oidc_issuer:
            raise AuthorizationError("token issuer mismatch")
        aud = claims.get("aud")
        if settings.oidc_audience and settings.oidc_audience not in str(aud):
            raise AuthorizationError("token audience mismatch")

    role = str(claims.get("role", "viewer"))
    scope_claim = claims.get("scope", "")
    scopes = scope_claim.split() if isinstance(scope_claim, str) else []

    return Principal(subject=str(claims.get("sub", "unknown")), role=role, scopes=scopes)



def authorize_tool(
    principal: Principal,
    tool_name: str,
    role_policies: dict[str, list[str]],
    scope_policies: dict[str, list[str]],
) -> None:
    allowed_by_role = set(role_policies.get(principal.role, []))
    allowed_by_scope: set[str] = set()

    for scope in principal.scopes:
        allowed_by_scope.update(scope_policies.get(scope, []))

    if tool_name in allowed_by_role or tool_name in allowed_by_scope:
        return

    raise AuthorizationError(
        f"principal '{principal.subject}' with role '{principal.role}' is not allowed to call '{tool_name}'"
    )
