from __future__ import annotations

import base64
import json
from dataclasses import dataclass

from server.config import Settings


@dataclass(frozen=True)
class Principal:
    subject: str
    role: str
    scopes: list[str]


class AuthorizationError(PermissionError):
    pass



def _decode_jwt_payload(token: str) -> dict:
    parts = token.split(".")
    if len(parts) < 2:
        return {}
    payload = parts[1]
    padding = "=" * ((4 - len(payload) % 4) % 4)
    decoded = base64.urlsafe_b64decode(payload + padding)
    return json.loads(decoded.decode("utf-8"))



def decode_bearer_token(token: str, settings: Settings) -> Principal:
    """Decode claims from a bearer token payload.

    This implementation parses JWT payload claims and is intended as a scaffold.
    Replace with strict signature/JWKS validation in production.
    """
    claims = _decode_jwt_payload(token)

    if settings.oidc_issuer and claims.get("iss") != settings.oidc_issuer:
        raise AuthorizationError("token issuer mismatch")
    if settings.oidc_audience and settings.oidc_audience not in str(claims.get("aud", "")):
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
