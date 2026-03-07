import unittest

from server.auth import AuthorizationError, Principal, authorize_tool, decode_bearer_token
from server.config import Settings

import base64
import json


def _make_jwt(claims: dict) -> str:
    """Build an unsigned JWT (header.payload.signature) for testing."""
    header = base64.urlsafe_b64encode(json.dumps({"alg": "none"}).encode()).rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    return f"{header}.{payload}.sig"


class TestAuthorizationDenied(unittest.TestCase):
    def test_authorize_tool_denies_wrong_role(self) -> None:
        principal = Principal(subject="u1", role="viewer", scopes=[])
        with self.assertRaises(AuthorizationError):
            authorize_tool(principal, "security_run_trivy_scan", {"viewer": ["k8s_list_pods"]}, {})

    def test_authorize_tool_denies_empty_policies(self) -> None:
        principal = Principal(subject="u1", role="admin", scopes=["aegis.read"])
        with self.assertRaises(AuthorizationError):
            authorize_tool(principal, "some_tool", {}, {})


class TestDecodeBearer(unittest.TestCase):
    def test_decode_extracts_claims(self) -> None:
        token = _make_jwt({"sub": "alice", "role": "admin", "scope": "aegis.read aegis.security"})
        settings = Settings()
        principal = decode_bearer_token(token, settings)
        self.assertEqual(principal.subject, "alice")
        self.assertEqual(principal.role, "admin")
        self.assertIn("aegis.read", principal.scopes)
        self.assertIn("aegis.security", principal.scopes)

    def test_decode_defaults_when_claims_missing(self) -> None:
        token = _make_jwt({})
        settings = Settings()
        principal = decode_bearer_token(token, settings)
        self.assertEqual(principal.subject, "unknown")
        self.assertEqual(principal.role, "viewer")
        self.assertEqual(principal.scopes, [])

    def test_decode_rejects_wrong_issuer(self) -> None:
        token = _make_jwt({"iss": "bad-issuer"})
        settings = Settings(oidc_issuer="https://idp.example.com")
        with self.assertRaises(AuthorizationError):
            decode_bearer_token(token, settings)

    def test_decode_rejects_wrong_audience(self) -> None:
        token = _make_jwt({"aud": "wrong-audience"})
        settings = Settings(oidc_audience="aegis-api")
        with self.assertRaises(AuthorizationError):
            decode_bearer_token(token, settings)


if __name__ == "__main__":
    unittest.main()
