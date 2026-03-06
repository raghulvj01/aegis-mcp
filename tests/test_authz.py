import unittest

from server.auth import AuthorizationError, Principal, authorize_tool


class TestAuthorization(unittest.TestCase):
    def test_authorize_tool_allows_role(self) -> None:
        principal = Principal(subject="u1", role="viewer", scopes=[])
        authorize_tool(principal, "k8s_list_pods", {"viewer": ["k8s_list_pods"]}, {})

    def test_authorize_tool_allows_scope(self) -> None:
        principal = Principal(subject="u2", role="none", scopes=["devsecops.read"])
        authorize_tool(principal, "git_recent_commits", {}, {"devsecops.read": ["git_recent_commits"]})

    def test_authorize_tool_denies_unknown_tool(self) -> None:
        principal = Principal(subject="u3", role="viewer", scopes=[])
        with self.assertRaises(AuthorizationError):
            authorize_tool(principal, "security_run_trivy_scan", {"viewer": ["k8s_list_pods"]}, {})


if __name__ == "__main__":
    unittest.main()
