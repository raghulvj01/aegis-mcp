import unittest

from server.auth import Principal, authorize_tool


class TestAuthorization(unittest.TestCase):
    def test_authorize_tool_allows_role(self) -> None:
        principal = Principal(subject="u1", role="viewer", scopes=[])
        authorize_tool(principal, "k8s_list_pods", {"viewer": ["k8s_list_pods"]}, {})

    def test_authorize_tool_allows_scope(self) -> None:
        principal = Principal(subject="u2", role="none", scopes=["aegis.read"])
        authorize_tool(principal, "git_recent_commits", {}, {"aegis.read": ["git_recent_commits"]})


if __name__ == "__main__":
    unittest.main()
