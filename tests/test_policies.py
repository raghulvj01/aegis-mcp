import unittest

from server.config import load_role_policies, load_scope_policies, Settings


class TestPolicies(unittest.TestCase):
    def test_role_policies_include_cicd(self) -> None:
        settings = Settings()
        policies = load_role_policies(settings)
        self.assertIn("cicd_pipeline_status", policies.get("admin", []))

    def test_scope_policies_include_cicd(self) -> None:
        settings = Settings()
        policies = load_scope_policies(settings)
        self.assertIn("cicd_pipeline_status", policies.get("devsecops.read", []))

    def test_viewer_cannot_access_trivy(self) -> None:
        settings = Settings()
        policies = load_role_policies(settings)
        self.assertNotIn("security_run_trivy_scan", policies.get("viewer", []))


if __name__ == "__main__":
    unittest.main()
