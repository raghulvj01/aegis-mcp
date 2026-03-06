import unittest

from server.config import load_role_policies, load_scope_policies, load_settings


class TestConfig(unittest.TestCase):
    def test_load_settings_defaults(self) -> None:
        settings = load_settings()
        self.assertTrue(settings.service_name)
        self.assertTrue(settings.environment)

    def test_policy_files_load(self) -> None:
        settings = load_settings()
        roles = load_role_policies(settings)
        scopes = load_scope_policies(settings)
        self.assertIn("viewer", roles)
        self.assertIn("devsecops.read", scopes)


if __name__ == "__main__":
    unittest.main()
