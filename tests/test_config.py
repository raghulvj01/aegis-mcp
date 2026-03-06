import unittest

from server.config import load_settings


class TestConfig(unittest.TestCase):
    def test_load_settings_defaults(self) -> None:
        settings = load_settings()
        self.assertTrue(settings.service_name)
        self.assertTrue(settings.environment)


if __name__ == "__main__":
    unittest.main()
