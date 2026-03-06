import unittest
from unittest.mock import patch, MagicMock

import requests

from tools.cicd.pipeline import pipeline_status


class TestPipelineStatus(unittest.TestCase):
    @patch("tools.cicd.pipeline.requests.get")
    def test_returns_pipeline_json(self, mock_get: MagicMock) -> None:
        mock_response = MagicMock()
        mock_response.json.return_value = {"id": "123", "status": "success"}
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        result = pipeline_status("https://ci.example.com", "123", "my-api-token")
        self.assertEqual(result["status"], "success")
        mock_get.assert_called_once_with(
            "https://ci.example.com/pipelines/123",
            headers={"Authorization": "Bearer my-api-token"},
            timeout=15,
        )

    @patch("tools.cicd.pipeline.requests.get", side_effect=requests.ConnectionError("connection refused"))
    def test_raises_runtime_error_on_connection_failure(self, _mock: MagicMock) -> None:
        with self.assertRaises(RuntimeError) as ctx:
            pipeline_status("https://ci.example.com", "123", "tok")
        self.assertIn("Cannot connect", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
