import unittest
from unittest.mock import patch, MagicMock

from tools.git.repo import get_recent_commits


class TestGitRecentCommits(unittest.TestCase):
    @patch("tools.git.repo.subprocess.check_output")
    def test_returns_parsed_commits(self, mock_output: MagicMock) -> None:
        mock_output.return_value = "abc123|Alice|Initial commit\ndef456|Bob|Add feature"
        commits = get_recent_commits(limit=2)
        self.assertEqual(len(commits), 2)
        self.assertEqual(commits[0]["hash"], "abc123")
        self.assertEqual(commits[0]["author"], "Alice")
        self.assertEqual(commits[1]["subject"], "Add feature")

    @patch("tools.git.repo.subprocess.check_output")
    def test_returns_empty_for_no_output(self, mock_output: MagicMock) -> None:
        mock_output.return_value = ""
        commits = get_recent_commits(limit=5)
        self.assertEqual(commits, [])

    @patch("tools.git.repo.subprocess.check_output", side_effect=FileNotFoundError)
    def test_raises_on_missing_git(self, _mock: MagicMock) -> None:
        with self.assertRaises(RuntimeError) as ctx:
            get_recent_commits()
        self.assertIn("git is not installed", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
