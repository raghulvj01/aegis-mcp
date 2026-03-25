"""Unit tests for Jenkins CI/CD integration tools."""

import unittest
from unittest.mock import patch, MagicMock

import jenkins

from tools.cicd.jenkins import (
    jenkins_list_jobs,
    jenkins_get_job_info,
    jenkins_create_job,
    jenkins_trigger_build,
    jenkins_get_build_info,
    jenkins_get_build_log,
    jenkins_delete_job,
)

URL = "https://jenkins.example.com"
USER = "admin"
TOKEN = "api-token-123"


class TestJenkinsListJobs(unittest.TestCase):
    @patch("tools.cicd.jenkins.jenkins.Jenkins")
    def test_returns_job_list(self, MockJenkins):
        server = MockJenkins.return_value
        server.get_whoami.return_value = {"fullName": "admin"}
        server.get_all_jobs.return_value = [
            {"name": "build-app", "url": "https://jenkins.example.com/job/build-app/", "color": "blue"},
            {"name": "deploy", "url": "https://jenkins.example.com/job/deploy/", "color": "red"},
        ]

        result = jenkins_list_jobs(URL, USER, TOKEN)

        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["name"], "build-app")
        self.assertEqual(result[1]["color"], "red")


class TestJenkinsGetJobInfo(unittest.TestCase):
    @patch("tools.cicd.jenkins.jenkins.Jenkins")
    def test_returns_job_details(self, MockJenkins):
        server = MockJenkins.return_value
        server.get_whoami.return_value = {"fullName": "admin"}
        server.get_job_info.return_value = {
            "name": "build-app",
            "url": "https://jenkins.example.com/job/build-app/",
            "description": "Main build",
            "buildable": True,
            "color": "blue",
            "lastBuild": {"number": 42},
            "lastSuccessfulBuild": {"number": 42},
            "lastFailedBuild": None,
            "healthReport": [{"score": 100}],
            "inQueue": False,
        }

        result = jenkins_get_job_info(URL, USER, TOKEN, "build-app")

        self.assertEqual(result["name"], "build-app")
        self.assertTrue(result["buildable"])
        self.assertEqual(result["last_build"]["number"], 42)


class TestJenkinsCreateJob(unittest.TestCase):
    @patch("tools.cicd.jenkins.jenkins.Jenkins")
    def test_creates_job_successfully(self, MockJenkins):
        server = MockJenkins.return_value
        server.get_whoami.return_value = {"fullName": "admin"}

        result = jenkins_create_job(URL, USER, TOKEN, "new-job")

        server.create_job.assert_called_once()
        self.assertEqual(result["status"], "created")
        self.assertEqual(result["job_name"], "new-job")

    @patch("tools.cicd.jenkins.jenkins.Jenkins")
    def test_creates_job_with_custom_xml(self, MockJenkins):
        server = MockJenkins.return_value
        server.get_whoami.return_value = {"fullName": "admin"}
        custom_xml = "<project><description>Custom</description></project>"

        result = jenkins_create_job(URL, USER, TOKEN, "custom-job", config_xml=custom_xml)

        server.create_job.assert_called_once_with("custom-job", custom_xml)
        self.assertEqual(result["status"], "created")


class TestJenkinsTriggerBuild(unittest.TestCase):
    @patch("tools.cicd.jenkins.jenkins.Jenkins")
    def test_triggers_build_without_params(self, MockJenkins):
        server = MockJenkins.return_value
        server.get_whoami.return_value = {"fullName": "admin"}
        server.build_job.return_value = 101

        result = jenkins_trigger_build(URL, USER, TOKEN, "build-app")

        server.build_job.assert_called_once_with("build-app", parameters=None)
        self.assertEqual(result["status"], "triggered")
        self.assertEqual(result["queue_item"], 101)

    @patch("tools.cicd.jenkins.jenkins.Jenkins")
    def test_triggers_build_with_params(self, MockJenkins):
        server = MockJenkins.return_value
        server.get_whoami.return_value = {"fullName": "admin"}
        server.build_job.return_value = 102

        result = jenkins_trigger_build(URL, USER, TOKEN, "build-app", parameters='{"BRANCH": "main"}')

        server.build_job.assert_called_once_with("build-app", parameters={"BRANCH": "main"})
        self.assertEqual(result["queue_item"], 102)


class TestJenkinsGetBuildInfo(unittest.TestCase):
    @patch("tools.cicd.jenkins.jenkins.Jenkins")
    def test_returns_build_details(self, MockJenkins):
        server = MockJenkins.return_value
        server.get_whoami.return_value = {"fullName": "admin"}
        server.get_build_info.return_value = {
            "number": 42,
            "result": "SUCCESS",
            "duration": 12000,
            "timestamp": 1700000000000,
            "building": False,
            "url": "https://jenkins.example.com/job/build-app/42/",
            "displayName": "#42",
        }

        result = jenkins_get_build_info(URL, USER, TOKEN, "build-app", 42)

        self.assertEqual(result["result"], "SUCCESS")
        self.assertEqual(result["build_number"], 42)
        self.assertFalse(result["building"])


class TestJenkinsGetBuildLog(unittest.TestCase):
    @patch("tools.cicd.jenkins.jenkins.Jenkins")
    def test_returns_console_output(self, MockJenkins):
        server = MockJenkins.return_value
        server.get_whoami.return_value = {"fullName": "admin"}
        server.get_build_console_output.return_value = "Started by user admin\nBUILD SUCCESS"

        result = jenkins_get_build_log(URL, USER, TOKEN, "build-app", 42)

        self.assertIn("BUILD SUCCESS", result["log"])
        self.assertFalse(result["truncated"])


class TestJenkinsDeleteJob(unittest.TestCase):
    @patch("tools.cicd.jenkins.jenkins.Jenkins")
    def test_deletes_job(self, MockJenkins):
        server = MockJenkins.return_value
        server.get_whoami.return_value = {"fullName": "admin"}

        result = jenkins_delete_job(URL, USER, TOKEN, "old-job")

        server.delete_job.assert_called_once_with("old-job")
        self.assertEqual(result["status"], "deleted")


class TestJenkinsConnectionError(unittest.TestCase):
    @patch("tools.cicd.jenkins.jenkins.Jenkins")
    def test_raises_runtime_error_on_auth_failure(self, MockJenkins):
        MockJenkins.return_value.get_whoami.side_effect = jenkins.JenkinsException("401")

        with self.assertRaises(RuntimeError) as ctx:
            jenkins_list_jobs(URL, USER, "bad-token")

        self.assertIn("Cannot connect", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
