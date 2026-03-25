"""Jenkins CI/CD integration tools for Aegis MCP.

Provides functions to manage Jenkins jobs and builds via the Jenkins REST API
using the ``python-jenkins`` library.  Credentials (URL, username, API token)
are passed per-call so no global state or environment variables are required.
"""

from __future__ import annotations

import json
from typing import Any

import jenkins


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _client(url: str, username: str, api_token: str) -> jenkins.Jenkins:
    """Return a configured Jenkins client, raising RuntimeError on failure."""
    try:
        server = jenkins.Jenkins(url, username=username, password=api_token)
        # Verify credentials by fetching the server version header
        server.get_whoami()
        return server
    except jenkins.JenkinsException as exc:
        raise RuntimeError(
            f"Cannot connect to Jenkins at '{url}': {exc}"
        ) from exc
    except Exception as exc:
        raise RuntimeError(
            f"Jenkins connection error: {exc}"
        ) from exc


# ---------------------------------------------------------------------------
# Tool functions
# ---------------------------------------------------------------------------

def jenkins_list_jobs(url: str, username: str, api_token: str) -> list[dict]:
    """List all jobs on a Jenkins server.

    Returns a list of dicts with keys: name, url, color (build status indicator).
    """
    server = _client(url, username, api_token)
    try:
        jobs = server.get_all_jobs()
        return [
            {
                "name": j.get("name", ""),
                "url": j.get("url", ""),
                "color": j.get("color", ""),
            }
            for j in jobs
        ]
    except jenkins.JenkinsException as exc:
        raise RuntimeError(f"Failed to list Jenkins jobs: {exc}") from exc


def jenkins_get_job_info(
    url: str, username: str, api_token: str, job_name: str
) -> dict:
    """Get detailed information about a Jenkins job.

    Returns build history, health reports, and configuration details.
    """
    server = _client(url, username, api_token)
    try:
        info = server.get_job_info(job_name)
        return {
            "name": info.get("name", ""),
            "url": info.get("url", ""),
            "description": info.get("description", ""),
            "buildable": info.get("buildable", False),
            "color": info.get("color", ""),
            "last_build": info.get("lastBuild"),
            "last_successful_build": info.get("lastSuccessfulBuild"),
            "last_failed_build": info.get("lastFailedBuild"),
            "health_report": info.get("healthReport", []),
            "in_queue": info.get("inQueue", False),
        }
    except jenkins.NotFoundException:
        raise RuntimeError(f"Jenkins job '{job_name}' not found")
    except jenkins.JenkinsException as exc:
        raise RuntimeError(
            f"Failed to get info for job '{job_name}': {exc}"
        ) from exc


def jenkins_create_job(
    url: str,
    username: str,
    api_token: str,
    job_name: str,
    config_xml: str = "",
) -> dict:
    """Create a new Jenkins job.

    Args:
        url: Jenkins server URL.
        username: Jenkins username.
        api_token: Jenkins API token.
        job_name: Name for the new job.
        config_xml: Jenkins job configuration XML.  If empty, a minimal
            freestyle project config is used.

    Returns:
        Dict with the created job name and URL.
    """
    if not config_xml:
        config_xml = jenkins.EMPTY_CONFIG_XML

    server = _client(url, username, api_token)
    try:
        server.create_job(job_name, config_xml)
        return {
            "status": "created",
            "job_name": job_name,
            "url": f"{url.rstrip('/')}/job/{job_name}/",
        }
    except jenkins.JenkinsException as exc:
        raise RuntimeError(
            f"Failed to create job '{job_name}': {exc}"
        ) from exc


def jenkins_trigger_build(
    url: str,
    username: str,
    api_token: str,
    job_name: str,
    parameters: str = "",
) -> dict:
    """Trigger a build for a Jenkins job.

    Args:
        url: Jenkins server URL.
        username: Jenkins username.
        api_token: Jenkins API token.
        job_name: Name of the job to build.
        parameters: Optional JSON string of build parameters,
            e.g. '{"BRANCH": "main"}'.

    Returns:
        Dict with the queue item number.
    """
    server = _client(url, username, api_token)
    try:
        params: dict[str, Any] | None = None
        if parameters:
            params = json.loads(parameters)

        queue_item = server.build_job(job_name, parameters=params)
        return {
            "status": "triggered",
            "job_name": job_name,
            "queue_item": queue_item,
        }
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"Invalid parameters JSON: {exc}"
        ) from exc
    except jenkins.JenkinsException as exc:
        raise RuntimeError(
            f"Failed to trigger build for '{job_name}': {exc}"
        ) from exc


def jenkins_get_build_info(
    url: str,
    username: str,
    api_token: str,
    job_name: str,
    build_number: int,
) -> dict:
    """Get information about a specific build.

    Returns build result, duration, timestamp, and other metadata.
    """
    server = _client(url, username, api_token)
    try:
        info = server.get_build_info(job_name, build_number)
        return {
            "job_name": job_name,
            "build_number": info.get("number"),
            "result": info.get("result"),
            "duration_ms": info.get("duration"),
            "timestamp": info.get("timestamp"),
            "building": info.get("building", False),
            "url": info.get("url", ""),
            "display_name": info.get("displayName", ""),
        }
    except jenkins.NotFoundException:
        raise RuntimeError(
            f"Build #{build_number} not found for job '{job_name}'"
        )
    except jenkins.JenkinsException as exc:
        raise RuntimeError(
            f"Failed to get build info for '{job_name}' #{build_number}: {exc}"
        ) from exc


def jenkins_get_build_log(
    url: str,
    username: str,
    api_token: str,
    job_name: str,
    build_number: int,
) -> dict:
    """Fetch the console output of a Jenkins build.

    Returns the full console log as a string (truncated to 50 000 chars to
    keep MCP responses manageable).
    """
    server = _client(url, username, api_token)
    try:
        output = server.get_build_console_output(job_name, build_number)
        max_len = 50_000
        truncated = len(output) > max_len
        return {
            "job_name": job_name,
            "build_number": build_number,
            "log": output[:max_len],
            "truncated": truncated,
        }
    except jenkins.NotFoundException:
        raise RuntimeError(
            f"Build #{build_number} not found for job '{job_name}'"
        )
    except jenkins.JenkinsException as exc:
        raise RuntimeError(
            f"Failed to get build log for '{job_name}' #{build_number}: {exc}"
        ) from exc


def jenkins_delete_job(
    url: str, username: str, api_token: str, job_name: str
) -> dict:
    """Delete a Jenkins job.

    Returns confirmation dict on success.
    """
    server = _client(url, username, api_token)
    try:
        server.delete_job(job_name)
        return {
            "status": "deleted",
            "job_name": job_name,
        }
    except jenkins.NotFoundException:
        raise RuntimeError(f"Jenkins job '{job_name}' not found")
    except jenkins.JenkinsException as exc:
        raise RuntimeError(
            f"Failed to delete job '{job_name}': {exc}"
        ) from exc
