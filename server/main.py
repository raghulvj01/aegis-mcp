from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from audit.audit_logger import audit_tool_call
from server.auth import authorize_tool, decode_bearer_token
from server.config import load_role_policies, load_scope_policies, load_settings
from tools.aws.ec2 import list_ec2_instances
from tools.cicd.pipeline import pipeline_status
from tools.git.repo import get_recent_commits
from tools.kubernetes.pods import list_pods
from tools.security.trivy import run_trivy_scan

settings = load_settings()
role_policies = load_role_policies(settings)
scope_policies = load_scope_policies(settings)

mcp = FastMCP(settings.service_name, json_response=True)


def _authorize(token: str, tool_name: str) -> None:
    principal = decode_bearer_token(token, settings)
    authorize_tool(principal, tool_name, role_policies, scope_policies)


@mcp.tool()
@audit_tool_call("aws_list_ec2_instances")
def aws_list_ec2_instances(token: str, region: str) -> list[dict]:
    _authorize(token, "aws_list_ec2_instances")
    return list_ec2_instances(region)


@mcp.tool()
@audit_tool_call("k8s_list_pods")
def k8s_list_pods(token: str, namespace: str = "default") -> list[dict]:
    _authorize(token, "k8s_list_pods")
    return list_pods(namespace)


@mcp.tool()
@audit_tool_call("security_run_trivy_scan")
def security_run_trivy_scan(token: str, image: str) -> dict:
    _authorize(token, "security_run_trivy_scan")
    return run_trivy_scan(image)


@mcp.tool()
@audit_tool_call("git_recent_commits")
def git_recent_commits(token: str, limit: int = 10) -> list[dict[str, str]]:
    _authorize(token, "git_recent_commits")
    return get_recent_commits(limit)


@mcp.tool()
@audit_tool_call("cicd_pipeline_status")
def cicd_pipeline_status(token: str, base_url: str, pipeline_id: str, api_token: str) -> dict:
    """Fetch the status of a CI/CD pipeline."""
    _authorize(token, "cicd_pipeline_status")
    return pipeline_status(base_url, pipeline_id, api_token)


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
