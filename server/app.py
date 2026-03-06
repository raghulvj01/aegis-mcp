from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from audit.audit_logger import audit_tool_call
from server.auth import authorize_tool, decode_bearer_token
from server.config import load_role_policies, load_scope_policies, load_settings
from tools.aws.ec2 import list_ec2_instances
from tools.git.repo import get_recent_commits
from tools.kubernetes.pods import list_pods
from tools.security.trivy import run_trivy_scan


def build_mcp() -> FastMCP:
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

    return mcp
