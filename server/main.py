from __future__ import annotations

import os

from mcp.server.fastmcp import FastMCP

from audit.audit_logger import audit_tool_call
from server.auth import authorize_tool, decode_bearer_token
from server.config import load_role_policies, load_scope_policies, load_settings
from tools.aws.ec2 import list_ec2_instances
from tools.aws.s3 import check_s3_public_access
from tools.cicd.pipeline import pipeline_status
from tools.git.repo import get_recent_commits
from tools.kubernetes.pods import list_pods
from tools.kubernetes.audit import k8s_security_audit
from tools.network.headers import check_http_headers
from tools.network.port_scanner import port_scan
from tools.network.ssl_checker import check_ssl_certificate
from tools.security.deps import check_dependencies
from tools.security.secrets import scan_secrets
from tools.security.semgrep import run_semgrep_scan
from tools.security.trivy import run_trivy_scan

settings = load_settings()
role_policies = load_role_policies(settings)
scope_policies = load_scope_policies(settings)

mcp = FastMCP(settings.service_name, json_response=True)

AUTH_DISABLED = os.getenv("MCP_AUTH_DISABLED", "false").lower() == "true"


def _authorize(token: str, tool_name: str) -> None:
    if AUTH_DISABLED or not token:
        return
    principal = decode_bearer_token(token, settings)
    authorize_tool(principal, tool_name, role_policies, scope_policies)


@mcp.tool()
@audit_tool_call("aws_list_ec2_instances")
def aws_list_ec2_instances(region: str, token: str = "") -> list[dict]:
    _authorize(token, "aws_list_ec2_instances")
    return list_ec2_instances(region)


@mcp.tool()
@audit_tool_call("k8s_list_pods")
def k8s_list_pods(namespace: str = "default", token: str = "") -> list[dict]:
    _authorize(token, "k8s_list_pods")
    return list_pods(namespace)


@mcp.tool()
@audit_tool_call("k8s_security_audit")
def k8s_security_audit_tool(namespace: str = "", token: str = "") -> list[dict]:
    """Audit Kubernetes clusters for misconfigurations and security risks (privileged containers, hostNetwork, exposed NodePorts, cluster-admin service accounts)."""
    _authorize(token, "k8s_security_audit")
    return k8s_security_audit(namespace)


@mcp.tool()
@audit_tool_call("security_run_trivy_scan")
def security_run_trivy_scan(image: str, token: str = "") -> dict:
    _authorize(token, "security_run_trivy_scan")
    return run_trivy_scan(image)


@mcp.tool()
@audit_tool_call("git_recent_commits")
def git_recent_commits(limit: int = 10, token: str = "") -> list[dict[str, str]]:
    _authorize(token, "git_recent_commits")
    return get_recent_commits(limit)


@mcp.tool()
@audit_tool_call("cicd_pipeline_status")
def cicd_pipeline_status(base_url: str, pipeline_id: str, api_token: str, token: str = "") -> dict:
    """Fetch the status of a CI/CD pipeline."""
    _authorize(token, "cicd_pipeline_status")
    return pipeline_status(base_url, pipeline_id, api_token)


# ── New zero-install tools ─────────────────────────────────────────


@mcp.tool()
@audit_tool_call("security_scan_secrets")
def security_scan_secrets(path: str, token: str = "") -> list[dict]:
    """Scan local files or directories for exposed secrets (API keys, tokens, passwords). This tool runs locally and has full access to the user's local filesystem (e.g. C:\\... paths)."""
    _authorize(token, "security_scan_secrets")
    return scan_secrets(path)


@mcp.tool()
@audit_tool_call("security_check_ssl_certificate")
def security_check_ssl_certificate(hostname: str, port: int = 443, token: str = "") -> dict:
    """Check SSL/TLS certificate details and expiry for a domain."""
    _authorize(token, "security_check_ssl_certificate")
    return check_ssl_certificate(hostname, port)


@mcp.tool()
@audit_tool_call("security_check_dependencies")
def security_check_dependencies(file_path: str, token: str = "") -> list[dict]:
    """Scan dependency files (requirements.txt, package.json) for known vulnerabilities via OSV.dev."""
    _authorize(token, "security_check_dependencies")
    return check_dependencies(file_path)


@mcp.tool()
@audit_tool_call("security_check_http_headers")
def security_check_http_headers(url: str, token: str = "") -> dict:
    """Audit HTTP security headers (HSTS, CSP, X-Frame-Options, etc.) for a URL."""
    _authorize(token, "security_check_http_headers")
    return check_http_headers(url)


@mcp.tool()
@audit_tool_call("aws_check_s3_public_access")
def aws_check_s3_public_access(region: str = "us-east-1", token: str = "") -> list[dict]:
    """Audit S3 buckets for public access settings."""
    _authorize(token, "aws_check_s3_public_access")
    return check_s3_public_access(region)


@mcp.tool()
@audit_tool_call("network_port_scan")
def network_port_scan(host: str, ports: str = "", token: str = "") -> list[dict]:
    """Perform a TCP port scan on common service ports for a host."""
    _authorize(token, "network_port_scan")
    return port_scan(host, ports)


@mcp.tool()
@audit_tool_call("security_semgrep_scan")
def security_semgrep_scan(path: str, config: str = "auto", token: str = "") -> dict:
    """Run a Semgrep SAST scan on a local directory or file. This tool runs locally and has full access to the user's local filesystem (e.g. C:\\... paths). Config can be 'auto', 'p/python', 'p/javascript', etc."""
    _authorize(token, "security_semgrep_scan")
    return run_semgrep_scan(path, config)


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
