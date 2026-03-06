# DevSecOps MCP Server

An internal [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server for DevOps and SecOps workflows. It exposes domain-specific tools for **AWS**, **Kubernetes**, **Security scanning**, and **Git** operations while enforcing role-based access control (RBAC) and emitting structured audit logs for every invocation.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Getting Started](#getting-started)
  - [Local Development](#local-development)
  - [ASGI with Health Endpoint](#asgi-with-health-endpoint)
  - [Docker](#docker)
- [Configuration](#configuration)
  - [Environment Variables](#environment-variables)
- [MCP Tools Reference](#mcp-tools-reference)
  - [aws\_list\_ec2\_instances](#aws_list_ec2_instances)
  - [k8s\_list\_pods](#k8s_list_pods)
  - [security\_run\_trivy\_scan](#security_run_trivy_scan)
  - [git\_recent\_commits](#git_recent_commits)
  - [cicd\_pipeline\_status](#cicd_pipeline_status)
- [Authentication and Authorization](#authentication-and-authorization)
  - [JWT Identity Extraction](#jwt-identity-extraction)
  - [Role-Based Access Control](#role-based-access-control)
  - [Scope-Based Access Control](#scope-based-access-control)
  - [Authorization Flow](#authorization-flow)
- [Policy Files](#policy-files)
  - [roles.yaml](#rolesyaml)
  - [scope\_rules.yaml](#scope_rulesyaml)
- [Audit Logging](#audit-logging)
- [Testing](#testing)
- [Security Best Practices](#security-best-practices)
- [Contributing](#contributing)
- [License](#license)

---

## Features

- **FastMCP server** with domain-specific tools for AWS, Kubernetes, security scanning, Git, and CI/CD pipelines.
- **JWT-based identity extraction** with tool-level RBAC checks.
- **Structured JSON audit logs** for every tool invocation (started, succeeded, failed with duration).
- **Policy-driven authorization** via externalized YAML files (`policies/roles.yaml` and `policies/scope_rules.yaml`).
- **Containerized deployment** with non-root runtime user and built-in health checks.
- **ASGI integration** with a FastAPI health endpoint alongside the MCP transport.

---

## Architecture

```
┌──────────────┐       ┌──────────────────────────────────┐
│  MCP Client  │──────▶│         FastMCP Server           │
│  (AI Agent)  │       │                                  │
└──────────────┘       │  ┌───────────┐  ┌─────────────┐  │
                       │  │ JWT Auth  │  │ Audit Logger│  │
                       │  └─────┬─────┘  └──────┬──────┘  │
                       │        │               │         │
                       │  ┌─────▼───────────────▼──────┐  │
                       │  │     Tool Dispatch Layer     │  │
                       │  └─────┬───┬───┬───┬──────────┘  │
                       └────────┼───┼───┼───┼─────────────┘
                                │   │   │   │
               ┌────────────────┘   │   │   └───────────────┐
               ▼                    ▼   ▼                   ▼
        ┌──────────┐     ┌──────┐ ┌──────────┐      ┌──────────┐
        │ AWS EC2  │     │ k8s  │ │  Trivy   │      │   Git    │
        │ (boto3)  │     │(kubectl)│(CLI scan)│      │  (CLI)   │
        └──────────┘     └──────┘ └──────────┘      └──────────┘
```

The server receives MCP tool-call requests over **streamable HTTP**. Each request carries a JWT bearer token that is decoded to extract the caller's identity (subject, role, scopes). The authorization layer checks the requested tool against YAML-defined role and scope policies. On success, the domain tool is invoked and an audit log entry is emitted.

---

## Project Structure

```
devsecops-mcp/
├── server/                  # Core MCP service modules
│   ├── __init__.py
│   ├── main.py              # Tool registration, authorization middleware, entry point
│   ├── auth.py              # JWT decoding, Principal model, RBAC enforcement
│   ├── config.py            # Settings loader, YAML policy parser
│   ├── health.py            # FastAPI health endpoint + MCP ASGI mount
│   └── logging.py           # Structured JSON log formatter
├── tools/                   # Domain-specific tool implementations
│   ├── __init__.py
│   ├── aws/
│   │   ├── __init__.py
│   │   └── ec2.py           # List EC2 instances via boto3
│   ├── kubernetes/
│   │   ├── __init__.py
│   │   └── pods.py          # List pods via kubectl
│   ├── security/
│   │   ├── __init__.py
│   │   └── trivy.py         # Run Trivy vulnerability scans
│   ├── git/
│   │   ├── __init__.py
│   │   └── repo.py          # Fetch recent git commits
│   └── cicd/
│       ├── __init__.py
│       └── pipeline.py      # CI/CD pipeline status
├── policies/                # Authorization policy definitions
│   ├── roles.yaml           # Role → tool mappings
│   └── scope_rules.yaml     # Scope → tool mappings
├── audit/                   # Audit logging
│   ├── __init__.py
│   └── audit_logger.py      # Decorator for structured audit events
├── tests/                   # Unit tests
│   ├── test_auth.py         # JWT decoding and claim validation tests
│   ├── test_authz.py        # Authorization logic tests
│   ├── test_cicd.py         # CI/CD pipeline tool tests
│   ├── test_config.py       # Configuration loader tests
│   ├── test_policies.py     # Policy file validation tests
│   └── test_tools.py        # Tool implementation tests
├── Dockerfile               # Container image (Python 3.12-slim, non-root)
├── .env.example             # Environment variable template
├── requirements.txt         # Python dependencies
└── README.md                # This file
```

---

## Prerequisites

- **Python 3.12+**
- **pip** (Python package manager)
- The following external tools are required for their respective MCP tools:
  - **AWS CLI / boto3 credentials** — for `aws_list_ec2_instances`
  - **kubectl** — for `k8s_list_pods`
  - **Trivy** — for `security_run_trivy_scan`
  - **Git** — for `git_recent_commits`

---

## Getting Started

### Local Development

```bash
# Clone the repository
git clone https://github.com/raghulvj01/devsecops-mcp.git
cd devsecops-mcp

# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate   # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Start the MCP server (streamable HTTP transport)
python -m server.main
```

### ASGI with Health Endpoint

Run the server with a `/health` endpoint and the MCP transport mounted at `/mcp`:

```bash
uvicorn server.health:app --host 0.0.0.0 --port 8000
```

Verify the health endpoint:

```bash
curl http://localhost:8000/health
# {"status": "ok", "service": "devsecops"}
```

### Docker

```bash
# Build the image
docker build -t devsecops-mcp .

# Run the container
docker run -p 8000:8000 devsecops-mcp
```

The Docker image uses a **non-root user** (UID 10001) and includes a built-in health check that polls the `/health` endpoint every 30 seconds.

---

## Configuration

### Environment Variables

All settings are loaded from environment variables with sensible defaults:

| Variable | Description | Default |
|---|---|---|
| `MCP_SERVICE_NAME` | Name of the MCP service | `devsecops` |
| `MCP_ENV` | Environment identifier (e.g., `dev`, `staging`, `prod`) | `dev` |
| `MCP_ROLES_FILE` | Path to the roles policy YAML file | `policies/roles.yaml` |
| `MCP_SCOPES_FILE` | Path to the scope rules YAML file | `policies/scope_rules.yaml` |
| `OIDC_ISSUER` | Expected JWT `iss` claim (optional; skipped if unset) | `None` |
| `OIDC_AUDIENCE` | Expected JWT `aud` claim (optional; skipped if unset) | `None` |

**Example:**

```bash
export MCP_SERVICE_NAME="devsecops-prod"
export MCP_ENV="production"
export OIDC_ISSUER="https://idp.example.com"
export OIDC_AUDIENCE="devsecops-api"
```

---

## MCP Tools Reference

Every tool requires a `token` parameter containing a JWT bearer token. The server decodes the token to extract the caller's identity and checks the requested tool against the configured RBAC policies before execution.

### `aws_list_ec2_instances`

List EC2 instances in a given AWS region.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `token` | `str` | Yes | JWT bearer token |
| `region` | `str` | Yes | AWS region (e.g., `us-east-1`) |

**Returns:** A list of objects with `instance_id`, `state`, and `type` fields.

**Allowed roles:** `viewer`, `admin`
**Allowed scopes:** `devsecops.read`

---

### `k8s_list_pods`

List Kubernetes pods in a namespace.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `token` | `str` | Yes | — | JWT bearer token |
| `namespace` | `str` | No | `default` | Kubernetes namespace |

**Returns:** A list of objects with `name` and `phase` fields.

**Allowed roles:** `viewer`, `admin`
**Allowed scopes:** `devsecops.read`

---

### `security_run_trivy_scan`

Run a Trivy vulnerability scan on a container image.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `token` | `str` | Yes | JWT bearer token |
| `image` | `str` | Yes | Container image reference (e.g., `nginx:latest`) |

**Returns:** Trivy scan results as a JSON object.

**Allowed roles:** `security`, `admin`
**Allowed scopes:** `devsecops.security`

---

### `git_recent_commits`

Fetch recent commits from the current Git repository.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `token` | `str` | Yes | — | JWT bearer token |
| `limit` | `int` | No | `10` | Number of commits to return |

**Returns:** A list of objects with `hash`, `author`, and `subject` fields.

**Allowed roles:** `viewer`, `security`, `admin`
**Allowed scopes:** `devsecops.read`

---

### `cicd_pipeline_status`

Fetch the status of a CI/CD pipeline.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `token` | `str` | Yes | JWT bearer token |
| `base_url` | `str` | Yes | Base URL of the CI/CD service API |
| `pipeline_id` | `str` | Yes | Unique identifier of the pipeline |
| `api_token` | `str` | Yes | API token for authenticating with the CI/CD service |

**Returns:** Pipeline status as a JSON object.

**Allowed roles:** `admin`
**Allowed scopes:** `devsecops.read`

---

## Authentication and Authorization

### JWT Identity Extraction

Every tool call requires a JWT bearer token. The server decodes the JWT payload (base64url) to extract the caller's identity as a `Principal`:

```python
@dataclass(frozen=True)
class Principal:
    subject: str    # From the JWT "sub" claim
    role: str       # From the JWT "role" claim (defaults to "viewer")
    scopes: list[str]  # From the JWT "scope" claim (space-separated)
```

> **Note:** The current implementation decodes JWT payload claims without cryptographic signature verification. This is a scaffold — replace `decode_bearer_token` in `server/auth.py` with your organization's JWKS/signature validation for production use.

Optional issuer and audience validation is performed when `OIDC_ISSUER` and `OIDC_AUDIENCE` environment variables are set.

### Role-Based Access Control

Roles are mapped to permitted tools in `policies/roles.yaml`. The server checks whether the caller's `role` claim grants access to the requested tool.

**Defined roles:**

| Role | Permitted Tools |
|---|---|
| `viewer` | `aws_list_ec2_instances`, `k8s_list_pods`, `git_recent_commits` |
| `security` | `security_run_trivy_scan`, `git_recent_commits` |
| `admin` | All tools (including `cicd_pipeline_status`) |

### Scope-Based Access Control

Scopes provide an alternative authorization path via the JWT `scope` claim (space-separated values). They are mapped to tools in `policies/scope_rules.yaml`.

**Defined scopes:**

| Scope | Permitted Tools |
|---|---|
| `devsecops.read` | `aws_list_ec2_instances`, `k8s_list_pods`, `git_recent_commits`, `cicd_pipeline_status` |
| `devsecops.security` | `security_run_trivy_scan` |

### Authorization Flow

```
JWT Token
    │
    ▼
Decode payload → Extract Principal (subject, role, scopes)
    │
    ├── Check OIDC issuer (if configured) → Reject on mismatch
    ├── Check OIDC audience (if configured) → Reject on mismatch
    │
    ▼
Authorize tool:
    ├── Is tool in role_policies[principal.role]?  → ALLOW
    ├── Is tool in scope_policies[any principal.scope]?  → ALLOW
    └── Neither?  → DENY (raises AuthorizationError)
```

A tool call is **allowed** if **either** the caller's role or any of their scopes grant access to the tool.

---

## Policy Files

### `roles.yaml`

Defines which tools each role can access:

```yaml
roles:
  viewer:
    - aws_list_ec2_instances
    - k8s_list_pods
    - git_recent_commits
  security:
    - security_run_trivy_scan
    - git_recent_commits
  admin:
    - aws_list_ec2_instances
    - k8s_list_pods
    - security_run_trivy_scan
    - git_recent_commits
    - cicd_pipeline_status
```

### `scope_rules.yaml`

Defines which tools each scope can access:

```yaml
scopes:
  devsecops.read:
    - aws_list_ec2_instances
    - k8s_list_pods
    - git_recent_commits
    - cicd_pipeline_status
  devsecops.security:
    - security_run_trivy_scan
```

To add new tools or roles, edit these files. The server loads them at startup from the paths configured by `MCP_ROLES_FILE` and `MCP_SCOPES_FILE`.

---

## Audit Logging

Every tool invocation is wrapped by the `@audit_tool_call` decorator, which emits structured JSON log entries to stdout:

**On invocation start:**

```json
{
  "timestamp": "2026-03-06T08:00:00+00:00",
  "level": "INFO",
  "message": "tool_call_started",
  "logger": "mcp.devsecops.audit",
  "event": "tool_call_started",
  "tool": "aws_list_ec2_instances",
  "args": "('eyJ...', 'us-east-1')",
  "kwargs": {}
}
```

**On success:**

```json
{
  "timestamp": "2026-03-06T08:00:01+00:00",
  "level": "INFO",
  "message": "tool_call_succeeded",
  "logger": "mcp.devsecops.audit",
  "event": "tool_call_succeeded",
  "tool": "aws_list_ec2_instances",
  "duration_ms": 342
}
```

**On failure:**

```json
{
  "timestamp": "2026-03-06T08:00:01+00:00",
  "level": "ERROR",
  "message": "tool_call_failed",
  "logger": "mcp.devsecops.audit",
  "event": "tool_call_failed",
  "tool": "aws_list_ec2_instances",
  "duration_ms": 15,
  "error": "principal 'user1' with role 'viewer' is not allowed to call 'security_run_trivy_scan'"
}
```

Export these logs to a SIEM platform (Datadog, ELK, CloudWatch) for durable audit retention.

---

## Testing

The project uses Python's built-in `unittest` framework. Tests are located in the `tests/` directory.

```bash
# Run all tests
python -m unittest discover tests/

# Run a specific test file
python -m unittest tests.test_authz
python -m unittest tests.test_config
```

**Test coverage:**

| Test File | Description |
|---|---|
| `tests/test_authz.py` | Validates role-based and scope-based authorization logic |
| `tests/test_auth.py` | Validates JWT decoding, claim defaults, and issuer/audience rejection |
| `tests/test_config.py` | Validates default settings are loaded correctly |
| `tests/test_policies.py` | Validates policy files include expected tool mappings |
| `tests/test_tools.py` | Validates git tool output parsing and error handling |
| `tests/test_cicd.py` | Validates CI/CD pipeline status tool |

---

## Security Best Practices

- **Enable JWT signature validation.** The scaffold decodes JWT payloads without verifying signatures. Replace `decode_bearer_token` in `server/auth.py` with JWKS-based validation using your corporate IdP before deploying to production.
- **Set `OIDC_ISSUER` and `OIDC_AUDIENCE`** to enforce issuer and audience claim validation.
- **Follow least privilege.** Only grant the minimum roles and scopes necessary. Gate write and delete operations behind dedicated roles.
- **Export audit logs.** Forward structured JSON logs to a SIEM (Datadog, ELK, CloudWatch) for durable retention and alerting.
- **Use the non-root Docker image.** The provided `Dockerfile` runs as UID 10001 to minimize container escape risk.
- **Rotate credentials.** Regularly rotate AWS credentials, kubeconfig tokens, and any other secrets used by the domain tools.
- **Review policy files.** Periodically audit `policies/roles.yaml` and `policies/scope_rules.yaml` to ensure access mappings remain appropriate.

---

## Contributing

1. Fork the repository.
2. Create a feature branch: `git checkout -b feature/my-new-tool`.
3. Add your tool implementation under `tools/<domain>/`.
4. Register the tool in `server/main.py` with `@mcp.tool()`, `@audit_tool_call()`, and an `_authorize()` call.
5. Update `policies/roles.yaml` and `policies/scope_rules.yaml` with appropriate access rules.
6. Add tests in the `tests/` directory.
7. Submit a pull request.

---

## License

This project is proprietary. See your organization's licensing terms.
