<div align="center">
  <h1>🛡️ Aegis MCP Server</h1>
  <p><b>An open-source Model Context Protocol (MCP) server for DevOps and Security automation workflows.</b></p>

  [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
  [![Python version](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
  [![MCP Protocol](https://img.shields.io/badge/MCP-Compatible-green.svg)](https://modelcontextprotocol.io/)
  [![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](https://www.docker.com/)
</div>

---

**Aegis MCP Server** empowers AI assistants (like Claude, Cursor, and GitHub Copilot) to perform cloud architecture administration, security scanning, and network analyses directly from their execution environments. It wraps powerful underlying tools and SDKs into secure, audited MCP tool sets.

---

## 🌟 Key Features

- 🚀 **FastMCP Server** — Exposes domain-specific tools for AWS, Kubernetes, security scanning, Git, network analysis, and CI/CD pipelines.
- 🔐 **Flexible Authorization** — JWT-based RBAC for production deployments; automatically disabled for local stdio sessions (Claude Desktop, Agent IDEs).
- 📜 **Structured Audit Logging** — Emits clean JSON audit logs for every invocation, suitable for SIEM integrations.
- 🛠 **Expandable Tooling** — Easily add new integrations. Includes ready-to-use scanners for dependencies, secrets, SSL/TLS certs, Semgrep, Trivy, and more.
- 📦 **Docker Ready** — Containerized deployment using a non-root runtime with built-in health checks.
- 🌐 **ASGI Integration** — FastAPI health endpoint alongside MCP streamable-http transport.

---

## 📐 Architecture

```mermaid
flowchart TD
    Client[MCP Client / AI Agent] -->|Tool Call| AuthZ[Auth & RBAC Layer]

    subgraph aegis-mcp["Aegis MCP Server"]
        AuthZ --> Audit[Audit Logger]
        Audit --> ToolsLayer[Tool Dispatch Layer]
    end

    ToolsLayer --> AWS[AWS SDK]
    ToolsLayer --> K8s[kubectl / K8s SDK]
    ToolsLayer --> Sec[Trivy / Semgrep]
    ToolsLayer --> Net[Nmap / SSL]
    ToolsLayer --> Git[Git CLI]
```

The server receives MCP tool-call requests over **streamable HTTP** or **stdio** transport. In HTTP mode, each request requires a JWT bearer token for authorization. In stdio mode (local usage), authorization is automatically disabled.

---

## 🧰 Available Tools

### Cloud & DevOps
| Tool | Description |
|------|-------------|
| `aws_list_ec2_instances` | List EC2 instances in a specific AWS region |
| `aws_check_s3_public_access` | Audit S3 buckets for public access settings |
| `k8s_list_pods` | List Kubernetes pods in a given namespace |
| `cicd_pipeline_status` | Fetch CI/CD pipeline execution status |
| `git_recent_commits` | Fetch recent commit history from the active Git repo |

### Application Security & SAST
| Tool | Description |
|------|-------------|
| `security_semgrep_scan` | Run Semgrep SAST scan on a local directory or file |
| `security_run_trivy_scan` | Run Trivy vulnerability scan on a container image |
| `security_scan_secrets` | Scan files/directories for exposed secrets |
| `security_check_dependencies` | Check dependency files for known CVEs via OSV.dev |

### Network & Infrastructure Security
| Tool | Description |
|------|-------------|
| `network_port_scan` | TCP port scan to detect exposed services |
| `security_check_ssl_certificate` | Validate SSL/TLS certificate details and expiry |
| `security_check_http_headers` | Audit URLs for security headers (HSTS, CSP, etc.) |

> [!IMPORTANT]
> **SAST (Semgrep scan) works only on Agent IDEs (e.g., Antigravity, Cursor) or Claude Co-work.**
> It does **not** work on Claude Desktop due to Windows subprocess pipe limitations with `semgrep-core.exe`. All other tools (secrets scan, SSL check, port scan, etc.) work on all platforms including Claude Desktop.

---

## 🚀 Getting Started

### Prerequisites

- **Python 3.12+**
- **Semgrep** — `pip install semgrep` (for SAST scanning)
- Optional: AWS CLI / `boto3`, `kubectl`, Trivy (for their respective tools)

### Installation

```bash
git clone https://github.com/raghulvj01/aegis-mcp.git
cd aegis-mcp

# Create virtual environment
python -m venv .venv

# Activate it
# Linux/Mac:
source .venv/bin/activate
# Windows:
.venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

---

## 🤖 Usage with AI Agents

### Agent IDE / Antigravity (Recommended)

Add to your MCP config (e.g., `mcp_config.json`):

```json
{
  "mcpServers": {
    "aegis": {
      "command": "c:\\path\\to\\aegis-mcp\\.venv\\Scripts\\python.exe",
      "args": ["c:\\path\\to\\aegis-mcp\\run_stdio.py"]
    }
  }
}
```

> ✅ **All 12 tools work**, including Semgrep SAST.

### Claude Desktop

Add to `claude_desktop_config.json`:
- **Windows**: `%LOCALAPPDATA%\Packages\Claude_...\LocalCache\Roaming\Claude\`
- **Mac**: `~/Library/Application Support/Claude/`

```json
{
  "mcpServers": {
    "aegis": {
      "command": "c:\\path\\to\\aegis-mcp\\.venv\\Scripts\\python.exe",
      "args": ["c:\\path\\to\\aegis-mcp\\run_stdio.py"]
    }
  }
}
```

> ⚠️ **11 of 12 tools work.** Semgrep SAST does not work due to Windows pipe limitations.

### Cursor / Windsurf (HTTP Mode)

Start the server, then add to `.cursor/mcp.json`:

```bash
uvicorn server.health:app --host 0.0.0.0 --port 8000
```

```json
{
  "mcpServers": {
    "aegis": {
      "url": "http://localhost:8000/mcp"
    }
  }
}
```

### Docker Deployment

```bash
docker build -t aegis-mcp .
docker run -p 8000:8000 aegis-mcp
```

---

## ⚙️ Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `MCP_AUTH_DISABLED` | Disable JWT auth (auto-set for stdio) | `false` |
| `MCP_SERVICE_NAME` | Name of the MCP service | `aegis` |
| `MCP_ENV` | Environment (`dev`, `staging`, `prod`) | `dev` |
| `MCP_ROLES_FILE` | Path to roles policy YAML | `policies/roles.yaml` |
| `MCP_SCOPES_FILE` | Path to scopes policy YAML | `policies/scope_rules.yaml` |
| `OIDC_ISSUER` | Expected JWT `iss` claim | *None* |
| `OIDC_AUDIENCE` | Expected JWT `aud` claim | *None* |

---

## 🗝 Access Control

In **HTTP mode**, every tool requires a `token` argument containing a JWT. The authorization layer checks roles and scopes defined in `policies/roles.yaml` and `policies/scope_rules.yaml`.

In **stdio mode** (local usage via `run_stdio.py`), authorization is **automatically disabled** — no token required.

### Policy Example (`policies/roles.yaml`)

```yaml
roles:
  viewer:
    - aws_list_ec2_instances
    - k8s_list_pods
  security:
    - security_run_trivy_scan
    - security_semgrep_scan
  admin:
    - aws_list_ec2_instances
    - k8s_list_pods
    - security_run_trivy_scan
    - security_semgrep_scan
    # ... all tools
```

---

## 📝 Audit Logging

The `@audit_tool_call` decorator emits structured JSON logs for every invocation:

```json
{
  "timestamp": "2026-03-06T08:00:01+00:00",
  "level": "INFO",
  "event": "tool_call_succeeded",
  "tool": "security_run_trivy_scan",
  "duration_ms": 1204
}
```

---

## 🛡️ Security Best Practices

1. **Enforce JWT Signature Validation** — Update `server/auth.py` to verify RS256 JWTs using your IdP's JWKS endpoint for production.
2. **Least-Privilege Credentials** — Assign ReadOnly IAM / K8s roles to the server environment.
3. **Monitor Audit Logs** — Forward JSON logs to a SIEM. Set up anomaly detection for aggressive looping.

---

## 🤝 Contributing

1. Fork the project
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Add your tool into `tools/<domain>/`
4. Register it via `@mcp.tool()` in `server/main.py` with `@audit_tool_call` and auth check
5. Add tests in `tests/`
6. Open a Pull Request

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.
