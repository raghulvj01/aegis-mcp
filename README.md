# DevSecOps MCP Server

Internal MCP server scaffold for DevOps/SecOps workflows.

## Features
- FastMCP server with domain tools (AWS, Kubernetes, Security, Git).
- JWT claim extraction plus role/scope RBAC checks before tool execution.
- Structured JSON audit logs for every tool invocation.
- Policy-driven authorization via `policies/roles.yaml` and `policies/scope_rules.yaml`.
- FastAPI app with `/health` and mounted `/mcp` endpoint.
- Containerized deployment with non-root runtime user.

## Project Layout
- `server/`: startup, app builder, config, auth, and shared logging
- `tools/`: domain-specific tools
- `policies/`: role/scope permission mappings
- `audit/`: audit logging decorator

## Run locally
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m server.main
```

## Run via ASGI app with health endpoint
```bash
uvicorn server.health:app --host 0.0.0.0 --port 8000
```

## Security notes
- Replace `decode_bearer_token` with strict JWKS signature verification from your IdP.
- Keep production tools least-privileged and gate write/delete operations.
- Export logs to SIEM (Datadog/ELK/CloudWatch) for durable audit retention.
