from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from server.app import build_mcp
from server.config import load_settings

settings = load_settings()
mcp = build_mcp()
app = FastAPI(title="devsecops-mcp")


@app.get("/health")
def health() -> JSONResponse:
    return JSONResponse({"status": "ok", "service": settings.service_name})


app.mount("/mcp", mcp.streamable_http_app())
