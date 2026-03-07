from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from mcp.server.fastmcp import FastMCP

from server.config import load_settings

settings = load_settings()
mcp = FastMCP(settings.service_name, json_response=True)
app = FastAPI(title="aegis-mcp")


@app.get("/health")
def health() -> JSONResponse:
    return JSONResponse({"status": "ok", "service": settings.service_name})


app.mount("/mcp", mcp.streamable_http_app())
