from __future__ import annotations

from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from server.config import load_settings
from server.main import mcp

settings = load_settings()


@mcp.custom_route("/health", methods=["GET"], include_in_schema=False)
async def health(_request: Request) -> Response:
    return JSONResponse({"status": "ok", "service": settings.service_name})


app = mcp.streamable_http_app()
