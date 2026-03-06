from __future__ import annotations

from server.app import build_mcp

mcp = build_mcp()


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
