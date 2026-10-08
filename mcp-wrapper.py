#!/usr/bin/env python3
"""FastMCP Streamable-HTTP wrapper with well-known endpoints and health checks.

Usage:
    python /path/to/mcp-streamable-http-wrapper.py

This imports `mcp` from `server.py`, mounts discovery endpoints, and runs
with transport='streamable-http'.
"""

import json
import os
import sys

sys.path.insert(0, os.path.expanduser("~/clawd/meok-labs-engine/shared"))
sys.path.insert(0, os.getcwd())

from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from server import mcp as mcp_server


SERVICE_NAME = os.path.basename(os.getcwd())
REPO_URL = f"https://github.com/CSOAI-ORG/{SERVICE_NAME}"


@mcp_server.custom_route("/.well-known/mcp/server-card.json", methods=["GET"])
async def server_card(request: Request) -> Response:
    return JSONResponse(
        {
            "$schema": "https://schema.smithery.ai/server-card.json",
            "version": "1.0.0",
            "protocolVersion": "2026-07-28",
            "serverInfo": {
                "name": SERVICE_NAME,
                "description": f"MEOK AI Labs — {SERVICE_NAME}",
                "vendor": "MEOK AI Labs",
                "homepage": "https://meok.ai",
                "repository": REPO_URL,
            },
            "transport": {
                "type": "streamable-http",
                "url": "http://localhost:8000/mcp",
            },
            "capabilities": {
                "tools": {"listChanged": False},
                "resources": {"listChanged": False},
                "prompts": {"listChanged": False},
            },
        },
        headers={
            "Access-Control-Allow-Origin": "*",
            "Cache-Control": "public, max-age=3600",
        },
    )


@mcp_server.custom_route("/.well-known/mcp", methods=["GET"])
async def mcp_manifest(request: Request) -> Response:
    return JSONResponse(
        {
            "mcp_version": "2026-07-28",
            "endpoints": [
                {
                    "type": "streamable-http",
                    "path": "/mcp",
                    "url": "http://localhost:8000/mcp",
                }
            ],
        },
        headers={
            "Access-Control-Allow-Origin": "*",
            "Cache-Control": "public, max-age=3600",
        },
    )


@mcp_server.custom_route("/health", methods=["GET"])
async def health(request: Request) -> Response:
    return JSONResponse({"status": "ok"})


if __name__ == "__main__":
    # MCP 2026-07-28 wire - header-add migration (2026-10-08): every ingress
    # exchange passes through translate_request, which validates Mcp-Method /
    # Mcp-Name, injects params._meta.protocolVersion = "2026-07-28" and strips
    # Mcp-Session-Id (stateless wire - it is never emitted). Legacy handshake
    # clients get a local initialize / server/discover answer from the shim.
    # json_response=True because the shim buffers bodies: no SSE stream passes
    # through it. Refs: MIGRATION_NOTE.md, MCP_2026_WIRE_MIGRATION_PLAN_2026-10-07.md.
    import uvicorn

    from mcp2026_shim import WIRE_2026, ShimASGI, ShimConfig

    HOST = os.environ.get("MCP_HOST", "0.0.0.0")
    PORT = int(os.environ.get("MCP_PORT", os.environ.get("PORT", "8000")))

    app = ShimASGI(
        mcp_server.streamable_http_app(json_response=True, host=HOST),
        ShimConfig(
            protocol_version=WIRE_2026,
            server_info={"name": SERVICE_NAME, "version": "2026-07-28-wire"},
        ),
    )
    uvicorn.run(app, host=HOST, port=PORT, log_level="info")
