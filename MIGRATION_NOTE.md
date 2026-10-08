# MIGRATION_NOTE - MCP 2026-07-28 wire - class `header-add`

**Date:** 2026-10-08 - **Lane:** M4 MCP-migration (header-add wave 2, batch 8) - **Branch:** `mcp-2026-wire-header-add`
**Runbook:** `MCP_2026_WIRE_MIGRATION_PLAN_2026-10-07.md` section 3 (header-add) + section 4 (the shim as bridge)
**Deprecation deadline:** the legacy wire dies **2027-07-28** - 12 months after the 2026-07-28 revision.

## 1. Transport reality

Server entry `server.py` runs stdio (`mcp.run()`); HTTP exposure is served by `mcp-wrapper.py` (`transport="streamable-http"`).

## 2. What changed in this branch

1. `pyproject.toml`: `"mcp>=1.0.0"` -> `"mcp>=2.0.0"` (2.x is the first SDK line speaking the 2026-07-28 spec; wave 1 verified `mcp` 2.3.0) and the packaging include list gained `mcp2026_shim.py` so the vendored shim ships in the wheel.
2. `server.py`: `from mcp.server.fastmcp import FastMCP` -> `from mcp.server.mcpserver import MCPServer as FastMCP` - required, because `mcp.server.fastmcp` raises `ModuleNotFoundError` by design in 2.x (FastMCP was renamed MCPServer). The pin is worthless if the import does not resolve.
3. `mcp2026_shim.py` vendored at the repo root (stdlib, zero third-party deps).
4. `mcp-wrapper.py`: every ingress request now passes through `ShimASGI(...)` in front of `mcp_server.streamable_http_app(json_response=True)`, and the in-code served declarations (`protocolVersion` / `mcp_version`) moved 2025-11-25 -> 2026-07-28. `json_response=True` because the shim buffers bodies - SSE through the wrapper is out of scope (plan section 4). `server.py` carries the migration note block only (HTTP is wired in the wrapper).

The shim does the four runbook duties at the transport: read/validate `Mcp-Method` and `Mcp-Name` on ingress, reject a missing `Mcp-Name` on `tools/call` / `resources/read` / `prompts/get` with `-32602`, emit `params._meta.protocolVersion = "2026-07-28"` on every outbound request, and never emit `Mcp-Session-Id` (it strips one if a proxy adds it).

## 3. Verify

```bash
PYTHONPATH= /opt/homebrew/bin/python3.11 ~/clawd/mcp_wire_audit.py audit --local iso-27001-ai-mcp
```

| state | era | migration |
|---|---|---|
| before (default branch) | 2026-07 | header-add |
| **after (this branch)** | **2026-07** | **handshake-removal** |
| control (migration-note block removed) | 2026-07 | header-add |

Files changed in this branch: `pyproject.toml`, `server.py`, `mcp-wrapper.py`, `mcp2026_shim.py`, `MIGRATION_NOTE.md`. The scanner reads the source/manifest files only: it skips `mcp2026_shim.py` by design (`SELF_FILES`) and does not scan `.md`, so neither `MIGRATION_NOTE.md` nor the shim contributes signals above.

**How to read the `after` row honestly.** The audit is a static scan and this tool excludes its own shim from the scan by design (`SELF_FILES`), so `protocol-2026-07-28`, `mcp-method-header`, `mcp-name-header`, `server-discover` and `session-id` in the `after` record are read from the migration-note text, not from executable handshake code. The `session-id` signal in particular is prose (the note documents that the shim *strips* the header) - the control run, which deletes only that note block, drops back to the row above and shows no `session-id` at all. Runtime evidence for the wire is the `mcp>=2.0.0` pin (2.3.0 speaks 2026-07-28) plus the vendored shim at the ingress; `mcp>=2.0.0` alone is not a wire signal for this scanner. **After-rows are note-text-driven until a post-merge re-audit.**

## 4. Follow-ups (not in this branch)

* Static declaration surfaces (`.well-known/*.json`, `server.json`, `README.md`, registry manifests) still declare an older wire - listed as follow-ups, not silent-edited (Art. 21: a declaration change gets its own commit).
* The *before* `2026-07` era here comes from `.well-known/agent-card.json` (`"mcp_name"` registry token) - a known false-positive class of this scanner, not wire code. The scanner needs a corroborating core signal, and that token supplies `mcp-name-header`.
* stdio carries no HTTP headers: `headers N/A at runtime` until the server is exposed over HTTP, where `ShimASGI` applies. A live probe per plan section 6.5 is owed after merge.

Verify command of record: `PYTHONPATH= /opt/homebrew/bin/python3.11 ~/clawd/mcp_wire_audit.py audit --local <repo>` -> `era: 2026-07`, `migration: none` is the acceptance target for class `header-add`; re-run it after merge, not on this branch's note text.

Plan: `MCP_2026_WIRE_MIGRATION_PLAN_2026-10-07.md` - deadline 2027-07-28 - measurement, not certification.
