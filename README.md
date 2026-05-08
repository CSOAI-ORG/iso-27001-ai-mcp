<div align="center">

# Iso 27001 Ai MCP

**MCP server for iso 27001 ai mcp operations**

[![PyPI](https://img.shields.io/pypi/v/meok-iso-27001-ai-mcp)](https://pypi.org/project/meok-iso-27001-ai-mcp/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MEOK AI Labs](https://img.shields.io/badge/MEOK_AI_Labs-MCP_Server-purple)](https://meok.ai)

</div>

## Overview

Iso 27001 Ai MCP provides AI-powered tools via the Model Context Protocol (MCP).

## Tools

| Tool | Description |
|------|-------------|
| `audit_isms` | Audit an Information Security Management System against ISO 27001:2022 |
| `risk_assessment` | Perform information security risk assessment per ISO 27005 methodology. |
| `gap_analysis` | Compare current controls to ISO 27001:2022 requirements and identify gaps. |
| `crosswalk_to_ai` | Map ISO 27001 controls to AI-specific requirements via ISO 42001 bridge. |
| `generate_soa` | Generate a Statement of Applicability (SoA) per ISO 27001:2022 clause 6.1.3(d). |
| `incident_classification` | Classify security incidents per ISO 27001 incident management framework |

## Installation

```bash
pip install meok-iso-27001-ai-mcp
```

## Usage with Claude Desktop

Add to your Claude Desktop MCP config (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "iso-27001-ai-mcp": {
      "command": "python",
      "args": ["-m", "meok_iso_27001_ai_mcp.server"]
    }
  }
}
```

## Usage with FastMCP

```python
from mcp.server.fastmcp import FastMCP

# This server exposes 6 tool(s) via MCP
# See server.py for full implementation
```

## License

MIT © [MEOK AI Labs](https://meok.ai)
