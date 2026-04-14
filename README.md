# ISO/IEC 27001 Information Security Management MCP Server

> **By [MEOK AI Labs](https://meok.ai)** -- Sovereign AI tools for everyone.

ISO/IEC 27001:2022 compliance assessment for AI systems. Audit against all 93 Annex A controls across 4 themes, perform ISO 27005 risk assessments, run gap analysis, generate Statement of Applicability, classify incidents, and bridge to ISO 42001 for AI-specific ISMS.

Part of the **CSOAI Governance Suite**: ISO 27001 + ISO 42001 + GDPR + SOC 2 + EU AI Act.

[![MIT License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![MEOK AI Labs](https://img.shields.io/badge/MEOK_AI_Labs-255+_servers-purple)](https://meok.ai)

## Tools

| Tool | Description |
|------|-------------|
| `audit_isms` | Audit against ISO 27001 Annex A controls (93 controls, 4 themes) |
| `risk_assessment` | Information security risk assessment per ISO 27005 |
| `gap_analysis` | Compare current controls to ISO 27001 requirements |
| `crosswalk_to_ai` | Map ISO 27001 controls to ISO 42001 AI requirements |
| `generate_soa` | Generate Statement of Applicability (certification requirement) |
| `incident_classification` | Classify security incidents with AI-specific categories |

## Quick Start

```bash
pip install mcp
git clone https://github.com/CSOAI-ORG/iso-27001-ai-mcp.git
cd iso-27001-ai-mcp
python server.py
```

## Claude Desktop Config

```json
{
  "mcpServers": {
    "iso-27001-ai": {
      "command": "python",
      "args": ["server.py"],
      "cwd": "/path/to/iso-27001-ai-mcp"
    }
  }
}
```

## Coverage

- **93 Annex A Controls** across 4 themes (Organizational, People, Physical, Technological)
- **7 ISMS Clauses** (4-10) with all subclauses
- **20 ISO 27001-to-42001 bridge mappings** with alignment ratings
- **10 ISO 27005 threat categories** for AI-specific risk assessment
- **AI incident classification** with adversarial, poisoning, extraction categories

## The Bridge Advantage

The `crosswalk_to_ai` tool uniquely maps ISO 27001 controls to ISO 42001 AI management requirements. Organizations with existing ISO 27001 certification can see exactly how their ISMS extends to AI governance.

## License

MIT -- see [LICENSE](LICENSE)
