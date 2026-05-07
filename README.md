[![iso-27001-ai-mcp MCP server](https://glama.ai/mcp/servers/CSOAI-ORG/iso-27001-ai-mcp/badges/score.svg)](https://glama.ai/mcp/servers/CSOAI-ORG/iso-27001-ai-mcp)
[![MCP Registry](https://img.shields.io/badge/MCP_Registry-Published-green)](https://registry.modelcontextprotocol.io)
[![PyPI](https://img.shields.io/pypi/v/iso-27001-ai-mcp)](https://pypi.org/project/iso-27001-ai-mcp/)

[![iso-27001-ai-mcp MCP server](https://glama.ai/mcp/servers/CSOAI-ORG/iso-27001-ai-mcp/badges/card.svg)](https://glama.ai/mcp/servers/CSOAI-ORG/iso-27001-ai-mcp)

<div align="center">

[![PyPI](https://img.shields.io/pypi/v/iso-27001-ai-mcp)](https://pypi.org/project/iso-27001-ai-mcp/)
[![Downloads](https://img.shields.io/pypi/dm/iso-27001-ai-mcp)](https://pypi.org/project/iso-27001-ai-mcp/)
[![GitHub stars](https://img.shields.io/github/stars/CSOAI-ORG/iso-27001-ai-mcp)](https://github.com/CSOAI-ORG/iso-27001-ai-mcp/stargazers)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

# ISO 27001 AI MCP

**ISMS audit, Annex A gap analysis, and Statement of Applicability generation for AI/ML systems against ISO 27001:2022.**

[![MEOK AI Labs](https://img.shields.io/badge/MEOK_AI_Labs-224+_servers-purple)](https://meok.ai)

[Install](#install) · [Tools](#tools) · [Pricing](#pricing) · [Attestation API](#attestation-api)

</div>

---

## Why This Exists

ISO 27001:2022 is the global standard for information security management, and the 2022 revision added 11 new controls (including A.5.23 cloud services, A.8.11 data masking, A.8.12 data leakage prevention) that directly affect AI deployments. Organisations running AI systems need to map model training pipelines, inference endpoints, and data flows into their ISMS scope.

Most consultancies charge 15-30K per ISO 27001 gap analysis. This MCP automates the ISMS audit against all 93 Annex A controls, generates Statements of Applicability, performs risk assessments per ISO 27005, crosswalks to AI-specific frameworks, and classifies security incidents under ISO 27035.

## Install

```bash
pip install iso-27001-ai-mcp
```

## Tools

| Tool | ISO Reference | What it does |
|------|--------------|--------------|
| `audit_isms` | Clauses 4-10 | Full ISMS audit against ISO 27001:2022 management clauses |
| `risk_assessment` | ISO 27005 | Information security risk assessment for AI assets |
| `gap_analysis` | Annex A (93 controls) | Control-by-control gap analysis against 2022 Annex A |
| `crosswalk_to_ai` | Annex A + AI frameworks | Map ISO 27001 controls to ISO 42001 / EU AI Act requirements |
| `generate_soa` | Clause 6.1.3 | Generate Statement of Applicability with justifications |
| `incident_classification` | ISO 27035 | Classify and triage AI security incidents |

## Example

```
Prompt: "Run an ISO 27001 gap analysis on our ML training pipeline.
We store training data in S3, run training on GPU clusters in eu-west-1,
and deploy models via a REST API with no authentication."

Result: Gap analysis across Annex A with critical findings on unauthenticated
API endpoints, missing data deletion policies, absent cloud service agreements,
and no DLP controls on model outputs. Statement of Applicability generated
with all 93 controls assessed.
```

## Pricing

| Tier | Price | What you get |
|------|-------|-------------|
| **Free** | £0 | 10 calls/day — ISMS audit + gap analysis |
| **Pro** | £199/mo | Unlimited + HMAC-signed attestations + verify URLs |
| **Enterprise** | £1,499/mo | Multi-tenant + co-branded reports + webhooks |

[Subscribe to Pro](https://buy.stripe.com/14A4gB3K4eUWgYR56o8k836) · [Enterprise](https://buy.stripe.com/4gM9AV80kaEG0ZT42k8k837)

## Attestation API

Every Pro/Enterprise audit produces a cryptographically signed certificate:

```
POST https://meok-attestation-api.vercel.app/sign
GET  https://meok-attestation-api.vercel.app/verify/{cert_id}
```

Zero-dep verifier: `pip install meok-attestation-verify`

## Links

- Website: [meok.ai](https://meok.ai)
- All MCP servers: [meok.ai/labs/mcp/servers](https://meok.ai/labs/mcp/servers)
- Enterprise support: nicholas@csoai.org

## License

MIT
<!-- mcp-name: io.github.CSOAI-ORG/iso-27001-ai-mcp -->
