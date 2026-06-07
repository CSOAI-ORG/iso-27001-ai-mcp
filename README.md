[![MCP Scorecard: 90/100](https://img.shields.io/badge/proofof.ai-90%2F100-5b21b6)](https://proofof.ai/scorecard/iso-27001-ai-mcp.html)

# Iso 27001 Ai MCP

> **⚖️ Built by [MEOK AI Labs](https://meok.ai) / [CSOAI](https://csoai.org).** Need this applied to _your_ system fast? Book a 30-min Founder Office Hour (£29) → **https://meok.ai/work** · Full governance platform → **https://meok.ai**

[![MEOK AI Labs](https://img.shields.io/badge/MEOK-AI%20Labs-667eea)](https://meok.ai)
[![EU AI Act](https://img.shields.io/badge/EU%20AI%20Act-Compliant-22c55e)](https://councilof.ai)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![PyPI](https://img.shields.io/badge/PyPI-Install-3775a9)](https://pypi.org/project/iso_27001_ai_mcp/)

> MEOK AI Labs MCP Server

MEOK AI Labs MCP Server

---

## 🚀 Quick Start

```bash
# Install via pip
pip install iso_27001_ai_mcp

# Or install via Smithery
npx -y @smithery/cli@latest install iso-27001-ai-mcp --client claude
```

## ✨ Features

- MCP protocol compliant
- Easy installation
- Well-documented API
- Production-ready
- Active maintenance

## 📖 Documentation

- [Full Documentation](https://docs.meok.ai/iso-27001-ai-mcp)
- [API Reference](https://api.meok.ai)
- [EU AI Act Compliance Guide](https://councilof.ai/compliance)

## 🛡️ Compliance

This MCP server is built with **EU AI Act compliance** built-in:

- ✅ Article 9 — Risk Management System
- ✅ Article 13 — Transparency & Instructions for Use
- ✅ Article 15 — Bias Detection & Testing
- ✅ Article 26 — FRIA Support (where applicable)
- ✅ Article 50 — AI Content Watermarking (where applicable)

Need help getting compliant? **[Book a free 15-min diagnostic →](https://cal.com/csoai/august-audit)**

## 🏢 Enterprise

Need custom development, SLA guarantees, or white-label deployment?

- **Pro:** $99/mo — Full MCP suite + EU AI Act tracking
- **Enterprise:** $499/mo — Custom dev + SLA + Dedicated support

[View Pricing →](https://councilof.ai/pricing) | [Contact Sales →](mailto:sales@csoai.org)

## 🤝 Part of the MEOK Ecosystem

This server is part of the **[MEOK AI Labs](https://meok.ai)** ecosystem — 300+ MCP servers for sovereign AI governance.

| Domain | Purpose |
|--------|---------|
| [councilof.ai](https://councilof.ai) | EU AI Act compliance marketplace |
| [safetyof.ai](https://safetyof.ai) | AI safety & monitoring |
| [meok.ai](https://meok.ai) | Sovereign AI platform |
| [cobolbridge.ai](https://cobolbridge.ai) | Legacy modernization |

## 📜 License

MIT © [CSOAI-ORG](https://github.com/CSOAI-ORG)

---

<p align="center">
  <sub>Built with 💜 by <a href="https://meok.ai">MEOK AI Labs</a> · UK Companies House 16939677</sub>
</p>
mcp-name: io.github.CSOAI-ORG/iso-27001-ai-mcp

# ISO 27001 AI MCP

> ISO/IEC 27001:2022 compliance assessment for AI systems — 93 Annex A controls across 4 themes, ISO 27005 risk assessment, Statement of Applicability generation, incident classification, and ISO 42001 bridge.

[![PyPI](https://img.shields.io/pypi/v/meok-iso-27001-ai-mcp)](https://pypi.org/project/meok-iso-27001-ai-mcp/)
[![npm](https://img.shields.io/npm/v/meok-iso-27001-ai-mcp)](https://www.npmjs.com/package/meok-iso-27001-ai-mcp)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![smithery](https://img.shields.io/badge/Smithery-MCP-orange)](https://smithery.ai)

## What This Does

ISO/IEC 27001:2022 is the international standard for Information Security Management Systems (ISMS). Its Annex A contains **93 controls** organized into **4 themes**: Organizational (37 controls), People (8), Physical (14), and Technological (34). Certification requires demonstrating that your ISMS meets clauses 4–10 and that your Statement of Applicability (SoA) addresses all relevant controls.

For AI systems, ISO 27001 is foundational — but it needs extension. This server audits your ISMS against all 93 controls, performs ISO 27005 risk assessments with AI-specific threat scenarios, generates gap analyses with prioritized remediation roadmaps, produces SoAs, classifies security incidents, and bridges to ISO 42001 for AI-specific governance.

## Quick Start

```bash
npx meok-setup --pack governance
```

## Tools

| Tool | Description | Parameters |
|------|-------------|------------|
| `audit_isms` | Audits your ISMS against all 93 Annex A controls. Returns per-theme compliance status (PASS/PARTIAL/FAIL), gap identification, critical gap flagging for high-priority controls (A.5.1, A.5.15, A.8.5, A.8.24, etc.), and certification readiness assessment. | `organization_context`, `scope_description`, `controls_implemented` |
| `risk_assessment` | Performs ISO 27005 information security risk assessment. Evaluates 10 AI-relevant threat categories (adversarial attacks, model theft, training data breach, supply chain compromise, insider threat, etc.), calculates likelihood × impact risk scores, and produces a treatment plan with specific Annex A control recommendations. | `system_description`, `assets`, `threat_scenarios`, `existing_controls` |
| `gap_analysis` | Compares your current controls to ISO 27001 requirements. Supports three targets: "full" (all 93 controls), "core" (critical subset), or "ai-focused" (AI-relevant controls only). Returns prioritized remediation roadmap in 3 phases: Critical (0–30 days), Standard (30–90 days), Remaining (90–180 days). | `current_controls`, `target_certification`, `focus_themes` |
| `crosswalk_to_ai` | Maps ISO 27001 controls to ISO 42001 AI-specific requirements. Shows how existing ISMS controls extend to AI governance (model security, training data protection, AI incident management) and identifies where AI-specific controls are needed. | `controls`, `focus_area` |
| `generate_soa` | Generates a Statement of Applicability per clause 6.1.3(d). Documents all 93 controls as Implemented, Excluded (with justification), or Not Yet Addressed. Required artifact for ISO 27001 certification audits. | `organization_name`, `controls_implemented`, `controls_excluded`, `exclusion_justifications` |
| `incident_classification` | Classifies security incidents per controls A.5.24–A.5.28. Determines severity (LOW→CRITICAL), priority (P1–P3), notification requirements, and response procedures. Includes AI-specific incident categories: adversarial attacks, data poisoning, model theft, prompt injection, bias incidents. | `incident_description`, `affected_assets`, `detection_method`, `data_breach`, `ai_system_involved` |

## Usage Examples

### Audit your AI company's ISMS

```
Use the audit_isms tool with:
  organization_context: "AI startup with 150 employees building ML models for healthcare diagnostics. Uses AWS for infrastructure, processes patient data, has a small security team."
  scope_description: "All AI systems, ML pipelines, patient data processing, cloud infrastructure, and development environments"
  controls_implemented: ["A.5.1", "A.5.9", "A.5.12", "A.5.15", "A.5.24", "A.6.3", "A.8.5", "A.8.7", "A.8.8", "A.8.15", "A.8.24"]
```

**Expected output:** Overall coverage ~12% (11/93 controls). Critical gaps flagged in A.5.34 (PII protection), A.8.12 (data leakage prevention), A.8.25 (secure SDLC). Certification NOT ready — 82 gaps to address.

### Assess risk for your ML pipeline

```
Use the risk_assessment tool with:
  system_description: "Production ML pipeline processing financial data for fraud detection. Uses gradient boosting models trained on 10M+ transaction records. Served via REST API with 99.9% SLA."
  assets: ["training data", "ML model weights", "feature store", "API keys", "model serving infrastructure", "customer transaction data"]
  existing_controls: ["A.5.15", "A.8.5", "A.8.15", "A.8.24"]
```

**Expected output:** Risk register with 10 threat assessments. Highest risks: training data breach (likely × high = risk score 16), model theft (possible × critical = 20). Treatment plan recommends implementing A.8.12, A.8.16, A.5.12 for the highest-priority gaps.

### Generate a gap analysis for AI-focused certification

```
Use the gap_analysis tool with:
  current_controls: ["A.5.1", "A.5.2", "A.5.15", "A.5.24", "A.6.3", "A.8.5", "A.8.7", "A.8.15", "A.8.16", "A.8.24"]
  target_certification: "ai-focused"
```

**Expected output:** 25 AI-critical controls evaluated. ~40% coverage. Phase 1 critical gaps: A.8.8 (vulnerability management), A.8.12 (data leakage), A.5.34 (PII protection). Estimated remediation: 3–6 months.

### Classify a security incident involving AI

```
Use the incident_classification tool with:
  incident_description: "Adversarial evasion attack detected on production fraud detection model. Attackers crafted transactions that bypassed ML model scoring. Approximately 200 fraudulent transactions processed before detection."
  affected_assets: ["fraud detection model", "transaction processing system", "customer accounts"]
  detection_method: "automated"
  data_breach: false
  ai_system_involved: true
```

**Expected output:** Severity HIGH (P1), AI incident category: adversarial attack. Immediate response: activate incident plan (A.5.24), contain model, preserve inference logs, assess model integrity. AI-specific controls: A.5.7, A.8.8, A.8.16.

## Installation

### Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "iso-27001-ai": {
      "command": "npx",
      "args": ["-y", "meok-iso-27001-ai-mcp"]
    }
  }
}
```

Or install via Smithery:
```bash
npx smithery mcp add nicholastempleman/iso-27001-ai-mcp
```

### Cursor

Add to `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "iso-27001-ai": {
      "command": "npx",
      "args": ["-y", "meok-iso-27001-ai-mcp"]
    }
  }
}
```

### VS Code

Add to `.vscode/mcp.json`:

```json
{
  "servers": {
    "iso-27001-ai": {
      "command": "npx",
      "args": ["-y", "meok-iso-27001-ai-mcp"]
    }
  }
}
```

### pip

```bash
pip install meok-iso-27001-ai-mcp
```

## Related Servers

| Server | Purpose |
|--------|---------|
| [iso-42001-ai](../iso-42001-ai-mcp/) | AI management system — Annex A controls and Annex B risk assessment |
| [gdpr-compliance-ai](../gdpr-compliance-ai-mcp/) | GDPR DPIA, data subject rights, breach notification |
| [eu-ai-act-compliance](../eu-ai-act-compliance-ai-mcp/) | EU AI Act risk classification and Annex IV documentation |
| [soc2-compliance-ai](../soc2-compliance-ai-mcp/) | SOC 2 Trust Service Criteria and control matrix |
| [csoai-governance-crosswalk](../csoai-governance-crosswalk-ai-mcp/) | 12 compliance frameworks mapped through 52 articles |

## Pricing

- **Free tier:** 10 calls/day per tool
- **Pro:** £79/mo — unlimited calls + cryptographically signed compliance attestations

## License

MIT © [MEOK AI Labs](https://meok.ai)

<!-- BUY-LADDER:START -->

## 💸 Try MEOK in 30 seconds — instant buy ladder

| Tier | Price | What you get | Stripe |
|---|---|---|---|
| Smoke test | **£1** | Signed sample MCP-Hardening report + Article 50 PDF | <https://buy.stripe.com/5kQ6oJ0xS3ce8sl7ew8k91j> |
| Quick Kit | **£9** | EU AI Act Article 50 implementation guide (C2PA + EU-Icon) | <https://buy.stripe.com/5kQ6oJ0xS3ce8sl7ew8k91j> |
| Founder Call | **£29** | 30-min 1-on-1 with the founder | <https://buy.stripe.com/5kQ6oJ0xS3ce8sl7ew8k91j> |

> Refundable. UK Stripe — VAT-clean. Builds on the 81-MCP MEOK fleet.
> Verify any signed report at <https://meok.ai/verify>.

<!-- BUY-LADDER:END -->
