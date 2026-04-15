# ISO 27001 AI

> By [MEOK AI Labs](https://meok.ai) — ISO/IEC 27001:2022 Information Security Management System compliance

## Installation

```bash
pip install iso-27001-ai-mcp
```

## Usage

```bash
python server.py
```

## Tools

### `audit_isms`
Audit against ISO 27001:2022 Annex A controls (93 controls across 4 themes: Organizational, People, Physical, Technological).

**Parameters:**
- `organization_description` (str): Description of the organization and its ISMS
- `scope` (str): Audit scope
- `api_key` (str): API key for authentication

### `risk_assessment`
Information security risk assessment per ISO 27005 methodology.

**Parameters:**
- `asset_description` (str): Description of the information asset
- `threat_description` (str): Threat scenario to assess
- `api_key` (str): API key

### `gap_analysis`
Compare current controls to ISO 27001 requirements and identify gaps.

**Parameters:**
- `current_controls` (str): Description of existing security controls
- `api_key` (str): API key

### `crosswalk_to_ai`
Map ISO 27001 controls to ISO 42001 AI management system requirements.

**Parameters:**
- `control_id` (str): ISO 27001 control identifier
- `api_key` (str): API key

### `generate_soa`
Generate Statement of Applicability (SoA) for certification.

**Parameters:**
- `organization_description` (str): Organization context
- `api_key` (str): API key

### `incident_classification`
Classify security incidents with AI-specific categories.

**Parameters:**
- `incident_description` (str): Description of the security incident
- `api_key` (str): API key

## Authentication

Free tier: 10 calls/day. Upgrade at [meok.ai/pricing](https://meok.ai/pricing) for unlimited access.

## License

MIT — MEOK AI Labs
