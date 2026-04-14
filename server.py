#!/usr/bin/env python3
"""
ISO/IEC 27001 Information Security Management MCP Server
=========================================================
By MEOK AI Labs | https://meok.ai

ISO/IEC 27001:2022 compliance assessment for AI systems. Covers all 93 controls
across 4 themes (Annex A), risk assessment per ISO 27005, Statement of Applicability
generation, incident classification, and bridging to ISO 42001 for AI-specific ISMS.

Reference: ISO/IEC 27001:2022 — Information security, cybersecurity and privacy
           protection — Information security management systems — Requirements

Install: pip install mcp
Run:     python server.py
"""

import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Optional

from mcp.server.fastmcp import FastMCP

# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------
FREE_DAILY_LIMIT = 10
_usage: dict[str, list[datetime]] = defaultdict(list)


def _check_rate_limit(caller: str = "anonymous", tier: str = "free") -> Optional[str]:
    if tier == "pro":
        return None
    now = datetime.now()
    cutoff = now - timedelta(days=1)
    _usage[caller] = [t for t in _usage[caller] if t > cutoff]
    if len(_usage[caller]) >= FREE_DAILY_LIMIT:
        return (
            f"Free tier limit reached ({FREE_DAILY_LIMIT}/day). "
            "Upgrade to MEOK AI Labs Pro for unlimited: https://meok.ai/mcp/iso-27001-ai/pro"
        )
    _usage[caller].append(now)
    return None


# ---------------------------------------------------------------------------
# FastMCP Server
# ---------------------------------------------------------------------------
mcp = FastMCP(
    "iso-27001-ai",
    instructions=(
        "ISO/IEC 27001:2022 Information Security Management System compliance server. "
        "Audit against all 93 Annex A controls across 4 themes, perform ISO 27005 risk "
        "assessments, run gap analysis, generate Statement of Applicability, classify "
        "security incidents, and crosswalk to ISO 42001 for AI-specific requirements. "
        "By MEOK AI Labs."
    ),
)

# ---------------------------------------------------------------------------
# ISO 27001:2022 Annex A — 93 Controls across 4 Themes
# ---------------------------------------------------------------------------

ANNEX_A_CONTROLS = {
    "A.5": {
        "theme": "Organizational controls",
        "title": "Organizational controls",
        "control_count": 37,
        "controls": {
            "A.5.1": {"title": "Policies for information security", "description": "Information security policy and topic-specific policies shall be defined, approved by management, published, communicated to and acknowledged by relevant personnel and relevant interested parties, and reviewed at planned intervals and if significant changes occur."},
            "A.5.2": {"title": "Information security roles and responsibilities", "description": "Information security roles and responsibilities shall be defined and allocated."},
            "A.5.3": {"title": "Segregation of duties", "description": "Conflicting duties and conflicting areas of responsibility shall be segregated."},
            "A.5.4": {"title": "Management responsibilities", "description": "Management shall require all personnel to apply information security in accordance with the established information security policy, topic-specific policies and procedures of the organization."},
            "A.5.5": {"title": "Contact with authorities", "description": "The organization shall establish and maintain contact with relevant authorities."},
            "A.5.6": {"title": "Contact with special interest groups", "description": "The organization shall establish and maintain contact with special interest groups or other specialist security forums and professional associations."},
            "A.5.7": {"title": "Threat intelligence", "description": "Information relating to information security threats shall be collected and analysed to produce threat intelligence."},
            "A.5.8": {"title": "Information security in project management", "description": "Information security shall be integrated into project management."},
            "A.5.9": {"title": "Inventory of information and other associated assets", "description": "An inventory of information and other associated assets, including owners, shall be developed and maintained."},
            "A.5.10": {"title": "Acceptable use of information and other associated assets", "description": "Rules for the acceptable use and procedures for handling information and other associated assets shall be identified, documented and implemented."},
            "A.5.11": {"title": "Return of assets", "description": "Personnel and other interested parties as appropriate shall return all organizational assets in their possession upon change or termination of their employment, contract or agreement."},
            "A.5.12": {"title": "Classification of information", "description": "Information shall be classified according to the information security needs of the organization based on confidentiality, integrity, availability and relevant interested party requirements."},
            "A.5.13": {"title": "Labelling of information", "description": "An appropriate set of procedures for information labelling shall be developed and implemented in accordance with the information classification scheme adopted by the organization."},
            "A.5.14": {"title": "Information transfer", "description": "Information transfer rules, procedures, or agreements shall be in place for all types of transfer facilities within the organization and between the organization and other parties."},
            "A.5.15": {"title": "Access control", "description": "Rules to control physical and logical access to information and other associated assets shall be established and implemented based on business and information security requirements."},
            "A.5.16": {"title": "Identity management", "description": "The full life cycle of identities shall be managed."},
            "A.5.17": {"title": "Authentication information", "description": "Allocation and management of authentication information shall be controlled by a management process including advising personnel of appropriate handling of authentication information."},
            "A.5.18": {"title": "Access rights", "description": "Access rights to information and other associated assets shall be provisioned, reviewed, modified and removed in accordance with the organization's topic-specific policy on and rules for access control."},
            "A.5.19": {"title": "Information security in supplier relationships", "description": "Processes and procedures shall be defined and implemented to manage the information security risks associated with the use of supplier's products or services."},
            "A.5.20": {"title": "Addressing information security within supplier agreements", "description": "Relevant information security requirements shall be established and agreed with each supplier based on the type of supplier relationship."},
            "A.5.21": {"title": "Managing information security in the ICT supply chain", "description": "Processes and procedures shall be defined and implemented to manage the information security risks associated with the ICT products and services supply chain."},
            "A.5.22": {"title": "Monitoring, review and change management of supplier services", "description": "The organization shall regularly monitor, review, evaluate and manage change in supplier information security practices and service delivery."},
            "A.5.23": {"title": "Information security for use of cloud services", "description": "Processes for acquisition, use, management and exit from cloud services shall be established in accordance with the organization's information security requirements."},
            "A.5.24": {"title": "Information security incident management planning and preparation", "description": "The organization shall plan and prepare for managing information security incidents by defining, establishing and communicating information security incident management processes, roles and responsibilities."},
            "A.5.25": {"title": "Assessment and decision on information security events", "description": "The organization shall assess information security events and decide if they are to be categorized as information security incidents."},
            "A.5.26": {"title": "Response to information security incidents", "description": "Information security incidents shall be responded to in accordance with the documented procedures."},
            "A.5.27": {"title": "Learning from information security incidents", "description": "Knowledge gained from information security incidents shall be used to strengthen and improve the information security controls."},
            "A.5.28": {"title": "Collection of evidence", "description": "The organization shall establish and implement procedures for the identification, collection, acquisition and preservation of evidence related to information security events."},
            "A.5.29": {"title": "Information security during disruption", "description": "The organization shall plan how to maintain information security at an appropriate level during disruption."},
            "A.5.30": {"title": "ICT readiness for business continuity", "description": "ICT readiness shall be planned, implemented, maintained and tested based on business continuity objectives and ICT continuity requirements."},
            "A.5.31": {"title": "Legal, statutory, regulatory and contractual requirements", "description": "Legal, statutory, regulatory and contractual requirements relevant to information security and the organization's approach to meet these requirements shall be identified, documented and kept up to date."},
            "A.5.32": {"title": "Intellectual property rights", "description": "The organization shall implement appropriate procedures to protect intellectual property rights."},
            "A.5.33": {"title": "Protection of records", "description": "Records shall be protected from loss, destruction, falsification, unauthorized access and unauthorized release."},
            "A.5.34": {"title": "Privacy and protection of PII", "description": "The organization shall identify and meet the requirements regarding the preservation of privacy and protection of PII as applicable per relevant legislation, regulations and contractual requirements."},
            "A.5.35": {"title": "Independent review of information security", "description": "The organization's approach to managing information security and its implementation including people, processes and technologies shall be reviewed independently at planned intervals, or when significant changes occur."},
            "A.5.36": {"title": "Compliance with policies, rules and standards for information security", "description": "Compliance with the organization's established information security policy, topic-specific policies, rules and standards shall be regularly reviewed."},
            "A.5.37": {"title": "Documented operating procedures", "description": "Operating procedures for information processing facilities shall be documented and made available to personnel who need them."},
        },
    },
    "A.6": {
        "theme": "People controls",
        "title": "People controls",
        "control_count": 8,
        "controls": {
            "A.6.1": {"title": "Screening", "description": "Background verification checks on all candidates to become personnel shall be carried out prior to joining the organization and on an ongoing basis taking into account applicable laws, regulations and ethics and be proportional to the business requirements, the classification of the information to be accessed and the perceived risks."},
            "A.6.2": {"title": "Terms and conditions of employment", "description": "The employment contractual agreements shall state the personnel's and the organization's responsibilities for information security."},
            "A.6.3": {"title": "Information security awareness, education and training", "description": "Personnel of the organization and relevant interested parties shall receive appropriate information security awareness, education and training and regular updates of the organization's information security policy, topic-specific policies and procedures, as relevant for their job function."},
            "A.6.4": {"title": "Disciplinary process", "description": "A disciplinary process shall be formalized and communicated to take actions against personnel and other relevant interested parties who have committed an information security policy violation."},
            "A.6.5": {"title": "Responsibilities after termination or change of employment", "description": "Information security responsibilities and duties that remain valid after termination or change of employment shall be defined, enforced and communicated to relevant personnel and other interested parties."},
            "A.6.6": {"title": "Confidentiality or non-disclosure agreements", "description": "Confidentiality or non-disclosure agreements reflecting the organization's needs for the protection of information shall be identified, documented, regularly reviewed and signed by personnel and other relevant interested parties."},
            "A.6.7": {"title": "Remote working", "description": "Security measures shall be implemented when personnel are working remotely to protect information accessed, processed or stored outside the organization's premises."},
            "A.6.8": {"title": "Information security event reporting", "description": "The organization shall provide a mechanism for personnel to report observed or suspected information security events through appropriate channels in a timely manner."},
        },
    },
    "A.7": {
        "theme": "Physical controls",
        "title": "Physical controls",
        "control_count": 14,
        "controls": {
            "A.7.1": {"title": "Physical security perimeters", "description": "Security perimeters shall be defined and used to protect areas that contain information and other associated assets."},
            "A.7.2": {"title": "Physical entry", "description": "Secure areas shall be protected by appropriate entry controls and access points."},
            "A.7.3": {"title": "Securing offices, rooms and facilities", "description": "Physical security for offices, rooms and facilities shall be designed and implemented."},
            "A.7.4": {"title": "Physical security monitoring", "description": "Premises shall be continuously monitored for unauthorized physical access."},
            "A.7.5": {"title": "Protecting against physical and environmental threats", "description": "Protection against physical and environmental threats, such as natural disasters and other intentional or unintentional physical threats to infrastructure shall be designed and implemented."},
            "A.7.6": {"title": "Working in secure areas", "description": "Security measures for working in secure areas shall be designed and implemented."},
            "A.7.7": {"title": "Clear desk and clear screen", "description": "Clear desk rules for papers and removable storage media and clear screen rules for information processing facilities shall be defined and appropriately enforced."},
            "A.7.8": {"title": "Equipment siting and protection", "description": "Equipment shall be sited securely and protected."},
            "A.7.9": {"title": "Security of assets off-premises", "description": "Off-site assets shall be protected."},
            "A.7.10": {"title": "Storage media", "description": "Storage media shall be managed through their life cycle of acquisition, use, transportation and disposal in accordance with the organization's classification scheme and handling requirements."},
            "A.7.11": {"title": "Supporting utilities", "description": "Information processing facilities shall be protected from power failures and other disruptions caused by failures in supporting utilities."},
            "A.7.12": {"title": "Cabling security", "description": "Cables carrying power, data or supporting information services shall be protected from interception, interference or damage."},
            "A.7.13": {"title": "Equipment maintenance", "description": "Equipment shall be maintained correctly to ensure availability, integrity and confidentiality of information."},
            "A.7.14": {"title": "Secure disposal or re-use of equipment", "description": "Items of equipment containing storage media shall be verified to ensure that any sensitive data and licensed software has been removed or securely overwritten prior to disposal or re-use."},
        },
    },
    "A.8": {
        "theme": "Technological controls",
        "title": "Technological controls",
        "control_count": 34,
        "controls": {
            "A.8.1": {"title": "User endpoint devices", "description": "Information stored on, processed by or accessible via user endpoint devices shall be protected."},
            "A.8.2": {"title": "Privileged access rights", "description": "The allocation and use of privileged access rights shall be restricted and managed."},
            "A.8.3": {"title": "Information access restriction", "description": "Access to information and other associated assets shall be restricted in accordance with the established topic-specific policy on access control."},
            "A.8.4": {"title": "Access to source code", "description": "Read and write access to source code, development tools and software libraries shall be appropriately managed."},
            "A.8.5": {"title": "Secure authentication", "description": "Secure authentication technologies and procedures shall be established and implemented based on information access restrictions and the topic-specific policy on access control."},
            "A.8.6": {"title": "Capacity management", "description": "The use of resources shall be monitored and adjusted in line with current and expected capacity requirements."},
            "A.8.7": {"title": "Protection against malware", "description": "Protection against malware shall be implemented and supported by appropriate user awareness."},
            "A.8.8": {"title": "Management of technical vulnerabilities", "description": "Information about technical vulnerabilities of information systems in use shall be obtained, the organization's exposure to such vulnerabilities shall be evaluated and appropriate measures shall be taken."},
            "A.8.9": {"title": "Configuration management", "description": "Configurations, including security configurations, of hardware, software, services and networks shall be established, documented, implemented, monitored and reviewed."},
            "A.8.10": {"title": "Information deletion", "description": "Information stored in information systems, devices or in any other storage media shall be deleted when no longer required."},
            "A.8.11": {"title": "Data masking", "description": "Data masking shall be used in accordance with the organization's topic-specific policy on access control and other related topic-specific policies, and business requirements, taking into consideration applicable legislation."},
            "A.8.12": {"title": "Data leakage prevention", "description": "Data leakage prevention measures shall be applied to systems, networks and any other devices that process, store or transmit sensitive information."},
            "A.8.13": {"title": "Information backup", "description": "Backup copies of information, software and systems shall be maintained and regularly tested in accordance with the agreed topic-specific policy on backup."},
            "A.8.14": {"title": "Redundancy of information processing facilities", "description": "Information processing facilities shall be implemented with redundancy sufficient to meet availability requirements."},
            "A.8.15": {"title": "Logging", "description": "Logs that record activities, exceptions, faults and other relevant events shall be produced, stored, protected and analysed."},
            "A.8.16": {"title": "Monitoring activities", "description": "Networks, systems and applications shall be monitored for anomalous behaviour and appropriate actions taken to evaluate potential information security incidents."},
            "A.8.17": {"title": "Clock synchronization", "description": "The clocks of information processing systems used by the organization shall be synchronized to approved time sources."},
            "A.8.18": {"title": "Use of privileged utility programs", "description": "The use of utility programs that can be capable of overriding system and application controls shall be restricted and tightly controlled."},
            "A.8.19": {"title": "Installation of software on operational systems", "description": "Procedures and measures shall be implemented to securely manage software installation on operational systems."},
            "A.8.20": {"title": "Networks security", "description": "Networks and network devices shall be secured, managed and controlled to protect information in systems and applications."},
            "A.8.21": {"title": "Security of network services", "description": "Security mechanisms, service levels and service requirements of network services shall be identified, implemented and monitored."},
            "A.8.22": {"title": "Segregation of networks", "description": "Groups of information services, users and information systems shall be segregated in the organization's networks."},
            "A.8.23": {"title": "Web filtering", "description": "Access to external websites shall be managed to reduce exposure to malicious content."},
            "A.8.24": {"title": "Use of cryptography", "description": "Rules for the effective use of cryptography, including cryptographic key management, shall be defined and implemented."},
            "A.8.25": {"title": "Secure development life cycle", "description": "Rules for the secure development of software and systems shall be established and applied."},
            "A.8.26": {"title": "Application security requirements", "description": "Information security requirements shall be identified, specified and approved when developing or acquiring applications."},
            "A.8.27": {"title": "Secure system architecture and engineering principles", "description": "Principles for engineering secure systems shall be established, documented, maintained and applied to any information system development activities."},
            "A.8.28": {"title": "Secure coding", "description": "Secure coding principles shall be applied to software development."},
            "A.8.29": {"title": "Security testing in development and acceptance", "description": "Security testing processes shall be defined and implemented in the development life cycle."},
            "A.8.30": {"title": "Outsourced development", "description": "The organization shall direct, monitor and review the activities related to outsourced system development."},
            "A.8.31": {"title": "Separation of development, test and production environments", "description": "Development, testing and production environments shall be separated and secured."},
            "A.8.32": {"title": "Change management", "description": "Changes to information processing facilities and information systems shall be subject to change management procedures."},
            "A.8.33": {"title": "Test information", "description": "Test information shall be appropriately selected, protected and managed."},
            "A.8.34": {"title": "Protection of information systems during audit testing", "description": "Audit tests and other assurance activities involving assessment of operational systems shall be planned and agreed between the tester and appropriate management."},
        },
    },
}

# ---------------------------------------------------------------------------
# ISO 27001 ISMS Clauses 4-10
# ---------------------------------------------------------------------------

ISMS_CLAUSES = {
    "4": {"title": "Context of the organization", "subclauses": ["4.1 Understanding the organization and its context", "4.2 Understanding the needs and expectations of interested parties", "4.3 Determining the scope of the ISMS", "4.4 Information security management system"]},
    "5": {"title": "Leadership", "subclauses": ["5.1 Leadership and commitment", "5.2 Policy", "5.3 Organizational roles, responsibilities and authorities"]},
    "6": {"title": "Planning", "subclauses": ["6.1 Actions to address risks and opportunities", "6.2 Information security objectives and planning to achieve them"]},
    "7": {"title": "Support", "subclauses": ["7.1 Resources", "7.2 Competence", "7.3 Awareness", "7.4 Communication", "7.5 Documented information"]},
    "8": {"title": "Operation", "subclauses": ["8.1 Operational planning and control", "8.2 Information security risk assessment", "8.3 Information security risk treatment"]},
    "9": {"title": "Performance evaluation", "subclauses": ["9.1 Monitoring, measurement, analysis and evaluation", "9.2 Internal audit", "9.3 Management review"]},
    "10": {"title": "Improvement", "subclauses": ["10.1 Continual improvement", "10.2 Nonconformity and corrective action"]},
}

# ---------------------------------------------------------------------------
# ISO 27001 to ISO 42001 Bridge Mappings
# ---------------------------------------------------------------------------

ISO27001_TO_ISO42001_BRIDGE = {
    "A.5.1": {"iso42001": "5.2, A.2.2", "alignment": "strong", "note": "Information security policy extends to AI-specific policy requirements under ISO 42001 clause 5.2 and Annex A.2.2 AI policies."},
    "A.5.2": {"iso42001": "5.3, A.2.3", "alignment": "strong", "note": "Security roles map to AI management system roles and responsibilities."},
    "A.5.7": {"iso42001": "A.6.2.4", "alignment": "partial", "note": "Threat intelligence extends to AI-specific threat monitoring including adversarial attacks, model poisoning, and data drift."},
    "A.5.8": {"iso42001": "8.1, A.3.3", "alignment": "strong", "note": "Information security in project management maps to AI system lifecycle management under ISO 42001."},
    "A.5.9": {"iso42001": "A.5.3, A.5.4", "alignment": "strong", "note": "Asset inventory extends to AI model inventory, dataset cataloguing, and AI component tracking."},
    "A.5.12": {"iso42001": "A.5.5", "alignment": "strong", "note": "Information classification maps directly to AI data classification requirements."},
    "A.5.15": {"iso42001": "A.7.4", "alignment": "strong", "note": "Access control extends to AI model access, training data access, and inference API access controls."},
    "A.5.19": {"iso42001": "A.10.3, A.10.4", "alignment": "strong", "note": "Supplier security extends to AI supply chain including model providers, data providers, and ML platform vendors."},
    "A.5.23": {"iso42001": "A.10.3", "alignment": "strong", "note": "Cloud services security directly applicable to AI cloud platforms (AWS SageMaker, Azure ML, GCP Vertex AI)."},
    "A.5.24": {"iso42001": "A.6.2.6", "alignment": "partial", "note": "Incident management extends to AI-specific incidents: model failures, bias detection, adversarial attacks, hallucination events."},
    "A.5.34": {"iso42001": "A.8.2, A.8.3, A.8.4, A.8.5", "alignment": "strong", "note": "PII protection maps to AI data protection controls including training data privacy, inference data handling, and model memorization risks."},
    "A.6.3": {"iso42001": "7.2, 7.3", "alignment": "strong", "note": "Security awareness training extends to AI-specific training on responsible AI use, prompt injection risks, and AI ethics."},
    "A.8.4": {"iso42001": "A.7.3", "alignment": "strong", "note": "Source code access controls extend to model code, training scripts, and ML pipeline access management."},
    "A.8.8": {"iso42001": "A.6.2.4, A.6.2.5", "alignment": "strong", "note": "Vulnerability management extends to AI model vulnerabilities, adversarial robustness testing, and model security scanning."},
    "A.8.10": {"iso42001": "A.8.5", "alignment": "strong", "note": "Information deletion extends to model retirement, training data disposal, and right to be forgotten in AI systems."},
    "A.8.11": {"iso42001": "A.8.4", "alignment": "strong", "note": "Data masking applies to training data anonymization, differential privacy in AI, and inference output sanitization."},
    "A.8.12": {"iso42001": "A.8.2", "alignment": "strong", "note": "Data leakage prevention extends to model extraction attacks, training data memorization leaks, and prompt injection data exfiltration."},
    "A.8.15": {"iso42001": "A.6.2.3", "alignment": "strong", "note": "Logging extends to AI audit logging: model decisions, confidence scores, input/output pairs for high-risk decisions."},
    "A.8.25": {"iso42001": "A.3.2, A.3.3", "alignment": "strong", "note": "Secure SDLC extends to ML development lifecycle including data pipeline security, model training integrity, and deployment security."},
    "A.8.28": {"iso42001": "A.7.3", "alignment": "partial", "note": "Secure coding extends to secure ML coding practices, safe tensor operations, and validated inference pipelines."},
}

# ---------------------------------------------------------------------------
# ISO 27005 Risk Assessment Framework
# ---------------------------------------------------------------------------

ISO_27005_RISK_CRITERIA = {
    "threat_categories": [
        "Adversarial attack (evasion, poisoning, extraction, inference)",
        "Model theft or unauthorized replication",
        "Training data breach or poisoning",
        "Supply chain compromise (model, data, or platform)",
        "Insider threat (model manipulation, data exfiltration)",
        "Infrastructure attack (DDoS on AI services, compute hijacking)",
        "Social engineering targeting AI operators",
        "Regulatory non-compliance (GDPR, EU AI Act, sector-specific)",
        "Third-party AI service compromise",
        "Physical security breach of AI infrastructure",
    ],
    "impact_levels": {
        "negligible": {"score": 1, "description": "Minimal impact, no regulatory notification required"},
        "low": {"score": 2, "description": "Limited impact, internal remediation sufficient"},
        "moderate": {"score": 3, "description": "Significant impact, management notification required"},
        "high": {"score": 4, "description": "Severe impact, regulatory notification may be required"},
        "critical": {"score": 5, "description": "Catastrophic impact, mandatory regulatory notification, potential system shutdown"},
    },
    "likelihood_levels": {
        "rare": {"score": 1, "description": "May occur only in exceptional circumstances"},
        "unlikely": {"score": 2, "description": "Could occur but not expected"},
        "possible": {"score": 3, "description": "Could occur at some time"},
        "likely": {"score": 4, "description": "Will probably occur in most circumstances"},
        "almost_certain": {"score": 5, "description": "Expected to occur in most circumstances"},
    },
}


# ---------------------------------------------------------------------------
# TOOL 1: Audit ISMS
# ---------------------------------------------------------------------------
@mcp.tool()
def audit_isms(
    organization_context: str,
    scope_description: str,
    controls_implemented: Optional[list[str]] = None,
    caller: str = "anonymous",
    tier: str = "free",
) -> str:
    """Audit an Information Security Management System against ISO 27001:2022
    Annex A controls (93 controls across 4 themes: Organizational, People,
    Physical, Technological). Returns compliance status per theme with gap
    identification and remediation priorities.

    Args:
        organization_context: Description of the organization, its AI systems, and ISMS scope
        scope_description: Specific scope of the ISMS audit (which systems, processes, locations)
        controls_implemented: List of Annex A control IDs already implemented (e.g. ["A.5.1", "A.8.24"])
        caller: Caller identifier for rate limiting
        tier: Access tier (free/pro)
    """
    if err := _check_rate_limit(caller, tier):
        return json.dumps({"error": err})

    implemented = set(controls_implemented or [])
    results = {
        "audit_type": "ISO/IEC 27001:2022 ISMS Audit",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "organization_context": organization_context,
        "scope": scope_description,
        "theme_results": {},
        "summary": {},
    }

    total_controls = 0
    total_implemented = 0
    total_gaps = 0
    critical_gaps = []

    for theme_id, theme_data in ANNEX_A_CONTROLS.items():
        theme_controls = theme_data["controls"]
        theme_implemented = []
        theme_gaps = []

        for ctrl_id, ctrl_info in theme_controls.items():
            total_controls += 1
            if ctrl_id in implemented:
                total_implemented += 1
                theme_implemented.append(ctrl_id)
            else:
                total_gaps += 1
                theme_gaps.append({"control": ctrl_id, "title": ctrl_info["title"], "description": ctrl_info["description"]})
                # Flag critical gaps
                if ctrl_id in {"A.5.1", "A.5.15", "A.5.24", "A.5.34", "A.8.5", "A.8.7", "A.8.12", "A.8.15", "A.8.24"}:
                    critical_gaps.append({"control": ctrl_id, "title": ctrl_info["title"], "priority": "CRITICAL"})

        coverage = (len(theme_implemented) / len(theme_controls) * 100) if theme_controls else 0
        results["theme_results"][theme_id] = {
            "theme": theme_data["theme"],
            "total_controls": len(theme_controls),
            "implemented": len(theme_implemented),
            "gaps": len(theme_gaps),
            "coverage_percent": round(coverage, 1),
            "gap_details": theme_gaps[:5],
            "status": "PASS" if coverage >= 80 else "PARTIAL" if coverage >= 50 else "FAIL",
        }

    overall_coverage = (total_implemented / total_controls * 100) if total_controls else 0
    results["summary"] = {
        "total_controls": total_controls,
        "implemented": total_implemented,
        "gaps": total_gaps,
        "overall_coverage_percent": round(overall_coverage, 1),
        "certification_ready": overall_coverage >= 85 and len(critical_gaps) == 0,
        "critical_gaps": critical_gaps,
        "recommendation": (
            "Organization meets minimum threshold for ISO 27001 certification consideration."
            if overall_coverage >= 85
            else f"Address {total_gaps} control gaps before certification. Priority: {len(critical_gaps)} critical gaps."
        ),
    }

    return json.dumps(results, indent=2)


# ---------------------------------------------------------------------------
# TOOL 2: Risk Assessment (ISO 27005)
# ---------------------------------------------------------------------------
@mcp.tool()
def risk_assessment(
    system_description: str,
    assets: list[str],
    threat_scenarios: Optional[list[str]] = None,
    existing_controls: Optional[list[str]] = None,
    caller: str = "anonymous",
    tier: str = "free",
) -> str:
    """Perform information security risk assessment per ISO 27005 methodology.
    Identifies threats, assesses likelihood and impact, calculates risk levels,
    and recommends treatment options with specific ISO 27001 Annex A controls.

    Args:
        system_description: Description of the AI system or information asset being assessed
        assets: List of information assets to assess (e.g. ["training data", "ML model", "API keys"])
        threat_scenarios: Specific threat scenarios to evaluate (or auto-generated if omitted)
        existing_controls: Currently implemented controls that reduce risk
        caller: Caller identifier for rate limiting
        tier: Access tier (free/pro)
    """
    if err := _check_rate_limit(caller, tier):
        return json.dumps({"error": err})

    existing = set(existing_controls or [])
    threats = threat_scenarios or ISO_27005_RISK_CRITERIA["threat_categories"]

    results = {
        "assessment_type": "ISO 27005 Information Security Risk Assessment",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "system": system_description,
        "assets_assessed": assets,
        "risk_register": [],
        "risk_matrix": {},
        "treatment_plan": [],
    }

    ai_threat_mapping = {
        "Adversarial attack": {"likelihood": "possible", "impact": "high", "controls": ["A.8.8", "A.8.16", "A.8.25", "A.8.29"]},
        "Model theft": {"likelihood": "possible", "impact": "critical", "controls": ["A.8.3", "A.8.4", "A.8.12", "A.8.24"]},
        "Training data breach": {"likelihood": "likely", "impact": "high", "controls": ["A.5.12", "A.5.34", "A.8.10", "A.8.11"]},
        "Supply chain compromise": {"likelihood": "possible", "impact": "high", "controls": ["A.5.19", "A.5.20", "A.5.21", "A.5.22"]},
        "Insider threat": {"likelihood": "unlikely", "impact": "critical", "controls": ["A.5.3", "A.6.1", "A.6.6", "A.8.2"]},
        "Infrastructure attack": {"likelihood": "possible", "impact": "high", "controls": ["A.7.1", "A.8.6", "A.8.14", "A.8.20"]},
        "Social engineering": {"likelihood": "likely", "impact": "moderate", "controls": ["A.6.3", "A.6.8", "A.8.5", "A.8.7"]},
        "Regulatory non-compliance": {"likelihood": "possible", "impact": "high", "controls": ["A.5.31", "A.5.34", "A.5.36"]},
        "Third-party AI service": {"likelihood": "possible", "impact": "high", "controls": ["A.5.19", "A.5.23", "A.8.21"]},
        "Physical security breach": {"likelihood": "rare", "impact": "high", "controls": ["A.7.1", "A.7.2", "A.7.4", "A.7.14"]},
    }

    risk_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "negligible": 0}

    for threat in threats:
        matched_key = None
        for key in ai_threat_mapping:
            if key.lower() in threat.lower():
                matched_key = key
                break

        if matched_key:
            mapping = ai_threat_mapping[matched_key]
        else:
            mapping = {"likelihood": "possible", "impact": "moderate", "controls": ["A.5.1", "A.5.7", "A.8.16"]}

        likelihood_score = ISO_27005_RISK_CRITERIA["likelihood_levels"][mapping["likelihood"]]["score"]
        impact_score = ISO_27005_RISK_CRITERIA["impact_levels"][mapping["impact"]]["score"]
        risk_score = likelihood_score * impact_score

        if risk_score >= 20:
            risk_level = "critical"
        elif risk_score >= 12:
            risk_level = "high"
        elif risk_score >= 6:
            risk_level = "medium"
        elif risk_score >= 3:
            risk_level = "low"
        else:
            risk_level = "negligible"

        mitigated = any(c in existing for c in mapping["controls"])
        if mitigated:
            risk_score = max(1, risk_score - 4)
            risk_level = "low" if risk_score <= 4 else risk_level

        risk_counts[risk_level] += 1

        entry = {
            "threat": threat,
            "likelihood": mapping["likelihood"],
            "impact": mapping["impact"],
            "inherent_risk_score": likelihood_score * impact_score,
            "residual_risk_score": risk_score,
            "risk_level": risk_level,
            "recommended_controls": mapping["controls"],
            "controls_in_place": [c for c in mapping["controls"] if c in existing],
            "treatment": "accept" if risk_level in ("negligible", "low") else "mitigate",
        }
        results["risk_register"].append(entry)

        if entry["treatment"] == "mitigate":
            missing = [c for c in mapping["controls"] if c not in existing]
            if missing:
                results["treatment_plan"].append({
                    "threat": threat,
                    "risk_level": risk_level,
                    "controls_to_implement": missing,
                    "control_descriptions": [
                        ANNEX_A_CONTROLS[c.split(".")[0] + "." + c.split(".")[1]]["controls"].get(c, {}).get("title", c)
                        for c in missing
                    ],
                })

    results["risk_matrix"] = risk_counts
    results["overall_risk_posture"] = (
        "CRITICAL" if risk_counts["critical"] > 0
        else "HIGH" if risk_counts["high"] > 2
        else "MODERATE" if risk_counts["high"] > 0 or risk_counts["medium"] > 3
        else "LOW"
    )

    return json.dumps(results, indent=2)


# ---------------------------------------------------------------------------
# TOOL 3: Gap Analysis
# ---------------------------------------------------------------------------
@mcp.tool()
def gap_analysis(
    current_controls: list[str],
    target_certification: str = "full",
    focus_themes: Optional[list[str]] = None,
    caller: str = "anonymous",
    tier: str = "free",
) -> str:
    """Compare current controls to ISO 27001:2022 requirements and identify gaps.
    Provides prioritized remediation roadmap with effort estimates.

    Args:
        current_controls: List of currently implemented Annex A control IDs
        target_certification: Target level - "full" (all 93), "core" (critical subset), or "ai-focused" (AI-relevant controls)
        focus_themes: Optional filter to specific themes ["A.5", "A.6", "A.7", "A.8"]
        caller: Caller identifier for rate limiting
        tier: Access tier (free/pro)
    """
    if err := _check_rate_limit(caller, tier):
        return json.dumps({"error": err})

    implemented = set(current_controls)
    themes = focus_themes or ["A.5", "A.6", "A.7", "A.8"]

    ai_critical_controls = {
        "A.5.1", "A.5.2", "A.5.7", "A.5.9", "A.5.12", "A.5.15", "A.5.19",
        "A.5.23", "A.5.24", "A.5.34", "A.6.3", "A.6.6", "A.8.2", "A.8.3",
        "A.8.4", "A.8.5", "A.8.8", "A.8.10", "A.8.11", "A.8.12", "A.8.15",
        "A.8.16", "A.8.24", "A.8.25", "A.8.28",
    }

    results = {
        "analysis_type": "ISO 27001:2022 Gap Analysis",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": target_certification,
        "gaps_by_theme": {},
        "prioritized_remediation": [],
        "summary": {},
    }

    total_required = 0
    total_met = 0
    all_gaps = []

    for theme_id in themes:
        if theme_id not in ANNEX_A_CONTROLS:
            continue
        theme = ANNEX_A_CONTROLS[theme_id]
        gaps = []
        met = []

        for ctrl_id, ctrl_info in theme["controls"].items():
            if target_certification == "ai-focused" and ctrl_id not in ai_critical_controls:
                continue
            total_required += 1
            if ctrl_id in implemented:
                total_met += 1
                met.append(ctrl_id)
            else:
                priority = "critical" if ctrl_id in ai_critical_controls else "standard"
                effort = "high" if ctrl_id.startswith("A.8") else "medium" if ctrl_id.startswith("A.5") else "low"
                gap = {
                    "control": ctrl_id,
                    "title": ctrl_info["title"],
                    "priority": priority,
                    "estimated_effort": effort,
                    "description": ctrl_info["description"],
                }
                gaps.append(gap)
                all_gaps.append(gap)

        results["gaps_by_theme"][theme_id] = {
            "theme": theme["theme"],
            "required": len(met) + len(gaps),
            "met": len(met),
            "gaps": len(gaps),
            "gap_details": gaps,
        }

    # Sort by priority then effort
    priority_order = {"critical": 0, "standard": 1}
    all_gaps.sort(key=lambda g: (priority_order.get(g["priority"], 2), g["control"]))

    results["prioritized_remediation"] = [
        {"phase": "Phase 1 — Critical (0-30 days)", "controls": [g for g in all_gaps if g["priority"] == "critical"][:10]},
        {"phase": "Phase 2 — Standard (30-90 days)", "controls": [g for g in all_gaps if g["priority"] == "standard"][:15]},
        {"phase": "Phase 3 — Remaining (90-180 days)", "controls": [g for g in all_gaps if g["priority"] == "standard"][15:]},
    ]

    coverage = (total_met / total_required * 100) if total_required else 0
    results["summary"] = {
        "total_required": total_required,
        "total_met": total_met,
        "total_gaps": len(all_gaps),
        "coverage_percent": round(coverage, 1),
        "critical_gaps": len([g for g in all_gaps if g["priority"] == "critical"]),
        "estimated_remediation_months": 6 if len(all_gaps) > 30 else 3 if len(all_gaps) > 10 else 1,
        "certification_readiness": "Ready" if coverage >= 90 else "Near-ready" if coverage >= 75 else "Significant work required",
    }

    return json.dumps(results, indent=2)


# ---------------------------------------------------------------------------
# TOOL 4: Crosswalk to AI (ISO 42001 Bridge)
# ---------------------------------------------------------------------------
@mcp.tool()
def crosswalk_to_ai(
    controls: Optional[list[str]] = None,
    focus_area: str = "all",
    caller: str = "anonymous",
    tier: str = "free",
) -> str:
    """Map ISO 27001 controls to AI-specific requirements via ISO 42001 bridge.
    Shows how existing ISMS controls extend to AI governance, identifying
    where additional AI-specific controls are needed.

    Args:
        controls: Specific ISO 27001 controls to map (or all mapped controls if omitted)
        focus_area: Focus on "all", "data_protection", "model_security", "supply_chain", or "incident_management"
        caller: Caller identifier for rate limiting
        tier: Access tier (free/pro)
    """
    if err := _check_rate_limit(caller, tier):
        return json.dumps({"error": err})

    focus_filters = {
        "data_protection": {"A.5.12", "A.5.34", "A.8.10", "A.8.11", "A.8.12"},
        "model_security": {"A.8.3", "A.8.4", "A.8.8", "A.8.24", "A.8.25", "A.8.28"},
        "supply_chain": {"A.5.19", "A.5.20", "A.5.21", "A.5.22", "A.5.23"},
        "incident_management": {"A.5.24", "A.5.25", "A.5.26", "A.5.27", "A.5.28"},
    }

    if controls:
        target_controls = set(controls)
    elif focus_area in focus_filters:
        target_controls = focus_filters[focus_area]
    else:
        target_controls = set(ISO27001_TO_ISO42001_BRIDGE.keys())

    results = {
        "crosswalk_type": "ISO 27001:2022 to ISO 42001:2023 Bridge",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "focus_area": focus_area,
        "mappings": [],
        "ai_gaps": [],
        "summary": {},
    }

    strong_count = 0
    partial_count = 0

    for ctrl_id in sorted(target_controls):
        if ctrl_id in ISO27001_TO_ISO42001_BRIDGE:
            bridge = ISO27001_TO_ISO42001_BRIDGE[ctrl_id]
            mapping = {
                "iso27001_control": ctrl_id,
                "iso27001_title": _get_control_title(ctrl_id),
                "iso42001_mapping": bridge["iso42001"],
                "alignment_strength": bridge["alignment"],
                "ai_extension_note": bridge["note"],
            }
            results["mappings"].append(mapping)
            if bridge["alignment"] == "strong":
                strong_count += 1
            else:
                partial_count += 1
        else:
            results["ai_gaps"].append({
                "iso27001_control": ctrl_id,
                "iso27001_title": _get_control_title(ctrl_id),
                "status": "No direct ISO 42001 mapping — AI-specific control may be needed",
            })

    results["summary"] = {
        "total_mapped": len(results["mappings"]),
        "strong_alignments": strong_count,
        "partial_alignments": partial_count,
        "unmapped_controls": len(results["ai_gaps"]),
        "recommendation": (
            "Your ISO 27001 ISMS provides a strong foundation for ISO 42001 AI management. "
            f"{strong_count} controls have strong alignment. Focus on extending "
            f"{partial_count} partially-aligned controls with AI-specific procedures."
        ),
    }

    return json.dumps(results, indent=2)


def _get_control_title(ctrl_id: str) -> str:
    parts = ctrl_id.split(".")
    theme_key = parts[0] + "." + parts[1]
    if theme_key in ANNEX_A_CONTROLS and ctrl_id in ANNEX_A_CONTROLS[theme_key]["controls"]:
        return ANNEX_A_CONTROLS[theme_key]["controls"][ctrl_id]["title"]
    return ctrl_id


# ---------------------------------------------------------------------------
# TOOL 5: Generate Statement of Applicability
# ---------------------------------------------------------------------------
@mcp.tool()
def generate_soa(
    organization_name: str,
    controls_implemented: list[str],
    controls_excluded: Optional[list[str]] = None,
    exclusion_justifications: Optional[dict[str, str]] = None,
    caller: str = "anonymous",
    tier: str = "free",
) -> str:
    """Generate a Statement of Applicability (SoA) per ISO 27001:2022 clause 6.1.3(d).
    The SoA documents which Annex A controls are applicable, implemented, excluded,
    and the justification for exclusions. Required for ISO 27001 certification.

    Args:
        organization_name: Name of the organization
        controls_implemented: List of implemented Annex A control IDs
        controls_excluded: Controls deliberately excluded with justification
        exclusion_justifications: Dict mapping excluded control IDs to justification text
        caller: Caller identifier for rate limiting
        tier: Access tier (free/pro)
    """
    if err := _check_rate_limit(caller, tier):
        return json.dumps({"error": err})

    implemented = set(controls_implemented)
    excluded = set(controls_excluded or [])
    justifications = exclusion_justifications or {}

    soa = {
        "document_type": "Statement of Applicability (SoA)",
        "standard": "ISO/IEC 27001:2022",
        "clause_reference": "6.1.3(d)",
        "organization": organization_name,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "1.0",
        "themes": {},
        "statistics": {},
    }

    total = 0
    implemented_count = 0
    excluded_count = 0
    not_addressed = 0

    for theme_id, theme_data in ANNEX_A_CONTROLS.items():
        theme_entries = []
        for ctrl_id, ctrl_info in theme_data["controls"].items():
            total += 1
            if ctrl_id in implemented:
                status = "Implemented"
                implemented_count += 1
                justification = "Control implemented and operational"
            elif ctrl_id in excluded:
                status = "Excluded"
                excluded_count += 1
                justification = justifications.get(ctrl_id, "Justification required — provide rationale for exclusion")
            else:
                status = "Not yet addressed"
                not_addressed += 1
                justification = "Control applicable but not yet implemented — include in risk treatment plan"

            theme_entries.append({
                "control_id": ctrl_id,
                "title": ctrl_info["title"],
                "applicability": "Applicable" if ctrl_id not in excluded else "Not applicable",
                "implementation_status": status,
                "justification": justification,
            })

        soa["themes"][theme_id] = {
            "theme_name": theme_data["theme"],
            "controls": theme_entries,
        }

    soa["statistics"] = {
        "total_controls": total,
        "implemented": implemented_count,
        "excluded": excluded_count,
        "not_yet_addressed": not_addressed,
        "implementation_percentage": round(implemented_count / total * 100, 1) if total else 0,
        "soa_complete": not_addressed == 0,
        "certification_note": (
            "SoA is complete — all controls addressed (implemented or excluded with justification)."
            if not_addressed == 0
            else f"SoA incomplete — {not_addressed} controls need to be addressed before certification."
        ),
    }

    return json.dumps(soa, indent=2)


# ---------------------------------------------------------------------------
# TOOL 6: Incident Classification
# ---------------------------------------------------------------------------
@mcp.tool()
def incident_classification(
    incident_description: str,
    affected_assets: list[str],
    detection_method: str = "automated",
    data_breach: bool = False,
    ai_system_involved: bool = False,
    caller: str = "anonymous",
    tier: str = "free",
) -> str:
    """Classify security incidents per ISO 27001 incident management framework
    (controls A.5.24-A.5.28). Determines severity, notification requirements,
    response procedures, and evidence collection needs. Includes AI-specific
    incident classification when AI systems are involved.

    Args:
        incident_description: Description of the security incident
        affected_assets: List of affected information assets
        detection_method: How the incident was detected (automated/manual/third-party/user-report)
        data_breach: Whether personal data was compromised
        ai_system_involved: Whether an AI system was involved in or affected by the incident
        caller: Caller identifier for rate limiting
        tier: Access tier (free/pro)
    """
    if err := _check_rate_limit(caller, tier):
        return json.dumps({"error": err})

    desc_lower = incident_description.lower()

    # Severity classification
    critical_indicators = ["ransomware", "data exfiltration", "complete system compromise", "nation-state", "supply chain attack", "model extraction", "training data stolen"]
    high_indicators = ["unauthorized access", "privilege escalation", "malware", "ddos", "data breach", "model poisoning", "adversarial attack"]
    medium_indicators = ["phishing", "policy violation", "misconfiguration", "vulnerability exploit", "prompt injection"]
    low_indicators = ["failed login", "port scan", "spam", "minor policy deviation"]

    if any(ind in desc_lower for ind in critical_indicators):
        severity = "CRITICAL"
        severity_score = 5
    elif any(ind in desc_lower for ind in high_indicators):
        severity = "HIGH"
        severity_score = 4
    elif any(ind in desc_lower for ind in medium_indicators):
        severity = "MEDIUM"
        severity_score = 3
    elif any(ind in desc_lower for ind in low_indicators):
        severity = "LOW"
        severity_score = 2
    else:
        severity = "MEDIUM"
        severity_score = 3

    if data_breach:
        severity_score = min(5, severity_score + 1)
        if severity_score >= 5:
            severity = "CRITICAL"

    ai_classification = None
    if ai_system_involved:
        ai_categories = {
            "adversarial": any(w in desc_lower for w in ["adversarial", "evasion", "perturbation"]),
            "data_poisoning": any(w in desc_lower for w in ["poisoning", "contamination", "training data"]),
            "model_theft": any(w in desc_lower for w in ["extraction", "theft", "stolen model", "model replication"]),
            "prompt_injection": any(w in desc_lower for w in ["prompt injection", "jailbreak", "prompt manipulation"]),
            "hallucination_harm": any(w in desc_lower for w in ["hallucination", "confabulation", "false output"]),
            "bias_incident": any(w in desc_lower for w in ["bias", "discrimination", "unfair", "disparate impact"]),
            "privacy_leak": any(w in desc_lower for w in ["memorization", "pii leak", "training data leak"]),
        }
        detected = [k for k, v in ai_categories.items() if v]
        ai_classification = {
            "ai_incident_categories": detected or ["general_ai_incident"],
            "ai_specific_controls": ["A.5.7 (AI threat intelligence)", "A.8.8 (AI vulnerability management)", "A.8.16 (AI monitoring)"],
            "iso42001_reference": "Report under ISO 42001 A.6.2.6 AI incident management",
        }

    notification_requirements = []
    if data_breach:
        notification_requirements.append({"authority": "Data Protection Authority", "timeframe": "72 hours (GDPR Art. 33)", "required": True})
        notification_requirements.append({"authority": "Affected Data Subjects", "timeframe": "Without undue delay (GDPR Art. 34)", "required": severity_score >= 4})
    if severity_score >= 4:
        notification_requirements.append({"authority": "Senior Management", "timeframe": "Immediate", "required": True})
        notification_requirements.append({"authority": "CERT/CSIRT", "timeframe": "4 hours", "required": True})
    if severity_score >= 3:
        notification_requirements.append({"authority": "Information Security Manager", "timeframe": "2 hours", "required": True})

    result = {
        "classification_type": "ISO 27001 Incident Classification",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "incident": {
            "description": incident_description,
            "affected_assets": affected_assets,
            "detection_method": detection_method,
            "data_breach": data_breach,
            "ai_system_involved": ai_system_involved,
        },
        "classification": {
            "severity": severity,
            "severity_score": severity_score,
            "priority": "P1" if severity_score >= 4 else "P2" if severity_score >= 3 else "P3",
        },
        "ai_classification": ai_classification,
        "notification_requirements": notification_requirements,
        "response_procedures": {
            "iso27001_controls": [
                {"control": "A.5.24", "action": "Activate incident management plan"},
                {"control": "A.5.25", "action": "Assess and categorize the incident"},
                {"control": "A.5.26", "action": "Execute incident response procedures"},
                {"control": "A.5.27", "action": "Document lessons learned post-incident"},
                {"control": "A.5.28", "action": "Preserve and collect digital evidence"},
            ],
            "immediate_actions": [
                "Contain the incident to prevent further damage",
                "Preserve evidence (logs, memory dumps, network captures)",
                "Notify relevant parties per notification requirements",
                "Activate incident response team",
            ],
        },
        "evidence_requirements": {
            "iso27001_control": "A.5.28 Collection of evidence",
            "evidence_types": [
                "System and application logs",
                "Network traffic captures",
                "Memory forensic images",
                "User activity records",
                "Configuration snapshots",
                "AI model inference logs" if ai_system_involved else None,
                "Training data integrity records" if ai_system_involved else None,
            ],
        },
    }
    # Remove None entries from evidence types
    result["evidence_requirements"]["evidence_types"] = [
        e for e in result["evidence_requirements"]["evidence_types"] if e
    ]

    return json.dumps(result, indent=2)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    mcp.run()
