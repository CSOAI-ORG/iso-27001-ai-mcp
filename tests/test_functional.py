import os
import sys
import pytest
from unittest.mock import patch

sys.path.insert(0, os.path.expanduser("~/clawd/meok-labs-engine/shared"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")
os.chdir(os.path.dirname(os.path.abspath(__file__)) + "/..")

import server as srv


@pytest.fixture(autouse=True)
def _pro_access():
    with patch.object(srv, "check_access", return_value=(True, "OK", "pro")):
        srv._usage.clear()
        yield
        srv._usage.clear()


# ── audit_isms ───────────────────────────────────────────────────────────────

class TestAuditISMS:
    def test_no_controls_shows_low_coverage(self):
        result = srv.audit_isms(
            organization_context="AI startup",
            scope_description="Cloud-based ML platform",
        )
        assert isinstance(result, dict)
        assert result["summary"]["overall_coverage_percent"] == 0.0
        assert result["summary"]["gaps"] == 93
        assert result["summary"]["certification_ready"] is False

    def test_partial_controls_shows_partial_coverage(self):
        result = srv.audit_isms(
            organization_context="AI startup",
            scope_description="Cloud-based ML platform",
            controls_implemented=["A.5.1", "A.8.24"],
        )
        assert result["summary"]["implemented"] == 2
        assert result["summary"]["gaps"] == 91
        assert 0 < result["summary"]["overall_coverage_percent"] < 50
        assert result["summary"]["certification_ready"] is False

    def test_theme_results_present(self):
        result = srv.audit_isms(
            organization_context="Enterprise",
            scope_description="Full ISMS scope",
            controls_implemented=["A.5.1", "A.5.15", "A.6.3", "A.7.1", "A.8.1"],
        )
        assert "A.5" in result["theme_results"]
        assert "A.6" in result["theme_results"]
        assert "A.7" in result["theme_results"]
        assert "A.8" in result["theme_results"]

    def test_critical_gaps_flagged(self):
        result = srv.audit_isms(
            organization_context="Startup",
            scope_description="Initial ISMS",
            controls_implemented=[],
        )
        critical = result["summary"]["critical_gaps"]
        assert len(critical) > 0
        assert any(g["priority"] == "CRITICAL" for g in critical)

    def test_high_coverage_passes_theme(self):
        all_controls = []
        for theme in srv.ANNEX_A_CONTROLS.values():
            all_controls.extend(theme["controls"].keys())
        result = srv.audit_isms(
            organization_context="Mature org",
            scope_description="Full scope",
            controls_implemented=all_controls,
        )
        assert result["summary"]["overall_coverage_percent"] == 100.0
        assert result["summary"]["certification_ready"] is True


# ── risk_assessment ──────────────────────────────────────────────────────────

class TestRiskAssessment:
    def test_returns_risk_matrix(self):
        result = srv.risk_assessment(
            system_description="AI-powered credit scoring platform",
            assets=["training data", "ML model", "API keys", "customer PII"],
        )
        assert isinstance(result, dict)
        assert "risk_matrix" in result
        for level in ("critical", "high", "medium", "low", "negligible"):
            assert level in result["risk_matrix"]
        assert "risk_register" in result
        assert len(result["risk_register"]) > 0

    def test_external_threats_mapped(self):
        result = srv.risk_assessment(
            system_description="External-facing AI service",
            assets=["ML model", "API endpoint"],
            threat_scenarios=["external threats", "adversarial attack"],
        )
        threats_found = [e["threat"] for e in result["risk_register"]]
        assert any("adversarial" in t.lower() for t in threats_found)

    def test_existing_controls_reduce_risk(self):
        result_no_ctrl = srv.risk_assessment(
            system_description="AI system",
            assets=["ML model"],
            threat_scenarios=["adversarial attack"],
        )
        result_with_ctrl = srv.risk_assessment(
            system_description="AI system",
            assets=["ML model"],
            threat_scenarios=["adversarial attack"],
            existing_controls=["A.8.8", "A.8.16", "A.8.25"],
        )
        entry_no = result_no_ctrl["risk_register"][0]
        entry_with = result_with_ctrl["risk_register"][0]
        assert entry_with["residual_risk_score"] <= entry_no["residual_risk_score"]

    def test_overall_risk_posture_present(self):
        result = srv.risk_assessment(
            system_description="Production AI system",
            assets=["training data", "model", "infrastructure"],
        )
        assert "overall_risk_posture" in result
        assert result["overall_risk_posture"] in ("CRITICAL", "HIGH", "MODERATE", "LOW")

    def test_treatment_plan_generated(self):
        result = srv.risk_assessment(
            system_description="AI system with no controls",
            assets=["ML model", "customer data"],
        )
        assert "treatment_plan" in result
        assert isinstance(result["treatment_plan"], list)


# ── gap_analysis ─────────────────────────────────────────────────────────────

class TestGapAnalysis:
    def test_full_target_identifies_gaps(self):
        result = srv.gap_analysis(
            current_controls=[],
            target_certification="full",
        )
        assert isinstance(result, dict)
        assert result["summary"]["total_gaps"] > 0
        assert result["summary"]["coverage_percent"] == 0.0

    def test_partial_coverage(self):
        result = srv.gap_analysis(
            current_controls=["A.5.1", "A.8.24"],
            target_certification="full",
        )
        assert result["summary"]["total_met"] == 2
        assert result["summary"]["coverage_percent"] > 0
        assert "Significant work" in result["summary"]["certification_readiness"]

    def test_prioritized_remediation_has_phases(self):
        result = srv.gap_analysis(
            current_controls=[],
            target_certification="full",
        )
        assert len(result["prioritized_remediation"]) == 3
        phases = [p["phase"] for p in result["prioritized_remediation"]]
        assert any("Critical" in p or "Phase 1" in p for p in phases)

    def test_ai_focused_target(self):
        result = srv.gap_analysis(
            current_controls=[],
            target_certification="ai-focused",
        )
        assert result["summary"]["total_required"] < 93

    def test_near_ready_when_close(self):
        many_controls = []
        for theme in srv.ANNEX_A_CONTROLS.values():
            for ctrl_id in theme["controls"]:
                many_controls.append(ctrl_id)
        subset = many_controls[:80]
        result = srv.gap_analysis(
            current_controls=subset,
            target_certification="full",
        )
        assert result["summary"]["coverage_percent"] > 75


# ── generate_soa ─────────────────────────────────────────────────────────────

class TestGenerateSoA:
    def test_soa_with_one_control(self):
        result = srv.generate_soa(
            organization_name="TestCorp",
            controls_implemented=["A.5.1"],
        )
        assert isinstance(result, dict)
        assert result["document_type"] == "Statement of Applicability (SoA)"
        assert result["organization"] == "TestCorp"
        assert result["statistics"]["implemented"] == 1
        assert result["statistics"]["not_yet_addressed"] == 92

    def test_soa_includes_all_themes(self):
        result = srv.generate_soa(
            organization_name="TestCorp",
            controls_implemented=["A.5.1"],
        )
        assert "A.5" in result["themes"]
        assert "A.6" in result["themes"]
        assert "A.7" in result["themes"]
        assert "A.8" in result["themes"]

    def test_soa_excluded_controls(self):
        result = srv.generate_soa(
            organization_name="TestCorp",
            controls_implemented=["A.5.1"],
            controls_excluded=["A.7.1", "A.7.2"],
            exclusion_justifications={"A.7.1": "Cloud-only, no physical premises", "A.7.2": "Managed by cloud provider"},
        )
        assert result["statistics"]["excluded"] == 2
        assert result["statistics"]["not_yet_addressed"] == 90

    def test_soa_complete_when_all_addressed(self):
        all_controls = []
        for theme in srv.ANNEX_A_CONTROLS.values():
            all_controls.extend(theme["controls"].keys())
        result = srv.generate_soa(
            organization_name="FullCorp",
            controls_implemented=all_controls,
        )
        assert result["statistics"]["soa_complete"] is True
        assert result["statistics"]["implementation_percentage"] == 100.0

    def test_soa_entries_have_justification(self):
        result = srv.generate_soa(
            organization_name="TestCorp",
            controls_implemented=["A.5.1"],
        )
        for theme_data in result["themes"].values():
            for entry in theme_data["controls"]:
                assert "justification" in entry
                assert isinstance(entry["justification"], str)
                assert len(entry["justification"]) > 0


# ── incident_classification ──────────────────────────────────────────────────

class TestIncidentClassification:
    def test_data_breach_high_severity(self):
        result = srv.incident_classification(
            incident_description="Unauthorized access to customer database — data breach confirmed",
            affected_assets=["customer database", "CRM system"],
            data_breach=True,
        )
        assert isinstance(result, dict)
        assert result["classification"]["severity"] in ("CRITICAL", "HIGH")
        assert result["classification"]["severity_score"] >= 4
        assert result["classification"]["priority"] in ("P1", "P2")

    def test_ransomware_is_critical(self):
        result = srv.incident_classification(
            incident_description="Ransomware attack encrypted production servers",
            affected_assets=["production servers", "backup systems"],
        )
        assert result["classification"]["severity"] == "CRITICAL"
        assert result["classification"]["priority"] == "P1"

    def test_low_incident(self):
        result = srv.incident_classification(
            incident_description="Failed login attempts from unknown IP",
            affected_assets=["login system"],
        )
        assert result["classification"]["severity"] == "LOW"

    def test_ai_incident_classification(self):
        result = srv.incident_classification(
            incident_description="Adversarial attack caused model to misclassify inputs",
            affected_assets=["ML model", "inference API"],
            ai_system_involved=True,
        )
        assert result["ai_classification"] is not None
        assert "ai_incident_categories" in result["ai_classification"]
        assert any("adversarial" in c for c in result["ai_classification"]["ai_incident_categories"])

    def test_data_breach_triggers_notification_requirements(self):
        result = srv.incident_classification(
            incident_description="Data breach involving customer records",
            affected_assets=["customer database"],
            data_breach=True,
        )
        notifications = result["notification_requirements"]
        authority_notify = next(n for n in notifications if n["authority"] == "Data Protection Authority")
        assert authority_notify["required"] is True
        assert "72 hours" in authority_notify["timeframe"]

    def test_evidence_requirements_present(self):
        result = srv.incident_classification(
            incident_description="Security incident",
            affected_assets=["server"],
        )
        assert "evidence_requirements" in result
        assert result["evidence_requirements"]["iso27001_control"] == "A.5.28 Collection of evidence"
        assert len(result["evidence_requirements"]["evidence_types"]) >= 4

    def test_response_procedures_reference_controls(self):
        result = srv.incident_classification(
            incident_description="Phishing attack leading to credential compromise",
            affected_assets=["email system", "user accounts"],
        )
        controls = result["response_procedures"]["iso27001_controls"]
        control_ids = [c["control"] for c in controls]
        assert "A.5.24" in control_ids
        assert "A.5.26" in control_ids
