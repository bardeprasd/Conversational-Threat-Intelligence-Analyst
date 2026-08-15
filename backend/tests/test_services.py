from app.schemas.threat_intel import EvidenceSource, ToolResult
from app.services.threat_intel import ThreatIntelService


def _source() -> EvidenceSource:
    return EvidenceSource(
        id="live-test",
        provider="Live Provider",
        title="Live provider evidence",
        url="https://example.test/evidence",
        observed_at="2026-08-14T00:00:00Z",
    )


def _result(tool: str, finding: dict) -> ToolResult:
    return ToolResult(
        tool=tool,
        status="ok",
        finding=finding,
        evidence=[_source()],
        confidence=0.82,
        trace_id="tr_test",
    )


class FakeLiveClient:
    def lookup_ioc(self, *, indicator: str, trace_id: str):
        return _result(
            "lookup_ioc",
            {
                "indicator": indicator,
                "verdict": "suspicious",
                "risk_score": 42,
                "asn": "AS64500 Live Test ASN",
            },
        )

    def profile_threat_actor(self, *, actor_name: str, trace_id: str):
        return _result(
            "profile_threat_actor",
            {
                "name": actor_name,
                "summary": "Live ATT&CK profile",
                "ttps": [{"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "execution"}],
            },
        )

    def assess_software_exposure(self, *, product: str, version: str, trace_id: str):
        return ToolResult(
            tool="assess_software_exposure",
            status="partial",
            finding={
                "product": product,
                "version": version,
                "verdict": "potentially_exposed",
                "matched_issues": [{"cve": "CVE-2099-0001", "severity": "high"}],
            },
            evidence=[_source()],
            confidence=0.68,
            warnings=["Verify CPE and vendor advisory."],
            trace_id=trace_id,
        )

    def pivot_related_entities(self, *, entity: str, relationship: str, trace_id: str):
        return _result(
            "pivot_related_entities",
            {
                "entity": entity,
                "relationship": relationship,
                "related_domains": ["live-related.example"],
            },
        )

    def get_entity_attribute(self, *, entity: str, attribute: str, trace_id: str):
        return _result(
            "get_entity_attribute",
            {"entity": entity, "attribute": attribute, "value": "AS64500 Live Test ASN"},
        )


class EmptyLiveClient:
    def lookup_ioc(self, **_kwargs):
        return None

    def profile_threat_actor(self, **_kwargs):
        return None

    def assess_software_exposure(self, **_kwargs):
        return None

    def pivot_related_entities(self, **_kwargs):
        return None

    def get_entity_attribute(self, **_kwargs):
        return None


def test_ioc_lookup_uses_live_provider_result():
    result = ThreatIntelService(live_client=FakeLiveClient()).lookup_ioc(
        indicator="45.83.122.10", trace_id="tr_test"
    )
    assert result.status == "ok"
    assert result.finding["indicator"] == "45.83.122.10"
    assert result.finding["asn"].startswith("AS64500")
    assert len(result.evidence) == 1


def test_actor_profile_uses_live_attack_evidence():
    result = ThreatIntelService(live_client=FakeLiveClient()).profile_threat_actor(
        actor_name="APT29", trace_id="tr_test"
    )
    assert result.status == "ok"
    assert result.finding["ttps"][0]["id"] == "T1059"
    assert result.evidence[0].provider == "Live Provider"


def test_exposure_live_result_remains_partial_until_verified():
    result = ThreatIntelService(live_client=FakeLiveClient()).assess_software_exposure(
        product="Confluence", version="7.13", trace_id="tr_test"
    )
    assert result.status == "partial"
    assert result.finding["verdict"] == "potentially_exposed"
    assert result.warnings


def test_pivot_returns_live_relationship_with_caveat():
    result = ThreatIntelService(live_client=FakeLiveClient()).pivot_related_entities(
        entity="45.83.122.10", relationship="domains", trace_id="tr_test"
    )
    assert result.status == "ok"
    assert "live-related.example" in result.finding["related_domains"]


def test_missing_live_ioc_never_becomes_benign():
    result = ThreatIntelService(live_client=EmptyLiveClient()).lookup_ioc(
        indicator="203.0.113.250", trace_id="tr_test"
    )
    assert result.status == "not_found"
    assert "verdict" not in result.finding
    assert "not a benign verdict" in result.warnings[0]
