from __future__ import annotations

import ipaddress
import re
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

import httpx

from app.core.config import Settings
from app.core.security import sanitize_untrusted_payload
from app.schemas.threat_intel import EvidenceSource, ToolResult


_HASH = re.compile(r"^[a-fA-F0-9]{32}(?:[a-fA-F0-9]{8}|[a-fA-F0-9]{32})?$")
_MITRE_ENTERPRISE_ATTACK = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)


def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _source(
    source_id: str,
    provider: str,
    title: str,
    url: str,
    observed_at: str | None = None,
) -> EvidenceSource:
    return EvidenceSource(
        id=source_id,
        provider=provider,
        title=title,
        url=url,
        observed_at=observed_at or _now(),
    )


def _indicator_kind(indicator: str) -> str:
    # Keep classification deterministic before touching external providers so
    # malformed indicators cannot steer arbitrary API paths.
    try:
        ipaddress.ip_address(indicator)
        return "ip"
    except ValueError:
        pass
    if _HASH.match(indicator):
        return "hash"
    return "domain"


class LiveThreatIntelClient:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def lookup_ioc(self, *, indicator: str, trace_id: str) -> ToolResult | None:
        normalized = indicator.strip().lower().rstrip(".,;)")
        kind = _indicator_kind(normalized)
        findings: dict[str, Any] = {"indicator": normalized, "providers": []}
        sources: list[EvidenceSource] = []
        warnings: list[str] = []

        with httpx.Client(timeout=self.settings.live_api_timeout_seconds) as client:
            # Each provider contributes evidence and signals independently; a
            # failed provider appends a warning instead of aborting the full lookup.
            self._add_virustotal_ioc(client, normalized, kind, findings, sources, warnings)
            if kind == "ip":
                self._add_abuseipdb(client, normalized, findings, sources, warnings)
            self._add_otx_ioc(client, normalized, kind, findings, sources, warnings)

        if not sources:
            return None

        malicious_signals = int(findings.get("malicious_signals", 0))
        suspicious_signals = int(findings.get("suspicious_signals", 0))
        abuse_score = int(findings.get("abuse_confidence_score", 0) or 0)
        otx_pulses = int(findings.get("otx_pulse_count", 0) or 0)
        # The score is a transparent triage heuristic across heterogeneous free
        # APIs, not a vendor-certified maliciousness score.
        risk_score = min(
            100,
            max(
                abuse_score,
                malicious_signals * 15 + suspicious_signals * 7 + min(otx_pulses * 5, 30),
            ),
        )
        verdict = "malicious" if risk_score >= 70 else "suspicious" if risk_score >= 25 else "unknown"
        findings["verdict"] = verdict
        findings["risk_score"] = risk_score

        sanitized, detections = sanitize_untrusted_payload(findings)
        if detections:
            warnings.append("Instruction-like provider content was quarantined.")

        return ToolResult(
            tool="lookup_ioc",
            status="ok",
            finding=sanitized,
            evidence=sources,
            confidence=self._confidence(len(sources), len(warnings), base=0.62),
            warnings=warnings,
            trace_id=trace_id,
        )

    def profile_threat_actor(self, *, actor_name: str, trace_id: str) -> ToolResult | None:
        actor = actor_name.strip().upper().replace(" ", "")
        with httpx.Client(timeout=self.settings.live_api_timeout_seconds) as client:
            response = client.get(_MITRE_ENTERPRISE_ATTACK)
            response.raise_for_status()
            objects = response.json().get("objects", [])

        # MITRE STIX links intrusion sets to techniques through relationship
        # objects, so actor matching and TTP extraction are intentionally separate.
        intrusion_sets = [
            item
            for item in objects
            if item.get("type") == "intrusion-set"
            and (
                item.get("name", "").upper().replace(" ", "") == actor
                or actor
                in {
                    alias.upper().replace(" ", "")
                    for alias in item.get("aliases", [])
                    if isinstance(alias, str)
                }
            )
        ]
        if not intrusion_sets:
            return None

        intrusion = intrusion_sets[0]
        intrusion_id = intrusion["id"]
        uses = {
            rel.get("target_ref")
            for rel in objects
            if rel.get("type") == "relationship"
            and rel.get("relationship_type") == "uses"
            and rel.get("source_ref") == intrusion_id
        }
        techniques = []
        for item in objects:
            if item.get("type") != "attack-pattern" or item.get("id") not in uses:
                continue
            external_id = next(
                (
                    ref.get("external_id")
                    for ref in item.get("external_references", [])
                    if ref.get("source_name") == "mitre-attack"
                ),
                "ATT&CK",
            )
            tactic = ", ".join(
                phase.get("phase_name", "")
                for phase in item.get("kill_chain_phases", [])
                if phase.get("phase_name")
            )
            techniques.append(
                {"id": external_id, "name": item.get("name", ""), "tactic": tactic}
            )

        finding = {
            "name": intrusion.get("name", actor),
            "summary": intrusion.get("description", "")[:800],
            "ttps": techniques[:10],
        }
        sanitized, detections = sanitize_untrusted_payload(finding)
        warnings = []
        if detections:
            warnings.append("Instruction-like provider content was quarantined.")

        return ToolResult(
            tool="profile_threat_actor",
            status="ok",
            finding=sanitized,
            evidence=[
                _source(
                    "live-mitre-enterprise-attack",
                    "MITRE ATT&CK",
                    "MITRE ATT&CK Enterprise STIX dataset",
                    "https://attack.mitre.org/",
                )
            ],
            confidence=self._confidence(1, len(warnings), base=0.74),
            warnings=warnings,
            trace_id=trace_id,
        )

    def assess_software_exposure(
        self, *, product: str, version: str, trace_id: str
    ) -> ToolResult | None:
        query = f"{product} {version}"
        # NVD keyword search is used for broad triage. The returned result stays
        # partial until an analyst verifies exact CPE and vendor advisory ranges.
        params: dict[str, Any] = {"keywordSearch": query, "resultsPerPage": 10}
        headers = {"apiKey": self.settings.nvd_api_key} if self.settings.nvd_api_key else {}
        with httpx.Client(timeout=self.settings.live_api_timeout_seconds) as client:
            response = client.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params=params,
                headers=headers,
            )
            response.raise_for_status()
            payload = response.json()

        vulnerabilities = payload.get("vulnerabilities", [])
        if not vulnerabilities:
            return None

        issues = []
        for item in vulnerabilities:
            cve = item.get("cve", {})
            metrics = cve.get("metrics", {})
            score = None
            severity = "unknown"
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if metrics.get(key):
                    metric = metrics[key][0]
                    cvss = metric.get("cvssData", {})
                    score = cvss.get("baseScore")
                    severity = metric.get("baseSeverity") or cvss.get("baseSeverity", severity)
                    break
            description = next(
                (
                    desc.get("value")
                    for desc in cve.get("descriptions", [])
                    if desc.get("lang") == "en"
                ),
                "",
            )
            issues.append(
                {
                    "cve": cve.get("id"),
                    "severity": str(severity).lower(),
                    "cvss": score if score is not None else "n/a",
                    "range": "verify affected CPE/version in NVD",
                    "summary": description[:350],
                    "fixed_versions": ["verify vendor advisory"],
                }
            )

        return ToolResult(
            tool="assess_software_exposure",
            status="partial",
            finding={
                "product": product,
                "version": version,
                "verdict": "potentially_exposed",
                "matched_issues": issues,
            },
            evidence=[
                _source(
                    "live-nvd-cves",
                    "NVD",
                    f"NVD CVE search for {query}",
                    "https://nvd.nist.gov/vuln/search",
                )
            ],
            confidence=0.68,
            warnings=[
                "Live NVD keyword search is evidence for triage, not proof of exact affected build. Verify CPE and vendor advisory."
            ],
            trace_id=trace_id,
        )

    def pivot_related_entities(
        self, *, entity: str, relationship: str, trace_id: str
    ) -> ToolResult | None:
        normalized = entity.strip().lower().rstrip(".,;)")
        kind = _indicator_kind(normalized)
        relations: dict[str, Any] = {"entity": normalized, "relationship": relationship}
        sources: list[EvidenceSource] = []
        warnings: list[str] = []

        with httpx.Client(timeout=self.settings.live_api_timeout_seconds) as client:
            # Relationship data is treated as investigative leads. The tool will
            # return not_found unless at least one related domain or IP is present.
            if self.settings.virustotal_api_key:
                self._add_virustotal_relations(client, normalized, kind, relationship, relations, sources, warnings)
            if kind == "ip" and self.settings.shodan_api_key:
                self._add_shodan_host(client, normalized, relations, sources, warnings)
            if self.settings.otx_api_key:
                self._add_otx_passive_dns(client, normalized, kind, relationship, relations, sources, warnings)

        if not sources or not any(relations.get(key) for key in ("related_domains", "related_ips")):
            return None

        return ToolResult(
            tool="pivot_related_entities",
            status="ok",
            finding=relations,
            evidence=sources,
            confidence=self._confidence(len(sources), 1, base=0.58),
            warnings=warnings
            or ["Relationships are leads for investigation, not proof of common ownership."],
            trace_id=trace_id,
        )

    def get_entity_attribute(
        self, *, entity: str, attribute: str, trace_id: str
    ) -> ToolResult | None:
        result = self.lookup_ioc(indicator=entity, trace_id=trace_id)
        if not result:
            return None
        normalized_attribute = attribute.strip().lower().replace(" ", "_")
        value = result.finding.get(normalized_attribute)
        if value is None and normalized_attribute == "registrar":
            value = result.finding.get("whois_registrar")
        if value is None:
            return None
        return ToolResult(
            tool="get_entity_attribute",
            status="ok",
            finding={
                "entity": entity.strip().lower(),
                "attribute": normalized_attribute,
                "value": value,
            },
            evidence=result.evidence,
            confidence=result.confidence,
            warnings=result.warnings,
            trace_id=trace_id,
        )

    @staticmethod
    def _confidence(source_count: int, warnings: int = 0, base: float = 0.66) -> float:
        return round(max(0.25, min(0.95, base + 0.08 * source_count - 0.04 * warnings)), 2)

    def _add_virustotal_ioc(
        self,
        client: httpx.Client,
        indicator: str,
        kind: str,
        findings: dict[str, Any],
        sources: list[EvidenceSource],
        warnings: list[str],
    ) -> None:
        if not self.settings.virustotal_api_key:
            return
        path = {"ip": "ip_addresses", "domain": "domains", "hash": "files"}[kind]
        url = f"https://www.virustotal.com/api/v3/{path}/{quote(indicator, safe='')}"
        try:
            response = client.get(url, headers={"x-apikey": self.settings.virustotal_api_key})
            response.raise_for_status()
            payload = response.json()
            attrs = payload.get("data", {}).get("attributes", {})
        except httpx.HTTPStatusError as exc:
            warnings.append(f"VirusTotal lookup failed: HTTP {exc.response.status_code}")
            return
        except Exception as exc:
            warnings.append(f"VirusTotal lookup failed: {type(exc).__name__}")
            return
        stats = attrs.get("last_analysis_stats", {})
        findings["providers"].append("VirusTotal")
        findings["malicious_signals"] = findings.get("malicious_signals", 0) + int(stats.get("malicious", 0) or 0)
        findings["suspicious_signals"] = findings.get("suspicious_signals", 0) + int(stats.get("suspicious", 0) or 0)
        if attrs.get("as_owner"):
            findings["asn"] = f"AS{attrs.get('asn')} {attrs.get('as_owner')}".strip()
        if attrs.get("country"):
            findings["country"] = attrs["country"]
        if attrs.get("registrar"):
            findings["whois_registrar"] = attrs["registrar"]
        sources.append(
            _source(
                f"live-vt-{kind}",
                "VirusTotal",
                f"VirusTotal report for {indicator}",
                f"https://www.virustotal.com/gui/{'ip-address' if kind == 'ip' else kind}/{indicator}",
            )
        )

    def _add_abuseipdb(
        self,
        client: httpx.Client,
        ip: str,
        findings: dict[str, Any],
        sources: list[EvidenceSource],
        warnings: list[str],
    ) -> None:
        if not self.settings.abuseipdb_api_key:
            return
        try:
            response = client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": "true"},
                headers={"Key": self.settings.abuseipdb_api_key, "Accept": "application/json"},
            )
            response.raise_for_status()
            data = response.json().get("data", {})
        except httpx.HTTPStatusError as exc:
            warnings.append(f"AbuseIPDB lookup failed: HTTP {exc.response.status_code}")
            return
        except Exception as exc:
            warnings.append(f"AbuseIPDB lookup failed: {type(exc).__name__}")
            return
        findings["providers"].append("AbuseIPDB")
        findings["abuse_confidence_score"] = data.get("abuseConfidenceScore", 0)
        findings["country"] = findings.get("country") or data.get("countryCode")
        if data.get("isp") and not findings.get("asn"):
            findings["asn"] = data["isp"]
        findings["total_reports"] = data.get("totalReports")
        sources.append(
            _source(
                "live-abuseipdb-check",
                "AbuseIPDB",
                f"AbuseIPDB check for {ip}",
                f"https://www.abuseipdb.com/check/{ip}",
            )
        )

    def _add_otx_ioc(
        self,
        client: httpx.Client,
        indicator: str,
        kind: str,
        findings: dict[str, Any],
        sources: list[EvidenceSource],
        warnings: list[str],
    ) -> None:
        if not self.settings.otx_api_key:
            return
        otx_type = {"ip": "IPv4", "domain": "domain", "hash": "file"}[kind]
        try:
            response = client.get(
                f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/{quote(indicator, safe='')}/general",
                headers={"X-OTX-API-KEY": self.settings.otx_api_key},
            )
            response.raise_for_status()
            payload = response.json()
        except httpx.HTTPStatusError as exc:
            warnings.append(f"OTX lookup failed: HTTP {exc.response.status_code}")
            return
        except Exception as exc:
            warnings.append(f"OTX lookup failed: {type(exc).__name__}")
            return
        pulse_count = payload.get("pulse_info", {}).get("count", 0)
        findings["providers"].append("AlienVault OTX")
        findings["otx_pulse_count"] = pulse_count
        if tags := payload.get("pulse_info", {}).get("related", {}).get("alienvault", {}).get("adversary"):
            findings["tags"] = tags[:8]
        sources.append(
            _source(
                "live-otx-general",
                "AlienVault OTX",
                f"OTX indicator details for {indicator}",
                f"https://otx.alienvault.com/indicator/{otx_type}/{indicator}",
            )
        )

    def _add_virustotal_relations(
        self,
        client: httpx.Client,
        entity: str,
        kind: str,
        relationship: str,
        relations: dict[str, Any],
        sources: list[EvidenceSource],
        warnings: list[str],
    ) -> None:
        if kind == "hash":
            return
        vt_object = "ip_addresses" if kind == "ip" else "domains"
        rels = []
        if relationship in {"all", "domains", "related_domains"}:
            rels.append("resolutions" if kind == "ip" else "subdomains")
        if relationship in {"all", "ips", "related_ips"} and kind == "domain":
            rels.append("resolutions")
        for rel in rels:
            try:
                response = client.get(
                    f"https://www.virustotal.com/api/v3/{vt_object}/{quote(entity, safe='')}/{rel}",
                    headers={"x-apikey": self.settings.virustotal_api_key},
                    params={"limit": 10},
                )
                response.raise_for_status()
                data = response.json().get("data", [])
            except httpx.HTTPStatusError as exc:
                warnings.append(
                    f"VirusTotal relation lookup failed: HTTP {exc.response.status_code}"
                )
                continue
            except Exception as exc:
                warnings.append(f"VirusTotal relation lookup failed: {type(exc).__name__}")
                continue
            for item in data:
                attrs = item.get("attributes", {})
                host_name = attrs.get("host_name") or item.get("id")
                ip_address = attrs.get("ip_address")
                if host_name and relationship in {"all", "domains", "related_domains"}:
                    relations.setdefault("related_domains", [])
                    if host_name not in relations["related_domains"]:
                        relations["related_domains"].append(host_name)
                if ip_address and relationship in {"all", "ips", "related_ips"}:
                    relations.setdefault("related_ips", [])
                    if ip_address not in relations["related_ips"]:
                        relations["related_ips"].append(ip_address)
        if rels:
            sources.append(
                _source(
                    "live-vt-relations",
                    "VirusTotal",
                    f"VirusTotal relationship graph for {entity}",
                    f"https://www.virustotal.com/gui/{'ip-address' if kind == 'ip' else kind}/{entity}/relations",
                )
            )

    def _add_shodan_host(
        self,
        client: httpx.Client,
        ip: str,
        relations: dict[str, Any],
        sources: list[EvidenceSource],
        warnings: list[str],
    ) -> None:
        try:
            response = client.get(
                f"https://api.shodan.io/shodan/host/{ip}",
                params={"key": self.settings.shodan_api_key},
            )
            response.raise_for_status()
            payload = response.json()
        except httpx.HTTPStatusError as exc:
            warnings.append(
                "Shodan lookup failed: "
                f"HTTP {exc.response.status_code}"
                f"{self._provider_error_detail(exc.response)}"
            )
            return
        except Exception as exc:
            warnings.append(f"Shodan lookup failed: {type(exc).__name__}")
            return
        domains = [item for item in payload.get("hostnames", []) if isinstance(item, str)]
        domains.extend(item for item in payload.get("domains", []) if isinstance(item, str))
        if domains:
            relations.setdefault("related_domains", [])
            for host in domains[:10]:
                if host not in relations["related_domains"]:
                    relations["related_domains"].append(host)
        sources.append(
            _source(
                "live-shodan-host",
                "Shodan",
                f"Shodan host profile for {ip}",
                f"https://www.shodan.io/host/{ip}",
            )
        )

    @staticmethod
    def _provider_error_detail(response: httpx.Response) -> str:
        try:
            payload = response.json()
        except ValueError:
            return ""
        error = payload.get("error") if isinstance(payload, dict) else None
        return f" ({error})" if error else ""

    def _add_otx_passive_dns(
        self,
        client: httpx.Client,
        entity: str,
        kind: str,
        relationship: str,
        relations: dict[str, Any],
        sources: list[EvidenceSource],
        warnings: list[str],
    ) -> None:
        if kind == "hash":
            return
        otx_type = "IPv4" if kind == "ip" else "domain"
        try:
            response = client.get(
                f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/{quote(entity, safe='')}/passive_dns",
                headers={"X-OTX-API-KEY": self.settings.otx_api_key},
            )
            response.raise_for_status()
            payload = response.json()
        except httpx.HTTPStatusError as exc:
            warnings.append(f"OTX passive DNS lookup failed: HTTP {exc.response.status_code}")
            return
        except Exception as exc:
            warnings.append(f"OTX passive DNS lookup failed: {type(exc).__name__}")
            return
        for item in payload.get("passive_dns", [])[:10]:
            hostname = item.get("hostname")
            address = item.get("address")
            if hostname and relationship in {"all", "domains", "related_domains"}:
                relations.setdefault("related_domains", [])
                if hostname not in relations["related_domains"]:
                    relations["related_domains"].append(hostname)
            if address and relationship in {"all", "ips", "related_ips"}:
                relations.setdefault("related_ips", [])
                if address not in relations["related_ips"]:
                    relations["related_ips"].append(address)
        sources.append(
            _source(
                "live-otx-passive-dns",
                "AlienVault OTX",
                f"OTX passive DNS for {entity}",
                f"https://otx.alienvault.com/indicator/{otx_type}/{entity}",
            )
        )
