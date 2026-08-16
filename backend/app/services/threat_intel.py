"""Stable service boundary between agent tools and live-provider operations."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from app.core.config import Settings, get_settings
from app.core.observability import trace_store
from app.schemas.threat_intel import ToolResult
from app.services.live_intel import LiveThreatIntelClient


class ThreatIntelService:
    """Live threat-intelligence service used by all agent tools."""

    def __init__(
        self,
        *,
        settings: Settings | None = None,
        live_client: LiveThreatIntelClient | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.live_client = live_client or LiveThreatIntelClient(self.settings)

    @staticmethod
    def _not_found(tool: str, finding: dict[str, Any], trace_id: str) -> ToolResult:
        return ToolResult(
            tool=tool,
            status="not_found",
            finding=finding,
            confidence=0.0,
            warnings=[
                "No configured live provider returned evidence. This is not a benign verdict."
            ],
            trace_id=trace_id,
        )

    def lookup_ioc(self, *, indicator: str, trace_id: str) -> ToolResult:
        normalized = indicator.strip().lower().rstrip(".,;)")
        live_result = self.live_client.lookup_ioc(indicator=normalized, trace_id=trace_id)
        return live_result or self._not_found(
            "lookup_ioc", {"indicator": normalized}, trace_id
        )

    def profile_threat_actor(self, *, actor_name: str, trace_id: str) -> ToolResult:
        normalized = actor_name.strip()
        live_result = self.live_client.profile_threat_actor(
            actor_name=normalized, trace_id=trace_id
        )
        return live_result or self._not_found(
            "profile_threat_actor", {"actor": normalized}, trace_id
        )

    def assess_software_exposure(
        self, *, product: str, version: str, trace_id: str
    ) -> ToolResult:
        live_result = self.live_client.assess_software_exposure(
            product=product, version=version, trace_id=trace_id
        )
        return live_result or self._not_found(
            "assess_software_exposure",
            {"product": product, "version": version},
            trace_id,
        )

    def pivot_related_entities(
        self,
        *,
        entity: str,
        relationship: str = "all",
        trace_id: str,
    ) -> ToolResult:
        normalized = entity.strip().lower().rstrip(".,;)")
        live_result = self.live_client.pivot_related_entities(
            entity=normalized, relationship=relationship, trace_id=trace_id
        )
        return live_result or self._not_found(
            "pivot_related_entities",
            {"entity": normalized, "relationship": relationship},
            trace_id,
        )

    def get_entity_attribute(
        self, *, entity: str, attribute: str, trace_id: str
    ) -> ToolResult:
        normalized = entity.strip().lower().rstrip(".,;)")
        normalized_attribute = attribute.strip().lower().replace(" ", "_")
        live_result = self.live_client.get_entity_attribute(
            entity=normalized, attribute=normalized_attribute, trace_id=trace_id
        )
        return live_result or self._not_found(
            "get_entity_attribute",
            {"entity": normalized, "attribute": normalized_attribute},
            trace_id,
        )


class ThreatToolbox:
    """One guarded dispatch point used by Agents SDK tools."""

    def __init__(self, service: ThreatIntelService | None = None) -> None:
        self.service = service or ThreatIntelService()
        self._tools: dict[str, Callable[..., ToolResult]] = {
            "lookup_ioc": self.service.lookup_ioc,
            "profile_threat_actor": self.service.profile_threat_actor,
            "assess_software_exposure": self.service.assess_software_exposure,
            "pivot_related_entities": self.service.pivot_related_entities,
            "get_entity_attribute": self.service.get_entity_attribute,
        }

    @property
    def tool_names(self) -> set[str]:
        return set(self._tools)

    def execute(self, tool_name: str, *, trace_id: str, **arguments: str) -> ToolResult:
        started = time.perf_counter()
        try:
            tool = self._tools[tool_name]
            result = tool(trace_id=trace_id, **arguments)
        except Exception as exc:  # provider/client failures cross this boundary
            result = ToolResult(
                tool=tool_name,
                status="error",
                finding={},
                confidence=0.0,
                warnings=[
                    "The intelligence provider is temporarily unavailable. Retry later; no finding was inferred."
                ],
                trace_id=trace_id,
            )
            trace_store.record(
                trace_id,
                kind="tool",
                name=tool_name,
                status="error",
                duration_ms=(time.perf_counter() - started) * 1000,
                metadata={"error_type": type(exc).__name__},
            )
            return result

        trace_store.record(
            trace_id,
            kind="tool",
            name=tool_name,
            status=result.status,
            duration_ms=(time.perf_counter() - started) * 1000,
            metadata={
                "arguments": arguments,
                "evidence_count": len(result.evidence),
                "confidence": result.confidence,
            },
        )
        return result


toolbox = ThreatToolbox()
