"""Structured evidence, findings, and security-scan response models."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class EvidenceSource(BaseModel):
    id: str
    provider: str
    title: str
    url: str
    observed_at: str


class ToolResult(BaseModel):
    """Structured boundary between untrusted intelligence and the agent."""

    model_config = ConfigDict(extra="forbid")

    tool: str
    status: Literal["ok", "partial", "not_found", "blocked", "error"]
    finding: dict[str, Any] = Field(default_factory=dict)
    evidence: list[EvidenceSource] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)
    warnings: list[str] = Field(default_factory=list)
    trace_id: str

    @model_validator(mode="after")
    def require_evidence_for_supported_finding(self) -> "ToolResult":
        if self.status in {"ok", "partial"} and not self.evidence:
            raise ValueError("Supported findings must include at least one evidence source")
        return self


class SecurityScan(BaseModel):
    safe: bool
    detections: list[str] = Field(default_factory=list)
    sanitized_text: str
