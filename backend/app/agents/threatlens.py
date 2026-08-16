"""ThreatLens agent contract, read-only tools, and model-facing guardrails."""

from __future__ import annotations

import json
from typing import Any

from agents import (
    Agent,
    GuardrailFunctionOutput,
    ModelSettings,
    RunContextWrapper,
    function_tool,
    input_guardrail,
)
from chatkit.agents import AgentContext
from chatkit.types import ProgressUpdateEvent
from pydantic import BaseModel

from app.core.config import get_settings
from app.core.security import AGENT_SECURITY_INSTRUCTIONS, scan_direct_prompt
from app.services.threat_intel import toolbox


class RequestContext(BaseModel):
    trace_id: str
    client_id: str = "anonymous"


def _trace_id(ctx: RunContextWrapper[AgentContext[RequestContext]]) -> str:
    return ctx.context.request_context.trace_id


async def _stream_tool_progress(
    ctx: RunContextWrapper[AgentContext[RequestContext]], text: str
) -> None:
    await ctx.context.stream(ProgressUpdateEvent(text=text))


def _untrusted_output(result: Any) -> str:
    payload = result.model_dump(mode="json")
    # Tool results may include provider-controlled text. Wrapping the JSON makes
    # the evidence boundary explicit for the model and pairs with the system rule
    # that content inside this block is data, not instructions.
    return (
        "<UNTRUSTED_EVIDENCE>\n"
        + json.dumps(payload, ensure_ascii=True, sort_keys=True)
        + "\n</UNTRUSTED_EVIDENCE>"
    )


@function_tool(
    description_override=(
        "Look up the reputation of exactly one IP address, domain, or file hash in the "
        "configured live intelligence providers. Use for IOC verdict, score, ASN, country, and tags."
    )
)
async def lookup_ioc(
    ctx: RunContextWrapper[AgentContext[RequestContext]], indicator: str
) -> str:
    """Return a structured, evidence-cited IOC finding."""

    await _stream_tool_progress(ctx, f"Running lookup_ioc for {indicator}")
    return _untrusted_output(
        toolbox.execute("lookup_ioc", trace_id=_trace_id(ctx), indicator=indicator)
    )


@function_tool(
    description_override=(
        "Profile a named threat actor and return observed MITRE ATT&CK techniques. "
        "Use only when the user supplies an actor such as APT29."
    )
)
async def profile_threat_actor(
    ctx: RunContextWrapper[AgentContext[RequestContext]], actor_name: str
) -> str:
    """Return a structured, evidence-cited threat-actor profile."""

    await _stream_tool_progress(ctx, f"Running profile_threat_actor for {actor_name}")
    return _untrusted_output(
        toolbox.execute(
            "profile_threat_actor", trace_id=_trace_id(ctx), actor_name=actor_name
        )
    )


@function_tool(
    description_override=(
        "Map a software product and version to known vulnerability rules. "
        "Use for exposure, vulnerability, or CVE questions. Accept major/minor "
        "version families such as 7.13 and report the result as triage until "
        "the exact patch is verified."
    )
)
async def assess_software_exposure(
    ctx: RunContextWrapper[AgentContext[RequestContext]], product: str, version: str
) -> str:
    """Return an evidence-cited exposure assessment for a software version."""

    await _stream_tool_progress(
        ctx, f"Running assess_software_exposure for {product} {version}"
    )
    return _untrusted_output(
        toolbox.execute(
            "assess_software_exposure",
            trace_id=_trace_id(ctx),
            product=product,
            version=version,
        )
    )


@function_tool(
    description_override=(
        "Pivot from a known IP or domain to related domains or IPs in the passive relationship "
        "data returned by live providers. Relationships are investigative leads, not proof of ownership."
    )
)
async def pivot_related_entities(
    ctx: RunContextWrapper[AgentContext[RequestContext]],
    entity: str,
    relationship: str = "all",
) -> str:
    """Return evidence-cited entities related to the starting IOC."""

    await _stream_tool_progress(ctx, f"Running pivot_related_entities for {entity}")
    return _untrusted_output(
        toolbox.execute(
            "pivot_related_entities",
            trace_id=_trace_id(ctx),
            entity=entity,
            relationship=relationship,
        )
    )


@function_tool(
    description_override=(
        "Get one attribute such as ASN, country, verdict, risk_score, registrar, or tags for "
        "an already identified IOC. Use for multi-turn follow-ups after resolving the reference."
    )
)
async def get_entity_attribute(
    ctx: RunContextWrapper[AgentContext[RequestContext]], entity: str, attribute: str
) -> str:
    """Return one evidence-cited attribute for an IOC."""

    await _stream_tool_progress(
        ctx, f"Running get_entity_attribute for {entity} ({attribute})"
    )
    return _untrusted_output(
        toolbox.execute(
            "get_entity_attribute",
            trace_id=_trace_id(ctx),
            entity=entity,
            attribute=attribute,
        )
    )


def _last_user_text(agent_input: str | list[dict[str, Any]]) -> str:
    # Guardrails can receive either a plain string or the expanded transcript.
    # Check only the latest user turn so older benign history does not mask a
    # direct injection attempt in the current request.
    if isinstance(agent_input, str):
        return agent_input
    for item in reversed(agent_input):
        if not isinstance(item, dict) or item.get("role") != "user":
            continue
        content = item.get("content", "")
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            chunks = [
                str(part.get("text", ""))
                for part in content
                if isinstance(part, dict) and part.get("type") in {"input_text", "text"}
            ]
            return " ".join(chunks)
    return ""


@input_guardrail(name="direct_prompt_injection", run_in_parallel=False)
def direct_prompt_injection_guardrail(
    _ctx: RunContextWrapper[AgentContext[RequestContext]],
    _agent: Agent[Any],
    agent_input: str | list[dict[str, Any]],
) -> GuardrailFunctionOutput:
    scan = scan_direct_prompt(_last_user_text(agent_input))
    return GuardrailFunctionOutput(
        output_info={"detections": scan.detections},
        tripwire_triggered=not scan.safe,
    )


_ROUTING_INSTRUCTIONS = """
You are ThreatLens, a defensive SOC threat-intelligence analyst.

Routing:
1. IOC reputation -> lookup_ioc.
2. Named threat actor or TTPs -> profile_threat_actor.
3. Product/version exposure -> assess_software_exposure. If the user gives a version family such as "7.13" without a patch, call the tool with that version and state that exact patch/CPE verification is still required.
4. Related domains/IPs -> pivot_related_entities.
5. Follow-up attribute such as "what is its ASN?" -> resolve the entity from chat history, then get_entity_attribute.

Answer contract:
- For factual intelligence, call the appropriate tool before answering.
- If essential arguments are missing, ask one concise clarification question and do not call a tool. A product plus major/minor version is sufficient for exposure triage.
- Cite every factual claim using the source title and URL returned by the tool.
- State the confidence percentage and all caveats. Clearly identify live-provider evidence and avoid overstating coverage.
- Never turn absence into a benign verdict. Never invent an entity, relationship, CVE, TTP, source, or score.
- Keep the answer concise and useful to a SOC analyst: verdict, evidence, caveat, next defensive step.
""".strip()


def build_agent() -> Agent[AgentContext[RequestContext]]:
    settings = get_settings()
    return Agent[AgentContext[RequestContext]](
        name="ThreatLens Analyst",
        handoff_description="Routes and answers defensive threat-intelligence investigations.",
        model=settings.openai_model,
        instructions=f"{_ROUTING_INSTRUCTIONS}\n\n{AGENT_SECURITY_INSTRUCTIONS}",
        tools=[
            lookup_ioc,
            profile_threat_actor,
            assess_software_exposure,
            pivot_related_entities,
            get_entity_attribute,
        ],
        input_guardrails=[direct_prompt_injection_guardrail],
        model_settings=ModelSettings(
            max_tokens=1400,
            # Serial tool calls make routing easier to audit in the assessment
            # trace and avoid duplicate lookups against quota-limited APIs.
            parallel_tool_calls=False,
            verbosity="low",
        ),
    )


assistant_agent = build_agent()
