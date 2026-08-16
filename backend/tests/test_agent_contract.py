"""Contract tests for the agent's tool allowlist and generated JSON schemas."""

from app.agents.threatlens import assistant_agent


def test_agent_exposes_only_expected_read_only_tools():
    names = {tool.name for tool in assistant_agent.tools}
    assert names == {
        "lookup_ioc",
        "profile_threat_actor",
        "assess_software_exposure",
        "pivot_related_entities",
        "get_entity_attribute",
    }
    assert all(not tool.needs_approval for tool in assistant_agent.tools)


def test_tools_use_strict_json_schemas():
    for tool in assistant_agent.tools:
        assert tool.strict_json_schema is True
        assert tool.params_json_schema["additionalProperties"] is False


def test_exposure_route_accepts_major_minor_version_for_triage():
    instructions = str(assistant_agent.instructions)
    exposure_tool = next(
        tool for tool in assistant_agent.tools if tool.name == "assess_software_exposure"
    )

    assert "major/minor version is sufficient for exposure triage" in instructions
    assert "Accept major/minor version families" in exposure_tool.description
