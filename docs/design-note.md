# ThreatLens Design Note

## Objective and boundary

ThreatLens is a defensive, read-only threat-intelligence assistant for SOC analysts. A browser chat interface connects to a FastAPI conversation gateway, and the OpenAI Agents SDK performs model-driven routing. The agent can retrieve and correlate intelligence but cannot execute containment, shell, exploit, or write actions.

## Intent routing

The agent exposes five strict-schema tools, each with a narrow description and validated arguments:

| User intent | Tool |
| --- | --- |
| IP, domain, or hash reputation | `lookup_ioc` |
| Named actor or ATT&CK techniques | `profile_threat_actor` |
| Product/version exposure | `assess_software_exposure` |
| Related domains or IPs | `pivot_related_entities` |
| Follow-up attribute such as ASN | `get_entity_attribute` |

The system routing contract requires a tool call before any factual intelligence answer. If an essential entity is absent, the agent asks one clarification question instead of guessing. Tool calls are serial to make traces understandable and avoid duplicate requests against quota-limited APIs.

Multi-turn references are resolved by loading recent thread items and passing that transcript to each Agents SDK run. Consequently, "its ASN" and "that IP" can resolve to an IOC established earlier in the same thread. The assessment store is intentionally in memory; durable storage is a production extension.

Tools return a common `ToolResult` containing status, structured finding, evidence URLs, confidence, warnings, and trace ID. A schema validator rejects `ok` or `partial` findings without evidence. IOC lookup combines independent provider signals into a documented triage score. Missing evidence returns `not_found` and is explicitly not treated as benign. Exposure lookup remains `partial` because NVD keyword search does not prove an exact CPE/version match.

## Prompt-injection defense

Defense is layered across both required attack paths.

**Direct injection:** Before model or tool execution, the conversation gateway scans the newest user message for high-signal instruction override, prompt exfiltration, role reassignment, and tool-coercion patterns. A match returns a fixed refusal and records a blocked guardrail trace. The Agents SDK input guardrail repeats this check as defense in depth. Agent policy also forbids disclosure of hidden instructions, credentials, or secrets and limits behavior to defensive analysis.

**Indirect injection:** All provider and dataset content is untrusted. Structured payloads are recursively scanned before entering the model context. Instruction-like strings are replaced with a quarantine marker while non-text facts remain available. The complete tool result is serialized inside an `<UNTRUSTED_EVIDENCE>` boundary, and the agent is instructed to treat that block only as data. Provider text therefore cannot authorize new tools or override system policy.

Only read-only tools are registered, strict schemas reject unexpected arguments, and no tool requires or permits arbitrary code execution. Model tracing disables sensitive payload capture. Provider exceptions are converted into evidence-free `error` results, preventing the model from filling gaps from memory.

## Tradeoffs

Regex detection is intentionally high-signal to limit false positives and is not considered sufficient by itself; sanitization, schema validation, tool allowlisting, and model policy remain independent controls. Live intelligence can be incomplete or stale, so every answer must expose sources, confidence, warnings, and verification steps. Production deployment would add authenticated users, durable state, shared rate limiting, caching, and exact CPE/vendor-advisory evaluation.
