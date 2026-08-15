from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import datetime
from typing import Any

from agents import RunConfig, Runner
from chatkit.agents import AgentContext, simple_to_agent_input, stream_agent_response
from chatkit.server import ChatKitServer
from chatkit.types import (
    AssistantMessageContent,
    AssistantMessageItem,
    ThreadItemAddedEvent,
    ThreadItemDoneEvent,
    ThreadMetadata,
    ThreadStreamEvent,
    UserMessageItem,
    UserMessageTextContent,
)

from .agent import RequestContext, assistant_agent
from .observability import trace_store
from .security import scan_direct_prompt
from .settings import get_settings


def _message_text(item: UserMessageItem | None) -> str:
    if item is None:
        return ""
    return " ".join(
        part.text for part in item.content if isinstance(part, UserMessageTextContent)
    ).strip()


class ThreatLensChatKitServer(ChatKitServer[RequestContext]):
    async def _load_agent_input(
        self,
        thread: ThreadMetadata,
        context: RequestContext,
        limit: int,
    ) -> list[dict[str, Any]]:
        # ChatKit owns thread/item persistence. Each Agents SDK run receives the
        # recent transcript explicitly, matching the SDK's manual memory strategy.
        items_page = await self.store.load_thread_items(
            thread.id, after=None, limit=limit, order="desc", context=context
        )
        return await simple_to_agent_input(list(reversed(items_page.data)))

    async def respond(
        self,
        thread: ThreadMetadata,
        input_user_message: UserMessageItem | None,
        context: RequestContext,
    ) -> AsyncIterator[ThreadStreamEvent]:
        query = _message_text(input_user_message)
        settings = get_settings()

        scan = scan_direct_prompt(query)
        if not scan.safe:
            trace_store.record(
                context.trace_id,
                kind="guardrail",
                name="direct_prompt_injection",
                status="blocked",
                metadata={"detections": scan.detections},
            )
            async for event in self._stream_static_message(
                thread,
                "I can help with defensive threat-intelligence analysis, but I cannot follow "
                "requests to override instructions, reveal secrets, or coerce tools. No model or "
                "intelligence tool was called.",
            ):
                yield event
            trace_store.complete(context.trace_id)
            return

        input_items = await self._load_agent_input(
            thread, context, settings.thread_history_limit
        )
        agent_context = AgentContext[RequestContext](
            thread=thread,
            store=self.store,
            request_context=context,
        )
        try:
            result = Runner.run_streamed(
                assistant_agent,
                input_items,
                context=agent_context,
                max_turns=settings.max_turns,
                run_config=RunConfig(
                    workflow_name="ThreatLens investigation",
                    group_id=thread.id,
                    trace_metadata={"chatkit_thread_id": thread.id},
                    trace_include_sensitive_data=False,
                ),
            )
            async for event in stream_agent_response(agent_context, result):
                yield event
        finally:
            trace_store.complete(context.trace_id)

    async def _stream_static_message(
        self, thread: ThreadMetadata, markdown: str
    ) -> AsyncIterator[ThreadStreamEvent]:
        message = AssistantMessageItem(
            id=self.store.generate_item_id("message", thread, {}),
            thread_id=thread.id,
            created_at=datetime.now(),
            content=[AssistantMessageContent(text=markdown)],
        )
        yield ThreadItemAddedEvent(item=message)
        yield ThreadItemDoneEvent(item=message)
