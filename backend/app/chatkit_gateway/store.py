from __future__ import annotations

from collections import defaultdict
from typing import Any

from chatkit.store import NotFoundError, Store
from chatkit.types import Attachment, Page, ThreadItem, ThreadMetadata


class InMemoryStore(Store[Any]):
    """Assessment-friendly store. Replace with a durable Store in production."""

    def __init__(self) -> None:
        self.threads: dict[str, ThreadMetadata] = {}
        self.items: dict[str, list[ThreadItem]] = defaultdict(list)
        self.attachments: dict[str, Attachment] = {}

    async def load_thread(self, thread_id: str, context: Any) -> ThreadMetadata:
        try:
            return self.threads[thread_id].model_copy(deep=True)
        except KeyError as exc:
            raise NotFoundError(thread_id) from exc

    async def save_thread(self, thread: ThreadMetadata, context: Any) -> None:
        self.threads[thread.id] = thread.model_copy(deep=True)

    async def load_thread_items(
        self,
        thread_id: str,
        after: str | None,
        limit: int,
        order: str,
        context: Any,
    ) -> Page[ThreadItem]:
        values = list(self.items.get(thread_id, []))
        if order == "desc":
            values.reverse()
        start = 0
        if after:
            for index, item in enumerate(values):
                if item.id == after:
                    start = index + 1
                    break
        selected = values[start : start + limit]
        has_more = start + limit < len(values)
        next_after = selected[-1].id if has_more and selected else None
        return Page(
            data=[item.model_copy(deep=True) for item in selected],
            has_more=has_more,
            after=next_after,
        )

    async def load_threads(
        self, limit: int, after: str | None, order: str, context: Any
    ) -> Page[ThreadMetadata]:
        values = sorted(self.threads.values(), key=lambda item: item.created_at)
        if order == "desc":
            values.reverse()
        start = 0
        if after:
            for index, thread in enumerate(values):
                if thread.id == after:
                    start = index + 1
                    break
        selected = values[start : start + limit]
        has_more = start + limit < len(values)
        return Page(
            data=[item.model_copy(deep=True) for item in selected],
            has_more=has_more,
            after=selected[-1].id if has_more and selected else None,
        )

    async def add_thread_item(
        self, thread_id: str, item: ThreadItem, context: Any
    ) -> None:
        existing = self.items[thread_id]
        if any(candidate.id == item.id for candidate in existing):
            await self.save_item(thread_id, item, context)
            return
        existing.append(item.model_copy(deep=True))

    async def save_item(self, thread_id: str, item: ThreadItem, context: Any) -> None:
        existing = self.items[thread_id]
        for index, candidate in enumerate(existing):
            if candidate.id == item.id:
                existing[index] = item.model_copy(deep=True)
                return
        existing.append(item.model_copy(deep=True))

    async def load_item(
        self, thread_id: str, item_id: str, context: Any
    ) -> ThreadItem:
        for item in self.items.get(thread_id, []):
            if item.id == item_id:
                return item.model_copy(deep=True)
        raise NotFoundError(item_id)

    async def delete_thread(self, thread_id: str, context: Any) -> None:
        self.threads.pop(thread_id, None)
        self.items.pop(thread_id, None)

    async def delete_thread_item(
        self, thread_id: str, item_id: str, context: Any
    ) -> None:
        self.items[thread_id] = [
            item for item in self.items.get(thread_id, []) if item.id != item_id
        ]

    async def save_attachment(self, attachment: Attachment, context: Any) -> None:
        self.attachments[attachment.id] = attachment.model_copy(deep=True)

    async def load_attachment(self, attachment_id: str, context: Any) -> Attachment:
        try:
            return self.attachments[attachment_id].model_copy(deep=True)
        except KeyError as exc:
            raise NotFoundError(attachment_id) from exc

    async def delete_attachment(self, attachment_id: str, context: Any) -> None:
        self.attachments.pop(attachment_id, None)
