from __future__ import annotations

import json
import logging
import time
import uuid
from collections import deque
from dataclasses import asdict, dataclass, field
from threading import Lock
from typing import Any


logger = logging.getLogger("threatlens")


@dataclass
class TraceEvent:
    at: float
    kind: str
    name: str
    status: str
    duration_ms: float | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class TraceRecord:
    trace_id: str
    started_at: float
    query: str
    events: list[TraceEvent] = field(default_factory=list)
    completed_at: float | None = None


class TraceStore:
    """Small in-process trace buffer; OpenAI SDK tracing remains enabled as well."""

    def __init__(self, max_traces: int = 200) -> None:
        self._traces: deque[TraceRecord] = deque(maxlen=max_traces)
        self._lock = Lock()

    def start(self, query: str) -> str:
        trace_id = f"tr_{uuid.uuid4().hex[:12]}"
        with self._lock:
            self._traces.append(TraceRecord(trace_id, time.time(), query[:500]))
        logger.info(json.dumps({"trace_id": trace_id, "event": "run.started"}))
        return trace_id

    def record(
        self,
        trace_id: str,
        *,
        kind: str,
        name: str,
        status: str,
        duration_ms: float | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        event = TraceEvent(
            at=time.time(),
            kind=kind,
            name=name,
            status=status,
            duration_ms=duration_ms,
            metadata=metadata or {},
        )
        with self._lock:
            record = next((item for item in self._traces if item.trace_id == trace_id), None)
            if record:
                record.events.append(event)
        logger.info(json.dumps({"trace_id": trace_id, "event": asdict(event)}))

    def complete(self, trace_id: str) -> None:
        with self._lock:
            record = next((item for item in self._traces if item.trace_id == trace_id), None)
            if record:
                record.completed_at = time.time()
        logger.info(json.dumps({"trace_id": trace_id, "event": "run.completed"}))

    def recent(self, limit: int = 20) -> list[dict[str, Any]]:
        with self._lock:
            return [asdict(item) for item in list(self._traces)[-limit:]][::-1]


trace_store = TraceStore()

