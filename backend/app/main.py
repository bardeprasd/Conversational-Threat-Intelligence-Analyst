from __future__ import annotations

import logging

from agents import set_default_openai_key
from chatkit.server import NonStreamingResult, StreamingResult
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import ValidationError

from .agent import RequestContext
from .chatkit_server import ThreatLensChatKitServer
from .observability import trace_store
from .rate_limit import SlidingWindowRateLimiter
from .settings import get_settings
from .store import InMemoryStore


settings = get_settings()
if settings.openai_api_key:
    # Configure the Agents SDK once at startup; tracing uses the same key with
    # sensitive payload capture disabled in the runner configuration.
    set_default_openai_key(settings.openai_api_key, use_for_tracing=True)

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)

app = FastAPI(
    title="ThreatLens Conversational Threat Intelligence",
    version="1.0.0",
    description="ChatKit + OpenAI Agents SDK assessment implementation",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

store = InMemoryStore()
chatkit_server = ThreatLensChatKitServer(store)
# Keep the public ChatKit endpoint bounded so free-tier provider APIs and model
# tokens are not exhausted during testing or demo runs.
rate_limiter = SlidingWindowRateLimiter(
    settings.rate_limit_requests, settings.rate_limit_window_seconds
)


@app.get("/")
async def root() -> dict[str, str | bool]:
    return {
        "name": "ThreatLens",
        "chatkit_endpoint": "/chatkit",
        "health": "/healthz",
        "mode": "agents_sdk",
    }


@app.get("/healthz")
async def health() -> dict[str, object]:
    return {
        "status": "ok",
        "mode": "agents_sdk",
        "model": settings.openai_model,
        "intelligence": "live-apis",
        "state": "chatkit_store_manual_history",
        "thread_history_limit": settings.thread_history_limit,
        "openai_configured": bool(settings.openai_api_key),
    }


@app.get("/api/traces")
async def recent_traces(limit: int = 20) -> dict[str, object]:
    # Expose only the local trace summary, capped to avoid dumping unbounded
    # request history through the demo endpoint.
    bounded = max(1, min(limit, 100))
    return {"data": trace_store.recent(bounded)}


@app.post("/chatkit")
async def chatkit_endpoint(request: Request) -> Response:
    client_id = request.headers.get("x-client-id") or (
        request.client.host if request.client else "anonymous"
    )
    allowed, retry_after = rate_limiter.allow(client_id)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail="Rate limit reached. Retry after the indicated interval.",
            headers={"Retry-After": str(retry_after)},
        )

    body = await request.body()
    trace_id = trace_store.start("chatkit_request")
    try:
        # ChatKitServer owns protocol parsing, thread lifecycle, and response
        # streaming; this endpoint adds rate limiting and trace headers around it.
        result = await chatkit_server.process(
            body,
            RequestContext(trace_id=trace_id, client_id=client_id),
        )
    except ValidationError as exc:
        trace_store.complete(trace_id)
        raise HTTPException(
            status_code=400, detail="Invalid ChatKit request payload"
        ) from exc
    if isinstance(result, StreamingResult):
        return StreamingResponse(
            result,
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Trace-Id": trace_id},
        )
    if isinstance(result, NonStreamingResult):
        trace_store.complete(trace_id)
        return Response(
            content=result.json,
            media_type="application/json",
            headers={"X-Trace-Id": trace_id},
        )
    raise HTTPException(status_code=500, detail="Unexpected ChatKit response type")
