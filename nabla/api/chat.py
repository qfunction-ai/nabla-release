"""Chat API — SSE streaming conversation with the supervisor agent."""

import asyncio
import json

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from nabla.auth import require_user
from nabla.log import get_logger
from nabla.rate_limit import limiter

logger = get_logger("api.chat")

router = APIRouter(prefix="/api/chat", tags=["chat"])


class ChatRequest(BaseModel):
    """Request body for a chat message.

    Attributes:
        message: The user's message to the supervisor.
        include_reasoning: Whether to include reasoning in the response.
    """
    message: str
    include_reasoning: bool = False


class ChatTurn(BaseModel):
    """One persisted conversation turn (B1 — the response model IS the
    contract)."""

    turn_id: str
    ts: str
    message: str
    answer: str
    reasoning: str | None = None


class ChatHistoryResponse(BaseModel):
    turns: list[ChatTurn]
    next_cursor: str | None = None


@router.get("/history", response_model=ChatHistoryResponse)
async def chat_history(
    limit: int = 200,
    before: str | None = None,
    auth: dict = Depends(require_user),
):
    """The authenticated user's transcript (B1/R-3).

    Nabla-owned store, never Letta's message list — the supervisor is
    shared with the pipeline, so a Letta-history endpoint would leak
    other users' chats and the pipeline's review prompts. Reasoning is
    returned only to the owning user (the store is scoped by identity).
    """
    from nabla.chat_history import load_history

    if limit < 1 or limit > 500:
        raise HTTPException(status_code=422, detail="limit must be 1-500")
    turns = load_history(user=auth.get("sub", ""), limit=limit, before_ts=before)
    next_cursor = turns[-1]["ts"] if len(turns) == limit else None
    return {
        "turns": [
            {
                "turn_id": t["turn_id"],
                "ts": t["ts"],
                "message": t["message"],
                "answer": t["answer"],
                "reasoning": t.get("reasoning"),
            }
            for t in turns
        ],
        "next_cursor": next_cursor,
    }


@router.post("/stream")
@limiter.limit("10/minute")
async def chat_stream(
    request: Request,
    body: ChatRequest,
    auth: dict = Depends(require_user),
):
    # R6-12 (round 6): chat messages are attacker-influenced text headed
    # for the supervisor's persistent context — cap them.
    if len(body.message) > 8000:
        raise HTTPException(status_code=413, detail="message too long (8KB cap)")
    """Stream a conversation with the supervisor agent via SSE.

    The supervisor agent reads shared blocks (anomaly_queue,
    threat_findings, system_phase, etc.) and provides analysis.
    """
    from nabla.client import get_client
    from nabla.agents.registry import find_agent

    client = get_client()
    agent = find_agent(client, "supervisor")

    if agent is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Supervisor agent not found — run 'nabla bootstrap' first",
        )

    async def event_generator():
        import queue
        import threading

        # Use a queue to decouple the sync Letta iterator from the
        # async generator. The sync iterator runs in a thread and
        # pushes chunks into the queue; the async loop pulls them out.
        chunk_queue: queue.Queue = queue.Queue()
        _SENTINEL = object()  # Signals end-of-stream
        assistant_text: list[str] = []  # accumulated for the transcript (B1)
        reasoning_text: list[str] = []

        def _drain_stream():
            """Run the sync Letta stream in a background thread."""
            try:
                stream = client.agents.messages.create(
                    agent_id=agent.id,
                    messages=[{"role": "user", "content": body.message}],
                    enable_thinking="true" if body.include_reasoning else "false",
                    streaming=True,
                )
                for chunk in stream:
                    chunk_queue.put(chunk)
            except Exception as e:
                chunk_queue.put(e)
            finally:
                chunk_queue.put(_SENTINEL)

        thread = threading.Thread(target=_drain_stream, daemon=True)
        thread.start()

        try:
            while True:
                # Poll the queue without blocking the event loop
                item = await asyncio.get_event_loop().run_in_executor(
                    None, chunk_queue.get,
                )
                if item is _SENTINEL:
                    break
                if isinstance(item, Exception):
                    raise item

                if item.message_type == "assistant_message":
                    if item.content:
                        assistant_text.append(item.content)
                    data = json.dumps({
                        "type": "assistant",
                        "content": item.content,
                    })
                    yield f"data: {data}\n\n"
                elif item.message_type == "reasoning_message":
                    if item.reasoning:
                        reasoning_text.append(item.reasoning)
                    if body.include_reasoning:
                        data = json.dumps({
                            "type": "reasoning",
                            "content": item.reasoning,
                        })
                        yield f"data: {data}\n\n"
                elif item.message_type == "tool_call_message":
                    data = json.dumps({
                        "type": "tool_call",
                        "content": item.tool_call.function.name if hasattr(item.tool_call, 'function') else str(item),
                    })
                    yield f"data: {data}\n\n"
                elif item.message_type == "tool_return_message":
                    data = json.dumps({
                        "type": "tool_return",
                    })
                    yield f"data: {data}\n\n"

            yield f"data: {json.dumps({'type': 'done'})}\n\n"

            # B1/R-3: persist the completed turn to the per-user
            # transcript (Nabla-owned, survives re-bootstrap). Only
            # reached on a clean end-of-stream — errored or crashed
            # turns write nothing.
            try:
                from nabla.chat_history import append_turn
                append_turn(
                    user=auth.get("sub", ""),
                    message=body.message,
                    answer="".join(assistant_text),
                    reasoning="".join(reasoning_text) if body.include_reasoning else None,
                )
            except Exception as e:
                logger.warning("Transcript write failed: %s", e)

        except Exception as e:
            logger.error("Chat stream error: %s", e)
            from nabla.safe_error import safe_error
            yield f"data: {json.dumps({'type': 'error', 'error': safe_error(e, 'Chat stream')})}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
