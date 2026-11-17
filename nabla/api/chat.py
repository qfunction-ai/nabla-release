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


@router.post("/stream")
@limiter.limit("10/minute")
async def chat_stream(
    request: Request,
    body: ChatRequest,
    _auth: None = Depends(require_user),
):
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
                    data = json.dumps({
                        "type": "assistant",
                        "content": item.content,
                    })
                    yield f"data: {data}\n\n"
                elif item.message_type == "reasoning_message":
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
