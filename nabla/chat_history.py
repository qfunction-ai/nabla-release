"""Per-user chat transcript store (B1/R-3, frontend batch Phase 5).

Nabla-owned append-only JSONL — NEVER Letta's message list. The chat
page and the pipeline share one supervisor agent, so a Letta-history
endpoint would leak every user's chats plus the pipeline's review
prompts. This store is scoped to the authenticated identity (JWT
`sub`) and survives agent re-bootstrap (the agent's context can be
wiped and rebuilt; the transcript is plain data on disk).

R-20 pattern: append-only, lock-guarded. Reads take the last-wins
view per turn (turn_id supersedes, future-proofing corrections).
"""

import json
from datetime import datetime, timezone
from pathlib import Path
import uuid


def transcript_store_path() -> Path:
    from nabla.config import get_settings
    d = Path(get_settings().data_dir) / "chat"
    d.mkdir(parents=True, exist_ok=True)
    return d / "transcripts.jsonl"


def append_turn(
    user: str,
    message: str,
    answer: str,
    reasoning: str | None = None,
    ts: str | None = None,
    turn_id: str | None = None,
) -> str:
    """Append one completed conversation turn.

    Called by chat_stream on turn completion — only after the assistant
    answer has fully arrived (a crashed or errored stream writes
    nothing; a partial answer is never persisted as if complete).
    """
    from nabla.persistence import file_lock

    record = {
        "turn_id": turn_id or str(uuid.uuid4()),
        "ts": ts or datetime.now(timezone.utc).isoformat(),
        "user": user,
        "message": message,
        "answer": answer,
        "reasoning": reasoning,
    }
    path = transcript_store_path()
    with file_lock(str(path)):
        with path.open("a") as f:
            f.write(json.dumps(record) + "\n")
    return record["turn_id"]


def load_history(
    user: str,
    limit: int = 200,
    before_ts: str | None = None,
) -> list[dict]:
    """The user's turns, newest first, up to `limit`.

    `before_ts` is the cursor: return turns strictly older than it
    (pagination for earlier history). Reasoning is returned only to the
    owning user — the store is already scoped by `user`, so the read
    enforces it by construction.
    """
    from nabla.persistence import file_lock

    path = transcript_store_path()
    if not path.exists():
        return []

    latest: dict[str, dict] = {}
    order: list[str] = []
    with file_lock(str(path)):
        for line in path.read_text().splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue  # silent by design: torn tail line from a crash mid-write (2026-11-23)
            if rec.get("user") != user:
                continue
            tid = rec.get("turn_id")
            if tid not in latest:
                order.append(tid)
            latest[tid] = rec  # last wins by file order

    turns = [latest[tid] for tid in order]
    if before_ts:
        turns = [t for t in turns if t.get("ts", "") < before_ts]
    turns.sort(key=lambda t: t.get("ts", ""), reverse=True)
    return turns[:limit]
