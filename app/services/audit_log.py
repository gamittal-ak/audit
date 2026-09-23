"""Bounded, task-scoped activity summaries. Never forward raw application logs."""
import json
import logging
import re
import time
import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone

from redis import Redis

from app.config import get_settings

MAX_ENTRIES = 300
LOG_TTL = 86400
_current = ContextVar("audit_activity", default=None)
logger = logging.getLogger(__name__)


def log_key(task_id):
    return f"task:{task_id}:activity"


def event(message, level="info"):
    """Record only explicit, user-facing summaries in the current audit context."""
    target = _current.get()
    if target is None:
        return
    client, task_id, state = target
    # Avoid repeatedly stalling audit work if the optional activity store is down.
    if time.monotonic() < state.get("retry_at", 0):
        return
    entry = {
        "id": uuid.uuid4().hex,
        "time": datetime.now(timezone.utc).strftime("%H:%M:%S"),
        "level": level if level in ("info", "warning", "error", "success") else "info",
        "message": re.sub(r"[\x00-\x1f\x7f]", " ", str(message))[:600],
    }
    try:
        with client.pipeline(transaction=True) as pipe:
            pipe.rpush(log_key(task_id), json.dumps(entry))
            pipe.ltrim(log_key(task_id), -MAX_ENTRIES, -1)
            pipe.expire(log_key(task_id), LOG_TTL)
            pipe.execute()
    except Exception:
        state["retry_at"] = time.monotonic() + 30
        logger.warning("Audit activity storage unavailable for task %s", task_id)


@contextmanager
def audit_activity(task_id):
    client = Redis.from_url(get_settings().redis_url, socket_connect_timeout=0.5, socket_timeout=0.5)
    token = _current.set((client, task_id, {}))
    try:
        yield
    finally:
        _current.reset(token)
        client.close()


async def read_activity(client, task_id):
    entries = []
    for raw in await client.lrange(log_key(task_id), -MAX_ENTRIES, -1):
        try:
            entry = json.loads(raw)
            if isinstance(entry, dict) and all(isinstance(entry.get(k), str) for k in ("id", "time", "level", "message")):
                if entry["level"] not in ("info", "warning", "error", "success"):
                    entry["level"] = "info"
                entries.append(entry)
        except (ValueError, TypeError):
            continue
    return entries
