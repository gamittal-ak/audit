import json
import logging
from datetime import datetime, timezone

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.auth import require_auth
from app.config import get_settings
from app.tasks.celery_app import celery_app
from app.tasks.report_task import run_report

logger = logging.getLogger(__name__)

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

_TASK_TTL = 86400        # keep task metadata for 24 h
_MAX_RECENT = 20         # show last 20 tasks


async def _redis():
    return await aioredis.from_url(get_settings().redis_url, decode_responses=True)


@router.post("/api/reports")
async def start_report(
    request: Request,
    switch_key: str = Form(...),
    account_name: str = Form(...),
    traffic_days: int = Form(15),
    _=Depends(require_auth),
):
    task = run_report.delay(switch_key, account_name, traffic_days)

    r = await _redis()
    now = datetime.now(timezone.utc)
    await r.hset(f"task:{task.id}", mapping={
        "account_name": account_name,
        "started_at": now.strftime("%Y-%m-%d %H:%M UTC"),
    })
    await r.expire(f"task:{task.id}", _TASK_TTL)
    await r.zadd("recent_tasks", {task.id: now.timestamp()})
    await r.zremrangebyrank("recent_tasks", 0, -(_MAX_RECENT + 1))
    await r.aclose()

    return RedirectResponse(url=f"/report/{task.id}", status_code=303)


@router.post("/api/reports/{task_id}/cancel")
async def cancel_report(task_id: str, request: Request, _=Depends(require_auth)):
    """Revoke (cancel) a running Celery task."""
    try:
        celery_app.control.revoke(task_id, terminate=True, signal="SIGTERM")
        # Mark cancelled in Redis metadata
        r = await _redis()
        await r.hset(f"task:{task_id}", "cancelled", "1")
        await r.aclose()
        logger.info("Task %s cancelled by user", task_id)
    except Exception:
        logger.exception("Failed to cancel task %s", task_id)
    return RedirectResponse(url="/", status_code=303)


@router.get("/api/tasks/recent", response_class=HTMLResponse)
async def recent_tasks(request: Request, _=Depends(require_auth)):
    try:
        r = await _redis()
        task_ids = await r.zrevrange("recent_tasks", 0, _MAX_RECENT - 1)

        tasks = []
        for tid in task_ids:
            meta = await r.hgetall(f"task:{tid}")
            if not meta:
                continue
            try:
                result = celery_app.AsyncResult(tid)
                state = result.state
                info = result.info if isinstance(result.info, dict) else {}
            except Exception:
                logger.exception("Could not fetch state for task %s", tid)
                state = "UNKNOWN"
                info = {}
            tasks.append({
                "task_id": tid,
                "account_name": meta.get("account_name", "Unknown"),
                "started_at": meta.get("started_at", ""),
                "cancelled": meta.get("cancelled") == "1",
                "state": state,
                "pct": info.get("pct", 0) if state in ("PROGRESS", "STARTED") else (100 if state == "SUCCESS" else 0),
                "step": info.get("step", "") if state in ("PROGRESS", "STARTED") else "",
            })
        await r.aclose()
    except Exception:
        logger.exception("Error fetching recent tasks")
        tasks = []

    any_running = any(t["state"] in ("PENDING", "STARTED", "PROGRESS") for t in tasks)
    return templates.TemplateResponse(
        "partials/task_list.html",
        {"request": request, "tasks": tasks, "any_running": any_running},
    )


@router.delete("/api/tasks/{task_id}")
async def delete_task(task_id: str, request: Request, _=Depends(require_auth)):
    """Delete a single task from the recent list and its report files."""
    try:
        r = await _redis()
        meta = await r.hgetall(f"task:{task_id}")
        await r.zrem("recent_tasks", task_id)
        await r.delete(f"task:{task_id}")
        await r.aclose()

        # Try to clean up report files
        if meta:
            _delete_report_files(task_id, meta.get("account_name", ""))

        logger.info("Deleted task %s", task_id)
    except Exception:
        logger.exception("Failed to delete task %s", task_id)
    return JSONResponse({"ok": True})


@router.post("/api/tasks/delete-selected")
async def delete_selected_tasks(request: Request, _=Depends(require_auth)):
    """Delete multiple selected tasks."""
    body = await request.json()
    task_ids = body.get("task_ids", [])
    if not task_ids:
        return JSONResponse({"ok": True, "deleted": 0})

    try:
        r = await _redis()
        for tid in task_ids:
            meta = await r.hgetall(f"task:{tid}")
            await r.zrem("recent_tasks", tid)
            await r.delete(f"task:{tid}")
            if meta:
                _delete_report_files(tid, meta.get("account_name", ""))
        await r.aclose()
        logger.info("Deleted %d tasks: %s", len(task_ids), task_ids)
    except Exception:
        logger.exception("Failed to delete selected tasks")
    return JSONResponse({"ok": True, "deleted": len(task_ids)})


@router.post("/api/tasks/delete-all")
async def delete_all_tasks(request: Request, _=Depends(require_auth)):
    """Delete all tasks from the recent list."""
    try:
        r = await _redis()
        task_ids = await r.zrange("recent_tasks", 0, -1)
        for tid in task_ids:
            meta = await r.hgetall(f"task:{tid}")
            await r.delete(f"task:{tid}")
            if meta:
                _delete_report_files(tid, meta.get("account_name", ""))
        await r.delete("recent_tasks")
        await r.aclose()
        logger.info("Deleted all %d tasks", len(task_ids))
    except Exception:
        logger.exception("Failed to delete all tasks")
    return JSONResponse({"ok": True})


def _delete_report_files(task_id: str, account_name: str):
    """Best-effort cleanup of report JSON/XLSX files for a task."""
    import shutil
    from pathlib import Path
    settings = get_settings()
    try:
        # Try to get file paths from Celery result
        result = celery_app.AsyncResult(task_id)
        if result and isinstance(result.info, dict):
            for key in ("json_path", "xlsx_path"):
                p = result.info.get(key)
                if p:
                    Path(p).unlink(missing_ok=True)
    except Exception:
        pass


@router.get("/api/reports/{task_id}/status", response_class=HTMLResponse)
async def get_status(task_id: str, request: Request, _=Depends(require_auth)):
    try:
        result = celery_app.AsyncResult(task_id)
        state = result.state
        info = result.info if isinstance(result.info, dict) else {}
    except Exception:
        logger.exception("Error fetching status for task %s", task_id)
        return templates.TemplateResponse(
            "partials/error.html",
            {"request": request, "error": "Could not retrieve task status. Please try refreshing."},
        )

    if state == "SUCCESS":
        json_path = info.get("json_path", "")
        account_name = info.get("account_name", "")
        xlsx_path = info.get("xlsx_path", "")
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                report_data = json.load(f)
            report = report_data.get("report", [])
        except Exception:
            logger.exception("Could not load report JSON from %s", json_path)
            report = []

        return templates.TemplateResponse(
            "partials/report_view.html",
            {
                "request": request,
                "report": report,
                "task_id": task_id,
                "account_name": account_name,
                "xlsx_path": xlsx_path,
            },
        )

    if state in ("FAILURE", "REVOKED"):
        if state == "REVOKED":
            error = "Report was cancelled."
        else:
            error = str(info.get("exc_message", "")) or str(result.info)
        return templates.TemplateResponse(
            "partials/error.html",
            {"request": request, "error": error},
        )

    # PENDING or PROGRESS — keep polling
    pct = info.get("pct", 0) if info else 0
    step = info.get("step", "Starting…") if info else "Starting…"
    return templates.TemplateResponse(
        "partials/progress.html",
        {
            "request": request,
            "task_id": task_id,
            "pct": pct,
            "step": step,
        },
    )
