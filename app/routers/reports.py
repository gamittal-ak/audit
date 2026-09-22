import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.auth import require_auth
from app.services.origin_findings import prepare_origin_report
from app.config import get_settings
from app.tasks.celery_app import celery_app
from app.tasks.report_task import run_report

logger = logging.getLogger(__name__)

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

_TASK_TTL = 30 * 86400   # keep task metadata for 30 days
_MAX_RECENT = 100        # show last 100 tasks


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
        seen_json_paths = set()

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

            if state == "PENDING" and meta.get("json_path") and Path(meta["json_path"]).exists():
                state = "SUCCESS"
                info = {
                    "json_path": meta["json_path"],
                    "xlsx_path": meta.get("xlsx_path", ""),
                    "account_name": meta.get("account_name", ""),
                }

            if meta.get("json_path"):
                seen_json_paths.add(meta["json_path"])

            tasks.append({
                "task_id": tid,
                "account_name": meta.get("account_name", "Unknown"),
                "started_at": meta.get("started_at", meta.get("completed_at", "")),
                "cancelled": meta.get("cancelled") == "1",
                "state": state,
                "pct": info.get("pct", 0) if state in ("PROGRESS", "STARTED") else (100 if state == "SUCCESS" else 0),
                "step": info.get("step", "") if state in ("PROGRESS", "STARTED") else "",
            })

        orphan_tasks = await _scan_orphaned_reports(r, seen_json_paths)
        tasks.extend(orphan_tasks)

        await r.aclose()
    except Exception:
        logger.exception("Error fetching recent tasks")
        tasks = []

    any_running = any(t["state"] in ("PENDING", "STARTED", "PROGRESS") for t in tasks)
    return templates.TemplateResponse(
        "partials/task_list.html",
        {"request": request, "tasks": tasks, "any_running": any_running},
    )


async def _scan_orphaned_reports(r, seen_json_paths: set) -> list:
    settings = get_settings()
    reports_dir = Path(settings.reports_base_dir)
    if not reports_dir.exists():
        return []

    orphans = []
    try:
        for json_file in sorted(reports_dir.rglob("report_*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
            if str(json_file) in seen_json_paths:
                continue
            synthetic_id = str(uuid.uuid5(uuid.NAMESPACE_URL, str(json_file)))
            existing = await r.hgetall(f"task:{synthetic_id}")
            if not existing:
                account_name = json_file.parent.name
                mtime = datetime.fromtimestamp(json_file.stat().st_mtime, tz=timezone.utc)
                started_at = mtime.strftime("%Y-%m-%d %H:%M UTC")
                xlsx_file = json_file.with_suffix(".xlsx")
                await r.hset(f"task:{synthetic_id}", mapping={
                    "account_name": account_name,
                    "started_at": started_at,
                    "json_path": str(json_file),
                    "xlsx_path": str(xlsx_file) if xlsx_file.exists() else "",
                })
                await r.expire(f"task:{synthetic_id}", _TASK_TTL)
                await r.zadd("recent_tasks", {synthetic_id: mtime.timestamp()})
                logger.info("Registered orphaned report %s as task %s", json_file, synthetic_id)
                existing = await r.hgetall(f"task:{synthetic_id}")

            seen_json_paths.add(existing.get("json_path", ""))
            orphans.append({
                "task_id": synthetic_id,
                "account_name": existing.get("account_name", "Unknown"),
                "started_at": existing.get("started_at", ""),
                "cancelled": False,
                "state": "SUCCESS",
                "pct": 100,
                "step": "",
            })
    except Exception:
        logger.exception("Error scanning orphaned reports")

    return orphans



async def _delete_tasks(task_ids: list[str]) -> dict:
    """Delete terminal reports, retaining metadata when cleanup fails."""
    deleted, failed = [], []
    r = await _redis()
    try:
        for task_id in dict.fromkeys(task_ids):
            try:
                meta = await r.hgetall(f"task:{task_id}")
                if not meta:
                    failed.append({"task_id": task_id, "error": "Report no longer exists. Refresh the list."})
                    continue
                result = celery_app.AsyncResult(task_id)
                state = result.state
                stored_report = meta.get("json_path") and Path(meta["json_path"]).exists()
                if not meta.get("cancelled") and (
                    state in ("STARTED", "PROGRESS", "RETRY")
                    or (state == "PENDING" and not stored_report)
                ):
                    failed.append({"task_id": task_id, "error": "A report is still running or queued. Cancel it before deleting."})
                    continue
                _delete_report_files(task_id, meta)
                async with r.pipeline(transaction=True) as pipe:
                    pipe.zrem("recent_tasks", task_id)
                    pipe.delete(f"task:{task_id}")
                    await pipe.execute()
                deleted.append(task_id)
            except Exception:
                logger.exception("Failed to delete report %s", task_id)
                failed.append({"task_id": task_id, "error": "Could not fully delete a report. Please retry."})
    finally:
        await r.aclose()
    return {"ok": not failed, "deleted": len(deleted), "deleted_ids": deleted, "failed": failed}


@router.delete("/api/tasks/{task_id}")
async def delete_task(task_id: str, request: Request, _=Depends(require_auth)):
    if not request.session.get("authenticated"):
        return JSONResponse({"error": "Please sign in again."}, status_code=401)
    try:
        return JSONResponse(await _delete_tasks([task_id]))
    except Exception:
        logger.exception("Report deletion unavailable")
        return JSONResponse({"error": "Deletion is unavailable. Please retry."}, status_code=503)


@router.post("/api/tasks/delete-selected")
async def delete_selected_tasks(request: Request, _=Depends(require_auth)):
    if not request.session.get("authenticated"):
        return JSONResponse({"error": "Please sign in again."}, status_code=401)
    try:
        body = await request.json()
        task_ids = body.get("task_ids") if isinstance(body, dict) else None
        if not isinstance(task_ids, list) or any(not isinstance(tid, str) or not tid for tid in task_ids):
            return JSONResponse({"error": "Select valid reports to delete."}, status_code=400)
    except (ValueError, TypeError):
        return JSONResponse({"error": "Invalid deletion request."}, status_code=400)
    try:
        return JSONResponse(await _delete_tasks(task_ids))
    except Exception:
        logger.exception("Bulk deletion unavailable")
        return JSONResponse({"error": "Deletion is unavailable. Please retry."}, status_code=503)


@router.post("/api/tasks/delete-all")
async def delete_all_tasks(request: Request, _=Depends(require_auth)):
    if not request.session.get("authenticated"):
        return JSONResponse({"error": "Please sign in again."}, status_code=401)
    try:
        r = await _redis()
        try:
            task_ids = await r.zrange("recent_tasks", 0, -1)
        finally:
            await r.aclose()
        return JSONResponse(await _delete_tasks(task_ids))
    except Exception:
        logger.exception("Bulk deletion unavailable")
        return JSONResponse({"error": "Deletion is unavailable. Please retry."}, status_code=503)


def _delete_report_files(task_id: str, meta: dict | None = None):
    paths = set()
    for key in ("json_path", "xlsx_path"):
        if (meta or {}).get(key):
            paths.add(meta[key])
    result = celery_app.AsyncResult(task_id)
    info = result.info
    if isinstance(info, dict):
        for key in ("json_path", "xlsx_path"):
            if info.get(key):
                paths.add(info[key])
    for path in list(paths):
        for suffix in (".json", ".xlsx"):
            paths.add(str(Path(path).with_suffix(suffix)))
    reports_dir = Path(get_settings().reports_base_dir).resolve()
    resolved = [Path(path).resolve() for path in paths]
    if any(not path.is_relative_to(reports_dir) or path == reports_dir for path in resolved):
        raise ValueError("Report path is outside the reports directory")
    # Propagate failures so the UI can report partial deletion and offer a retry.
    for path in resolved:
        path.unlink(missing_ok=True)
    result.forget()
    for parent in {path.parent for path in resolved}:
        try:
            if parent != reports_dir and not any(parent.iterdir()):
                parent.rmdir()
        except OSError:
            logger.debug("Report directory was not empty: %s", parent)


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

    if state == "PENDING" and not info:
        try:
            r = await _redis()
            meta = await r.hgetall(f"task:{task_id}")
            await r.aclose()
            if meta.get("json_path") and Path(meta["json_path"]).exists():
                state = "SUCCESS"
                info = {
                    "json_path": meta["json_path"],
                    "xlsx_path": meta.get("xlsx_path", ""),
                    "account_name": meta.get("account_name", ""),
                }
        except Exception:
            logger.exception("Error fetching task hash fallback for %s", task_id)

    if state == "SUCCESS":
        json_path = info.get("json_path", "")
        account_name = info.get("account_name", "")
        xlsx_path = info.get("xlsx_path", "")
        report_data = {}
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                report_data = prepare_origin_report(json.load(f))
            report = report_data.get("report", [])
        except Exception:
            logger.exception("Could not load report JSON from %s", json_path)
            report = []

        # Build flat property list for chart.js
        chart_props = []
        for g in report:
            for p in g.get("properties", []):
                chart_props.append({
                    "name": p.get("name", ""),
                    "id": p.get("id", ""),
                    "cpcodes": p.get("cpcodes", []),
                    "cert_expiry_days": p.get("cert_expiry_days"),
                })
        chart_json = json.dumps({"properties": chart_props})

        # Origin data for template
        origin_inventory = report_data.get("origin_inventory", [])
        origin_certificates = report_data.get("origin_certificates", [])
        origin_actions = report_data.get("origin_action_groups", report_data.get("origin_actions", []))
        origin_coverage = report_data.get("origin_coverage", {})

        return templates.TemplateResponse(
            "partials/report_view.html",
            {
                "request": request,
                "report": report,
                "task_id": task_id,
                "account_name": account_name,
                "xlsx_path": xlsx_path,
                "chart_json": chart_json,
                "origin_inventory": origin_inventory,
                "origin_certificates": origin_certificates,
                "origin_actions": origin_actions,
                "origin_coverage": origin_coverage,
                "origin_findings_summary": report_data.get("origin_findings_summary", {}),
                "audit_timestamp": report_data.get("audit_timestamp", ""),
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
