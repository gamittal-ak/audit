import json
import logging
import tempfile
from pathlib import Path

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from starlette.background import BackgroundTask
from starlette.concurrency import run_in_threadpool

from app.auth import require_auth
from app.config import get_settings
from app.services.excel_service import generate_excel
from app.tasks.celery_app import celery_app

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("/api/reports/{task_id}/download/xlsx")
async def download_xlsx(task_id: str, request: Request, _=Depends(require_auth)):
    if not request.session.get("authenticated"):
        return JSONResponse({"error": "Please sign in again."}, status_code=401)
    info = {}
    try:
        result = celery_app.AsyncResult(task_id)
        if result.state == "SUCCESS" and isinstance(result.result, dict):
            info = result.result
    except Exception:
        logger.exception("Could not read report result for download")
    if not info.get("json_path"):
        r = await aioredis.from_url(get_settings().redis_url, decode_responses=True)
        try:
            info = {**info, **await r.hgetall(f"task:{task_id}")}
        finally:
            await r.aclose()
    json_path = info.get("json_path", "")
    xlsx_path = info.get("xlsx_path", "")
    path = Path(xlsx_path) if xlsx_path else None
    has_origins = False
    if json_path and Path(json_path).is_file():
        try:
            with open(json_path, encoding="utf-8") as stream:
                data = json.load(stream)
            has_origins = bool(data.get("origin_inventory"))
        except (OSError, ValueError):
            logger.exception("Could not load report evidence for download")
            raise HTTPException(status_code=500, detail="Report evidence could not be read.")
    if not has_origins:
        if not path or not path.is_file():
            raise HTTPException(status_code=404, detail="Excel file not found")
        return FileResponse(path=path, filename=path.name,
                            media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

    # Reinterpret saved evidence with the same policy used by the UI. Original
    # JSON/XLSX files stay untouched; the temporary download is removed afterward.
    with tempfile.NamedTemporaryFile(prefix="audit-export-", suffix=".xlsx", delete=False) as stream:
        export_path = Path(stream.name)
    try:
        await run_in_threadpool(generate_excel, json_path, str(export_path))
    except Exception:
        export_path.unlink(missing_ok=True)
        logger.exception("Could not prepare updated origin findings export")
        raise HTTPException(status_code=500, detail="Excel export could not be prepared. Please retry.")
    return FileResponse(
        path=export_path,
        filename=path.name if path else Path(json_path).with_suffix(".xlsx").name,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        background=BackgroundTask(export_path.unlink, missing_ok=True),
    )
