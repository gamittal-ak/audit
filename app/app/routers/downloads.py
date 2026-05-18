from pathlib import Path

from celery.result import AsyncResult
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse

from app.auth import require_auth

router = APIRouter()


@router.get("/api/reports/{task_id}/download/xlsx")
async def download_xlsx(task_id: str, request: Request, _=Depends(require_auth)):
    result = AsyncResult(task_id)
    if result.state != "SUCCESS":
        raise HTTPException(status_code=404, detail="Report not ready")

    info = result.result or {}
    xlsx_path = info.get("xlsx_path", "")
    if not xlsx_path or not Path(xlsx_path).exists():
        raise HTTPException(status_code=404, detail="Excel file not found")

    filename = Path(xlsx_path).name
    return FileResponse(
        path=xlsx_path,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        filename=filename,
    )
