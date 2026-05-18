from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from app.auth import require_auth
from app.config import get_settings
from app.services.akamai_client import AkamaiClient
from app.services.edgegrid_auth import auth_from_edgerc
import asyncio

router = APIRouter()


@router.get("/api/accounts/search")
async def search_accounts(q: str, request: Request, _=Depends(require_auth)):
    if len(q.strip()) < 3:
        return JSONResponse([])

    settings = get_settings()
    base_url, auth = auth_from_edgerc(settings.edgerc_path, settings.edgerc_section)
    sem = asyncio.Semaphore(1)

    async with AkamaiClient(base_url, auth, sem) as client:
        results = await client.search_accounts(q.strip())

    return JSONResponse(results)
