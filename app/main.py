import json

import bcrypt
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from app.auth import require_auth
from app.config import get_settings
from app.routers import accounts, downloads, reports

settings = get_settings()

app = FastAPI(title="Akamai Audit Tool", docs_url=None, redoc_url=None)

# Session middleware (signed cookie, HttpOnly + SameSite handled by Starlette)
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.secret_key,
    https_only=False,   # set True in prod behind HTTPS
    same_site="strict",
)

app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")

# Include routers
app.include_router(accounts.router)
app.include_router(reports.router)
app.include_router(downloads.router)


# ------------------------------------------------------------------ Auth pages

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if request.session.get("authenticated"):
        return RedirectResponse(url="/", status_code=302)
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@app.post("/login")
async def do_login(request: Request, password: str = Form(...)):
    if bcrypt.checkpw(password.encode("utf-8"), settings.app_password.encode("utf-8")):
        request.session["authenticated"] = True
        return RedirectResponse(url="/", status_code=303)
    return templates.TemplateResponse(
        "login.html",
        {"request": request, "error": "Incorrect password"},
        status_code=401,
    )


@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=302)


# ------------------------------------------------------------------ Page routes

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    if not request.session.get("authenticated"):
        return RedirectResponse(url="/login", status_code=302)
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/report/{task_id}", response_class=HTMLResponse)
async def report_page(task_id: str, request: Request):
    if not request.session.get("authenticated"):
        return RedirectResponse(url="/login", status_code=302)
    return templates.TemplateResponse(
        "report.html", {"request": request, "task_id": task_id}
    )
