from fastapi import Request
from fastapi.responses import RedirectResponse


def require_auth(request: Request):
    """Dependency that redirects to /login if the session is not authenticated."""
    if not request.session.get("authenticated"):
        return RedirectResponse(url="/login", status_code=302)
    return None
