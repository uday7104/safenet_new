"""SafeNet API.  Run:  uvicorn app.main:app --reload

Decisions come from comparing the input with reference data in MongoDB (see app/engine.py). No ML model is loaded."""
import hmac
import os
import threading
from pathlib import Path
from typing import Literal, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from pymongo.errors import PyMongoError

from . import db, engine, seed
from .reference import REF

ROOT = Path(__file__).resolve().parent.parent

app = FastAPI(title="SafeNet", description="Scam & phishing checker based on a reference database")
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")


def _startup():
    """Create indexes and fill any empty reference collection (runs in the background so the server starts at once)."""
    try:
        db.init_db()
        counts = seed.seed_if_empty()
        if counts:
            print("Reference database seeded:", counts)
    except Exception as e:  # noqa: BLE001  (the checker keeps working on built-in lists)
        print("WARNING: MongoDB not reachable, using built-in lists only and not saving history:", str(e)[:120])
    REF.invalidate()


if os.environ.get("AUTO_SEED", "1") == "1":
    threading.Thread(target=_startup, daemon=True).start()


@app.exception_handler(PyMongoError)
async def mongo_unavailable(request: Request, exc: PyMongoError):
    return JSONResponse(status_code=503, content={"detail": "Database unavailable. Check MONGODB_URI and that MongoDB is running."})


# History and reference management expose or change data, so they are protected:
#  - ADMIN_TOKEN set   -> send header  X-Admin-Token: <token>
#  - ADMIN_TOKEN unset -> only requests from this machine (localhost) are allowed
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN")
LOCAL_HOSTS = {"127.0.0.1", "::1", "localhost", "testclient"}


def require_admin(request: Request, x_admin_token: Optional[str] = Header(None)):
    if ADMIN_TOKEN:
        if not x_admin_token or not hmac.compare_digest(x_admin_token, ADMIN_TOKEN):
            raise HTTPException(401, "Admin token required.")
    elif not request.client or request.client.host not in LOCAL_HOSTS:
        raise HTTPException(403, "Only available locally. Set the ADMIN_TOKEN environment variable to enable remote access.")


class AnalyzeRequest(BaseModel):
    text: Optional[str] = Field(None, max_length=10000)
    url: Optional[str] = Field(None, max_length=2000)
    email: Optional[str] = Field(None, max_length=320)


class BlacklistRequest(BaseModel):
    kind: Literal["url", "domain", "email"]
    value: str = Field(..., min_length=3, max_length=2000)
    note: Optional[str] = Field(None, max_length=300)


@app.get("/")
def index():
    return FileResponse(ROOT / "static" / "index.html")


@app.post("/analyze")
def analyze(req: AnalyzeRequest):
    text, url, email = (req.text or "").strip(), (req.url or "").strip(), (req.email or "").strip()
    if not (text or url or email):
        raise HTTPException(400, "Provide a message, a link and/or a sender email to check.")
    result = engine.analyze(text, url, email)
    try:  # a storage problem must never break the check itself
        result["id"] = db.save_analysis(text, url, email, result)
    except Exception as e:  # noqa: BLE001
        print("DB save failed:", str(e)[:120])
        result["id"] = None
    return result


@app.get("/stats")
def stats():
    """What the engine compares against (sizes of the reference collections)."""
    REF.ensure()
    return REF.stats()


@app.post("/reference/blacklist", dependencies=[Depends(require_admin)])
def add_blacklist(req: BlacklistRequest):
    """Report a new scam link, domain or sender email. It is caught from the next check onward."""
    seed.add_blacklist(req.kind, req.value, req.note)
    return {"added": req.kind, "value": req.value}


@app.get("/history", dependencies=[Depends(require_admin)])
def history(limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0),
            level: Optional[str] = Query(None, pattern="^(?i:low|medium|high|unknown)$"), q: Optional[str] = None):
    items, total = db.list_analyses(limit, offset, level, q)
    return {"total": total, "limit": limit, "offset": offset, "items": items}


@app.get("/history/summary", dependencies=[Depends(require_admin)])
def history_summary():
    return db.summary()


@app.get("/history/export.csv", dependencies=[Depends(require_admin)])
def history_export():
    return PlainTextResponse(db.export_csv(), media_type="text/csv",
                             headers={"Content-Disposition": "attachment; filename=safenet_history.csv"})


@app.get("/history/{analysis_id}", dependencies=[Depends(require_admin)])
def history_item(analysis_id: str):
    row = db.get_analysis(analysis_id)
    if not row:
        raise HTTPException(404, "Analysis not found.")
    return row


@app.delete("/history/{analysis_id}", dependencies=[Depends(require_admin)])
def history_delete(analysis_id: str):
    if not db.delete_analysis(analysis_id):
        raise HTTPException(404, "Analysis not found.")
    return {"deleted": analysis_id}


@app.get("/health")
def health():
    return {"status": "ok"}
