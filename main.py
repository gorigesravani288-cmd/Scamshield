"""ScamShield AI - FastAPI app. Local: uvicorn main:app --reload"""
import os, threading, time
from collections import defaultdict, deque
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

import service
from explain import llm_info
from ui_html import INDEX_HTML

RATE_LIMIT, RATE_WINDOW = int(os.getenv("RATE_LIMIT", "30")), 60  # requests per IP per minute
_hits = defaultdict(deque)


def _feed_loop():
    while True:
        service.refresh_blocklist()
        time.sleep(24 * 3600)


@asynccontextmanager
async def lifespan(_):
    if os.getenv("BLOCKLIST_FEED", "0") == "1":  # opt in: downloads the free OpenPhish feed daily
        threading.Thread(target=_feed_loop, daemon=True).start()
    yield


app = FastAPI(title="ScamShield AI", docs_url=None, redoc_url=None, lifespan=lifespan)


@app.middleware("http")
async def guard(request: Request, call_next):
    if request.url.path.startswith("/api/analyze"):
        # the LAST x-forwarded-for entry is the one our own proxy (Render) appended; earlier ones are client-controlled
        xff = request.headers.get("x-forwarded-for")
        ip = xff.split(",")[-1].strip() if xff else (request.client.host if request.client else "?")
        q, now = _hits[ip], time.time()
        while q and now - q[0] > RATE_WINDOW:
            q.popleft()
        if len(q) >= RATE_LIMIT:
            return JSONResponse({"detail": "Too many checks. Wait a minute and try again."}, status_code=429)
        q.append(now)
        if len(_hits) > 5000:
            for k in [k for k, v in _hits.items() if not v]:
                del _hits[k]
    resp = await call_next(request)
    resp.headers.update({"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
                         "Content-Security-Policy": "default-src 'self'; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; script-src 'unsafe-inline'; img-src 'self' data:"})
    return resp


class TextIn(BaseModel):
    text: str = Field(..., max_length=20000)
    lang: str = Field("en", max_length=2)


class LinkIn(BaseModel):
    url: str = Field(..., max_length=2048)


@app.get("/", response_class=HTMLResponse)
def index():
    return INDEX_HTML


@app.get("/api/health")
def health():
    info = llm_info()
    return {"status": "ok", "mode": "ai+rules+links" if info["enabled"] else "rules+links", "ai_model": info["enabled"],
            "ai_explanations": info["enabled"], "llm_host": info["host"], "blocklist_size": len(service.BLOCKLIST)}


@app.post("/api/analyze/text")
def analyze_text(body: TextIn):
    try:
        return service.analyze_text(body.text, body.lang if body.lang in ("en", "hi", "te") else "en")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/analyze/link")
def analyze_link(body: LinkIn):
    try:
        return service.analyze_link(body.url)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
