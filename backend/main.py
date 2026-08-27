"""Sentinel inference API (FastAPI). Fully offline: loads local model weights,
makes no outbound calls. Security is built in — see the middleware and the
/api/analyze handler (allowlist, size cap, UUID paths, subprocess isolation,
rate limiting, locked CORS, security headers)."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import uuid
from collections import deque

from fastapi import FastAPI, UploadFile, File, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

ALLOWED_EXT = {".csv", ".txt", ".tsv", ".pcap", ".pcapng"}
MAX_BYTES = 25 * 1024 * 1024          # 25 MB hard cap, enforced server-side
CHUNK = 1 << 20
ANALYZE_TIMEOUT_S = 60
RATE_MAX, RATE_WINDOW_S = 20, 60      # 20 analyses / minute / client
FRONTEND_ORIGIN = os.environ.get("FRONTEND_ORIGIN", "http://localhost:3000")

app = FastAPI(title="Sentinel API", version="1.0.0", docs_url=None, redoc_url=None)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_ORIGIN],   # locked to the real frontend origin, never "*"
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
    max_age=600,
)

_rate: dict[str, deque] = {}


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    resp.headers["Cache-Control"] = "no-store"
    return resp


def _client_id(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _rate_limit(cid: str):
    now = time.time()
    dq = _rate.setdefault(cid, deque())
    while dq and now - dq[0] > RATE_WINDOW_S:
        dq.popleft()
    if len(dq) >= RATE_MAX:
        raise HTTPException(status_code=429, detail="Rate limit exceeded. Try again shortly.")
    dq.append(now)


@app.get("/healthz")
def healthz():
    return {"status": "ok", "model": os.path.exists(os.path.join(ROOT, "models", "world_model.npz"))}


@app.get("/api/benchmark")
def get_benchmark():
    from backend.infer import benchmark
    return benchmark()


@app.get("/api/demo-capture")
def demo_capture():
    """Replays the bundled fixture capture through the REAL pipeline — a one-click
    'it works' that is genuine inference, not a canned response."""
    path = os.path.join(ROOT, "data", "demo_capture.csv")
    if not os.path.exists(path):
        from pipeline.synth import write_csv
        os.makedirs(os.path.dirname(path), exist_ok=True)
        write_csv(path)
    return _run_isolated(path, "csv", source="Demo capture — bundled fixture, real inference")


@app.post("/api/analyze")
async def analyze(request: Request, file: UploadFile = File(...)):
    _rate_limit(_client_id(request))
    name = file.filename or "upload"
    ext = os.path.splitext(name)[1].lower()
    if ext not in ALLOWED_EXT:
        raise HTTPException(status_code=400, detail=f"Unsupported file type '{ext}'. Allowed: .csv, .pcap, .pcapng")
    kind = "pcap" if ext in (".pcap", ".pcapng") else "csv"

    # UUID path in a scoped temp dir — the client filename never touches the FS.
    workdir = tempfile.mkdtemp(prefix="sentinel_")
    safe_path = os.path.join(workdir, uuid.uuid4().hex + ext)
    size = 0
    try:
        with open(safe_path, "wb") as out:
            while True:
                chunk = await file.read(CHUNK)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_BYTES:
                    raise HTTPException(status_code=413, detail=f"File exceeds {MAX_BYTES // (1024*1024)} MB limit.")
                out.write(chunk)
        if size == 0:
            raise HTTPException(status_code=400, detail="Empty file.")
        return _run_isolated(safe_path, kind, source=f"{name} · {size // 1024} KB")
    finally:
        _cleanup(workdir)


def _run_isolated(path: str, kind: str, source: str):
    """Run parsing + inference in a subprocess with a timeout so a malformed or
    adversarial capture cannot crash or hang the API process."""
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "backend.runner", path, kind],
            cwd=ROOT, capture_output=True, text=True, timeout=ANALYZE_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=422, detail="Analysis timed out — capture too large or malformed.")
    if not proc.stdout.strip():
        raise HTTPException(status_code=422, detail="Analysis failed (no output).")
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        raise HTTPException(status_code=422, detail="Analysis produced invalid output.")
    if "error" in data:
        raise HTTPException(status_code=400, detail=data["error"])
    data["source"] = source
    return JSONResponse(data)


def _cleanup(workdir: str):
    try:
        for f in os.listdir(workdir):
            os.remove(os.path.join(workdir, f))
        os.rmdir(workdir)
    except OSError:
        pass
