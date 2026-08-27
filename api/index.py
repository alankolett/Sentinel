"""Vercel Python Function — same-origin /api/* live inference for the deployed
site. Reuses the exact trained-model inference used by the offline FastAPI demo
(backend.infer), running IN-PROCESS (no subprocess) so it is serverless-safe.

Routes (Vercel rewrites /api/(.*) here; FastAPI matches the original path):
  GET  /api/benchmark      -> real evaluation metrics
  GET  /api/demo-capture   -> real model analysis of the bundled capture
  POST /api/analyze        -> real model analysis of an uploaded CSV/PCAP
  GET  /api/health         -> liveness + model-present check

If this function is unavailable, the frontend transparently falls back to the
precomputed REAL model output under /real, so the site never shows fake numbers.
"""
from __future__ import annotations

import os
import sys
import tempfile
import uuid

# make the repo root importable (backend/, pipeline/, models/, config/)
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from fastapi import FastAPI, UploadFile, File, HTTPException, Request  # noqa: E402
from fastapi.middleware.cors import CORSMiddleware  # noqa: E402
from fastapi.responses import JSONResponse  # noqa: E402

ALLOWED_EXT = {".csv", ".txt", ".tsv", ".pcap", ".pcapng"}
MAX_BYTES = 25 * 1024 * 1024
CHUNK = 1 << 20
FRONTEND_ORIGIN = os.environ.get("FRONTEND_ORIGIN", "*")

app = FastAPI(title="Sentinel API", version="1.0.0", docs_url=None, redoc_url=None)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_ORIGIN] if FRONTEND_ORIGIN != "*" else ["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
    max_age=600,
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.get("/api/health")
def health():
    return {"status": "ok", "model": os.path.exists(os.path.join(ROOT, "models", "world_model.npz"))}


@app.get("/api/benchmark")
def get_benchmark():
    from backend.infer import benchmark
    return benchmark()


@app.get("/api/demo-capture")
def demo_capture():
    from backend.infer import analyze_csv
    path = os.path.join(ROOT, "data", "demo_capture.csv")
    if not os.path.exists(path):
        raise HTTPException(status_code=500, detail="Demo capture missing.")
    try:
        data = analyze_csv(path)
    except Exception as e:  # pragma: no cover
        raise HTTPException(status_code=422, detail=f"Analysis failed: {e}")
    data["source"] = "Synthetic infiltration capture · CIC-IDS schema · CIC-IDS2018-trained model"
    return JSONResponse(data)


@app.post("/api/analyze")
async def analyze(file: UploadFile = File(...)):
    from backend.infer import analyze_csv
    name = file.filename or "upload"
    ext = os.path.splitext(name)[1].lower()
    if ext not in ALLOWED_EXT:
        raise HTTPException(status_code=400, detail=f"Unsupported file type '{ext}'. Allowed: .csv, .pcap, .pcapng")
    kind = "pcap" if ext in (".pcap", ".pcapng") else "csv"

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
        if kind == "pcap":
            from backend.runner import pcap_to_csv
            csv_path = safe_path + ".flows.csv"
            pcap_to_csv(safe_path, csv_path)
            safe_path = csv_path
        data = analyze_csv(safe_path)
        data["source"] = f"{name} · {size // 1024} KB · real inference"
        return JSONResponse(data)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Analysis failed: {e}")
    finally:
        try:
            for f in os.listdir(workdir):
                os.remove(os.path.join(workdir, f))
            os.rmdir(workdir)
        except OSError:
            pass
