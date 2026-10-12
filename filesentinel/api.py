"""Local FileSentinel metadata triage API."""
import asyncio
from contextlib import suppress
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import subprocess
import sys
import tempfile
import time
import uuid
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

ROOT = Path(__file__).resolve().parent
WEB = ROOT / "web"
DATA = Path(os.environ.get("FILESENTINEL_DATA", Path(__file__).resolve().parents[1] / ".data" / "filesentinel"))
MAX_UPLOAD = 64 * 1024 * 1024
TOKEN = secrets.token_urlsafe(32)
AI_BRIDGE = None
ACTIVE = set()
DATA.mkdir(parents=True, exist_ok=True, mode=0o700)
os.chmod(DATA, 0o700)
DB = DATA / "scans.sqlite"


def connect():
    db = sqlite3.connect(DB, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    return db


def init_db():
    with connect() as db:
        db.execute("CREATE TABLE IF NOT EXISTS scans (id TEXT PRIMARY KEY, created REAL NOT NULL, state TEXT NOT NULL, name TEXT NOT NULL, detail TEXT NOT NULL, report TEXT, ai TEXT)")
        db.execute("UPDATE scans SET state='FAILED', detail='Analysis interrupted by application restart; upload and scan again.' WHERE state IN ('QUEUED','ANALYZING','AI_REVIEWING')")
    cutoff = time.time() - 24 * 60 * 60
    for abandoned in DATA.glob("incoming-*"):
        with suppress(OSError):
            if abandoned.stat().st_mtime < cutoff:
                abandoned.unlink()


init_db()
app = FastAPI(title="FileSentinel", version="0.1.0", docs_url=None, redoc_url=None, openapi_url=None)
app.state.ai_bridge = None


@app.middleware("http")
async def local_guard(request: Request, call_next):
    host = request.headers.get("host", "")
    if urlparse("http://" + host).hostname not in ("127.0.0.1", "localhost", "testserver"):
        return JSONResponse({"detail": "Local access only"}, status_code=403)
    origin = request.headers.get("origin")
    if origin and urlparse(origin).netloc != host:
        return JSONResponse({"detail": "Cross-origin request rejected"}, status_code=403)
    if request.method not in ("GET", "HEAD", "OPTIONS") and not secrets.compare_digest(request.headers.get("x-filesentinel-token", ""), TOKEN):
        return JSONResponse({"detail": "Session token missing. Reload the workspace."}, status_code=403)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
    return response


def _limit_child():
    import resource
    resource.setrlimit(resource.RLIMIT_CPU, (25, 25))
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_FSIZE, (2 * 1024 * 1024, 2 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
    with suppress(Exception):
        resource.setrlimit(resource.RLIMIT_NPROC, (8, 8))


def _run_worker(sample):
    worker = ROOT / "worker.py"
    env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "HOME": "/nonexistent"}
    bwrap = "/usr/bin/bwrap"
    if Path(bwrap).exists():
        cmd = [bwrap, "--die-with-parent", "--new-session", "--unshare-all", "--ro-bind", "/usr", "/usr"]
        for mount in ("/lib", "/lib64", "/etc/ld.so.cache"):
            if Path(mount).exists() and not Path(mount).is_symlink():
                cmd += ["--ro-bind", mount, mount]
        cmd += ["--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp", "--ro-bind", str(worker), "/worker.py", "--ro-bind", str(sample), "/input.bin", "--chdir", "/tmp", "--clearenv", "--setenv", "PATH", "/usr/bin:/bin", "--setenv", "LANG", "C.UTF-8", "--", "/usr/bin/python3", "-I", "-B", "/worker.py", "/input.bin"]
        try:
            p = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False, env={}, preexec_fn=_limit_child)
            if p.returncode == 0:
                return json.loads(p.stdout[:1024 * 1024]), "BWRAP"
            # Namespace restrictions vary by host; the fallback remains explicitly limited.
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
            pass
    p = subprocess.run([sys.executable, "-I", "-B", str(worker), str(sample)], stdin=subprocess.DEVNULL,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False,
                       cwd=str(sample.parent), env=env, preexec_fn=_limit_child)
    if p.returncode != 0:
        raise RuntimeError("Metadata worker failed or exceeded a resource limit")
    return json.loads(p.stdout[:1024 * 1024]), "PROCESS_LIMITED"


def _report_meta(result, isolation):
    limitations = list(result.get("limitations", []))
    if isolation != "BWRAP":
        limitations.insert(0, "Host disabled unprivileged namespaces; worker ran with process resource limits only. Network and host-file isolation are not guaranteed.")
    limitations += ["No target bytes were executed, loaded, installed, or imported.", "Deep disassembly, signatures, reputation lookups, and emulation are not integrated in this release."]
    return {"identity": {k: result[k] for k in ("size_bytes", "sha256", "sha1", "md5", "family", "mime")},
            "structure": result.get("details", {}), "engine_runs": [
                {"engine": "FileSentinel metadata worker", "version": "0.1.0", "status": "COMPLETED", "tier": "STATIC", "isolation": isolation},
                {"engine": "Detect It Easy / LIEF / YARA-X / capa / FLOSS / Ghidra", "status": "NOT_INSTALLED", "tier": "STATIC"},
                {"engine": "Speakeasy", "status": "NOT_INSTALLED", "tier": "EMULATED"},
                {"engine": "Dynamic sandbox", "status": "NOT_INTEGRATED", "tier": "DYNAMIC_SANDBOX"}],
            "findings": [], "limitations": limitations,
            "coverage": {"status": "PARTIAL", "meaning": "Limited format metadata only; this is not a malware verdict."},
            "native_execution": "NEVER_PERFORMED", "evidence_tier": "STATIC"}


def _row(scan_id):
    with connect() as db:
        row = db.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    if row is None:
        raise HTTPException(404, "Scan not found")
    result = dict(row)
    result["report"] = json.loads(result["report"]) if result["report"] else None
    result["ai"] = json.loads(result["ai"]) if result["ai"] else None
    return result


async def _analyze(scan_id, sample):
    ACTIVE.add(scan_id)
    try:
        with connect() as db:
            db.execute("UPDATE scans SET state='ANALYZING', detail='Hashing and inspecting bounded file metadata.' WHERE id=?", (scan_id,))
        result, isolation = await asyncio.to_thread(_run_worker, sample)
        report = _report_meta(result, isolation)
        ai = None
        bridge = getattr(app.state, "ai_bridge", None)
        try:
            ai_configured = bridge is not None and any(p.get("configured") for p in bridge.providers())
        except Exception:
            ai_configured = False
        if ai_configured:
            with connect() as db:
                db.execute("UPDATE scans SET state='AI_REVIEWING', detail='Static metadata complete; requesting a bounded AI assessment.' WHERE id=?", (scan_id,))
            try:
                safe_structure = {k: v for k, v in report["structure"].items() if isinstance(v, (bool, int, float))}
                ai_input = {"findings": [], "coverage": {"discovered": "1 uploaded artifact", "accounted": "1 input artifact", "inspected": "headers and limited metadata only", "percent": None},
                            "limitations": report["limitations"] + [f"Detected family: {result['family']}; MIME: {result['mime']}; bytes: {result['size_bytes']}; SHA-256: {result['sha256']}. Bounded numeric/boolean structure indicators: {json.dumps(safe_structure, ensure_ascii=True)[:1000]}. No raw file bytes, original filename, local paths, archive member names, strings, or file content were sent."]}
                ai = await asyncio.to_thread(bridge.explain, ai_input)
                report["engine_runs"].append({"engine": "Shared AI assessment", "status": "COMPLETED", "tier": "AI_COMMENTARY"})
            except Exception:
                report["limitations"].append("AI assessment unavailable; deterministic metadata remains available.")
                report["engine_runs"].append({"engine": "Shared AI assessment", "status": "FAILED", "tier": "AI_COMMENTARY"})
        else:
            report["engine_runs"].append({"engine": "Shared AI assessment", "status": "NOT_CONFIGURED", "tier": "AI_COMMENTARY"})
        with connect() as db:
            db.execute("UPDATE scans SET state='COMPLETED', detail=?, report=?, ai=? WHERE id=?",
                       ("Static triage and configured AI assessment complete." if ai else "Static metadata triage complete; no AI provider configured or assessment unavailable.", json.dumps(report), json.dumps(ai) if ai else None, scan_id))
    except subprocess.TimeoutExpired:
        with connect() as db: db.execute("UPDATE scans SET state='TIMEOUT',detail='Analysis reached its 30-second worker limit.' WHERE id=?", (scan_id,))
    except Exception:
        with connect() as db: db.execute("UPDATE scans SET state='FAILED',detail='Metadata analysis failed. No safety verdict was produced.' WHERE id=?", (scan_id,))
    finally:
        with suppress(OSError): sample.unlink()
        ACTIVE.discard(scan_id)


@app.get("/api/session")
async def session():
    bridge = getattr(app.state, "ai_bridge", None)
    try:
        configured = bridge is not None and any(p.get("configured") for p in bridge.providers())
    except Exception:
        configured = False
    return {"token": TOKEN, "version": "0.1.0", "ai_configured": configured, "max_upload": MAX_UPLOAD}


@app.get("/api/scans")
async def history():
    with connect() as db:
        rows = db.execute("SELECT id,created,state,name,detail,report,ai FROM scans ORDER BY created DESC LIMIT 100").fetchall()
    return [{"id": r["id"], "created": r["created"], "state": r["state"], "name": r["name"], "detail": r["detail"],
             "family": json.loads(r["report"])["identity"]["family"] if r["report"] else None,
             "assessment": json.loads(r["ai"]).get("assessment") if r["ai"] else None} for r in rows]


@app.post("/api/scans", status_code=202)
async def create_scan(request: Request):
    if len(ACTIVE) >= 2:
        raise HTTPException(429, "Two scans are already active. Wait for one to finish.")
    total = 0
    clean_name = re.sub(r"[^\w.() -]", "_", request.headers.get("x-filename", "sample.bin").split("/")[-1].split("\\")[-1])[:120].strip() or "sample.bin"
    DATA.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, raw_path = tempfile.mkstemp(prefix="incoming-", dir=DATA)
    os.fchmod(fd, 0o600)
    sample = Path(raw_path)
    try:
        with os.fdopen(fd, "wb") as f:
            async for chunk in request.stream():
                total += len(chunk)
                if total > MAX_UPLOAD:
                    raise HTTPException(413, "File exceeds the 64 MiB per-scan limit")
                f.write(chunk)
        if not total:
            raise HTTPException(422, "Choose a file to inspect")
        scan_id = uuid.uuid4().hex
        with connect() as db:
            db.execute("INSERT INTO scans(id,created,state,name,detail) VALUES(?,?,?,?,?)", (scan_id, time.time(), "QUEUED", clean_name, "Waiting for the local metadata worker."))
        ACTIVE.add(scan_id)
        asyncio.create_task(_analyze(scan_id, sample))
        return {"id": scan_id, "state": "QUEUED"}
    except Exception:
        with suppress(OSError): sample.unlink()
        raise


@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: str):
    return _row(scan_id)


@app.delete("/api/scans/{scan_id}", status_code=204)
async def delete_scan(scan_id: str):
    with connect() as db:
        row = db.execute("SELECT state FROM scans WHERE id=?", (scan_id,)).fetchone()
        if row is None: raise HTTPException(404, "Scan not found")
        if row["state"] in ("QUEUED", "ANALYZING", "AI_REVIEWING"): raise HTTPException(409, "Wait for the active scan to finish before deleting it")
        db.execute("DELETE FROM scans WHERE id=?", (scan_id,))
    return None


@app.get("/")
async def index():
    return FileResponse(WEB / "index.html")


app.mount("/", StaticFiles(directory=WEB), name="filesentinel-static")
