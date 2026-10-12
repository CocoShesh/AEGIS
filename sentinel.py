"""AEGIS: one local origin, four evidence workspaces."""
import argparse
import asyncio
from contextlib import asynccontextmanager
import http.client
import os
from pathlib import Path
import socket
import subprocess
import sys
from urllib.parse import urlparse

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response, FileResponse
from fastapi.staticfiles import StaticFiles

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'repository'))
os.environ.setdefault('REPOSENTINEL_DATA', str(ROOT / '.data' / 'repositories'))
from reposentinel.api import app as repository_app
import repository_ai
repository_app.state.ai_bridge = repository_ai

ANDROID_PORT = None
MAX_UPLOAD = 256 * 1024 * 1024

@asynccontextmanager
async def lifespan(app):
    global ANDROID_PORT
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        ANDROID_PORT = sock.getsockname()[1]
    child = subprocess.Popen([sys.executable, str(ROOT/'server.py'), '--port', str(ANDROID_PORT)], cwd=ROOT)
    try:
        for _ in range(100):
            if child.poll() is not None:
                raise RuntimeError('Android analyzer could not start; check the terminal log.')
            try:
                with socket.create_connection(('127.0.0.1', ANDROID_PORT), timeout=.1):
                    break
            except OSError:
                await asyncio.sleep(.1)
        else:
            raise RuntimeError('Android analyzer startup timed out.')
        async with repository_app.router.lifespan_context(repository_app):
            yield
    finally:
        child.terminate()
        try:
            await asyncio.to_thread(child.wait, timeout=10)
        except subprocess.TimeoutExpired:
            child.kill()
            await asyncio.to_thread(child.wait)

app = FastAPI(title='AEGIS', lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)

@app.middleware('http')
async def local_boundary(request: Request, call_next):
    host = request.headers.get('host', '')
    if urlparse('http://' + host).hostname not in ('127.0.0.1', 'localhost', 'testserver'):
        return JSONResponse({'error': 'Local access only'}, status_code=403)
    origin = request.headers.get('origin')
    if origin and urlparse(origin).netloc != host:
        return JSONResponse({'error': 'Cross-origin request rejected'}, status_code=403)
    # Require same-origin/browser or CLI requests, including navigation-shaped POSTs.
    if request.headers.get('sec-fetch-site') in ('cross-site', 'same-site'):
        return JSONResponse({'error': 'Same-origin access required'}, status_code=403)
    response = await call_next(request)
    response.headers['Cache-Control'] = 'no-store'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'no-referrer'
    return response

app.mount('/landing', StaticFiles(directory=ROOT/'landing'), name='landing-assets')
app.mount('/shared', StaticFiles(directory=ROOT/'shared'), name='shared-assets')

from filesentinel.api import app as filesentinel_app
filesentinel_app.state.ai_bridge = repository_ai

app.mount('/file', filesentinel_app, name='filesentinel')

@app.get('/')
def landing():
    return FileResponse(ROOT/'landing/index.html', headers={'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"})

@app.get('/android')
def android_redirect():
    return RedirectResponse('/android/', status_code=307)

@app.get('/repository')
def repository_redirect():
    return RedirectResponse('/repository/', status_code=307)

@app.get('/file')
def filesentinel_redirect():
    return RedirectResponse('/file/', status_code=307)

app.mount('/repository', repository_app)


def forward(path, method, headers, body):
    if ANDROID_PORT is None:
        return JSONResponse({'error': 'Android analyzer is starting'}, status_code=503)
    # Never forward to a caller-selected host or remote URL.
    connection = http.client.HTTPConnection('127.0.0.1', ANDROID_PORT, timeout=120)
    blocked = {'host','origin','connection','transfer-encoding','content-length','upgrade','proxy-authorization','proxy-connection'}
    outgoing = {k:v for k,v in headers.items() if k.lower() not in blocked}
    outgoing['Host'] = f'127.0.0.1:{ANDROID_PORT}'
    if 'origin' in headers:
        outgoing['Origin'] = f'http://127.0.0.1:{ANDROID_PORT}'
    outgoing['Content-Length'] = str(len(body))
    try:
        connection.request(method, path, body=body, headers=outgoing)
        upstream = connection.getresponse()
        payload = upstream.read(128 * 1024 * 1024 + 1)
        if len(payload) > 128 * 1024 * 1024:
            return JSONResponse({'error':'Android response exceeds the local gateway limit'}, status_code=502)
        excluded = {'connection','transfer-encoding','content-length','server','date'}
        return Response(payload, status_code=upstream.status, headers={k:v for k,v in upstream.getheaders() if k.lower() not in excluded})
    except (OSError, http.client.HTTPException):
        return JSONResponse({'error':'Android analyzer unavailable. Restart AEGIS.'}, status_code=502)
    finally:
        connection.close()

@app.api_route('/{path:path}', methods=['GET','HEAD','POST'])
async def android(request: Request, path: str):
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > MAX_UPLOAD:
            return JSONResponse({'error':'Upload exceeds 256 MiB'}, status_code=413)
        body.extend(chunk)
    target = '/' if path == 'android/' else '/' + path
    if request.url.query:
        target += '?' + request.url.query
    return await asyncio.to_thread(forward, target, request.method, dict(request.headers), bytes(body))

if __name__ == '__main__':
    parser=argparse.ArgumentParser(description='AEGIS local workbench')
    parser.add_argument('--port', type=int, default=8797)
    args=parser.parse_args()
    import uvicorn
    uvicorn.run(app, host='127.0.0.1', port=args.port)
