from concurrent.futures import ProcessPoolExecutor
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlparse
import json, secrets, uuid, multiprocessing
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from . import storage
from .core import validate_url, MAX_TOTAL, redact
from .jobs import execute
from .scanners import status
from .reporting import sbom, sarif, html_report

TOKEN=secrets.token_urlsafe(32)
POOL=None
FUTURES={}
TERMINAL={'PARTIAL','COMPLETED','FAILED','CANCELLED','LIMIT_EXCEEDED'}
@asynccontextmanager
async def lifespan(app):
    global POOL
    with storage.connect() as db:
        db.execute("UPDATE scans SET state='FAILED', detail='Scan interrupted by application restart. Start a new scan.' WHERE state NOT IN ('PARTIAL','COMPLETED','FAILED','CANCELLED','LIMIT_EXCEEDED')")
    POOL=ProcessPoolExecutor(max_workers=1,mp_context=multiprocessing.get_context('spawn'),max_tasks_per_child=1)
    yield
    POOL.shutdown(wait=True,cancel_futures=True)

app=FastAPI(title='RepoSentinel',version='0.1.0',lifespan=lifespan)
@app.middleware('http')
async def local_guard(request:Request,call_next):
    host=request.headers.get('host','').split(':')[0]
    if host not in ('127.0.0.1','localhost','testserver'): return JSONResponse({'detail':'Local access only'},status_code=403)
    origin=request.headers.get('origin')
    if origin and urlparse(origin).netloc!=request.headers.get('host'):
        return JSONResponse({'detail':'Cross-origin request rejected'},status_code=403)
    if request.method not in ('GET','HEAD','OPTIONS') and not secrets.compare_digest(request.headers.get('x-reposentinel-token',''),TOKEN):
        return JSONResponse({'detail':'Session token missing. Reload the app.'},status_code=403)
    response=await call_next(request)
    response.headers['X-Content-Type-Options']='nosniff'
    response.headers['Referrer-Policy']='no-referrer'
    response.headers['Cache-Control']='no-store'
    response.headers['Content-Security-Policy']="default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'"
    return response

class ScanInput(BaseModel):
    url:str=Field(default='',max_length=300)
    ref:str=Field(default='',max_length=200)
    demo:bool=False
class ReviewInput(BaseModel):
    disposition:str
    note:str=Field(default='',max_length=4000)

def record(scan_id):
    obj=storage.get(scan_id)
    if not obj: raise HTTPException(404,'Scan not found')
    if obj['state'] not in TERMINAL:obj['report']=None
    return obj

def report(scan_id):
    obj=record(scan_id)
    if not obj['report']: raise HTTPException(409,'The scan has not produced a report')
    return obj['report']

def submit(**kwargs):
    active=sum(not f.done() for f in FUTURES.values())
    if active>=3: raise HTTPException(429,'Three scans are already queued. Wait for one to finish.')
    scan_id=uuid.uuid4().hex
    storage.update(scan_id,'QUEUED','Waiting for the local static worker')
    if POOL is None: raise HTTPException(503,'Worker is starting')
    bridge=getattr(app.state,'ai_bridge',None)
    auto_ai=bridge is not None
    FUTURES[scan_id]=POOL.submit(execute,scan_id,auto_ai=auto_ai,**kwargs)
    def completed(future):
        if future.cancelled():
            storage.update(scan_id,'CANCELLED','Queued scan was cancelled at shutdown')
        elif future.exception() is not None:
            storage.update(scan_id,'FAILED','Static worker failed. Retained evidence is incomplete; start a new scan.')
        elif auto_ai:
            finish_ai(scan_id,bridge)
    FUTURES[scan_id].add_done_callback(completed)
    for key in list(FUTURES):
        if key!=scan_id and FUTURES[key].done(): del FUTURES[key]
    return {'id':scan_id,'state':'QUEUED'}

def finish_ai(scan_id,bridge):
    obj=storage.get(scan_id)
    if not obj or obj['state']!='AI_REVIEWING':return
    r=obj['report']
    try:
        result=bridge.explain(r)
        storage.save_ai(scan_id,result)
        detail='Static engines and AI assessment complete.'
    except Exception:
        for run in r.get('scanner_runs',[]):
            if run['engine']=='AI review':run.update(status='FAILED',detail='AI assessment unavailable: configured providers did not return a valid response. Retry in AI explanation.')
        detail='Static engines complete. AI assessment failed; static evidence remains available.'
    storage.update(scan_id,r['state'],detail,r)

@app.get('/api/session')
def session(): return {'token':TOKEN,'version':'0.1.0'}
@app.get('/api/scanners')
def scanners(): return status()
@app.get('/api/scans')
def scans(): return storage.history()
@app.post('/api/scans',status_code=202)
def create_scan(body:ScanInput):
    if not body.demo:
        try: validate_url(body.url)
        except ValueError as ex: raise HTTPException(422,str(ex))
    return submit(url=body.url,ref=body.ref,demo=body.demo)
@app.post('/api/scans/upload',status_code=202)
async def upload(request:Request):
    body=bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body)>MAX_TOTAL: raise HTTPException(413,'Archive exceeds 80 MB')
    if not body: raise HTTPException(422,'Choose a tar.gz repository snapshot')
    return submit(archive=bytes(body))
@app.get('/api/scans/{scan_id}')
def scan(scan_id:str): return record(scan_id)
@app.delete('/api/scans/{scan_id}')
def remove_scan(scan_id:str):
    future=FUTURES.get(scan_id)
    if future is not None and not future.done():raise HTTPException(409,'Wait for the scan to finish before removing it.')
    result=storage.remove(scan_id)
    if result=='missing':raise HTTPException(404,'Scan not found')
    if result=='active':raise HTTPException(409,'Wait for the scan to finish before removing it.')
    FUTURES.pop(scan_id,None)
    return {'removed':True}
@app.post('/api/scans/{scan_id}/findings/{finding_id}/review')
def review(scan_id:str,finding_id:str,body:ReviewInput):
    if body.disposition not in ('EXPECTED_BEHAVIOR','FALSE_POSITIVE','NEEDS_INVESTIGATION','UNSAFE','UNKNOWN'): raise HTTPException(422,'Choose a supported review disposition')
    r=report(scan_id)
    if not any(f['id']==finding_id for f in r['findings']): raise HTTPException(404,'Finding not found')
    storage.review(scan_id,finding_id,body.disposition,redact(body.note))
    return {'saved':True}
@app.get('/api/scans/{scan_id}/export/{kind}')
def export(scan_id:str,kind:str):
    r=report(scan_id)
    if kind=='html': return HTMLResponse(html_report(r),headers={'Content-Disposition':'attachment; filename="reposentinel-report.html"'})
    obj=r if kind=='json' else sbom(r) if kind=='sbom' else sarif(r) if kind=='sarif' else None
    if obj is None: raise HTTPException(404,'Unknown export format')
    return Response(json.dumps(obj,indent=2),media_type='application/json',headers={'Content-Disposition':f'attachment; filename="reposentinel-{kind}.json"'})

class AIInput(BaseModel):
    consent:bool=False

@app.get('/api/ai/providers')
def ai_providers():
    bridge=getattr(app.state,'ai_bridge',None)
    return bridge.providers() if bridge else []

@app.post('/api/scans/{scan_id}/ai/explain')
def ai_explain(scan_id:str,body:AIInput):
    if not body.consent: raise HTTPException(422,'Consent is required before sending a findings summary to AI.')
    r=report(scan_id)
    bridge=getattr(app.state,'ai_bridge',None)
    if bridge is None: raise HTTPException(503,'AI is available through the AEGIS launcher with APKTrust configuration.')
    try:
        result=bridge.explain(r)
        storage.save_ai(scan_id,result)
        return result
    except ValueError as ex:raise HTTPException(503,str(ex))

DIST=Path(__file__).resolve().parent.parent/'dist'
if DIST.is_dir(): app.mount('/',StaticFiles(directory=DIST,html=True),name='web')
