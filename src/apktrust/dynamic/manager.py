"""Generic orchestration, durable jobs, cross-process locking and opt-in artifact access."""
import asyncio, fcntl, hashlib, json, os, threading, time, uuid
from pathlib import Path
from .config import load_config
from .models import *
from .store import DynamicStore
from .security import verified_apk, redact
from .providers.firebase_test_lab import FirebaseTestLabProvider
PROVIDERS={'firebase_test_lab':FirebaseTestLabProvider}
STAGES={DynamicJobStatus.UPLOADING:'Uploading',DynamicJobStatus.QUEUED:'Queued by provider',DynamicJobStatus.RUNNING:'Running remote test'}
class DynamicManager:
    def __init__(self,root,data,get_scan,registry=None,poll_seconds=5):
        self.root=Path(root);self.workspace=Path(data)/'dynamic';self.workspace.mkdir(parents=True,exist_ok=True,mode=0o700)
        self.store=DynamicStore(Path(data)/'scans.sqlite3');self.get_scan=get_scan;self.registry=registry or PROVIDERS;self.poll_seconds=poll_seconds
        self.threads={};self.health_cache=None;self.gate=threading.BoundedSemaphore(2)
    def provider(self,config=None,name=None):
        cfg=config or load_config(self.root);name=name or cfg['provider']
        if name not in self.registry:raise DynamicError('UNKNOWN','Unknown dynamic provider')
        return self.registry[name](cfg)
    def health(self,refresh=False):
        cfg=load_config(self.root);key=json.dumps(cfg,sort_keys=True)
        if not refresh and self.health_cache and self.health_cache[0]==key and time.time()-self.health_cache[1]<60:return self.health_cache[2]
        result=serial(asyncio.run(self.provider(cfg).health_check()));self.health_cache=(key,time.time(),result);return result
    def metadata(self,scan):return {'package_name':scan.get('package'),'min_sdk':scan.get('min_sdk'),'target_sdk':scan.get('target_sdk'),'supported_abis':scan.get('supported_abis',[]),'format':scan.get('format'),'split_name':scan.get('split_name')}
    def input_path(self,scan_id):
        import re
        if not re.fullmatch(r'[a-f0-9]{12}',scan_id):raise DynamicError('APK_INCOMPATIBLE','Invalid scan identifier')
        return self.workspace.resolve()/'inputs'/scan_id/'app.apk'
    def request(self,scan,job_id='',consent=False):return DynamicRequest(scan['id'],str(self.input_path(scan['id'])),str(self.workspace),scan['sha256'],self.metadata(scan),consent,job_id)
    def attach(self,scan,source):
        # Called only for local retention/re-attachment, never calls any remote transport.
        if scan.get('format')!='APK':raise DynamicError('APK_INCOMPATIBLE','Cloud Robo MVP requires a standalone APK; XAPK/APKS installation is not supported')
        digest=hashlib.sha256()
        with open(source,'rb') as f:
            for block in iter(lambda:f.read(1024*1024),b''):digest.update(block)
        if digest.hexdigest()!=scan['sha256']:raise DynamicError('APK_INCOMPATIBLE','Selected APK does not match this scan SHA-256')
        target=self.input_path(scan['id']);target.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        if target.parent.resolve()!=target.parent or target.is_symlink():raise DynamicError('APK_INCOMPATIBLE','Unsafe artifact workspace')
        import shutil, tempfile
        fd,temp=tempfile.mkstemp(dir=target.parent)
        try:
            with os.fdopen(fd,'wb') as dst,open(source,'rb') as src:shutil.copyfileobj(src,dst,1024*1024)
            os.chmod(temp,0o600);os.replace(temp,target)
        finally:Path(temp).unlink(missing_ok=True)
        verified_apk(self.request(scan,consent=True))
    def has_input(self,scan):
        try:verified_apk(self.request(scan,consent=True));return True
        except DynamicError:return False
    def start(self,scan_id,provider,consent):
        if consent is not True:raise DynamicError('UPLOAD_FAILED','Cloud upload requires explicit --confirm-cloud-upload or checked UI consent')
        scan=self.get_scan(scan_id)
        if not scan:raise DynamicError('APK_INCOMPATIBLE','Scan not found or cleared from history')
        cfg=load_config(self.root)
        if not cfg['enabled']:raise DynamicError('DISABLED','Enable dynamic analysis in dynamic-config.json or APKTRUST_DYNAMIC_ENABLED')
        self.provider(cfg,provider);verified_apk(self.request(scan,consent=True))
        settings=cfg.get(provider,{})
        id=uuid.uuid4().hex;job=DynamicJob(id,scan_id,provider,created_at=time.time(),uploaded_sha256=scan['sha256'],audit={'apktrust_version':'0.4.0','consent_at':time.time(),'test_timeout_seconds':settings.get('timeout_seconds'),'job_timeout_seconds':settings.get('job_timeout_seconds')})
        self.event(job,'Preparing APK');self.store.create(job,cfg,time.time());self.launch(id);return serial(job)
    def event(self,job,stage):
        job.stage=stage
        if not job.events or job.events[-1]['stage']!=stage:job.events.append({'timestamp':time.time(),'stage':stage,'status':job.status})
        job.events=job.events[-200:]
    def launch(self,id):
        if self.threads.get(id) and self.threads[id].is_alive():return
        thread=threading.Thread(target=self._work,args=(id,),daemon=True);self.threads[id]=thread;thread.start()
    def resume(self):
        for data in self.store.list():
            if DynamicJobStatus(data['status']) not in TERMINAL:self.launch(data['id'])
    def _work(self,id):
        locks=self.workspace/'locks';locks.mkdir(exist_ok=True)
        with (locks/(id+'.lock')).open('a') as guard:
            try:fcntl.flock(guard,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:return
            with self.gate:asyncio.run(self._execute(id))
    async def _execute(self,id):
        job=self.store.get(id)
        if not job or job.status in TERMINAL:return
        cfg=self.store.config(id);provider=self.provider(cfg,job.provider)
        try:
            if not job.remote_job_id:
                # On restart an UPLOADING job may already exist remotely: never repeat its upload.
                if job.status!=DynamicJobStatus.PENDING:raise DynamicError('UPLOAD_FAILED','Submission was interrupted without a remote identifier; check the provider console before manually retrying')
                scan=self.get_scan(job.scan_id)
                if not scan:raise DynamicError('APK_INCOMPATIBLE','Scan no longer available')
                self.event(job,'Selecting device');self.store.save(job)
                health=await provider.health_check()
                if health.status!=ProviderState.READY:raise health.error or DynamicError('UNAVAILABLE','Dynamic provider is not ready')
                job.device=await provider.prepare(self.request(scan,id,True));self.store.save(job)
                job.status=DynamicJobStatus.UPLOADING;job.started_at=time.time();self.event(job,'Uploading APK and awaiting provider validation');self.store.save(job)
                submitted=await provider.submit(self.request(scan,id,True))
                submitted.provider=job.provider;submitted.uploaded_sha256=job.uploaded_sha256;submitted.created_at=job.created_at;submitted.started_at=job.started_at;submitted.audit.update(job.audit);submitted.events=job.events;job=submitted
                self.event(job,'Queued by provider');self.store.save(job)
            deadline=job.created_at+cfg.get(job.provider,{}).get('job_timeout_seconds',900)
            while job.status not in TERMINAL:
                if time.time()>deadline:
                    try:await provider.cancel(job)
                    except DynamicError:pass
                    job.status=DynamicJobStatus.TIMED_OUT;raise DynamicError('TEST_TIMEOUT','APKTrust job deadline reached; remote cancellation requested but may need verification in provider console')
                current=self.store.get(id)
                if current and current.stage=='Cancellation requested':
                    job.stage=current.stage
                job=await provider.get_status(job);self.event(job,STAGES.get(job.status,'Collecting results'));self.store.save(job)
                if job.status not in TERMINAL:await asyncio.sleep(self.poll_seconds)
            terminal=job.status;job.status=DynamicJobStatus.COLLECTING;self.event(job,'Collecting results');self.store.save(job)
            self.event(job,'Downloading metadata');self.store.save(job)
            result=await asyncio.wait_for(provider.collect_results(job),timeout=max(1,min(180,deadline-time.time())));job.status=result.status;job.completed_at=time.time()
            result.provider_metadata['audit']={**{k:v for k,v in job.audit.items() if k in ('project','test_type','test_timeout_seconds','job_timeout_seconds','adapter_version','transport_version','auto_google_login','apktrust_version','consent_at')},'uploaded_sha256':job.uploaded_sha256,'remote_job_id':job.remote_job_id,'submission_timestamp':job.started_at,'completion_timestamp':job.completed_at}
            self.event(job,'Correlating evidence');self.store.save(job)
            self.event(job,'Completed' if job.status==DynamicJobStatus.COMPLETED else 'Completed with gaps');self.store.complete(job,result)
        except asyncio.TimeoutError:
            job.status=DynamicJobStatus.TIMED_OUT;job.error=DynamicError('TEST_TIMEOUT','Result collection deadline reached');job.completed_at=time.time();self.event(job,'Completed with gaps')
            self.store.complete(job,DynamicResult(job.provider,job.id,job.status,device=job.device,analysis_gaps=[job.error.message,'Static analysis remains valid.']))
        except DynamicError as error:
            if job.status!=DynamicJobStatus.TIMED_OUT:job.status=DynamicJobStatus.TIMED_OUT if error.code=='TEST_TIMEOUT' else getattr(error,'job_status',DynamicJobStatus.NOT_RUN if error.code in ('APK_INCOMPATIBLE','DEVICE_UNAVAILABLE','DISABLED','AUTH_ERROR','GCLOUD_MISSING','PROJECT_NOT_FOUND') else DynamicJobStatus.INCONCLUSIVE)
            job.error=DynamicError(error.code,error.message);job.completed_at=time.time();self.event(job,'Execution not started' if job.status==DynamicJobStatus.NOT_RUN else 'Completed with gaps')
            result=DynamicResult(job.provider,job.id,job.status,job.started_at,job.completed_at,job.device,analysis_gaps=[error.message,'Dynamic verification was not completed. Static analysis remains valid.'])
            self.store.complete(job,result)
        except Exception:
            job.status=DynamicJobStatus.INCONCLUSIVE;job.error=DynamicError('UNKNOWN','Unexpected provider error; no runtime conclusion can be drawn');job.completed_at=time.time();self.event(job,'Completed with gaps')
            self.store.complete(job,DynamicResult(job.provider,job.id,job.status,analysis_gaps=[job.error.message,'Static analysis remains valid.']))
    def cancel(self,id,scan_id):
        job=self.store.get(id)
        if not job or job.scan_id!=scan_id:raise DynamicError('UNKNOWN','Dynamic job not found for this scan')
        if job.status in TERMINAL:return serial(job)
        if not job.remote_job_id:raise DynamicError('UPLOAD_FAILED','Submission is in progress; cancel after the remote identifier is recorded')
        provider=self.provider(self.store.config(id),job.provider);job=asyncio.run(provider.cancel(job));job.audit['cancellation_requested_at']=time.time();self.event(job,'Cancellation requested');self.store.save(job);return serial(job)
    def detail(self,scan_id):
        scan=self.get_scan(scan_id)
        if not scan:raise DynamicError('UNKNOWN','Scan not found')
        jobs=self.store.list(scan_id)
        return {'jobs':jobs,'retained_apk':self.has_input(scan),'results':{j['id']:self.store.result(j['id']) for j in jobs if self.store.result(j['id'])}}
    def read_artifact(self,scan_id,job_id,artifact_id,offset=0,limit=65536):
        job=self.store.get(job_id);result=self.store.result(job_id)
        if not self.get_scan(scan_id) or not job or job.scan_id!=scan_id or not result:raise DynamicError('UNKNOWN','Artifact not found for this scan')
        data=next((a for a in result['artifacts'] if a['id']==artifact_id),None)
        if not data or data['status']!='AVAILABLE':raise DynamicError('RESULT_COLLECTION_FAILED','Artifact is unavailable')
        artifact=DynamicArtifact(**data)
        if artifact.type=='video':raise DynamicError('RESULT_COLLECTION_FAILED','Video downloads are not automatic; use the authenticated provider console')
        if artifact.type=='screenshot':
            if offset or (artifact.size is not None and artifact.size>8*1024*1024):raise DynamicError('RESULT_COLLECTION_FAILED','Screenshot exceeds 8 MiB preview limit')
            limit=8*1024*1024
        else:limit=min(max(limit,1),65536);offset=max(offset,0)
        raw=asyncio.run(self.provider(self.store.config(job_id),job.provider).read_artifact(artifact,offset,limit))
        source_bytes=len(raw)
        if artifact.type in ('logcat','log','execution_result'):raw=redact(raw.decode('utf-8','replace')).encode()
        return artifact,raw,source_bytes
