import asyncio, hashlib, re, time
from ..base import DynamicProvider
from ..models import *
from ..security import verified_apk, redact
from .gcloud_client import GCloudTestLabClient, classify_error
FTL_EXIT_MAP={0:DynamicJobStatus.COMPLETED,1:DynamicJobStatus.FAILED,2:DynamicJobStatus.FAILED,10:DynamicJobStatus.FAILED,15:DynamicJobStatus.INCONCLUSIVE,18:DynamicJobStatus.FAILED,19:DynamicJobStatus.CANCELLED,20:DynamicJobStatus.INCONCLUSIVE}
EXIT_ERRORS={1:'UNKNOWN',2:'APK_INCOMPATIBLE',10:'TEST_FAILED',15:'INFRASTRUCTURE_ERROR',18:'DEVICE_UNAVAILABLE',19:'CANCELLED',20:'INFRASTRUCTURE_ERROR'}
GAPS=['Full filesystem tracing: NOT_AVAILABLE','Syscall tracing: NOT_AVAILABLE','Full PCAP: NOT_AVAILABLE','Runtime memory dump: NOT_AVAILABLE','Frida instrumentation: NOT_AVAILABLE','Robo exploration is limited; authentication-required and unvisited paths may not be reached.','Behavior not observed during this execution is not evidence of absence.','Network and permission behavior require explicit evidence; reference metadata alone is insufficient.']
SOURCE='FIREBASE_TEST_LAB'

def validation_error(data):
    if data.get('state')!='INVALID':return None
    reasons=[data.get('invalidMatrixDetails')]+[d.get('reason') for d in data.get('extendedInvalidMatrixDetails',[]) if isinstance(d,dict)]
    for reason in reasons:
        if reason=='SERVICE_NOT_ACTIVATED':return DynamicError('API_DISABLED','Firebase validation failed: required Cloud Testing or Cloud Tool Results API is disabled. Enable both APIs in the configured project; no Robo execution occurred.')
        if reason=='TEST_QUOTA_EXCEEDED':return DynamicError('QUOTA_EXCEEDED','Firebase validation failed: test quota is unavailable; no Robo execution occurred.')
        if reason=='UNKNOWN_PERMISSION_ERROR':return DynamicError('PERMISSION_DENIED','Firebase validation failed: project permissions were denied; no Robo execution occurred.')
        if reason in ('MALFORMED_APK','NO_CODE_APK','INVALID_INPUT_APK','INVALID_APK_PREVIEW_SDK'):return DynamicError('APK_INCOMPATIBLE','Firebase validation rejected the APK; no Robo execution occurred.')
    return DynamicError('UPLOAD_FAILED','Firebase matrix validation failed before Robo execution. Inspect the existing matrix in the provider console; do not automatically re-upload.')

def catalog_tag_applies(tags, names, version):
    """Catalog tags may apply to a model or only named Android versions."""
    for tag in tags:
        name,sep,versions=str(tag).lower().partition('=')
        if name in names and (not sep or str(version) in versions.split(',')):
            return True
    return False

def select_device(devices,metadata,configured):
    if metadata.get('format')!='APK' or metadata.get('split_name') not in ('',None) or not metadata.get('package_name') or metadata.get('package_name')=='Unknown package':raise DynamicError('APK_INCOMPATIBLE','No compatible Firebase Test Lab device found: a standalone APK with parsed metadata is required')
    if configured.get('model') and not any(d['model']==configured['model'] for d in devices):raise DynamicError('DEVICE_UNAVAILABLE','Configured Firebase device is not currently available')
    min_sdk=metadata.get('min_sdk')
    if not isinstance(min_sdk,int):raise DynamicError('APK_INCOMPATIBLE','No compatible Firebase Test Lab device found: minSdk compatibility is unknown')
    target_sdk=metadata.get('target_sdk')
    if not isinstance(target_sdk,int) or target_sdk<1 or min_sdk<1:raise DynamicError('APK_INCOMPATIBLE','No compatible Firebase Test Lab device found: targetSdk compatibility is unknown')
    abis=set(metadata.get('supported_abis',[])); candidates=[]
    for device in devices:
        if device.get('deprecated') or device.get('unstable'):continue
        if configured.get('model') and device['model']!=configured['model']:continue
        if not configured.get('model') and device.get('form')!='VIRTUAL':continue
        if configured.get('version') and str(device['version'])!=str(configured['version']):continue
        if device.get('api_level',0)<min_sdk:continue
        # Android 14/15 installation floors, not Play Store submission requirements.
        if device['api_level']>=35 and target_sdk<24 or device['api_level']==34 and target_sdk<23:continue
        if abis and not abis.intersection(device.get('abis',[])):continue
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,99}',str(device.get('model',''))):continue
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,100}',str(device.get('version',''))):continue
        candidates.append(device)
    if not candidates:raise DynamicError('APK_INCOMPATIBLE','No compatible Firebase Test Lab device found; configured device may be unavailable or incompatible')
    selected=max(candidates,key=lambda d:(d['api_level'],d['model']))
    return {'model':selected['model'],'version':str(selected['version']),'android_version':str(selected['version']),'api_level':selected['api_level'],'locale':configured.get('locale','en'),'orientation':configured.get('orientation','portrait'),'form':selected['form']}

def matrix_status(data):
    state=data.get('state'); executions=data.get('testExecutions',[])
    if state=='FINISHED':return {'SUCCESS':DynamicJobStatus.COMPLETED,'FAILURE':DynamicJobStatus.FAILED,'INCONCLUSIVE':DynamicJobStatus.INCONCLUSIVE,'SKIPPED':DynamicJobStatus.NOT_RUN}.get(data.get('outcomeSummary'),DynamicJobStatus.INCONCLUSIVE)
    if state=='CANCELLED':return DynamicJobStatus.CANCELLED
    if state=='ERROR':return DynamicJobStatus.INCONCLUSIVE
    if state=='INVALID':return DynamicJobStatus.FAILED
    if state=='PENDING' or any(e.get('state')=='PENDING' for e in executions):return DynamicJobStatus.QUEUED
    if state in ('RUNNING','IN_PROGRESS'):return DynamicJobStatus.RUNNING
    if state in ('VALIDATING','VALIDATED','UNSUPPORTED_ENVIRONMENT'):return DynamicJobStatus.QUEUED if state!='UNSUPPORTED_ENVIRONMENT' else DynamicJobStatus.NOT_RUN
    return DynamicJobStatus.QUEUED

class FirebaseTestLabProvider(DynamicProvider):
    id='firebase_test_lab';adapter_version='1.0'
    def __init__(self,config,client=None):self.config=config;self.settings=config['firebase_test_lab'];self.client=client or GCloudTestLabClient()
    async def discover_devices(self):
        project=self.settings['project_id']
        if not project:raise DynamicError('PROJECT_NOT_FOUND','Google Cloud project ID is missing')
        models=await asyncio.to_thread(self.client.models,project);versions=await asyncio.to_thread(self.client.versions,project)
        if not isinstance(models,list) or not isinstance(versions,list):raise DynamicError('RESULT_COLLECTION_FAILED','Device catalog has unexpected structure')
        version_map={str(v['id']):v for v in versions if isinstance(v,dict) and 'id' in v}
        devices=[]
        for model in models:
            tags=[str(t).lower() for t in model.get('tags',[])]
            for version in model.get('supportedVersionIds',[]):
                v=version_map.get(str(version),{});vt=[str(t).lower() for t in v.get('tags',[])]
                try:api=int(v.get('apiLevel',version))
                except (TypeError,ValueError):continue
                devices.append({'model':model.get('id',''),'name':model.get('name',''),'version':str(version),'api_level':api,'form':model.get('form','UNKNOWN'),'abis':model.get('supportedAbis',[]),'deprecated':catalog_tag_applies(tags+vt,{'deprecated'},version),'unstable':catalog_tag_applies(tags+vt,{'beta','preview','reduced_stability'},version)})
        return devices
    async def health_check(self):
        checks={'gcloud installed':False,'authenticated':False,'project configured':bool(self.settings['project_id']),'project accessible':False,'Cloud Testing API enabled':False,'Cloud Tool Results API enabled':False,'Test Lab accessible':False,'available devices':False}
        health=DynamicProviderStatus(self.id,ProviderState.NOT_CONFIGURED,checks,enabled=self.config['enabled'],timeout_seconds=self.settings['timeout_seconds'])
        checks['gcloud installed']=self.client.installed()
        if not checks['gcloud installed']:health.error=DynamicError('GCLOUD_MISSING','gcloud missing');return health
        try:
            checks['authenticated']=await asyncio.to_thread(self.client.authenticated)
            if not checks['authenticated']:raise DynamicError('AUTH_ERROR','gcloud is not authenticated; run gcloud auth login')
            if not checks['project configured']:health.error=DynamicError('PROJECT_NOT_FOUND','Google Cloud project ID is missing');return health
            checks['project accessible']=await asyncio.to_thread(self.client.project_exists,self.settings['project_id'])
            if not checks['project accessible']:raise DynamicError('PROJECT_NOT_FOUND','Configured project was not found')
            services=await asyncio.to_thread(self.client.enabled_services,self.settings['project_id'])
            checks['Cloud Testing API enabled']='testing.googleapis.com' in services
            checks['Cloud Tool Results API enabled']='toolresults.googleapis.com' in services
            missing=[name for name in ('testing.googleapis.com','toolresults.googleapis.com') if name not in services]
            if missing:raise DynamicError('API_DISABLED','Required Google APIs are disabled: '+', '.join(missing)+'. Enable these APIs before uploading an APK.')
            health.devices=await self.discover_devices();checks['Test Lab accessible']=True
            checks['available devices']=any(d['form']=='VIRTUAL' and not d['deprecated'] and not d['unstable'] for d in health.devices)
            if self.settings['device'].get('model') or self.settings['device'].get('version'):
                select_device(health.devices,{'format':'APK','package_name':'configuration.probe','min_sdk':1,'target_sdk':35,'supported_abis':[]},self.settings['device'])
            if not checks['available devices']:raise DynamicError('DEVICE_UNAVAILABLE','No usable virtual Android devices are available')
            health.status=ProviderState.READY if self.config['enabled'] else ProviderState.NOT_CONFIGURED
            if not self.config['enabled']:health.error=DynamicError('DISABLED','Dynamic analysis is disabled; enable it in configuration')
        except DynamicError as error:
            health.error=error;health.status=ProviderState.DEGRADED if error.code=='QUOTA_EXCEEDED' else ProviderState.UNAVAILABLE
            if error.code=='QUOTA_EXCEEDED':health.quota_status='EXHAUSTED'
        return health
    async def prepare(self,request):
        return select_device(await self.discover_devices(),request.metadata,self.settings['device'])
    async def submit(self,request):
        path=verified_apk(request)
        if not self.config['enabled']:raise DynamicError('DISABLED','Dynamic analysis is disabled')
        device=await self.prepare(request)
        label='APKTrust-'+re.sub(r'[^A-Za-z0-9_-]','',request.scan_id)[:48]
        code,data,stderr=await asyncio.to_thread(self.client.submit,self.settings['project_id'],path,device,self.settings['timeout_seconds'],label,self.settings['collect']['video'])
        remote=data.get('testMatrixId')
        if code and not remote and code in (10,15,18,19,20):
            error=DynamicError(EXIT_ERRORS[code],'Firebase returned exit code '+str(code));error.job_status=FTL_EXIT_MAP[code];raise error
        if not remote or not re.fullmatch(r'[A-Za-z0-9_-]{1,200}',remote):
            error=classify_error(code,stderr) if code else DynamicError('UPLOAD_FAILED','Submission returned no matrix identifier; do not automatically retry because a remote job may exist')
            if code in EXIT_ERRORS and error.code=='UNKNOWN':error=DynamicError(EXIT_ERRORS[code],'Firebase submission did not complete')
            error.job_status=FTL_EXIT_MAP.get(code,DynamicJobStatus.FAILED) if code else DynamicJobStatus.INCONCLUSIVE
            raise error
        job=DynamicJob(request.job_id,request.scan_id,self.id,matrix_status(data),remote,device,time.time(),time.time(),uploaded_sha256=request.sha256,stage='Queued by Firebase',audit={'project':self.settings['project_id'],'test_type':'robo','test_timeout_seconds':self.settings['timeout_seconds'],'job_timeout_seconds':self.settings['job_timeout_seconds'],'adapter_version':self.adapter_version,'transport_version':self.client.adapter_version,'auto_google_login':False})
        job.error=validation_error(data)
        job.provider_result_url=self._url(data)
        return job
    @staticmethod
    def _url(data):
        url=data.get('resultStorage',{}).get('resultsUrl')
        return url if isinstance(url,str) and re.fullmatch(r'https://console\.firebase\.google\.com/[^\s<>\"]+',url) else None
    async def get_status(self,job):
        data=await asyncio.to_thread(self.client.matrix,job.audit['project'],job.remote_job_id)
        job.status=matrix_status(data);job.provider_result_url=self._url(data) or job.provider_result_url
        job.stage='Running Robo test' if job.status==DynamicJobStatus.RUNNING else 'Queued by Firebase'
        if job.status in TERMINAL:
            job.completed_at=time.time();job.stage='Collecting results'
            if job.status!=DynamicJobStatus.COMPLETED:
                code='TEST_FAILED' if job.status==DynamicJobStatus.FAILED else 'INFRASTRUCTURE_ERROR' if job.status==DynamicJobStatus.INCONCLUSIVE else 'DEVICE_UNAVAILABLE' if job.status==DynamicJobStatus.NOT_RUN else 'CANCELLED'
                job.error=validation_error(data) or DynamicError(code,'Firebase execution did not complete successfully; dynamic verification has gaps')
        return job
    async def cancel(self,job):
        if job.remote_job_id:await asyncio.to_thread(self.client.cancel,job.audit['project'],job.remote_job_id)
        # A cancel response is a request, not proof the remote execution stopped.
        job.stage='Cancellation requested';return job
    async def collect_results(self,job):
        data=await asyncio.to_thread(self.client.matrix,job.audit['project'],job.remote_job_id)
        result=DynamicResult(self.id,job.id,matrix_status(data),job.started_at,time.time(),job.device,analysis_gaps=list(GAPS))
        result.provider_metadata={'remote_job_id':job.remote_job_id,'result_url':self._url(data),'outcome':data.get('outcomeSummary','UNKNOWN'),'execution_count':len(data.get('testExecutions',[]))}
        error=validation_error(data)
        if error:
            job.error=error;result.analysis_gaps.append(error.message)
            result.provider_metadata['validation_error_code']=error.code
        root=data.get('resultStorage',{}).get('googleCloudStorage',{}).get('gcsPath')
        catalog_failed=False
        if root:
            try:
                objects,truncated=await asyncio.to_thread(self.client.objects,root)
                if truncated:result.analysis_gaps.append('Artifact catalog exceeded 10,000 objects; listing is partial.')
                bucket,prefix=self.client.gcs_parts(root)
                for item in objects:
                    name=item.get('name','')
                    if not name.startswith(prefix.rstrip('/')+'/'):continue
                    lower=name.lower();kind='screenshot' if lower.endswith(('.png','.jpg','.jpeg')) else 'video' if lower.endswith(('.mp4','.webm')) else 'logcat' if 'logcat' in lower else 'log' if lower.endswith(('.log','.txt')) else 'execution_result' if lower.endswith(('.xml','.json')) else None
                    if not kind:continue
                    flag='screenshots' if kind=='screenshot' else 'video' if kind=='video' else 'logs'
                    if not self.settings['collect'][flag]:continue
                    uri='gs://'+bucket+'/'+name
                    try:size=int(item.get('size',0))
                    except (TypeError,ValueError):size=None
                    result.artifacts.append(DynamicArtifact(hashlib.sha256(uri.encode()).hexdigest()[:16],kind,uri,status=ArtifactStatus.AVAILABLE,size=size,content_type=item.get('contentType'),evidence_source=SOURCE))
            except DynamicError:catalog_failed=True;result.analysis_gaps.append('Remote artifact metadata could not be fetched.');result.artifacts.append(DynamicArtifact('catalog-error','catalog',root,status=ArtifactStatus.FAILED_TO_FETCH,evidence_source=SOURCE))
        else:result.analysis_gaps.append('Firebase did not return a result storage reference.')
        for kind,flag in [('logcat','logs'),('screenshot','screenshots'),('video','video')]:
            if not any(a.type==kind for a in result.artifacts):result.artifacts.append(DynamicArtifact('missing-'+kind,kind,status=(ArtifactStatus.FAILED_TO_FETCH if catalog_failed else ArtifactStatus.MISSING) if self.settings['collect'][flag] else ArtifactStatus.NOT_SUPPORTED,evidence_source=SOURCE))
        # Tool Results issues are structured evidence; never infer permissions/crashes from filenames.
        durations=[]
        for execution in data.get('testExecutions',[])[:20]:
            ref=execution.get('toolResultsStep')
            if not ref:result.analysis_gaps.append('An execution has no Tool Results metadata.');continue
            try:step=await asyncio.to_thread(self.client.step,ref)
            except DynamicError:result.analysis_gaps.append('Tool Results execution metadata could not be fetched.');continue
            durations.append(step.get('runDuration',{}))
            for issue in step.get('testExecutionStep',{}).get('testIssues',[])[:200]:
                category=issue.get('category','UNKNOWN');kind='APP_CRASHED' if category in ('APP_CRASH','APP_CRASHED','CRASH') else 'TEST_FAILURE'
                result.observations.append(DynamicObservation('obs-'+str(len(result.observations)+1),kind,redact(str(issue.get('errorMessage') or category))[:1000],execution.get('timestamp'),SOURCE,'DYNAMIC_FIREBASE',{'category':category,'severity':issue.get('severity','UNKNOWN')}))
        result.provider_metadata['run_durations']=durations
        if result.status==DynamicJobStatus.COMPLETED:
            result.observations.append(DynamicObservation('robo-completed','ROBO_INTERACTION','Firebase reports the Robo execution completed; explored screens and paths are not established by this summary.',evidence_source=SOURCE,source_label='DYNAMIC_FIREBASE'))
        elif not result.observations:
            result.observations.append(DynamicObservation('execution-outcome','TEST_FAILURE','Firebase execution outcome: '+result.status,evidence_source=SOURCE,source_label='DYNAMIC_FIREBASE'))
        result.analysis_gaps=list(dict.fromkeys(result.analysis_gaps))
        return result
    async def read_artifact(self,artifact,offset=0,limit=65536):
        return await asyncio.to_thread(self.client.artifact,artifact.remote_uri,offset,limit)
