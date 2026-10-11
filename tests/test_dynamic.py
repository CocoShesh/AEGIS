import asyncio, copy, hashlib, json, os, sqlite3, sys, tempfile, time, unittest
from pathlib import Path
from unittest.mock import Mock, patch
from test_scanner import scanner, MANIFEST
from apktrust.dynamic.models import *
from apktrust.dynamic.config import load_config, DEFAULT
from apktrust.dynamic.security import run_command, verified_apk, CommandResult, redact
from apktrust.dynamic.providers.firebase_test_lab import FirebaseTestLabProvider, select_device, matrix_status, FTL_EXIT_MAP
from apktrust.dynamic.providers.gcloud_client import GCloudTestLabClient, classify_error
from apktrust.dynamic.manager import DynamicManager
from apktrust.dynamic.correlation import correlate

MODEL={'id':'available-virtual','name':'Available device','form':'VIRTUAL','supportedVersionIds':['30','35'],'supportedAbis':['x86_64','arm64-v8a'],'tags':[]}
VERSIONS=[{'id':'30','apiLevel':30},{'id':'35','apiLevel':35}]
META={'package_name':'org.test.app','format':'APK','split_name':'','min_sdk':23,'target_sdk':35,'supported_abis':[]}
def config():
    c=copy.deepcopy(DEFAULT);c['enabled']=True;c['firebase_test_lab']['project_id']='test-project';return c
def client():
    c=Mock();c.adapter_version='mock';c.installed.return_value=True;c.authenticated.return_value=True;c.project_exists.return_value=True;c.enabled_services.return_value={'testing.googleapis.com','toolresults.googleapis.com'};c.models.return_value=[MODEL];c.versions.return_value=VERSIONS;return c
def devices():return [{'model':MODEL['id'],'version':v['id'],'api_level':v['apiLevel'],'form':'VIRTUAL','abis':MODEL['supportedAbis'],'deprecated':False,'unstable':False} for v in VERSIONS]

class HealthTests(unittest.TestCase):
    def health(self,c,cfg=None):return asyncio.run(FirebaseTestLabProvider(cfg or config(),c).health_check())
    def test_absent(self):
        c=client();c.installed.return_value=False;h=self.health(c);self.assertEqual(h.status,ProviderState.NOT_CONFIGURED);self.assertEqual(h.error.code,'GCLOUD_MISSING');c.models.assert_not_called()
    def test_ready(self):
        h=self.health(client());self.assertEqual(h.status,ProviderState.READY);self.assertTrue(all(h.checks.values()));self.assertEqual(h.quota_status,'UNKNOWN');self.assertEqual(len(h.devices),2)
    def test_catalog_access_does_not_imply_enabled_execution_apis(self):
        c=client();c.enabled_services.return_value={'testing.googleapis.com'}
        h=self.health(c);self.assertEqual(h.status,ProviderState.UNAVAILABLE);self.assertEqual(h.error.code,'API_DISABLED')
        self.assertIn('toolresults.googleapis.com',h.error.message);c.models.assert_not_called()
    def test_not_authenticated(self):
        c=client();c.authenticated.return_value=False;h=self.health(c);self.assertEqual(h.status,ProviderState.UNAVAILABLE);self.assertEqual(h.error.code,'AUTH_ERROR')
    def test_project_missing(self):
        cfg=config();cfg['firebase_test_lab']['project_id']=None;h=self.health(client(),cfg);self.assertEqual(h.status,ProviderState.NOT_CONFIGURED)
    def test_project_not_found(self):
        c=client();c.project_exists.side_effect=DynamicError('PROJECT_NOT_FOUND','Project missing');self.assertEqual(self.health(c).error.code,'PROJECT_NOT_FOUND')
    def test_permission_denied(self):
        c=client();c.models.side_effect=DynamicError('PERMISSION_DENIED','denied');self.assertEqual(self.health(c).error.code,'PERMISSION_DENIED')
    def test_api_disabled(self):
        c=client();c.models.side_effect=DynamicError('API_DISABLED','disabled');self.assertEqual(self.health(c).error.code,'API_DISABLED')
    def test_network_failure(self):
        c=client();c.models.side_effect=DynamicError('NETWORK_ERROR','failed');self.assertEqual(self.health(c).error.code,'NETWORK_ERROR')
    def test_quota_degraded(self):
        c=client();c.models.side_effect=DynamicError('QUOTA_EXCEEDED','quota');h=self.health(c);self.assertEqual(h.status,ProviderState.DEGRADED);self.assertEqual(h.quota_status,'EXHAUSTED')
    def test_no_devices(self):
        c=client();c.models.return_value=[];self.assertEqual(self.health(c).error.code,'DEVICE_UNAVAILABLE')
    def test_disabled_remains_optional(self):
        cfg=config();cfg['enabled']=False;self.assertEqual(self.health(client(),cfg).status,ProviderState.NOT_CONFIGURED)

class DeviceTests(unittest.TestCase):
    def test_live_catalog_arm_ids_are_valid_and_preview_is_skipped(self):
        c=client();c.models.return_value=[dict(MODEL,id='MediumPhone.arm',supportedVersionIds=['35','36','37'],supportedAbis=['arm64-v8a'],tags=['preview=37']),dict(MODEL,id='MediumTablet.arm',tags=['deprecated=30'])]
        c.versions.return_value=VERSIONS+[{'id':'36','apiLevel':36},{'id':'37','apiLevel':37}]
        catalog=asyncio.run(FirebaseTestLabProvider(config(),c).discover_devices())
        chosen=select_device(catalog,dict(META,min_sdk=26,target_sdk=36,supported_abis=['arm64-v8a','x86_64']),{})
        self.assertEqual((chosen['model'],chosen['version']),('MediumPhone.arm','36'))
        self.assertTrue(next(d for d in catalog if d['version']=='37')['unstable'])
        self.assertFalse(next(d for d in catalog if d['model']=='MediumTablet.arm' and d['version']=='35')['deprecated'])
    def test_catalog_model_injection_is_rejected(self):
        for model in ['model,version=99','$(command)',';rm -rf','../device','-flag','']:
            with self.assertRaises(DynamicError):select_device([dict(devices()[0],model=model)],META,{})
    def test_configured_available(self):self.assertEqual(select_device(devices(),META,{'model':MODEL['id'],'version':'30'})['version'],'30')
    def test_configured_unavailable(self):
        with self.assertRaises(DynamicError) as error:select_device(devices(),META,{'model':'missing'})
        self.assertEqual(error.exception.code,'DEVICE_UNAVAILABLE')
    def test_fallback_latest_virtual(self):self.assertEqual(select_device(devices(),META,{})['version'],'35')
    def test_no_compatible_sdk(self):
        with self.assertRaises(DynamicError):select_device(devices(),dict(META,min_sdk=99),{})
    def test_unknown_compatibility(self):
        with self.assertRaises(DynamicError):select_device(devices(),dict(META,min_sdk=None),{})
    def test_low_target_sdk_falls_back(self):self.assertEqual(select_device(devices(),dict(META,target_sdk=22),{})['version'],'30')
    def test_unknown_target_sdk_not_run(self):
        with self.assertRaises(DynamicError):select_device(devices(),dict(META,target_sdk=None),{})
    def test_abi_mismatch(self):
        with self.assertRaises(DynamicError):select_device(devices(),dict(META,supported_abis=['mips']),{})
    def test_no_split_or_container(self):
        for meta in [dict(META,format='XAPK'),dict(META,split_name='config.en')]:
            with self.assertRaises(DynamicError):select_device(devices(),meta,{})
    def test_deprecated_and_physical_skipped(self):
        ds=devices();ds[-1]['deprecated']=True;ds.append(dict(ds[0],model='physical',api_level=99,form='PHYSICAL'))
        self.assertEqual(select_device(ds,META,{})['version'],'30')

class ProviderTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.id='123456789abc';self.path=self.root/'inputs'/self.id/'app.apk';self.path.parent.mkdir(parents=True);self.path.write_bytes(b'apk fixture')
        self.request=DynamicRequest(self.id,str(self.path),str(self.root),hashlib.sha256(self.path.read_bytes()).hexdigest(),META,True,'a'*32)
    def tearDown(self):self.temp.cleanup()
    def test_submit_async_and_no_login(self):
        runner=Mock(return_value=CommandResult(0,json.dumps({'testMatrixId':'matrix-abc','state':'PENDING'}),''));cli=GCloudTestLabClient(runner)
        cli.models=Mock(return_value=[MODEL]);cli.versions=Mock(return_value=VERSIONS)
        job=asyncio.run(FirebaseTestLabProvider(config(),cli).submit(self.request));self.assertEqual(job.remote_job_id,'matrix-abc');self.assertEqual(job.device['version'],'35')
        args=runner.call_args.args[0];self.assertIn('--no-auto-google-login',args);self.assertIn('--async',args);self.assertNotIn('--environment-variables',args);self.assertEqual(args[args.index('--app')+1],str(self.path))
    def test_validation_diagnostic_recovers_existing_matrix_without_resubmission(self):
        runner=Mock(return_value=CommandResult(1,'','Matrix [matrix-existing] failed during validation.'))
        cli=GCloudTestLabClient(runner);cli.models=Mock(return_value=[MODEL]);cli.versions=Mock(return_value=VERSIONS)
        cli.matrix=Mock(return_value={'testMatrixId':'matrix-existing','state':'INVALID','invalidMatrixDetails':'SERVICE_NOT_ACTIVATED'})
        job=asyncio.run(FirebaseTestLabProvider(config(),cli).submit(self.request))
        self.assertEqual(job.remote_job_id,'matrix-existing');self.assertEqual(job.error.code,'API_DISABLED');self.assertEqual(runner.call_count,1)
    def test_matrix_recovery_read_failure_retains_identifier(self):
        cli=GCloudTestLabClient(Mock(return_value=CommandResult(1,'','Matrix [matrix-existing] failed during validation.')))
        cli.matrix=Mock(side_effect=DynamicError('NETWORK_ERROR','read unavailable'))
        code,data,_=cli.submit('p',self.path,{'model':'m','version':'35','locale':'en','orientation':'portrait'},300,'label',True)
        self.assertEqual(data['testMatrixId'],'matrix-existing');self.assertEqual(data['state'],'VALIDATING')
    def test_validation_failure_keeps_reason_in_results(self):
        c=client();c.matrix.return_value={'state':'INVALID','invalidMatrixDetails':'SERVICE_NOT_ACTIVATED'}
        job=DynamicJob('a'*32,self.id,'firebase_test_lab',remote_job_id='matrix-existing',audit={'project':'p'})
        result=asyncio.run(FirebaseTestLabProvider(config(),c).collect_results(job))
        self.assertEqual(job.error.code,'API_DISABLED');self.assertTrue(any('no Robo execution' in g for g in result.analysis_gaps))
    def test_exit_outcomes(self):
        for code,status in [(10,'FAILED'),(15,'INCONCLUSIVE'),(18,'FAILED'),(19,'CANCELLED'),(20,'INCONCLUSIVE')]:
            c=client();c.submit.return_value=(code,{},'')
            with self.assertRaises(DynamicError) as error:asyncio.run(FirebaseTestLabProvider(config(),c).submit(self.request))
            self.assertEqual(error.exception.job_status,status)
    def test_timeout(self):
        c=client();c.submit.side_effect=DynamicError('TEST_TIMEOUT','timeout')
        with self.assertRaises(DynamicError) as e:asyncio.run(FirebaseTestLabProvider(config(),c).submit(self.request))
        self.assertEqual(e.exception.code,'TEST_TIMEOUT')
    def test_no_matrix_never_claims_completed(self):
        c=client();c.submit.return_value=(0,{},'')
        with self.assertRaises(DynamicError) as e:asyncio.run(FirebaseTestLabProvider(config(),c).submit(self.request))
        self.assertEqual(e.exception.job_status,'INCONCLUSIVE')
    def test_status_normalization(self):
        for state,outcome,status in [('FINISHED','SUCCESS','COMPLETED'),('FINISHED','FAILURE','FAILED'),('FINISHED','INCONCLUSIVE','INCONCLUSIVE'),('FINISHED','SKIPPED','NOT_RUN'),('ERROR',None,'INCONCLUSIVE'),('CANCELLED',None,'CANCELLED'),('INVALID',None,'FAILED'),('PENDING',None,'QUEUED'),('RUNNING',None,'RUNNING')]:self.assertEqual(matrix_status({'state':state,'outcomeSummary':outcome}),status)
    def test_artifact_metadata_and_crash(self):
        c=client();c.matrix.return_value={'state':'FINISHED','outcomeSummary':'FAILURE','resultStorage':{'googleCloudStorage':{'gcsPath':'gs://bucket/results/job'},'resultsUrl':'https://console.firebase.google.com/project/test/testlab/results'},'testExecutions':[{'toolResultsStep':{'projectId':'p','historyId':'h','executionId':'e','stepId':'s'},'timestamp':'2026-10-11T00:00:00Z'}]}
        c.gcs_parts.side_effect=GCloudTestLabClient.gcs_parts;c.objects.return_value=([{'name':'results/job/device/logcat','size':'123'},{'name':'results/job/device/screen.png','size':'456'},{'name':'results/job/device/video.mp4','size':'10000000'}],False)
        c.step.return_value={'runDuration':{'seconds':'300'},'testExecutionStep':{'testIssues':[{'category':'APP_CRASH','errorMessage':'A crash','severity':'SEVERE'}]}}
        p=FirebaseTestLabProvider(config(),c);job=DynamicJob('a'*32,self.id,p.id,remote_job_id='matrix',audit={'project':'test-project'})
        r=asyncio.run(p.collect_results(job));self.assertEqual({a.type for a in r.artifacts},{'logcat','screenshot','video'});self.assertTrue(all(a.local_path is None for a in r.artifacts));self.assertEqual(r.observations[0].type,'APP_CRASHED');self.assertEqual(r.observations[0].evidence_source,'FIREBASE_TEST_LAB');c.artifact.assert_not_called();self.assertIn('Full PCAP: NOT_AVAILABLE',r.analysis_gaps)
    def test_missing_artifact_distinct_from_fetch_error(self):
        c=client();c.matrix.return_value={'state':'FINISHED','outcomeSummary':'SUCCESS'}
        r=asyncio.run(FirebaseTestLabProvider(config(),c).collect_results(DynamicJob('a',self.id,'firebase_test_lab',audit={'project':'p'},remote_job_id='m')))
        self.assertTrue(all(a.status=='MISSING' for a in r.artifacts))
    def test_consent_before_any_remote_operation(self):
        self.request.confirm_cloud_upload=False;c=client()
        with self.assertRaises(DynamicError):asyncio.run(FirebaseTestLabProvider(config(),c).submit(self.request))
        c.models.assert_not_called();c.submit.assert_not_called()

class SecurityTests(unittest.TestCase):
    def test_configured_arm_model_is_accepted(self):
        with tempfile.TemporaryDirectory() as temp,patch.dict(os.environ,{},clear=True):
            cfg=config();cfg['firebase_test_lab']['device']['model']='MediumPhone.arm'
            (Path(temp)/'dynamic-config.json').write_text(json.dumps({'dynamic':cfg}))
            self.assertEqual(load_config(temp)['firebase_test_lab']['device']['model'],'MediumPhone.arm')
    def test_untrusted_filenames_never_shell(self):
        for name in ['app;rm -rf.apk','$(command).apk',"'app'.apk",'../../app.apk']:
            runner=Mock(return_value=CommandResult(0,'{}',''));c=GCloudTestLabClient(runner);c.submit('project',Path('/tmp')/name,{'model':'model','version':'35','locale':'en','orientation':'portrait'},300,'APKTrust-safe',True)
            self.assertIsInstance(runner.call_args.args[0],list);self.assertIn(str(Path('/tmp')/name),runner.call_args.args[0])
    def test_real_shell_metacharacters_are_literal(self):
        text='$(touch /tmp/SHOULD_NOT_EXIST);rm -rf.apk'
        output=run_command([sys.executable,'-c','import sys;print(sys.argv[1])',text]);self.assertEqual(output.stdout.strip(),text)
    def test_runner_uses_shell_false_and_secret_env_removed(self):
        import subprocess
        real=subprocess.Popen;calls=[]
        def spy(*args,**kwargs):calls.append(kwargs);return real(*args,**kwargs)
        with patch('apktrust.dynamic.security.subprocess.Popen',side_effect=spy),patch.dict(os.environ,{'GROQ_API_KEY':'never-forward','APKTRUST_FTL_PROJECT_ID':'test'}):
            run_command([sys.executable,'-c','print("ok")'])
        self.assertFalse(calls[0]['shell']);self.assertNotIn('GROQ_API_KEY',calls[0]['env']);self.assertNotIn('APKTRUST_FTL_PROJECT_ID',calls[0]['env'])
    def test_cap_and_timeout(self):
        with self.assertRaises(DynamicError):run_command([sys.executable,'-c','print("x"*2000000)'])
        with self.assertRaises(DynamicError) as error:run_command([sys.executable,'-c','import time;time.sleep(2)'],timeout=.05)
        self.assertEqual(error.exception.code,'TEST_TIMEOUT')
    def test_path_escape_hash_and_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);path=root/'inputs'/'123456789abc'/'app.apk';path.parent.mkdir(parents=True);path.write_bytes(b'app');digest=hashlib.sha256(b'app').hexdigest()
            req=DynamicRequest('123456789abc',str(path),str(root),digest,META,True);self.assertEqual(verified_apk(req),path)
            req.apk_path=str(root/'../../app.apk')
            with self.assertRaises(DynamicError):verified_apk(req)
            req.apk_path=str(path);req.sha256='0'*64
            with self.assertRaises(DynamicError):verified_apk(req)
            req.sha256=digest;path.unlink();path.symlink_to(root/'outside.apk');(root/'outside.apk').write_bytes(b'app')
            with self.assertRaises(DynamicError):verified_apk(req)
    def test_config_injection_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            for value in ['model,version=99','$(command)',';rm -rf','../../device']:
                cfg=config();cfg['firebase_test_lab']['device']['model']=value;(Path(temp)/'dynamic-config.json').write_text(json.dumps({'dynamic':cfg}))
                with self.assertRaises(DynamicError):load_config(temp)
    def test_device_credentials_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            cfg=config();cfg['firebase_test_lab']['device']['password']='private';(Path(temp)/'dynamic-config.json').write_text(json.dumps({'dynamic':cfg}))
            with self.assertRaises(DynamicError):load_config(temp)
    def test_auto_login_cannot_be_enabled(self):
        with tempfile.TemporaryDirectory() as temp:
            cfg=config();cfg['firebase_test_lab']['no_auto_google_login']=False;(Path(temp)/'dynamic-config.json').write_text(json.dumps({'dynamic':cfg}))
            with self.assertRaises(DynamicError):load_config(temp)
    def test_env_blank_device_and_secret_exclusion(self):
        with tempfile.TemporaryDirectory() as temp,patch.dict(os.environ,{},clear=True):
            (Path(temp)/'.env').write_text('APKTRUST_FTL_DEVICE_MODEL=\nAPKTRUST_FTL_PROJECT_ID=test-project\nVT_API_KEY=private-secret\nAPKTRUST_DYNAMIC_ENABLED=true\n')
            cfg=load_config(temp);self.assertIsNone(cfg['firebase_test_lab']['device']['model']);self.assertNotIn('private-secret',json.dumps(cfg));self.assertTrue(cfg['enabled'])
    def test_error_redaction(self):
        self.assertNotIn('ya29.secret-token',redact('Authorization: Bearer ya29.secret-token'))
        e=classify_error(403,'secret-token private_key anything');self.assertNotIn('secret',e.message)
    def test_endpoint_and_redirect_boundary(self):
        c=GCloudTestLabClient()
        with self.assertRaises(DynamicError):c.request('attacker.invalid','/')
        with self.assertRaises(DynamicError):c.gcs_parts('https://attacker.invalid/results')

class FakeProvider:
    id='firebase_test_lab'
    uploads=0
    def __init__(self,cfg):self.cfg=cfg
    async def health_check(self):return DynamicProviderStatus(self.id,ProviderState.READY)
    async def prepare(self,request):return {'model':'mock-device','version':'35'}
    async def submit(self,request):
        type(self).uploads+=1
        return DynamicJob(request.job_id,request.scan_id,self.id,DynamicJobStatus.QUEUED,'matrix-mock',{'model':'mock-device','version':'35'},audit={'project':'test-project'})
    async def get_status(self,job):job.status=DynamicJobStatus.COMPLETED;return job
    async def collect_results(self,job):return DynamicResult(self.id,job.id,DynamicJobStatus.COMPLETED,device=job.device,analysis_gaps=['Mock limited coverage'])
    async def cancel(self,job):return job

class PersistenceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.data=self.root/'data';self.data.mkdir();self.scan={'id':'123456789abc','sha256':hashlib.sha256(b'app').hexdigest(),'package':'org.test.app','format':'APK','min_sdk':23,'findings':[],'permissions':[]}
        with sqlite3.connect(self.data/'scans.sqlite3') as c:c.execute('CREATE TABLE scans(id TEXT PRIMARY KEY,report TEXT)');c.execute('INSERT INTO scans VALUES (?,?)',(self.scan['id'],json.dumps(self.scan)))
        (self.root/'dynamic-config.json').write_text(json.dumps({'dynamic':config()}));self.registry={'firebase_test_lab':FakeProvider};FakeProvider.uploads=0
        self.manager=self.make();source=self.root/'source.apk';source.write_bytes(b'app');self.manager.attach(self.scan,source)
    def tearDown(self):
        for thread in self.manager.threads.values():thread.join(2)
        self.temp.cleanup()
    def make(self):return DynamicManager(self.root,self.data,lambda id:self.scan if id==self.scan['id'] else None,registry=self.registry,poll_seconds=.01)
    def wait(self,manager,id):
        for _ in range(200):
            if manager.store.result(id):return manager.store.get(id)
            time.sleep(.01)
        self.fail('Job did not complete')
    def test_end_to_end_durable_metadata(self):
        j=self.manager.start(self.scan['id'],'firebase_test_lab',True);job=self.wait(self.manager,j['id']);self.assertEqual(job.status,'COMPLETED');self.assertEqual(job.remote_job_id,'matrix-mock');self.assertEqual(job.uploaded_sha256,self.scan['sha256'])
        restored=self.make();self.assertEqual(restored.store.get(j['id']).device['model'],'mock-device');self.assertIsNotNone(restored.store.result(j['id']));self.assertEqual(FakeProvider.uploads,1)
        with sqlite3.connect(self.data/'scans.sqlite3') as c:report=json.loads(c.execute('SELECT report FROM scans').fetchone()[0])
        self.assertEqual(report['analysis_completion'],'COMPLETED_WITH_GAPS');self.assertNotIn('token',json.dumps(report))
    def test_resume_remote_does_not_upload(self):
        job=DynamicJob('b'*32,self.scan['id'],'firebase_test_lab',DynamicJobStatus.RUNNING,'matrix-existing',created_at=time.time(),uploaded_sha256=self.scan['sha256'],audit={'project':'test-project'})
        self.manager.store.create(job,config(),time.time());new=self.make();new.resume();self.wait(new,job.id);self.assertEqual(FakeProvider.uploads,0)
    def test_interrupted_upload_never_repeats(self):
        job=DynamicJob('c'*32,self.scan['id'],'firebase_test_lab',DynamicJobStatus.UPLOADING,created_at=time.time())
        self.manager.store.create(job,config(),time.time());new=self.make();new.resume();done=self.wait(new,job.id);self.assertEqual(done.status,'INCONCLUSIVE');self.assertEqual(FakeProvider.uploads,0)
    def test_no_consent_no_job(self):
        with self.assertRaises(DynamicError):self.manager.start(self.scan['id'],'firebase_test_lab',False)
        self.assertEqual(self.manager.store.list(),[])
    def test_no_static_failure_from_dynamic_error(self):
        class Broken(FakeProvider):
            async def health_check(self):return DynamicProviderStatus(self.id,ProviderState.UNAVAILABLE,error=DynamicError('AUTH_ERROR','Not authenticated'))
        self.manager.registry['firebase_test_lab']=Broken
        j=self.manager.start(self.scan['id'],'firebase_test_lab',True);job=self.wait(self.manager,j['id']);self.assertEqual(job.status,'NOT_RUN')
        self.assertEqual(job.stage,'Execution not started');self.assertEqual(job.audit['test_timeout_seconds'],300)
        self.assertEqual(self.manager.store.result(job.id)['coverage'],'NOT_RUN')
        with sqlite3.connect(self.data/'scans.sqlite3') as c:report=json.loads(c.execute('SELECT report FROM scans').fetchone()[0])
        self.assertEqual(report['findings'],[]);self.assertEqual(report['analysis_completion'],'COMPLETED_WITH_GAPS')
    def test_wrong_scan_cannot_access_artifact(self):
        with self.assertRaises(DynamicError):self.manager.read_artifact('bad','a'*32,'artifact')
    def test_replacement_provider_needs_no_database_changes(self):
        self.manager.registry['other_provider']=FakeProvider
        j=self.manager.start(self.scan['id'],'other_provider',True);self.assertEqual(self.wait(self.manager,j['id']).status,'COMPLETED');self.assertIsNotNone(self.manager.store.result(j['id']))

class CorrelationTests(unittest.TestCase):
    def test_not_run_is_not_limited_runtime_coverage(self):
        result=serial(DynamicResult('firebase_test_lab','job',DynamicJobStatus.NOT_RUN))
        report=correlate({'findings':[],'coverage':[{'name':'Dynamic sandbox'}]},result)
        self.assertEqual(result['coverage'],'NOT_RUN')
        self.assertEqual(report['dynamic_coverage']['status'],'NOT_RUN')
        self.assertNotIn('LIMITED',report['coverage'][0]['detail'])
    def test_support_and_contradiction_preserve_static(self):
        scan={'sha256':'hash','risk':'Review required','permissions':['android.permission.RECORD_AUDIO'],'findings':[{'id':'F-001','rule':'installer','origin':'Static','evidence':[{'id':'static'}],'confidence':'Low','status':'Needs review'}]}
        result=serial(DynamicResult('firebase_test_lab','job',DynamicJobStatus.COMPLETED,device={'model':'virtual'},observations=[DynamicObservation('1','ACTIVITY_OBSERVED','Installer UI observed',evidence_source='FIREBASE_TEST_LAB',source_label='DYNAMIC_FIREBASE',attributes={'action':'android.intent.action.INSTALL_PACKAGE'}),DynamicObservation('2','PERMISSION_DIALOG','Mic requested',evidence_source='FIREBASE_TEST_LAB',source_label='DYNAMIC_FIREBASE',attributes={'permission':'android.permission.RECORD_AUDIO'})]))
        report=correlate(scan,result);self.assertEqual(report['findings'][0]['evidence'],scan['findings'][0]['evidence']);self.assertEqual(report['risk'],scan['risk']);self.assertEqual(report['findings'][0]['runtime_evidence'][0]['relationship'],'supports');self.assertEqual(len(report['dynamic_correlations']['job']),1);self.assertNotIn('runtime_evidence',scan['findings'][0])
        again=correlate(report,result);self.assertEqual(len(again['findings'][0]['runtime_evidence']),1)
    def test_unobserved_behavior_leaves_unresolved(self):
        scan={'findings':[{'id':'F','rule':'installer','evidence':[{'id':'static'}]}]};result=serial(DynamicResult('firebase_test_lab','job',DynamicJobStatus.COMPLETED));report=correlate(scan,result);self.assertEqual(report['findings'],scan['findings'])
    def test_crash_has_source_label(self):
        result=serial(DynamicResult('firebase_test_lab','job',DynamicJobStatus.FAILED,observations=[DynamicObservation('1','APP_CRASHED','Crash',evidence_source='FIREBASE_TEST_LAB',source_label='DYNAMIC_FIREBASE')]))
        r=correlate({'findings':[]},result);self.assertEqual(r['findings'][0]['evidence_source'],'FIREBASE_TEST_LAB');self.assertEqual(r['findings'][0]['source_label'],'DYNAMIC_FIREBASE')
    def test_screenshot_export_default_exclusion(self):
        report={'dynamic_results':{'j':{'artifacts':[{'id':'s','type':'screenshot','remote_uri':'sensitive'},{'id':'l','type':'logcat'}],'observations':[{'type':'SCREENSHOT','artifact_ids':['s']}]}}}
        out=scanner.export_report(report);self.assertNotIn('sensitive',json.dumps(out));self.assertIn('sensitive',json.dumps(scanner.export_report(report,True)));self.assertIn('sensitive',json.dumps(report))
if __name__=='__main__':unittest.main()
