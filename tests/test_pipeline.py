"""Completion-gate regressions. All providers and parser processes are mocked."""
import hashlib,json,tempfile,threading,time,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from urllib.request import Request,urlopen
from urllib.error import HTTPError
from http.server import ThreadingHTTPServer
from test_scanner import scanner
from test_dynamic import FakeProvider,config
from apktrust.dynamic.manager import DynamicManager

class PipelineTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.data=self.root/'data';self.data.mkdir()
  self.patches=[patch.object(scanner,'DATA',self.data),patch.object(scanner,'jobs',{}),patch.object(scanner,'_dynamic_manager',None)]
  for p in self.patches:p.start()
  (self.root/'dynamic-config.json').write_text(json.dumps({'dynamic':config()}))
  self.manager=DynamicManager(self.root,self.data,scanner.get_scan,registry={'firebase_test_lab':FakeProvider},poll_seconds=.01);scanner._dynamic_manager=self.manager;FakeProvider.uploads=0
  self.server=ThreadingHTTPServer(('127.0.0.1',0),scanner.Handler);self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start();self.base=f'http://127.0.0.1:{self.server.server_port}/api/v1'
  self.report={'sha256':hashlib.sha256(b'fixture').hexdigest(),'format':'APK','package':'org.mock.app','filename':'mock.apk','min_sdk':23,'target_sdk':35,'supported_abis':[],'state':'PARTIAL','created':time.time(),'size':7,'version':'1','permissions':[],'findings':[],'inventory':[],'coverage':[],'limitations':[]}
 def tearDown(self):
  self.server.shutdown();self.server.server_close();self.thread.join(2)
  for thread in self.manager.threads.values():thread.join(2)
  for p in reversed(self.patches):p.stop()
  self.temp.cleanup()
 def request(self,path,data=None):
  try:
   with urlopen(Request(self.base+path,data=data,headers={'Content-Type':'application/octet-stream'}),timeout=3) as r:return r.status,json.load(r)
  except HTTPError as e:return e.code,json.load(e)
 def test_vt_upload_requires_explicit_consent(self):
  status,value=self.request('/scans?filename=app.apk&vt_upload=true',b'x')
  self.assertEqual(status,400);self.assertIn('consent',value['error'])
 def test_vt_fresh_analysis_before_ai_and_temporary_file_deleted(self):
  id='123456789abc';path=self.data/'fixture.apk';path.write_bytes(b'fixture');scanner.jobs[id]={}
  def fresh(report,input_path,workspace,persist,progress):
   self.assertEqual(input_path.read_bytes(),b'fixture');persist({'analysis_id':'remote-1','uploaded_sha256':report['sha256']});return {'provider':'virustotal','status':'FOUND','fresh_analysis':True,'stats':{'malicious':1}}
  def ai(report):
   self.assertTrue(report['reputation']['results'][0]['fresh_analysis']);return {'provider':'groq','summary':'Mocked'}
  with patch.object(scanner.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout=json.dumps(self.report))),patch.object(scanner.integrations,'vt_file_analysis',side_effect=fresh),patch.object(scanner.integrations,'collect_vt_intelligence',return_value={'status':'COMPLETE','groups':[]}),patch.object(scanner.integrations,'reputation',side_effect=lambda report,fresh_vt=None:{'results':[fresh_vt,{'provider':'urlhaus','status':'NOT_FOUND'}]}),patch.object(scanner.integrations,'explain',side_effect=ai):
   scanner.slots.acquire();scanner.worker(id,str(path),'fixture.apk',auto_ai=True,vt_upload=True)
  self.assertEqual(scanner.get_scan(id)['vt_submission']['analysis_id'],'remote-1');self.assertFalse((self.data/'vt-inputs'/f'{id}.apk').exists())
 def test_vt_network_endpoint_persists_separate_evidence(self):
  self.report['id']='123456789abc';scanner.save(self.report)
  value={'provider':'virustotal','relationships':[],'evidence_source':'VIRUSTOTAL_REPORT'}
  with patch.object(scanner.integrations,'vt_network',return_value=value) as query:
   status,result=self.request('/scans/123456789abc/reputation/network',b'')
  self.assertEqual(status,200);self.assertEqual(result,value)
  self.assertEqual(scanner.get_scan('123456789abc')['vt_network'],value)
  self.assertEqual(scanner.get_scan('123456789abc')['findings'],self.report['findings'])
  self.assertEqual(query.call_args.args[0]['sha256'],self.report['sha256'])
 def test_static_save_does_not_publish_while_ai_is_running(self):
  entered=threading.Event();release=threading.Event();captured=[]
  def ai(report):
   captured.append(report);entered.set();release.wait(5);return {'provider':'groq','summary':'Combined summary','findings':[]}
  with patch.object(scanner.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout=json.dumps(self.report))),patch.object(scanner.integrations,'explain',side_effect=ai),patch.object(scanner.integrations,'reputation',return_value={'results':[{'provider':'virustotal','status':'NOT_FOUND'},{'provider':'urlhaus','status':'NOT_FOUND'}]}):
   code,job=self.request('/scans?filename=mock.apk&auto_ai=true&auto_reputation=true',b'fixture');self.assertEqual(code,202)
   try:
    self.assertTrue(entered.wait(2));code,status=self.request('/scans/'+job['id']+'/status')
    self.assertNotIn('report',status);self.assertEqual(status['state'],'ANALYZING');self.assertIsNone(status['progress'])
    self.assertEqual(status['pipeline']['stages']['ai']['status'],'RUNNING');self.assertIn('reputation',captured[0])
    code,_=self.request('/scans/'+job['id']+'/report.json');self.assertEqual(code,409)
    self.assertEqual(scanner.clear_history()['cleared'],0);self.assertIsNotNone(scanner.get_scan(job['id']))
   finally:release.set()
   for _ in range(100):
    code,status=self.request('/scans/'+job['id']+'/status')
    if 'report' in status:break
    time.sleep(.01)
   self.assertIn('report',status);self.assertEqual(status['report']['pipeline']['stages']['ai']['status'],'COMPLETED')
   self.assertGreaterEqual(status['report']['duration'],status['report']['static_duration'])
 def test_upload_cloud_execution_requires_explicit_consent(self):
  code,_=self.request('/scans?filename=mock.apk&auto_dynamic=true',b'fixture');self.assertEqual(code,400);self.assertEqual(FakeProvider.uploads,0)
 def test_dynamic_finishes_before_ai_and_temporary_apk_is_removed(self):
  captured=[];scanid='123456789abc';scanner.jobs[scanid]={'progress':10};path=self.root/'mock.apk';path.write_bytes(b'fixture')
  def ai(report):captured.append(report);return {'provider':'groq','summary':'Includes runtime','findings':[]}
  with patch.object(scanner.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout=json.dumps(self.report))),patch.object(scanner.integrations,'explain',side_effect=ai),patch.object(scanner.integrations,'reputation',return_value={'results':[{'provider':'virustotal','status':'NOT_FOUND'},{'provider':'urlhaus','status':'NOT_FOUND'}]}):
   scanner.slots.acquire();scanner.worker(scanid,str(path),'mock.apk',auto_ai=True,auto_reputation=True,auto_dynamic=True)
  self.assertEqual(FakeProvider.uploads,1);self.assertIn('dynamic_results',captured[0]);self.assertIn('reputation',captured[0]);self.assertEqual(captured[0]['pipeline']['stages']['dynamic']['status'],'COMPLETED')
  self.assertFalse(self.manager.input_path(scanid).exists());self.assertFalse(scanner.get_scan(scanid)['local_apk_retained'])
 def test_unavailable_dynamic_device_is_skipped_before_ai(self):
  from apktrust.dynamic.models import DynamicError
  class NoDevice(FakeProvider):
   async def prepare(self,request):raise DynamicError('DEVICE_UNAVAILABLE','No compatible virtual device')
  self.manager.registry={'firebase_test_lab':NoDevice};captured=[];scanid='123456789abc';scanner.jobs[scanid]={'progress':10};path=self.root/'mock.apk';path.write_bytes(b'fixture')
  def ai(report):captured.append(report);return {'provider':'groq','summary':'Runtime verification unavailable','findings':[]}
  with patch.object(scanner.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout=json.dumps(self.report))),patch.object(scanner.integrations,'explain',side_effect=ai):
   scanner.slots.acquire();scanner.worker(scanid,str(path),'mock.apk',auto_ai=True,auto_dynamic=True)
  self.assertEqual(captured[0]['pipeline']['stages']['dynamic']['status'],'SKIPPED');self.assertEqual(FakeProvider.uploads,0)
  self.assertEqual(scanner.get_scan(scanid)['pipeline']['stages']['ai']['status'],'COMPLETED')
 def test_restart_does_not_repeat_interrupted_provider_request(self):
  self.report.update(id='123456789abc',pipeline={'state':'RUNNING','started_at':time.time(),'stages':{k:{'status':'COMPLETED' if k=='static' else 'RUNNING' if k=='ai' else 'SKIPPED','detail':'fixture'} for k in ('static','reputation','dynamic','ai')}},enrichment_requested={'ai':True,'reputation':False,'dynamic':False})
  scanner.save(self.report)
  with patch.object(scanner.integrations,'explain') as ai:scanner.run_pipeline(self.report['id'],recover=True);ai.assert_not_called()
  self.assertEqual(scanner.get_scan(self.report['id'])['pipeline']['stages']['ai']['status'],'FAILED')
