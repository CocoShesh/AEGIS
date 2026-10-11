"""Local HTTP + CLI tests. No external provider is ever contacted."""
import contextlib, io, json, sqlite3, tempfile, threading, unittest
from pathlib import Path
from unittest.mock import patch
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from http.server import ThreadingHTTPServer
from test_scanner import scanner
from test_dynamic import FakeProvider, config
from apktrust.dynamic.manager import DynamicManager
from apktrust.cli import consent
from apktrust.dynamic.models import DynamicError

class DynamicAPITests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.data=self.root/'data';self.data.mkdir()
        self.patches=[patch.object(scanner,'DATA',self.data),patch.object(scanner,'_dynamic_manager',None)]
        for p in self.patches:p.start()
        scanner.connection().close();self.scan={'id':'123456789abc','sha256':__import__('hashlib').sha256(b'fixture').hexdigest(),'format':'APK','package':'org.test.app','min_sdk':23,'findings':[],'permissions':[],'state':'PARTIAL'};scanner.save(self.scan)
        (self.root/'dynamic-config.json').write_text(json.dumps({'dynamic':config()}))
        self.manager=DynamicManager(self.root,self.data,scanner.get_scan,registry={'firebase_test_lab':FakeProvider},poll_seconds=.01);scanner._dynamic_manager=self.manager
        source=self.root/'fixture.apk';source.write_bytes(b'fixture');self.manager.attach(self.scan,source)
        self.server=ThreadingHTTPServer(('127.0.0.1',0),scanner.Handler);self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start();self.url=f'http://127.0.0.1:{self.server.server_port}'
    def tearDown(self):
        self.server.shutdown();self.server.server_close();self.thread.join(2)
        for thread in self.manager.threads.values():thread.join(2)
        for p in reversed(self.patches):p.stop()
        self.temp.cleanup()
    def request(self,path,body=None,origin=None,raw=False):
        headers={'Content-Type':'application/octet-stream' if raw else 'application/json'}
        if origin:headers['Origin']=origin
        data=body if raw else json.dumps(body).encode() if body is not None else None
        req=Request(self.url+'/api/v1'+path,data=data,headers=headers)
        try:
            with urlopen(req) as r:return r.status,json.load(r)
        except HTTPError as e:return e.code,json.load(e)
    def test_consent_enforced_on_server(self):
        code,data=self.request('/scans/'+self.scan['id']+'/dynamic',{'provider':'firebase_test_lab'});self.assertEqual(code,400);self.assertEqual(self.manager.store.list(),[])
    def test_same_origin_enforced(self):
        code,data=self.request('/scans/'+self.scan['id']+'/dynamic',{'confirm_cloud_upload':True},origin='https://attacker.invalid');self.assertEqual(code,403);self.assertEqual(self.manager.store.list(),[])
    def test_job_persists_over_http_refresh(self):
        code,job=self.request('/scans/'+self.scan['id']+'/dynamic',{'confirm_cloud_upload':True});self.assertEqual(code,202)
        self.manager.threads[job['id']].join(2)
        code,data=self.request('/scans/'+self.scan['id']+'/dynamic');self.assertEqual(code,200);self.assertEqual(data['jobs'][0]['status'],'COMPLETED');self.assertIn(job['id'],data['results']);self.assertTrue(data['retained_apk'])
    def test_wrong_artifact_hash_rejected(self):
        code,data=self.request('/scans/'+self.scan['id']+'/dynamic/artifact',b'wrong APK',raw=True);self.assertEqual(code,400);self.assertEqual(data['code'],'APK_INCOMPATIBLE')
    def test_local_attach_does_not_upload_cloud(self):
        code,data=self.request('/scans/'+self.scan['id']+'/dynamic/artifact',b'fixture',raw=True);self.assertEqual(code,200);self.assertFalse(data['uploaded_to_cloud']);self.assertEqual(self.manager.store.list(),[])
    def test_unknown_scan_denied(self):
        code,_=self.request('/scans/abcdef123456/dynamic',{'confirm_cloud_upload':True});self.assertEqual(code,404)
    def test_static_rule_catalog_matches_enabled_checks(self):
        code,rows=self.request('/rules');self.assertEqual(code,200)
        ids=[r['id'] for r in rows];self.assertEqual(len(ids),len(set(ids)))
        self.assertIn('accessibility-service',ids);self.assertIn('network-user-trust',ids)
        self.assertTrue(all(r['evidence_tier'] in ('MANIFEST_CONFIG','BYTE_REFERENCE') for r in rows))

class CLIConsentTests(unittest.TestCase):
    def test_noninteractive_requires_flag(self):
        args=type('Args',(),{'confirm_cloud_upload':False})()
        with patch('sys.stdin.isatty',return_value=False):
            with self.assertRaises(DynamicError):consent(args)
    def test_interactive_defaults_no(self):
        args=type('Args',(),{'confirm_cloud_upload':False})()
        with patch('sys.stdin.isatty',return_value=True),patch('builtins.input',return_value=''),contextlib.redirect_stdout(io.StringIO()):self.assertFalse(consent(args))
    def test_explicit_flag(self):self.assertTrue(consent(type('Args',(),{'confirm_cloud_upload':True})()))
