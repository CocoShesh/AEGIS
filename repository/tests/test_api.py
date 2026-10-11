import json
import pytest
from fastapi.testclient import TestClient
from reposentinel import api,storage
from reposentinel.core import analyze,demo_objects
@pytest.fixture
def client(tmp_path,monkeypatch):
    monkeypatch.setattr(storage,'DATA',tmp_path)
    r=analyze(demo_objects(),{'name':'fixture','provenance':'synthetic_demo'});r['id']='test-scan'
    storage.update('test-scan','PARTIAL','done',r)
    return TestClient(api.app)

def test_mutations_require_session_and_reject_cross_origin(client):
    body={'disposition':'UNSAFE','note':'review'}
    path='/api/scans/test-scan/findings/'+client.get('/api/scans/test-scan').json()['report']['findings'][0]['id']+'/review'
    assert client.post(path,json=body).status_code==403
    token=client.get('/api/session').json()['token']
    assert client.post(path,json=body,headers={'X-Reposentinel-Token':token,'Origin':'https://evil.test'}).status_code==403

def test_review_is_persisted_separately_and_exported(client):
    r=client.get('/api/scans/test-scan').json()['report'];f=r['findings'][0]
    token=client.get('/api/session').json()['token']
    path=f'/api/scans/test-scan/findings/{f["id"]}/review'
    assert client.post(path,json={'disposition':'EXPECTED_BEHAVIOR','note':'Verified fixture'},headers={'X-Reposentinel-Token':token}).status_code==200
    reviewed=client.get('/api/scans/test-scan').json()['report']['findings'][0]
    assert reviewed['review']['note']=='Verified fixture'
    assert reviewed['evidence']==f['evidence']
    assert 'Verified fixture' in client.get('/api/scans/test-scan/export/html').text
    assert client.get('/api/scans/test-scan/export/sarif').json()['version']=='2.1.0'
    assert client.get('/api/scans/test-scan/export/sbom').json()['bomFormat']=='CycloneDX'

def test_nonexistent_finding_and_invalid_disposition_fail(client):
    token=client.get('/api/session').json()['token'];headers={'X-Reposentinel-Token':token}
    assert client.post('/api/scans/test-scan/findings/nope/review',json={'disposition':'UNSAFE'},headers=headers).status_code==404
    assert client.post('/api/scans/test-scan/findings/nope/review',json={'disposition':'SAFE'},headers=headers).status_code==422

def test_html_export_escapes_hostile_source(client):
    r=storage.get('test-scan')['report'];r['findings'][0]['title']='<script>alert(1)</script>'
    storage.update('test-scan','PARTIAL','done',r)
    html=client.get('/api/scans/test-scan/export/html').text
    assert '<script>' not in html
    assert '&lt;script&gt;' in html

def test_local_host_boundary(client):
    assert client.get('/api/session',headers={'host':'evil.test'}).status_code==403

def test_remove_scan_deletes_retained_evidence_and_requires_session(client):
    path='/api/scans/test-scan'
    assert client.delete(path).status_code==403
    token=client.get('/api/session').json()['token'];headers={'X-Reposentinel-Token':token}
    assert client.delete(path,headers={**headers,'Origin':'https://evil.test'}).status_code==403
    storage.review('test-scan','fixture','UNKNOWN','local note')
    storage.save_ai('test-scan',{'summary':'local commentary'})
    storage.update('other-scan','COMPLETED','retained',{'findings':[]})
    assert client.delete(path,headers=headers).json()=={'removed':True}
    assert client.get(path).status_code==404
    assert client.get(path+'/export/json').status_code==404
    assert [h['id'] for h in client.get('/api/scans').json()]==['other-scan']
    with storage.connect() as db:
        assert db.execute('SELECT count(*) FROM reviews WHERE scan_id=?',('test-scan',)).fetchone()[0]==0
        assert db.execute('SELECT count(*) FROM ai_commentary WHERE scan_id=?',('test-scan',)).fetchone()[0]==0
    assert client.delete(path,headers=headers).status_code==404

def test_remove_active_scan_is_rejected(client):
    storage.update('test-scan','ANALYZING','working')
    token=client.get('/api/session').json()['token']
    assert client.delete('/api/scans/test-scan',headers={'X-Reposentinel-Token':token}).status_code==409
    assert storage.get('test-scan') is not None

def test_automatic_ai_holds_workbench_and_exports_until_review_finishes(client):
    from types import SimpleNamespace
    r=storage.get('test-scan')['report']
    r['scanner_runs']=[{'engine':'AI review','status':'NOT_REQUESTED','detail':'pending'}]
    storage.update('test-scan','AI_REVIEWING','AI in progress',r)
    assert client.get('/api/scans/test-scan').json()['report'] is None
    assert client.get('/api/scans/test-scan/export/json').status_code==409
    result={'assessment':'REVIEW_REQUIRED','summary':'Inspect the findings.','provider':'test','model':'fixture'}
    api.finish_ai('test-scan',SimpleNamespace(explain=lambda report:result))
    response=client.get('/api/scans/test-scan').json()
    assert response['state']=='PARTIAL'
    assert response['report']['ai_explanation']['assessment']=='REVIEW_REQUIRED'
    assert response['report']['scanner_runs'][0]['status']=='COMPLETED'
    assert client.get('/api/scans/test-scan/export/json').status_code==200

def test_automatic_ai_failure_releases_static_evidence(client):
    from types import SimpleNamespace
    r=storage.get('test-scan')['report'];r['scanner_runs']=[{'engine':'AI review','status':'NOT_REQUESTED'}]
    storage.update('test-scan','AI_REVIEWING','AI in progress',r)
    def fail(report):raise ValueError('provider failure')
    api.finish_ai('test-scan',SimpleNamespace(explain=fail))
    response=client.get('/api/scans/test-scan').json()
    assert response['state']=='PARTIAL'
    assert response['report']['scanner_runs'][0]['status']=='FAILED'
    assert response['report']['findings']

def test_gateway_scan_schedules_automatic_ai(client,monkeypatch):
    from concurrent.futures import Future
    from types import SimpleNamespace
    calls=[];future=Future()
    def submit(*args,**kwargs):calls.append(kwargs);return future
    monkeypatch.setattr(api,'POOL',SimpleNamespace(submit=submit))
    monkeypatch.setattr(api,'FUTURES',{})
    monkeypatch.setattr(api.app.state,'ai_bridge',SimpleNamespace(explain=lambda r:{}),raising=False)
    token=client.get('/api/session').json()['token']
    response=client.post('/api/scans',json={'url':'https://github.com/example/repository'},headers={'X-Reposentinel-Token':token})
    assert response.status_code==202
    assert calls[0]['auto_ai'] is True
