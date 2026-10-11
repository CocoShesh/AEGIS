"""Optional live tests; excluded from unittest's test_*.py discovery.
Run explicitly with pytest. Health/catalog test never submits an APK.
"""
import asyncio, json, os, sqlite3, sys, tempfile, time
from pathlib import Path
import pytest
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'src'))
from apktrust.dynamic.config import load_config
from apktrust.dynamic.manager import DynamicManager
from apktrust.dynamic.models import TERMINAL
from apktrust.dynamic.providers.firebase_test_lab import FirebaseTestLabProvider

@pytest.mark.firebase
@pytest.mark.skipif(os.environ.get('APKTRUST_FTL_INTEGRATION_TEST')!='1',reason='Live Firebase access is explicitly disabled')
def test_live_health_and_device_catalog():
    provider=FirebaseTestLabProvider(load_config(ROOT));health=asyncio.run(provider.health_check())
    assert health.status=='READY',health.error
    assert health.devices

@pytest.mark.firebase
@pytest.mark.skipif(os.environ.get('APKTRUST_FTL_INTEGRATION_TEST')!='1' or os.environ.get('APKTRUST_FTL_CONFIRM_CLOUD_UPLOAD')!='1' or not os.environ.get('APKTRUST_FTL_TEST_APK'),reason='Live APK upload requires test APK and additional explicit cloud consent')
def test_live_robo_submission():
    import server
    apk=Path(os.environ['APKTRUST_FTL_TEST_APK']).resolve()
    # Bounded analyzer child, not in-process parsing of an untrusted APK.
    import subprocess
    response=subprocess.run([sys.executable,str(ROOT/'server.py'),'--worker',str(apk),'--filename',apk.name],capture_output=True,text=True,timeout=90)
    assert response.returncode==0
    scan=json.loads(response.stdout)
    with tempfile.TemporaryDirectory() as temp:
        root=Path(temp);data=root/'data';data.mkdir()
        cfg=load_config(ROOT);(root/'dynamic-config.json').write_text(json.dumps({'dynamic':cfg}))
        with sqlite3.connect(data/'scans.sqlite3') as c:
            c.execute('CREATE TABLE scans(id TEXT PRIMARY KEY,report TEXT)');c.execute('INSERT INTO scans VALUES (?,?)',(scan['id'],json.dumps(scan)))
        manager=DynamicManager(root,data,lambda id:scan if id==scan['id'] else None);manager.attach(scan,apk)
        job=manager.start(scan['id'],'firebase_test_lab',True)
        deadline=time.time()+cfg['firebase_test_lab']['job_timeout_seconds']+60
        while time.time()<deadline:
            result=manager.store.result(job['id'])
            if result:
                assert result['status'] in TERMINAL
                assert manager.store.get(job['id']).remote_job_id
                assert result['coverage']=='LIMITED'
                return
            time.sleep(5)
        pytest.fail('Provider deadline exceeded')
