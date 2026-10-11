"""Real loopback server/worker contract, isolated from retained app data."""
import json,os,socket,subprocess,sys,time,urllib.request

def test_completed_worker_does_not_keep_server_port_open(tmp_path):
    with socket.socket() as probe:
        probe.bind(('127.0.0.1',0));port=probe.getsockname()[1]
    env={**os.environ,'REPOSENTINEL_DATA':str(tmp_path/'data')}
    proc=subprocess.Popen([sys.executable,'-m','reposentinel','serve','--port',str(port)],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    base=f'http://127.0.0.1:{port}'
    def get(path):
        with urllib.request.urlopen(base+path,timeout=2) as r:return json.load(r)
    try:
        for _ in range(60):
            try:token=get('/api/session')['token'];break
            except OSError:time.sleep(.1)
        else:raise AssertionError('Server did not start')
        req=urllib.request.Request(base+'/api/scans',data=b'{"demo":true}',headers={'Content-Type':'application/json','X-Reposentinel-Token':token},method='POST')
        with urllib.request.urlopen(req,timeout=3) as r:scan_id=json.load(r)['id']
        for _ in range(1200):
            scan=get('/api/scans/'+scan_id)
            if scan['report']:break
            assert scan['state']!='FAILED',scan['detail']
            time.sleep(.1)
        else:raise AssertionError('Worker did not finish')
        assert scan['report']['coverage']['accounted']==10
        assert any(len(f['provenance'])>1 for f in scan['report']['findings'])
        proc.terminate();proc.wait(timeout=10)
        with socket.socket() as restarted:
            restarted.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            restarted.bind(('127.0.0.1',port))
    finally:
        if proc.poll() is None:proc.kill();proc.wait(timeout=5)
