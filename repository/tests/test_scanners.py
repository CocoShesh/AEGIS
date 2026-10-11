from pathlib import Path
from unittest.mock import patch
from reposentinel.scanners import run_scanners

def test_scanner_spawn_allowlist_and_sanitized_environment(tmp_path):
    marker=tmp_path/'target-executed'
    source=f'open({str(marker)!r},"w").write("ran")'.encode()
    calls=[]
    def fake_run(cmd,**kwargs):
        calls.append((cmd,kwargs))
        assert Path(cmd[0]).name in ('semgrep','bandit')
        assert isinstance(cmd,list)
        assert 'shell' not in kwargs or kwargs['shell'] is False
        assert 'SSH_AUTH_SOCK' not in kwargs['env']
        assert 'AWS_ACCESS_KEY_ID' not in kwargs['env']
        assert kwargs['cwd']!=str(tmp_path)
        output=Path(cmd[cmd.index('--output')+1] if '--output' in cmd else cmd[cmd.index('-o')+1])
        output.write_text('{"results":[]}')
        class Result:returncode=0
        return Result()
    with patch('reposentinel.scanners.REGISTRY',[{'id':'semgrep','label':'Semgrep','version':'1.180.0'},{'id':'bandit','label':'Bandit','version':'1.9.4'}]),patch('reposentinel.scanners.executable',side_effect=lambda n:'/owned/bin/'+n),patch('reposentinel.scanners.subprocess.run',side_effect=fake_run):
        runs,findings=run_scanners([{'path':'payload.py','kind':'file','data':source}])
    assert len(calls)==2
    assert not marker.exists()
    assert not findings
    assert all(r['status'] in ('COMPLETED','NOT_INTEGRATED') for r in runs)

def test_real_scanners_do_not_obey_target_ignore_files_or_execute_source(tmp_path):
    from reposentinel.scanners import executable
    import pytest
    if not executable('semgrep') or not executable('bandit'):pytest.skip('Optional scanner executables not installed')
    marker=tmp_path/'target-ran'
    source=f'from pathlib import Path\nPath({str(marker)!r}).write_text("ran")\neval(user_input) # nosemgrep\n'.encode()
    objects=[{'path':'payload.py','kind':'file','data':source},{'path':'.semgrepignore','kind':'file','data':b'*\n'},{'path':'.bandit','kind':'file','data':b'[bandit]\nexclude = payload.py\n'}]
    runs,findings=run_scanners(objects)
    assert all(r['status']=='COMPLETED' for r in runs if r['engine'] in ('Semgrep','Bandit'))
    assert any(f['engine']=='Semgrep' and f['path']=='payload.py' for f in findings)
    assert any(f['engine']=='Bandit' and f['path']=='payload.py' for f in findings)
    assert not marker.exists()
