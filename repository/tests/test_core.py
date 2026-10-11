import io, json, tarfile
from unittest.mock import patch
import pytest
from reposentinel.core import analyze,read_archive,validate_url,demo_objects,redact,decode_layers,parse_source,MAX_FILE

def archive(entries):
    data=io.BytesIO()
    with tarfile.open(fileobj=data,mode='w:gz') as t:
        for path,body,kind in entries:
            m=tarfile.TarInfo(path); m.size=len(body)
            if kind=='symlink':m.type=tarfile.SYMTYPE;m.linkname='/etc/passwd';m.size=0
            t.addfile(m,io.BytesIO(body) if kind!='symlink' else None)
    return data.getvalue()

def test_hostile_paths_are_rejected_without_writing():
    for path in ['root/../../escape.py','/root/escape.py']:
        with pytest.raises(ValueError,match='Unsafe'): read_archive(archive([(path,b'bad','file')]))

def test_symlink_is_accounted_and_never_followed():
    objects=read_archive(archive([('root/link',b'','symlink')]))
    r=analyze(objects,{'name':'test'})
    assert r['files'][0]['kind']=='symlink'
    assert r['files'][0]['source'] is None
    assert r['coverage']['unresolved']==1
    assert r['coverage']['accounted']==1

def test_large_file_is_explicitly_unresolved():
    objects=read_archive(archive([('root/large.py',__import__('os').urandom(MAX_FILE+1),'file')]))
    r=analyze(objects,{'name':'test'})
    assert r['files'][0]['sha256'] is None
    assert r['files'][0]['status']=='UNRESOLVED'
    assert r['coverage']['percent']==0

def test_demo_has_valid_evidence_complete_accounting_and_gaps():
    r=analyze(demo_objects(),{'name':'sample','provenance':'synthetic_demo'})
    paths={f['path']:f for f in r['files']}
    assert r['coverage']['accounted']==len(demo_objects())
    assert r['coverage']['silently_skipped']==0
    assert r['coverage']['percent']<100
    assert any(f['rule_id']=='RS-CHAIN-001' for f in r['findings'])
    assert any(d['recovered']=='eval(userInput)' for d in r['derived'])
    for f in r['findings']:
        assert f['path'] in paths
        assert 1<=f['start_line']<=len(paths[f['path']]['source'].splitlines())
    assert any(e['source']=='src/main.py' and e['target']=='src/credentials.py' for e in r['graph']['edges'])

def test_no_target_execution_during_core_analysis(tmp_path):
    sentinel=tmp_path/'executed'
    source=f'from pathlib import Path\nPath({str(sentinel)!r}).write_text("ran")\nexec("print(1)")'
    with patch('subprocess.run',side_effect=AssertionError('No process should start')):
        r=analyze([{'path':'bad.py','kind':'file','data':source.encode()}],{'name':'fixture'})
    assert not sentinel.exists()
    assert r['findings']

def test_secrets_are_removed_from_source_evidence_and_report():
    # Synthetic markers generated locally; these are not provider credentials.
    import hashlib
    marker=hashlib.sha256(b'RepoSentinel redaction test only').hexdigest()
    secret='_'.join(('ghp',marker[:36]))
    sample_password='fixture-'+marker[36:]
    body=f'token = "{secret}"\npassword = "{sample_password}"'
    r=analyze([{'path':'.env','kind':'file','data':body.encode()}],{'name':'fixture'})
    encoded=json.dumps(r)
    assert secret not in encoded
    assert sample_password not in encoded
    assert '[REDACTED]' in encoded

def test_decoding_never_evaluates_recovered_program(tmp_path):
    import base64
    sentinel=tmp_path/'decoded-ran'
    payload=f'open({str(sentinel)!r},"w").write("bad")'
    encoded=base64.b64encode(payload.encode()).decode()
    recovered=decode_layers('x.py',f'b64decode("{encoded}")')
    assert recovered[0]['recovered']==payload
    assert not sentinel.exists()

def test_invalid_urls_cannot_redirect_intake_to_arbitrary_hosts():
    for url in ['http://github.com/a/b','https://evil.test/a/b','https://github.com@evil.test/a/b','https://github.com/a/b/tree/main','https://github.com/a/b?x=1']:
        with pytest.raises(ValueError): validate_url(url)
    assert validate_url('https://github.com/owner/repo.git')==('owner','repo')

def test_parse_failure_is_not_counted_as_success():
    r=analyze([{'path':'broken.py','kind':'file','data':b'def broken('}],{'name':'fixture'})
    assert r['files'][0]['status']=='UNRESOLVED'
    assert r['coverage']['percent']==0

def test_duplicate_archive_entries_rejected():
    with pytest.raises(ValueError,match='Duplicate'): read_archive(archive([('root/a.py',b'a','file'),('root/a.py',b'b','file')]))

def test_private_key_block_is_redacted():
    # Construct a deliberately invalid PEM-shaped fixture at runtime.
    label=' '.join(('RSA','PRIVATE','KEY'))
    text=f'-----BEGIN {label}-----\nSENSITIVEKEYBODY\n-----END {label}-----'
    assert 'SENSITIVEKEYBODY' not in redact(text)
    assert 'user:password@' not in redact('https://user:password@example.invalid/repo')

def test_extensionless_repository_documentation_is_inspected():
    r=analyze([{'path':'README','kind':'file','data':b'Hello World'}],{'name':'fixture'})
    assert r['files'][0]['classification']=='DOCUMENTATION'
    assert r['coverage']['inspected']==1

def test_dependency_inventory_redacts_embedded_url_credentials():
    r=analyze([{'path':'package.json','kind':'file','data':b'{"dependencies":{"sample":"https://user:password@example.invalid/package"}}'}],{'name':'fixture'})
    assert 'user:password@' not in json.dumps(r)

def test_nested_decoding_keeps_original_source_anchor():
    import base64
    inner='b64decode("'+base64.b64encode(b'eval(userInput)').decode()+'")'
    encoded=base64.b64encode(inner.encode()).decode()
    source='\n'*8+f'atob("{encoded}")'
    r=analyze([{'path':'x.js','kind':'file','data':source.encode()}],{'name':'fixture'})
    assert [d['line'] for d in r['derived']]==[9,9]
    assert any(f.get('derived_id') and f['start_line']==9 for f in r['findings'])

def test_decoded_secret_is_detected_before_safe_display_redaction():
    import base64
    encoded=base64.b64encode(b'password = "supersecretvalue"').decode()
    r=analyze([{'path':'x.py','kind':'file','data':f'b64decode("{encoded}")'.encode()}],{'name':'fixture'})
    assert any(f['rule_id']=='RS-SECRET-001' and f.get('derived_id') for f in r['findings'])
    assert 'supersecretvalue' not in json.dumps(r)
