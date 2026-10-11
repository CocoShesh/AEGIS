from pathlib import Path
import json
import pytest
from reposentinel.scanner_outputs import normalize_output,OutputError
from reposentinel.scanners import REGISTRY,command
from reposentinel.normalize import finish_report

SOURCE=Path('/owned/source')
PATHS={'package-lock.json':['{"name":"lodash"}'],'.github/workflows/ci.yml':['on: pull_request_target'],'config.py':['token="do-not-retain-this-value"'],'payload.ps1':['powershell -enc TEST']}
def engine(id):return next(x for x in REGISTRY if x['id']==id)
def parse(id,raw):return normalize_output(engine(id),raw,SOURCE,PATHS)

def test_gitleaks_discards_secret_values_in_all_fields():
 raw=[{'File':'/owned/source/config.py','StartLine':1,'RuleID':'api-key','Description':'API key','Match':'do-not-retain-this-value','Secret':'do-not-retain-this-value'}]
 findings,_,_=parse('gitleaks',raw)
 assert len(findings)==1 and findings[0]['category']=='secret'
 assert 'do-not-retain-this-value' not in json.dumps(findings)

def test_zizmor_sarif_maps_static_location():
 raw={'runs':[{'results':[{'ruleId':'template-injection','level':'error','message':{'text':'Untrusted template'},'locations':[{'physicalLocation':{'artifactLocation':{'uri':'file:///owned/source/.github/workflows/ci.yml'},'region':{'startLine':1}}}]}]}]}
 findings,_,gaps=parse('zizmor',raw)
 assert not gaps and findings[0]['engine']=='zizmor' and findings[0]['severity']=='high'

def test_package_advisories_preserve_unknown_severity():
 raw={'results':[{'source':{'path':'/owned/source/package-lock.json'},'packages':[{'package':{'name':'lodash','version':'4.17.20'},'vulnerabilities':[{'id':'GHSA-test','summary':'Known issue'}]}]}]}
 findings,_,_=parse('osv-scanner',raw)
 assert findings[0]['severity']=='info' and findings[0]['category']=='dependency'

def test_syft_catalog_and_grype_use_same_package_anchor():
 artifact={'name':'lodash','version':'4.17.20','type':'npm','locations':[{'path':'/owned/source/package-lock.json'}]}
 _,packages,_=parse('syft',{'artifacts':[artifact]})
 findings,_,_=parse('grype',{'matches':[{'artifact':artifact,'vulnerability':{'id':'GHSA-test','severity':'High','fix':{'versions':['4.17.21']}}}]})
 assert packages[0]['path']==findings[0]['path']=='package-lock.json'
 assert findings[0]['engine']=='Grype'

def test_unmapped_scanner_paths_become_gaps_not_injected_files():
 findings,_,gaps=parse('gitleaks',[{'File':'/etc/passwd','StartLine':1,'RuleID':'test'}])
 assert not findings and gaps

def test_yara_application_signature_is_not_malware_verdict():
 findings,_,_=parse('yara-x',[{'path':'/owned/source/payload.ps1','rules':['RS_YARA_POWERSHELL_ENCODED']}])
 assert findings[0]['confidence']=='medium'
 assert 'not proof' in findings[0]['message']

def test_owned_commands_have_no_target_execution_or_config():
 for item in REGISTRY:
  cmd=command(item['id'],'/owned/bin/'+item['id'],SOURCE,Path('/owned/out.json'),Path('/owned'))
  assert isinstance(cmd,list)
  assert not any(x in cmd for x in ('--fix','--shell','install','build','run'))
  if item['id']=='gitleaks':assert '--ignore-gitleaks-allow' in cmd and '--redact=100' in cmd
  if item['id']=='zizmor':assert '--offline' in cmd and '--no-config' in cmd
  if item['id']=='trivy':assert '--offline-scan' in cmd and '--skip-db-update' in cmd

@pytest.mark.parametrize('id',['gitleaks','syft','grype','osv-scanner','zizmor','yara-x'])
def test_malformed_output_is_not_clean(id):
 with pytest.raises(OutputError):parse(id,'not-json-object')

def test_trivy_requires_actual_output_schema():
 with pytest.raises(OutputError):parse('trivy',{})
 findings,_,_=parse('trivy',{'SchemaVersion':2,'Results':[{'Target':'package-lock.json','Vulnerabilities':[{'VulnerabilityID':'CVE-test','PkgName':'lodash','InstalledVersion':'4.17.20','Severity':'HIGH'}]}]})
 assert findings[0]['category']=='dependency'

def test_ai_commentary_persists_separately_and_reloads(tmp_path,monkeypatch):
 from reposentinel import storage
 monkeypatch.setattr(storage,'DATA',tmp_path)
 storage.update('fixture','PARTIAL',report={'findings':[],'scanner_runs':[{'engine':'AI review','status':'NOT_REQUESTED'}]})
 payload={'summary':'Synthetic commentary','provider':'test','model':'test'}
 storage.save_ai('fixture',payload)
 result=storage.get('fixture')['report']
 assert result['ai_explanation']==payload
 assert result['scanner_runs'][0]['status']=='COMPLETED'
 with storage.connect() as db:
  assert 'Synthetic commentary' not in db.execute('SELECT report FROM scans WHERE id=?',('fixture',)).fetchone()['report']
