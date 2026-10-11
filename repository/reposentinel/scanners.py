"""Application-owned scanner commands. No shell, target config, or target plugins."""
import json, os, shutil, subprocess, tempfile, sys
from .scanner_outputs import normalize_output
from pathlib import Path
LOCK=json.loads((Path(__file__).resolve().parent.parent/'tools/scanners.lock.json').read_text())
from .core import finding, redact, MAX_FILE
ROOT=Path(__file__).resolve().parent.parent
REGISTRY=[
 {'id':'semgrep','label':'Semgrep','version':'1.180.0','network':'OFFLINE','capability':'Source pattern analysis'},
 {'id':'bandit','label':'Bandit','version':'1.9.4','network':'OFFLINE','capability':'Python security analysis'},
 {'id':'trivy','label':'Trivy','version':None,'network':'OFFLINE','capability':'Dependencies and configuration; local advisory DB'},
 {'id':'osv-scanner','label':'OSV-Scanner','version':None,'network':'METADATA_ONLY','capability':'Dependency advisories'},
 {'id':'gitleaks','label':'Gitleaks','version':None,'network':'OFFLINE','capability':'Credential detection'},
 {'id':'syft','label':'Syft','version':None,'network':'OFFLINE','capability':'Full SBOM catalog'},
 {'id':'grype','label':'Grype','version':None,'network':'OFFLINE','capability':'SBOM vulnerability analysis; local advisory DB'},
 {'id':'zizmor','label':'zizmor','version':None,'network':'OFFLINE','capability':'GitHub Actions analysis'},
 {'id':'yara-x','label':'YARA-X','version':None,'network':'OFFLINE','capability':'Artifact signatures'},
]
for entry in REGISTRY:
    if entry['id'] in LOCK:entry['version']=LOCK[entry['id']]['version']

def executable(name):
    name=LOCK.get(name,{}).get('binary',name)
    for base in (ROOT/'.tools/bin', Path(sys.executable).parent, ROOT/'.venv/bin'):
        p=base/name
        if p.is_file(): return str(p)
    return shutil.which(name)
def status():
    return [{**r,'installed':bool(executable(r['id'])),'enabled':r.get('supported',True) and bool(executable(r['id']))} for r in REGISTRY]


CACHE=ROOT/'.scanner-cache'
MAX_OUTPUT=16*1024*1024

def command(id,binary,source,out,base):
    rules=ROOT/'rules'
    if id=='semgrep':return [binary,'scan','--config',str(rules/'semgrep.yml'),'--json','--output',str(out),'--metrics','off','--disable-version-check','--disable-nosem','--no-git-ignore','--x-ignore-semgrepignore-files','--no-rewrite-rule-ids','--max-target-bytes','1000000','--timeout','10',str(source)]
    if id=='bandit':return [binary,'-r',str(source),'-f','json','-o',str(out),'--ignore-nosec','--ini',str(rules/'bandit.ini'),'-c',str(rules/'bandit.yml')]
    if id=='gitleaks':return [binary,'dir',str(source),'--config',str(rules/'gitleaks.toml'),'--gitleaks-ignore-path',str(base/'empty-ignore'),'--ignore-gitleaks-allow','--redact=100','--max-archive-depth','0','--max-decode-depth','2','--max-target-megabytes','1','--report-format','json','--report-path',str(out),'--no-banner','--no-color','--timeout','90']
    if id=='zizmor':return [binary,'--offline','--no-config','--no-ignores','--no-exit-codes','--collect','all','--strict-collection','--format','sarif',str(source)]
    if id=='syft':return [binary,'scan','dir:'+str(source),'--config',str(rules/'scanner-config.yaml'),'-o','syft-json='+str(out)]
    if id=='grype':return [binary,'sbom:'+str(base/'syft.json'),'--config',str(rules/'scanner-config.yaml'),'-o','json','--file',str(out)]
    if id=='trivy':return [binary,'fs',str(source),'--config',str(rules/'scanner-config.yaml'),'--cache-dir',str(CACHE/'trivy'),'--scanners','vuln,misconfig','--offline-scan','--skip-db-update','--skip-java-db-update','--skip-check-update','--ignorefile',str(base/'empty-ignore'),'--format','json','--output',str(out),'--timeout','90s','--disable-telemetry','--skip-version-check']
    if id=='osv-scanner':return [binary,'scan','source','-r',str(source),'--config',str(rules/'osv.toml'),'--format','json','--output-file',str(out),'--no-ignore','--no-resolve','--no-call-analysis','go','--no-call-analysis','rust','--allow-no-lockfiles']
    if id=='yara-x':return [binary,'scan','--recursive','--threads','2','--timeout','90','--disable-console-logs','--output-format','json',str(rules/'artifacts.yar'),str(source)]
    raise ValueError('Unknown scanner')

def run_scanners(objects,progress=lambda *_:None):
    runs=[];results=[]
    with tempfile.TemporaryDirectory(prefix='reposentinel-') as td:
        base=Path(td);source=base/'source';source.mkdir();home=base/'home';home.mkdir();(base/'empty-ignore').write_text('')
        paths={};excluded=0
        for obj in objects:
            if obj.get('kind','file')!='file' or obj.get('size',len(obj['data']))>MAX_FILE:excluded+=1;continue
            p=Path(obj['path'])
            if p.is_absolute() or '..' in p.parts:raise ValueError('Invalid scanner input path')
            target=source/p;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(obj['data']);target.chmod(0o400)
            paths[obj['path']]=obj['data'].decode(errors='replace').splitlines()
        env={'PATH':str(Path(sys.executable).parent)+':/usr/bin:/bin','HOME':str(home),'LANG':'C.UTF-8','NO_COLOR':'1','SEMGREP_SEND_METRICS':'off','SEMGREP_ENABLE_VERSION_CHECK':'0','SYFT_CHECK_FOR_APP_UPDATE':'false','SYFT_GOLANG_SEARCH_REMOTE_LICENSES':'false','SYFT_GOLANG_USE_PACKAGES_LIB':'false','SYFT_GOLANG_SEARCH_LOCAL_MOD_CACHE_LICENSES':'false','SYFT_GOLANG_SEARCH_LOCAL_VENDOR_LICENSES':'false','SYFT_JAVA_USE_NETWORK':'false','SYFT_JAVASCRIPT_SEARCH_REMOTE_LICENSES':'false','SYFT_PYTHON_SEARCH_REMOTE_LICENSES':'false','SYFT_CPP_VCPKG_ALLOW_GIT_CLONE':'false','SYFT_PACKAGE_SEARCH_INDEXED_ARCHIVES':'false','SYFT_PACKAGE_SEARCH_UNINDEXED_ARCHIVES':'false','GRYPE_CHECK_FOR_APP_UPDATE':'false','GRYPE_DB_AUTO_UPDATE':'false','GRYPE_DB_CACHE_DIR':str(CACHE/'grype'),'ZIZMOR_OFFLINE':'1'}
        for r in REGISTRY:
            id=r['id'];binary=executable(id)
            run={'engine':r['label'],'version':r['version']}
            if not binary:runs.append({**run,'status':'NOT_INSTALLED','detail':'Run tools/install_scanners.py for local optional engines'});continue
            if id=='grype' and not (base/'syft.json').exists():runs.append({**run,'status':'UNAVAILABLE','detail':'Syft SBOM unavailable; vulnerability analysis not performed'});continue
            if id=='zizmor' and not any(p.startswith('.github/workflows/') or Path(p).name in ('action.yml','action.yaml','.pre-commit-config.yaml') for p in paths):runs.append({**run,'status':'NOT_APPLICABLE','detail':'No supported workflow/action inputs in this snapshot'});continue
            progress('STATIC_SCANNING',f'Running {r["label"]} with application-owned configuration')
            out=base/(id+'.json');stdout_output=id in ('zizmor','yara-x')
            try:
                cmd=command(id,binary,source,out,base)
                # Outputs go to files rather than unbounded pipes. No target command is executed.
                with out.open('wb') if stdout_output else open(os.devnull,'wb') as stdout, (base/'errors.log').open('wb') as stderr:
                    completed=subprocess.run(cmd,cwd=base,env=env,stdout=stdout,stderr=stderr,timeout=110,check=False)
                accepted=(0,1) if id in ('semgrep','bandit','gitleaks','osv-scanner') else (0,11,12,13,14) if id=='zizmor' else (0,)
                if completed.returncode not in accepted or not out.exists():raise ValueError('Scanner failed; '+redact((base/'errors.log').read_text(errors='replace')[-600:]))
                if out.stat().st_size>MAX_OUTPUT:raise ValueError('Scanner output exceeded 16 MB')
                text=out.read_text()
                if id=='yara-x':
                    try:raw=json.loads(text)
                    except json.JSONDecodeError:raw=[json.loads(line) for line in text.splitlines() if line.strip()]
                    if isinstance(raw,dict):
                        if 'version' not in raw or not isinstance(raw.get('matches'),list):raise ValueError('Invalid YARA-X output schema')
                        raw=[{'file':m.get('file'),'rules':[m.get('rule')]} for m in raw.get('matches',[])] if 'matches' in raw else raw.get('files',[raw])
                else:raw=json.loads(text)
                found,inventory,gaps=normalize_output(r,raw,source,paths)
                results.extend(found)
                if excluded:gaps.append(f'{excluded} oversized/non-regular objects not submitted')
                detail=f'{len(found)} findings'
                if id=='syft':detail=f'{len(inventory)} cataloged packages; not a vulnerability verdict'
                if id=='yara-x':detail+='; three application-owned signatures only'
                if id=='zizmor':detail+='; offline workflow audits only'
                if id=='trivy':
                    metadata=CACHE/'trivy/db/metadata.json'
                    if metadata.exists():detail+='; advisory DB '+str(json.loads(metadata.read_text()).get('UpdatedAt','unknown'))
                if id=='grype':
                    metadata=CACHE/'grype-provenance.json'
                    if metadata.exists():detail+='; advisory DB '+str(json.loads(metadata.read_text()).get('built','unknown'))
                if gaps:detail+='; '+'; '.join(gaps)
                runs.append({**run,'status':'PARTIAL' if gaps else 'COMPLETED','detail':detail,**({'inventory':inventory} if inventory else {})})
            except (subprocess.TimeoutExpired,ValueError,OSError,TypeError,KeyError) as ex:
                runs.append({**run,'status':'FAILED','detail':redact(str(ex))[-700:]})
    return runs,results
