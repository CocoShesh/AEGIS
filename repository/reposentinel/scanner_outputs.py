"""Normalize owned scanner JSON without retaining credential values or arbitrary paths."""
import json
from pathlib import Path
from urllib.parse import unquote,urlparse
from .core import finding,redact

class OutputError(ValueError): pass

def normalize_output(engine,raw,source,paths):
    findings=[];inventory=[];gaps=[]
    def path_of(value):
        value=unquote(str(value or ''))
        if value.startswith('file://'):value=urlparse(value).path
        p=Path(value)
        if p.is_absolute():
            try:value=str(p.relative_to(source))
            except ValueError:return None
        else:
            value=value.removeprefix('./')
            if value.startswith('source/'):value=value[7:]
        return value if value in paths else None
    def emit(path,line,rule,title,severity='medium',confidence='medium',category='vulnerability',message='',evidence=None):
        path=path_of(path)
        if path is None:gaps.append('Result could not be mapped to an inspected source object');return
        try:line=max(1,int(line or 1))
        except (TypeError,ValueError):line=1
        lines=paths[path];line=min(line,max(1,len(lines)))
        severity=str(severity).lower();confidence=str(confidence).lower()
        if severity not in ('critical','high','medium','low','info'):severity='info'
        if confidence not in ('high','medium','low'):confidence='medium'
        snippet=evidence if evidence is not None else lines[line-1] if lines else ''
        f=finding(path,line,str(rule)[:180],str(title)[:120],severity,confidence,category,str(message)[:3000],str(snippet))
        f['engine']=engine['label'];f['engine_version']=engine['version'];findings.append(f)
    def anchor(package,locations=None):
        for loc in locations or []:
            p=path_of(loc.get('path') or loc.get('accessPath') or '')
            if p:return p
        for name in ('package-lock.json','requirements.txt','poetry.lock','Cargo.lock','go.sum','yarn.lock','pnpm-lock.yaml','package.json'):
            for p,lines in paths.items():
                if Path(p).name==name and any(package in line for line in lines):return p
        return None
    id=engine['id']
    if id in ('semgrep','bandit'):
        if not isinstance(raw,dict) or not isinstance(raw.get('results'),list):raise OutputError('Invalid scanner JSON')
        gaps.extend('Scanner parsing error' for _ in raw.get('errors',[]))
        for item in raw['results']:
            if id=='semgrep':
                extra=item.get('extra',{});emit(item.get('path'),item.get('start',{}).get('line'),item.get('check_id'),extra.get('message','Static pattern'),{'ERROR':'high','WARNING':'medium','INFO':'low'}.get(extra.get('severity'),'medium'),message=extra.get('message',''))
            else:emit(item.get('filename'),item.get('line_number'),item.get('test_id'),item.get('issue_text','Python issue'),item.get('issue_severity'),item.get('issue_confidence'),message=item.get('issue_text',''))
    elif id=='gitleaks':
        if not isinstance(raw,list):raise OutputError('Invalid Gitleaks JSON')
        for item in raw:
            # Never carry Match, Secret or raw source for a credential detection.
            emit(item.get('File'),item.get('StartLine'),item.get('RuleID'),item.get('Description','Potential credential'), 'high','medium','secret','Potential credential detected. Verify and rotate if active.','[REDACTED CREDENTIAL MATCH]')
    elif id=='zizmor':
        if not isinstance(raw,dict) or not isinstance(raw.get('runs'),list):raise OutputError('Invalid SARIF JSON')
        for run in raw['runs']:
            for item in run.get('results',[]):
                locations=item.get('locations',[])
                if not locations:gaps.append('SARIF finding without source location');continue
                loc=locations[0].get('physicalLocation',{});message=item.get('message',{}).get('text','Workflow issue')
                uri=loc.get('artifactLocation',{}).get('uri')
                for logical in locations[0].get('logicalLocations',[]):
                    candidate=logical.get('properties',{}).get('symbolic',{}).get('key',{}).get('Local',{}).get('verbatim_path')
                    if candidate and path_of(candidate):uri=candidate;break
                emit(uri,loc.get('region',{}).get('startLine'),item.get('ruleId'),message,{'error':'high','warning':'medium','note':'low'}.get(item.get('level'),'medium'),category='supply_chain',message=message)
    elif id=='trivy':
        if not isinstance(raw,dict) or raw.get('SchemaVersion')!=2:raise OutputError('Invalid Trivy JSON')
        for result in raw.get('Results',[]):
            target=result.get('Target','')
            for v in result.get('Vulnerabilities',[]) or []:
                emit(target,1,v.get('VulnerabilityID','advisory')+':'+v.get('PkgName',''),v.get('VulnerabilityID','Advisory')+' · '+v.get('PkgName',''),v.get('Severity'),'high','dependency',f"{v.get('PkgName')} {v.get('InstalledVersion')}; fixed: {v.get('FixedVersion') or 'not listed'}. {v.get('Title','')}",evidence='Package/version matched against the local advisory database')
            for v in result.get('Misconfigurations',[]) or []:
                cause=v.get('CauseMetadata',{});emit(target,cause.get('StartLine',1),v.get('ID','misconfiguration'),v.get('Title','Configuration issue'),v.get('Severity'),'medium','vulnerability',v.get('Message',''))
    elif id=='osv-scanner':
        if not isinstance(raw,dict) or not isinstance(raw.get('results'),list):raise OutputError('Invalid OSV JSON')
        for result in raw['results']:
            path=result.get('source',{}).get('path','')
            for p in result.get('packages',[]):
                pkg=p.get('package',{})
                for v in p.get('vulnerabilities',[]):
                    # OSV often has no normalized severity; retain uncertainty rather than inflate it.
                    sev=next((x.get('database_specific',{}).get('severity') for x in [v] if x.get('database_specific',{}).get('severity')), 'info')
                    emit(path,1,v.get('id','advisory')+':'+pkg.get('name',''),v.get('id','Advisory')+' · '+pkg.get('name',''),sev,'high','dependency',f"{pkg.get('name')} {pkg.get('version')}. {v.get('summary','Known advisory match')}",evidence='Declared/locked package matched against OSV advisories')
    elif id=='syft':
        if not isinstance(raw,dict) or not isinstance(raw.get('artifacts'),list):raise OutputError('Invalid Syft JSON')
        for a in raw['artifacts'][:2000]:
            path=anchor(a.get('name',''),a.get('locations',[]))
            inventory.append({'name':redact(str(a.get('name','')))[:300],'version':redact(str(a.get('version','')))[:100],'ecosystem':str(a.get('type',''))[:80],'scope':'syft catalog','path':path or '', 'resolved':True,'engine':'Syft'})
        if len(raw['artifacts'])>2000:gaps.append('SBOM inventory capped at 2000 packages')
    elif id=='grype':
        if not isinstance(raw,dict) or not isinstance(raw.get('matches'),list):raise OutputError('Invalid Grype JSON')
        for m in raw['matches']:
            a=m.get('artifact',{});v=m.get('vulnerability',{});path=anchor(a.get('name',''),a.get('locations',[]))
            emit(path,1,v.get('id','advisory')+':'+a.get('name',''),v.get('id','Advisory')+' · '+a.get('name',''),v.get('severity'),'high','dependency',f"{a.get('name')} {a.get('version')}; fixed versions: {', '.join(v.get('fix',{}).get('versions',[])) or 'not listed'}",evidence='SBOM package/version matched against the local advisory database')
    elif id=='yara-x':
        # Supported CLI uses JSON lines, normalized to a list by the adapter.
        if not isinstance(raw,list):raise OutputError('Invalid YARA-X JSON')
        for item in raw:
            path=item.get('path') or item.get('file') or item.get('target')
            for match in item.get('rules',item.get('matches',[])):
                name=match if isinstance(match,str) else match.get('identifier') or match.get('rule') or match.get('name')
                emit(path,1,name or 'artifact-signature',str(name or 'Artifact signature'),'medium','medium','behavior','Application-owned YARA signature match. A static pattern is not proof of malicious behavior.',evidence='Bounded static artifact-signature match')
    else:raise OutputError('Unknown output adapter')
    return findings,inventory,list(dict.fromkeys(gaps))
