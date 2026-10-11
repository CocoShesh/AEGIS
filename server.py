#!/usr/bin/env python3
"""APKTrust local workbench. Standard-library runtime; never executes APK content."""
import argparse, hashlib, html, json, os, re, sqlite3, struct, subprocess, sys, tempfile, threading, time, uuid, zipfile
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
sys.path.insert(0,str(ROOT/'src'))
from apktrust.dynamic.manager import DynamicManager
from apktrust.dynamic.models import DynamicError
import integrations
from static_manifest import analyze_manifest, RULES as MANIFEST_RULES
from android_resources import XmlResources, ResourceGap
DATA = ROOT / '.data'
MAX_UPLOAD = 256 * 1024 * 1024
MAX_ENTRY = 16 * 1024 * 1024
MAX_TOTAL = 128 * 1024 * 1024
VERSION = '0.4.0'
ANDROID = '{http://schemas.android.com/apk/res/android}'

def binary_manifest(data):
    """Decode bounded Android binary XML string pools and start-element attributes."""
    if data.lstrip().startswith(b'<'): return ET.fromstring(data)
    if len(data) < 8 or struct.unpack_from('<H', data)[0] != 3: raise ValueError('Unsupported manifest encoding')
    strings, root, stack = [], None, []
    off = 8
    def varlen(pos, wide=False):
        if wide:
            v = struct.unpack_from('<H', data, pos)[0]; pos += 2
            if v & 0x8000: v = ((v & 0x7fff) << 16) | struct.unpack_from('<H', data, pos)[0]; pos += 2
        else:
            v = data[pos]; pos += 1
            if v & 0x80: v = ((v & 0x7f) << 8) | data[pos]; pos += 1
        return v, pos
    while off + 8 <= len(data):
        kind, header, size = struct.unpack_from('<HHI', data, off)
        if size < header or header < 8 or off + size > len(data): raise ValueError('Malformed XML chunk')
        if kind == 1:
            count, styles, flags, start, _ = struct.unpack_from('<IIIII', data, off + 8)
            if count > 100000 or off + header + count * 4 > off + size: raise ValueError('Invalid string pool')
            for i in range(count):
                pos = off + start + struct.unpack_from('<I', data, off + header + i * 4)[0]
                if flags & 0x100:
                    _, pos = varlen(pos); length, pos = varlen(pos)
                    if pos + length > off + size: raise ValueError('String outside pool')
                    strings.append(data[pos:pos+length].decode('utf-8', 'replace'))
                else:
                    length, pos = varlen(pos, True)
                    if pos + length * 2 > off + size: raise ValueError('String outside pool')
                    strings.append(data[pos:pos+length*2].decode('utf-16le', 'replace'))
        elif kind == 0x102:
            base = off + 16
            ns, name, ast, asize, acount = struct.unpack_from('<IIHHH', data, base)
            node = ET.Element(strings[name])
            if acount > 10000 or asize < 20: raise ValueError('Invalid XML attributes')
            for i in range(acount):
                p = base + ast + i * asize
                if p + 20 > off + size: raise ValueError('Truncated attribute')
                ans, aname, raw, _, _, dtype, value = struct.unpack_from('<IIIHBBI', data, p)
                key = ('{' + strings[ans] + '}' if ans != 0xffffffff else '') + strings[aname]
                val = strings[raw] if raw != 0xffffffff else strings[value] if dtype == 3 else ('true' if value else 'false') if dtype == 0x12 else f'@0x{value:08x}' if dtype==1 else str(value)
                node.set(key, val)
            if stack: stack[-1].append(node)
            elif root is None: root = node
            stack.append(node)
        elif kind == 0x103:
            if stack: stack.pop()
        off += size
    if root is None: raise ValueError('No manifest root')
    return root

RULES = [
 ('dynamic-loader','Dynamic DEX loading reference','medium','Code execution',rb'DexClassLoader|InMemoryDexClassLoader','A loader API reference was found. A string reference alone does not prove executable code is loaded or remotely supplied.'),
 ('shell-exec','Process execution reference','medium','Code execution',rb'java/lang/Runtime|java\.lang\.Runtime|ProcessBuilder','A process API reference is present. Decompilation and call tracing are required to establish reachability and arguments.'),
 ('webview-bridge','WebView JavaScript bridge reference','medium','WebView',rb'addJavascriptInterface','A JavaScript bridge reference can expose native capabilities to web content. Its configuration and reachable origins need review.'),
 ('tls-bypass','TLS error handling reference','low','Network',rb'onReceivedSslError|SslErrorHandler','An SSL-error handler is referenced. This may be safe cancellation or unsafe bypass; the fallback index cannot distinguish them.'),
 ('installer','Package installation capability reference','low','Code execution',rb'REQUEST_INSTALL_PACKAGES|application/vnd.android.package-archive','Package installation indicators were found. Legitimate self-updaters also use these capabilities.'),
]

def analyze_apk(path, filename, budget=None):
    digest = hashlib.sha256()
    with open(path,'rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''): digest.update(block)
    report = dict(id=uuid.uuid4().hex[:12], filename=filename, sha256=digest.hexdigest(), size=os.path.getsize(path), created=time.time(), state='PARTIAL', package='Unknown package', version='Unknown', findings=[], coverage=[], endpoints=[], permissions=[], components=[], inventory=[], tools={'apktrust':VERSION,'python':sys.version.split()[0],'manifest':'bounded AXML parser 0.1','index':'bounded byte-reference index 0.1'}, signer='Not verified', limitations=['No JADX or call/data-flow analysis is configured. Byte-reference signals are contextual, not behavior conclusions.','Signing certificates and signature validity are not verified.','Remote dynamic execution and AI enrichment have not been requested. Source comparison and native semantic analysis are not configured.'], demo=False)
    def finding(rule, title, severity, category, message, evidence, confidence='Medium'):
        report['findings'].append(dict(id=f'F-{len(report["findings"])+1:03}',rule=rule,title=title,severity=severity,category=category,confidence=confidence,status='Needs review',description=message,evidence=evidence, origin='Static', remediation='Review the evidence and confirm reachability with decompilation or isolated runtime analysis.', benign='This capability may be used by legitimate application functionality. Context is required.'))
    with zipfile.ZipFile(path) as z:
        entries=z.infolist()
        seen=validate_archive(entries)
        if 'AndroidManifest.xml' not in seen: raise ValueError('APK must contain AndroidManifest.xml. A valid APK component is required.')
        report['coverage'].append(dict(name='Archive intake',status='Complete',detail=f'{len(entries)} entries validated; SHA-256 recorded',analyzed=len(entries),total=len(entries)))
        consumed=budget['indexed_bytes'] if budget else 0; indexed=0; eligible=0; rule_hits={}; urls={}
        def resource_bytes(name):
            nonlocal consumed
            if name not in seen:raise ResourceGap('Referenced resource is absent')
            entry=z.getinfo(name);limit=8*1024*1024 if name=='resources.arsc' else 2*1024*1024
            if entry.file_size>limit or consumed+entry.file_size>MAX_TOTAL:raise ResourceGap('Referenced resource exceeds shared analysis budget')
            data=z.read(entry);consumed+=len(data)
            if budget:budget['indexed_bytes']=consumed
            return data
        xml_resources=XmlResources(resource_bytes,binary_manifest,seen)
        for i in entries:
            if i.is_dir(): continue
            kind='DEX' if i.filename.endswith('.dex') else 'Native' if i.filename.endswith('.so') else 'Manifest' if i.filename=='AndroidManifest.xml' else 'Asset'
            item=dict(path=i.filename,size=i.file_size,kind=kind,status='Not analyzed',reason='Non-code asset; inventoried only')
            report['inventory'].append(item)
            if kind=='Manifest':
                if i.file_size>MAX_ENTRY or consumed+i.file_size>MAX_TOTAL:
                    item.update(status='Skipped',reason='Manifest exceeds shared indexing budget')
                    report['coverage'].append(dict(name='Manifest & permissions',status='Partial',detail=item['reason'],analyzed=0,total=1))
                    continue
                try:
                    manifest_data=z.read(i); consumed+=len(manifest_data)
                    if budget:budget['indexed_bytes']=consumed
                    manifest=binary_manifest(manifest_data)
                    sdk=manifest.find('uses-sdk')
                    def sdk_int(value):
                        try:return int(value)
                        except (TypeError,ValueError):return None
                    report['min_sdk']=sdk_int(sdk.get(ANDROID+'minSdkVersion','1')) if sdk is not None else 1
                    report['target_sdk']=sdk_int(sdk.get(ANDROID+'targetSdkVersion',str(report['min_sdk']))) if sdk is not None else report['min_sdk']
                    report['supported_abis']=sorted({entry.filename.split('/')[1] for entry in entries if re.fullmatch(r'lib/[^/]+/[^/]+\.so',entry.filename)})
                    report['apk_type']='split' if manifest.get('split') else 'standalone'
                    report['split_name']=manifest.get('split','')
                    report['version_code']=manifest.get(ANDROID+'versionCode','Unknown')
                    report['package']=manifest.get('package','Unknown package'); report['version']=manifest.get(ANDROID+'versionName','Unknown')
                    analyze_manifest(manifest,report,finding,xml_resources)
                    item.update(status='Analyzed',reason='Manifest attributes parsed')
                    report['coverage'].append(dict(name='Manifest & permissions',status='Complete',detail='Text or binary XML attributes parsed; no full IPC reachability analysis',analyzed=1,total=1))
                except Exception as e:
                    item.update(status='Failed',reason=str(e)[:200]); report['coverage'].append(dict(name='Manifest & permissions',status='Failed',detail=str(e)[:200],analyzed=0,total=1))
            elif kind in ('DEX','Native') or i.filename.endswith(('.js','.json','.xml','.txt','.properties','.html')):
                eligible+=1
                if i.file_size>MAX_ENTRY or consumed+i.file_size>MAX_TOTAL:
                    item.update(status='Skipped',reason='Bounded indexing budget exceeded'); continue
                data=z.read(i); consumed+=len(data); indexed+=1
                if budget:budget['indexed_bytes']=consumed
                item.update(status='Indexed',reason='Byte references only; no control-flow or native semantic analysis')
                for rule,title,sev,cat,pattern,msg in RULES:
                    match=re.search(pattern,data)
                    if match:
                        ev=dict(id=f'E-{rule}-{indexed}',path=i.filename,snippet=match.group().decode('ascii','replace'),offset=match.start(),analyzer='byte-reference-index',location=f'byte offset {match.start()}',sha256=report['sha256'])
                        if rule not in rule_hits: rule_hits[rule]=(title,sev,cat,msg,[])
                        if len(rule_hits[rule][4])<20: rule_hits[rule][4].append(ev)
                for match in re.finditer(rb'https?://[A-Za-z0-9._~:/?#@!$&()*+,;=%-]{4,500}',data):
                    url=match.group().decode('ascii').rstrip('.,;')
                    if len(urls)<500 and url not in urls: urls[url]=dict(url=url,host=urlparse(url).hostname or 'Unknown',scheme=urlparse(url).scheme,path=i.filename,offset=match.start(),status='Static reference')
        parsed_paths={path for values in xml_resources.cache.values() for path,_ in values}
        for item in report['inventory']:
            if item['path'] in parsed_paths:item.update(status='Analyzed',reason='Manifest-referenced XML structure parsed; see configuration coverage for gaps')
            elif item['path']=='resources.arsc' and xml_resources.table is not None:item.update(status='Analyzed',reason='Resource table inspected for referenced XML IDs; unsupported values remain gaps')
        if report['tools'].get('manifest_rules'):
            gaps=report.get('static_analysis_gaps',[])
            complete=report.get('manifest_checks_complete',False)
            report['coverage'].append(dict(name='Manifest capability & component checks',status='Complete' if complete else 'Partial',detail='Permission, service, component protection and capability combinations; declarations only',analyzed=1 if complete else 0,total=1))
            report['coverage'].append(dict(name='Referenced XML configuration',status='Partial' if gaps else 'Complete',detail='; '.join(gaps) if gaps else 'Declared XML configuration resolved where referenced; no runtime policy verification',analyzed=0 if gaps else 1,total=1))
            report['limitations'].extend(gaps)
        for rule,(title,sev,cat,msg,evidence) in rule_hits.items(): finding(rule,title,sev,cat,msg,evidence,'Low')
        report['endpoints']=list(urls.values())
        report['coverage'].append(dict(name='Bounded reference indexing',status='Complete' if indexed==eligible else 'Partial',detail=f'{indexed} of {eligible} eligible files indexed; signals only',analyzed=indexed,total=eligible))
        for name in ['Signature verification','DEX decompilation & data flow','Native semantic analysis','Dynamic sandbox','Source comparison','AI explanation']:
            report['coverage'].append(dict(name=name,status='Not run',detail='Optional enrichment not requested' if name in ('AI explanation','Dynamic sandbox') else 'Analyzer not configured',analyzed=0,total=1))
    if budget: budget['indexed_bytes']=consumed
    # Coverage denotes completed analyzer stages, never a claim of whole-code analysis.
    report['coverage_percent']=round(100*sum(c['status']=='Complete' for c in report['coverage'])/len(report['coverage']))
    report['confidence']='Low'
    report['risk']='High' if any(f['severity']=='high' for f in report['findings']) else 'Review required' if any(f['severity'] in ('medium','low') for f in report['findings']) else 'Inconclusive'
    report['duration']=0
    return report

def validate_archive(entries):
    if len(entries)>50000: raise ValueError('Archive exceeds 50,000 entry limit')
    declared=sum(i.file_size for i in entries)
    if declared > 2*1024**3: raise ValueError('Archive exceeds 2 GiB uncompressed budget')
    seen=set()
    for i in entries:
        p=Path(i.filename)
        if i.filename.startswith(('/', '\\')) or '..' in p.parts or '\\' in i.filename or re.match(r'^[A-Za-z]:', i.filename): raise ValueError('Unsafe archive path rejected')
        if (i.external_attr >> 16) & 0o170000 == 0o120000: raise ValueError('Archive symlink rejected')
        if i.filename in seen: raise ValueError('Duplicate archive entry rejected')
        seen.add(i.filename)
        if i.file_size>1024*1024 and i.file_size/max(i.compress_size,1)>200: raise ValueError('Excessive compression ratio rejected')
    return seen

def analyze(path, filename):
    if Path(filename).suffix.lower() not in ('.xapk','.apks'):
        r=analyze_apk(path,filename);r['format']='APK';r['package_splits']=[];return r
    digest=hashlib.sha256()
    with open(path,'rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''):digest.update(block)
    r=dict(id=uuid.uuid4().hex[:12],filename=filename,sha256=digest.hexdigest(),size=os.path.getsize(path),created=time.time(),state='PARTIAL',package='Unknown package',version='Unknown',format=Path(filename).suffix[1:].upper(),findings=[],coverage=[],endpoints=[],permissions=[],components=[],inventory=[],package_splits=[],tools={'apktrust':VERSION,'python':sys.version.split()[0],'intake':'package-set 0.2'},signer='Not verified',limitations=['Package-set signature consistency, installability and device-specific split selection are not verified. All included APK variants are inventoried; no variant is installed.','OBB and other container assets are inventoried only; their content remains unanalyzed.','Decompilation, semantic data flow and source comparison are not configured. Remote dynamic execution and AI enrichment have not been requested.'],demo=False,duration=0,confidence='Low')
    budget={'indexed_bytes':0};successful=[];entry_count=0;declared_total=0
    with zipfile.ZipFile(path) as z:
        entries=z.infolist();validate_archive(entries)
        apks=[i for i in entries if not i.is_dir() and i.filename.lower().endswith('.apk')]
        if not apks:raise ValueError('Package container contains no APK components')
        if len(apks)>128:raise ValueError('Container exceeds 128 APK component limit')
        r['coverage'].append(dict(name='Container intake',status='Complete',detail=f'{len(entries)} outer entries validated; container SHA-256 recorded',analyzed=len(entries),total=len(entries)))
        for i in entries:
            if i.is_dir():continue
            isapk=i.filename.lower().endswith('.apk')
            outer=dict(path=i.filename,size=i.file_size,kind='APK component' if isapk else 'OBB' if i.filename.lower().endswith('.obb') else 'Container asset',status='Pending' if isapk else 'Not analyzed',reason='Component intake pending' if isapk else 'Inventoried only; content not analyzed')
            r['inventory'].append(outer)
            if not isapk:continue
            component=dict(path=i.filename,size=i.file_size,status='Failed',package='Unknown',version='Unknown',split_name=None,role='Unknown',sha256=None,coverage_percent=0,findings=0)
            r['package_splits'].append(component)
            # Never use an attacker-supplied pathname as an extraction destination.
            with tempfile.TemporaryDirectory(prefix='apktrust-component-',dir=os.environ.get('APKTRUST_TEMP')) as td:
                child=Path(td)/'component.apk'
                try:
                    if i.file_size>MAX_UPLOAD:raise ValueError('APK component exceeds 256 MiB limit')
                    component_hash=hashlib.sha256();written=0
                    with z.open(i) as src,open(child,'wb') as dst:
                        while True:
                            chunk=src.read(1024*1024)
                            if not chunk:break
                            written+=len(chunk)
                            if written>MAX_UPLOAD:raise ValueError('APK component exceeds stream budget')
                            component_hash.update(chunk);dst.write(chunk)
                    component['sha256']=component_hash.hexdigest()
                    with zipfile.ZipFile(child) as cz:
                        nested=cz.infolist();validate_archive(nested)
                        entry_count+=len(nested);declared_total+=sum(n.file_size for n in nested)
                        if entry_count>50000 or declared_total>2*1024**3:raise ValueError('Shared nested archive budget exceeded')
                    sub=analyze_apk(str(child),i.filename,budget)
                    successful.append(sub)
                    component.update(status='Partial',package=sub['package'],version=sub['version'],version_code=sub.get('version_code','Unknown'),split_name=sub.get('split_name'),role='Base' if sub.get('split_name')=='' else 'Split' if sub.get('split_name') else 'Unknown',coverage_percent=sub['coverage_percent'],findings=len(sub['findings']))
                    outer.update(status='Partial',reason='Component indexed; advanced analyzer gaps remain')
                    prefix=i.filename+'!/'
                    for item in sub['inventory']:item['path']=prefix+item['path'];item['component']=i.filename;r['inventory'].append(item)
                    for c in sub['coverage']:c['name']=i.filename+' · '+c['name'];c['component']=i.filename;r['coverage'].append(c)
                    for f in sub['findings']:
                        f['id']=f'F-{len(r["findings"])+1:03}';f['component']=i.filename
                        for ev in f['evidence']:ev['id']=f'P{len(r["package_splits"])}-'+ev['id'];ev['path']=prefix+ev['path'];ev['component']=i.filename;ev['container_sha256']=r['sha256']
                        r['findings'].append(f)
                    for e in sub['endpoints']:e['path']=prefix+e['path'];e['component']=i.filename;r['endpoints'].append(e)
                    for c in sub['components']:c['artifact']=i.filename;r['components'].append(c)
                    r['permissions']=sorted(set(r['permissions'])|set(sub['permissions']))
                    r.setdefault('permission_details',[]).extend({**detail,'artifact':i.filename} for detail in sub.get('permission_details',[]))
                    r.setdefault('static_analysis_gaps',[]).extend(i.filename+' · '+gap for gap in sub.get('static_analysis_gaps',[]))
                    r.setdefault('manifest_configuration',[]).append({'artifact':i.filename,'backup_policy':sub.get('backup_policy',{}),'rules_version':sub.get('tools',{}).get('manifest_rules')})
                except Exception as e:
                    component['error']=str(e)[:200];outer.update(status='Failed',reason=component['error'])
                    r['coverage'].append(dict(name=i.filename+' · Component analysis',component=i.filename,status='Failed',detail=component['error'],analyzed=0,total=1))
    count=len(successful)
    r['coverage'].append(dict(name='APK component intake',status='Complete' if count==len(apks) else 'Partial',detail=f'{count} of {len(apks)} APK components processed; see per-component analyzer gaps',analyzed=count,total=len(apks)))
    assets=sum(item['kind'] in ('OBB','Container asset') for item in r['inventory'])
    if assets:r['coverage'].append(dict(name='OBB / container asset content',status='Not run',detail='All outer assets inventoried; content analysis unavailable',analyzed=0,total=assets))
    known={sub['package'] for sub in successful if sub['package']!='Unknown package'}
    versions={sub['version'] for sub in successful if sub['version']!='Unknown'}
    bases=[sub for sub in successful if sub.get('split_name')=='']
    if len(known)==1:r['package']=next(iter(known))
    if len(versions)==1:r['version']=next(iter(versions))
    if len(known)>1:r['limitations'].append('Mixed package identities found. This container is not verified as one installable package set.')
    if len(bases)!=1:r['limitations'].append(f'{len(bases)} base manifests found. Base selection is ambiguous or incomplete; device compatibility is unknown.')
    if len(versions)>1:r['limitations'].append('Component version names differ; package-set consistency is unverified.')
    r['coverage_percent']=round(100*sum(c['status']=='Complete' for c in r['coverage'])/len(r['coverage']))
    r['risk']='High' if any(f['severity']=='high' for f in r['findings']) else 'Review required' if any(f['severity'] in ('medium','low') for f in r['findings']) else 'Inconclusive'
    return r

def connection():
    DATA.mkdir(exist_ok=True)
    conn=sqlite3.connect(DATA/'scans.sqlite3')
    conn.execute("CREATE TABLE IF NOT EXISTS scans (id TEXT PRIMARY KEY, report TEXT NOT NULL, archive_batch TEXT NOT NULL DEFAULT '')")
    if 'archive_batch' not in {row[1] for row in conn.execute('PRAGMA table_info(scans)')}:
        conn.execute("ALTER TABLE scans ADD COLUMN archive_batch TEXT NOT NULL DEFAULT ''")
        conn.commit()
    return conn

def save(report):
    with connection() as c:c.execute('INSERT INTO scans (id,report) VALUES (?,?) ON CONFLICT(id) DO UPDATE SET report=excluded.report',(report['id'],json.dumps(report)))

def get_scan(id):
    with connection() as c: row=c.execute("SELECT report FROM scans WHERE id=? AND archive_batch=''",(id,)).fetchone()
    return json.loads(row[0]) if row else None

jobs={}; lock=threading.Lock(); slots=threading.BoundedSemaphore(2)

def clear_history():
    batch=uuid.uuid4().hex
    with connection() as c:
        c.execute('BEGIN IMMEDIATE')
        ids=[row[0] for row in c.execute("SELECT id,report FROM scans WHERE archive_batch=''") if json.loads(row[1]).get('pipeline',{}).get('state')!='RUNNING']
        c.executemany("UPDATE scans SET archive_batch=? WHERE id=? AND archive_batch=''",[(batch,id) for id in ids])
    # These are completed results, not analyzer caches. Running jobs are left alone.
    with lock:
        for id in ids:
            if jobs.get(id,{}).get('progress')==100:jobs.pop(id,None)
    return {'cleared':len(ids),'undo_token':batch,'scope':'Completed reports hidden from history; running scans and API keys retained'}

def restore_history(batch):
    with connection() as c:
        cursor=c.execute("UPDATE scans SET archive_batch='' WHERE archive_batch=?",(batch,))
    return {'restored':cursor.rowcount}

_dynamic_manager=None

def dynamic_manager():
    global _dynamic_manager
    if _dynamic_manager is None or _dynamic_manager.store.path!=DATA/'scans.sqlite3':
        connection().close()
        _dynamic_manager=DynamicManager(ROOT,DATA,get_scan)
    return _dynamic_manager

def export_report(scan,include_screenshots=False):
    import copy
    report=copy.deepcopy(scan)
    report['evidence_source_labels']=['STATIC','SOURCE_COMPARISON','DYNAMIC_FIREBASE','AI_ASSESSMENT']
    report['export_screenshots_included']=include_screenshots
    if not include_screenshots:
        for result in report.get('dynamic_results',{}).values():
            removed={a['id'] for a in result['artifacts'] if a['type']=='screenshot'}
            result['artifacts']=[a for a in result['artifacts'] if a['type']!='screenshot']
            result['observations']=[o for o in result['observations'] if o['type']!='SCREENSHOT']
            for obs in result['observations']:obs['artifact_ids']=[id for id in obs.get('artifact_ids',[]) if id not in removed]
    return report

PIPELINE_VERSION=2
PIPELINE_TERMINAL={'COMPLETED','COMPLETED_WITH_GAPS'}

def update_scan(id,changes):
    """Merge into the current scan inside a transaction, preserving runtime/review evidence."""
    with connection() as c:
        c.execute('BEGIN IMMEDIATE')
        row=c.execute("SELECT report FROM scans WHERE id=? AND archive_batch=''",(id,)).fetchone()
        if not row:return None
        report=json.loads(row[0]);changes(report)
        c.execute('UPDATE scans SET report=? WHERE id=?',(json.dumps(report),id))
        return report

def pipeline_stage(id,name,status,detail='',**extra):
    def change(r):
        stage=r['pipeline']['stages'][name]
        stage.update(status=status,detail=detail,**extra)
        if status=='RUNNING':stage.setdefault('started_at',time.time())
        if status in ('COMPLETED','SKIPPED','FAILED'):stage['finished_at']=time.time()
        r['pipeline']['stage']=name
    report=update_scan(id,change)
    if report:
        jobs.setdefault(id,{'id':id}).update(state='ANALYZING',progress=None,stage=detail or name,pipeline=report['pipeline'])
    return report

def run_pipeline(id,recover=False):
    """Static evidence is persisted internally; the public report waits for every selected stage."""
    report=get_scan(id)
    if not report:return
    requested=report['enrichment_requested'];manager=None
    for name in ('reputation','dynamic','ai'):
        report=get_scan(id)
        if not report:return
        current=report['pipeline']['stages'][name]
        if current['status'] in ('COMPLETED','SKIPPED','FAILED'):continue
        if recover and current['status']=='RUNNING' and not ((name=='dynamic' and current.get('job_id')) or (name=='reputation' and requested.get('vt_upload') and report.get('vt_submission',{}).get('analysis_id'))):
            pipeline_stage(id,name,'FAILED','Interrupted by application restart; no external request was repeated.')
            continue
        if not requested.get(name):
            pipeline_stage(id,name,'SKIPPED','Cloud upload not consented' if name=='dynamic' else 'Not selected')
            continue
        labels={'reputation':'Checking VirusTotal & URLhaus','dynamic':'Preparing cloud dynamic analysis','ai':'Synthesizing intelligence from collected evidence'}
        pipeline_stage(id,name,'RUNNING',labels[name])
        try:
            if name=='dynamic':
                manager=dynamic_manager()
                job_id=current.get('job_id')
                if not job_id:
                    if not manager.has_input(report):raise DynamicError('APK_INCOMPATIBLE','No compatible retained standalone APK is available')
                    from apktrust.dynamic.config import load_config
                    cfg=load_config(ROOT)
                    job=manager.start(id,cfg['provider'],True);job_id=job['id']
                    pipeline_stage(id,name,'RUNNING','Preparing APK',job_id=job_id)
                cfg=manager.store.config(job_id);provider=manager.store.get(job_id).provider
                deadline=manager.store.get(job_id).created_at+cfg.get(provider,{}).get('job_timeout_seconds',900)+180
                last_stage=None
                while True:
                    result=manager.store.result(job_id);job=manager.store.get(job_id)
                    if result:break
                    if time.time()>deadline:
                        try:manager.cancel(job_id,id)
                        except DynamicError:pass
                        raise DynamicError('TEST_TIMEOUT','Dynamic deadline reached; execution could not be verified')
                    with connection() as c:visible=c.execute("SELECT 1 FROM scans WHERE id=? AND archive_batch=''",(id,)).fetchone()
                    if not visible:return
                    if job.stage!=last_stage:
                        pipeline_stage(id,name,'RUNNING',job.stage,job_id=job_id);last_stage=job.stage
                    time.sleep(.5)
                complete=result['status']=='COMPLETED'
                pipeline_stage(id,name,'COMPLETED' if complete else 'SKIPPED' if result['status']=='NOT_RUN' else 'FAILED',
                    'Robo execution completed · LIMITED runtime coverage' if complete else (job.error.message if job.error else 'Dynamic execution '+result['status']),job_id=job_id,provider=provider)
            else:
                field='ai_explanation' if name=='ai' else 'reputation'
                # AI runs last and sees the current report, including collected runtime/reputation evidence.
                if name=='reputation' and requested.get('vt_upload'):
                    fresh=None
                    try:
                        if report.get('format')!='APK':raise integrations.IntegrationError('Fresh VT analysis currently supports standalone APK files; bundle scans use hash lookup.')
                        fresh=integrations.vt_file_analysis(report,DATA/'vt-inputs'/f'{id}.apk',DATA/'vt-inputs',
                            lambda job:update_scan(id,lambda r:r.update(vt_submission=job)),
                            lambda message:pipeline_stage(id,name,'RUNNING',message))
                    except integrations.IntegrationError as error:
                        update_scan(id,lambda r:r.update(vt_upload_error=str(error)))
                    value=integrations.reputation(get_scan(id),fresh_vt=fresh)
                    if not fresh:value['upload_gap']=get_scan(id).get('vt_upload_error','Fresh VT analysis unavailable')
                else:value=integrations.explain(get_scan(id)) if name=='ai' else integrations.reputation(get_scan(id))
                update_scan(id,lambda r:r.update({field:value}))
                if name=='reputation' and any(row.get('provider')=='virustotal' and row.get('status')=='FOUND' for row in value.get('results',[])):
                    try:evidence=integrations.collect_vt_intelligence(get_scan(id),lambda message:pipeline_stage(id,name,'RUNNING',message))
                    except integrations.IntegrationError:evidence={'provider':'virustotal','status':'UNAVAILABLE','groups':[],'detail':'VT evidence collection unavailable; engine results retained.'}
                    update_scan(id,lambda r:r.update(vt_intelligence=evidence))
                if name=='ai':
                    hosted=value.get('provider')!='local'
                    pipeline_stage(id,name,'COMPLETED' if hosted else 'FAILED' if value.get('errors') else 'SKIPPED',
                        'Intelligence summary generated' if hosted else 'Hosted AI unavailable; local evidence summary retained' if value.get('errors') else 'No AI key configured; local evidence summary retained',provider=value.get('provider'))
                else:
                    rows=value.get('results',[]);valid=[r for r in rows if r.get('status') in ('FOUND','NOT_FOUND')]
                    if value.get('upload_gap'):valid=[]
                    pipeline_stage(id,name,'COMPLETED' if len(valid)==2 else 'FAILED' if value.get('upload_gap') or any(r.get('status')=='FAILED' for r in rows) else 'SKIPPED',
                        'Fresh VT analysis and URLhaus lookup completed' if value.get('results',[{}])[0].get('fresh_analysis') and len(valid)==2 else 'Both hash lookups completed' if len(valid)==2 else value.get('upload_gap') or '; '.join(('VirusTotal' if r.get('provider')=='virustotal' else 'URLhaus')+': '+str(r.get('detail') or r.get('status','Unavailable')) for r in rows if r.get('status') not in ('FOUND','NOT_FOUND')) or 'One or more reputation providers are unavailable')
                    if get_scan(id).get('vt_intelligence',{}).get('status') in ('PARTIAL','UNAVAILABLE'):
                        update_scan(id,lambda r:r.setdefault('limitations',[]).append('VT extended evidence has access/quota gaps; inspect collection states.'))
        except (integrations.IntegrationError,DynamicError) as error:
            if name!='dynamic':update_scan(id,lambda r:r.update({('ai_explanation' if name=='ai' else 'reputation'):{'status':'FAILED','detail':str(error)}}))
            pipeline_stage(id,name,'SKIPPED' if isinstance(error,DynamicError) and error.code in ('DISABLED','APK_INCOMPATIBLE','GCLOUD_MISSING','AUTH_ERROR','DEVICE_UNAVAILABLE','PROJECT_NOT_FOUND') else 'FAILED',str(error),error_code=getattr(error,'code','PROVIDER_ERROR'))
        except Exception:
            if name!='dynamic':update_scan(id,lambda r:r.update({('ai_explanation' if name=='ai' else 'reputation'):{'status':'FAILED','detail':'Provider could not complete; static evidence remains valid.'}}))
            pipeline_stage(id,name,'FAILED','Provider could not complete; static evidence remains valid.',error_code='UNKNOWN')
    finished=time.time()
    def finalize(r):
        stages=r['pipeline']['stages'];gaps=r.get('vt_intelligence',{}).get('status') in ('PARTIAL','UNAVAILABLE') or any(x['status']!='COMPLETED' for x in stages.values()) or any(x['status']!='Complete' for x in r.get('coverage',[]) if x.get('name')!='AI explanation')
        r['pipeline'].update(state='COMPLETED_WITH_GAPS' if gaps else 'COMPLETED',finished_at=finished,stage='Report ready')
        r.update(duration=round(finished-r['pipeline']['started_at'],2),analysis_finished_at=finished,analysis_completion=r['pipeline']['state'])
        # Do not relabel bounded code coverage as full APK coverage after cloud enrichment.
        for stage in r.get('coverage',[]):
            if stage.get('name')=='AI explanation':
                stage.update(status='Complete' if stages['ai']['status']=='COMPLETED' else 'Failed' if stages['ai']['status']=='FAILED' else 'Not run',detail=stages['ai']['detail'])
        r['coverage_percent']=round(100*sum(x['status']=='Complete' for x in r.get('coverage',[]))/len(r['coverage'])) if r.get('coverage') else 0
        r['limitations']=[x for x in r.get('limitations',[]) if 'have not been requested' not in x]
        if not r.get('retain_dynamic_requested') and r.get('local_apk_retained'):
            dynamic_manager().input_path(id).unlink(missing_ok=True);r['local_apk_retained']=False
    report=update_scan(id,finalize)
    (DATA/'vt-inputs'/f'{id}.apk').unlink(missing_ok=True)
    if report:jobs.setdefault(id,{'id':id}).update(state=report['pipeline']['state'],stage='Report ready',progress=100,report=report,pipeline=report['pipeline'])

def recover_pipelines():
    with connection() as c:reports=[json.loads(row[0]) for row in c.execute("SELECT report FROM scans WHERE archive_batch='' ")]
    for report in reports:
        if report.get('pipeline',{}).get('state')=='RUNNING':
            threading.Thread(target=run_pipeline,args=(report['id'],True),daemon=True).start()

def worker(id,path,filename,retain_dynamic=False,auto_ai=False,auto_reputation=False,auto_dynamic=False,vt_upload=False):
    start=time.time();temp_workspace=tempfile.TemporaryDirectory(prefix='job-',dir=DATA)
    try:
        def limits():
            import resource
            resource.setrlimit(resource.RLIMIT_AS,(768*1024**2,768*1024**2));resource.setrlimit(resource.RLIMIT_CPU,(60,60));resource.setrlimit(resource.RLIMIT_FSIZE,(32*1024**2,32*1024**2))
        jobs[id].update(stage='Static analysis · manifests and bounded reference indexing',progress=None)
        result=subprocess.run([sys.executable,str(ROOT/'server.py'),'--worker',path,'--filename',filename],capture_output=True,text=True,timeout=90,preexec_fn=limits if os.name=='posix' else None,env={'PATH':os.environ.get('PATH',''),'LANG':'C.UTF-8','APKTRUST_TEMP':temp_workspace.name})
        if result.returncode:raise ValueError(result.stderr.strip()[-500:] or 'Analyzer worker failed')
        report=json.loads(result.stdout);static_finished=time.time()
        report.update(id=id,static_duration=round(static_finished-start,2),duration=round(static_finished-start,2),cache_used=False,analysis_started_at=start,execution='Fresh analyzer subprocess',evidence_source='STATIC',retain_dynamic_requested=retain_dynamic)
        report['enrichment_requested']={'ai':auto_ai,'reputation':auto_reputation or vt_upload,'dynamic':auto_dynamic,'vt_upload':vt_upload}
        report['pipeline']={'version':PIPELINE_VERSION,'state':'RUNNING','started_at':start,'stage':'Static analysis complete','stages':{
            'static':{'status':'COMPLETED','detail':'Bounded static checks completed; semantic analysis remains limited','started_at':start,'finished_at':static_finished},
            **{name:{'status':'PENDING','detail':'Waiting'} for name in ('reputation','dynamic','ai')}}}
        if retain_dynamic or auto_dynamic:
            try:dynamic_manager().attach(report,path);report['local_apk_retained']=True
            except DynamicError as error:report.setdefault('limitations',[]).append(error.message);report['local_apk_retained']=False
        if vt_upload:
            vt_dir=DATA/'vt-inputs';vt_dir.mkdir(exist_ok=True,mode=0o700)
            if report.get('format')=='APK':
                import shutil
                target=vt_dir/f'{id}.apk'
                with open(path,'rb') as source,open(target,'xb') as dest:
                    os.chmod(target,0o600);shutil.copyfileobj(source,dest,1024*1024)
        save(report);run_pipeline(id)
    except Exception as error:jobs[id].update(state='FAILED',stage='Scan failed',progress=100,error=str(error))
    finally:
        Path(path).unlink(missing_ok=True);(DATA/'vt-inputs'/f'{id}.apk').unlink(missing_ok=True);temp_workspace.cleanup();slots.release()

class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args): pass
    def respond(self,status,data,ctype='application/json',extra=None):
        body=json.dumps(data).encode() if ctype=='application/json' else data.encode() if isinstance(data,str) else data
        self.send_response(status); self.send_header('Content-Type',ctype);self.send_header('Content-Length',str(len(body)))
        self.send_header('X-Content-Type-Options','nosniff');self.send_header('Referrer-Policy','no-referrer');self.send_header('Cache-Control','no-store')
        self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'")
        for k,v in (extra or {}).items():self.send_header(k,v)
        self.end_headers();self.wfile.write(body)
    def do_GET(self):
        host=self.headers.get('Host','')
        if host not in (f'127.0.0.1:{self.server.server_port}',f'localhost:{self.server.server_port}'):
            return self.respond(403,{'error':'Local loopback Host required'})
        p=urlparse(self.path).path
        if p=='/api/v1/rules':
            catalog=[dict(id=r[0],title=r[1],category=r[3],evidence_tier='BYTE_REFERENCE',status='Enabled') for r in RULES]
            catalog.extend(dict(id=id,title=title,category=category,evidence_tier='MANIFEST_CONFIG',status='Enabled') for id,title,category in [('debuggable','Debuggable application build','Manifest'),('cleartext-policy','Cleartext traffic configuration','Network')]+MANIFEST_RULES)
            return self.respond(200,catalog)
        if p=='/api/v1/dynamic/providers':
            try:return self.respond(200,[dynamic_manager().health()])
            except DynamicError as e:return self.respond(200,[{'provider':'firebase_test_lab','status':'UNAVAILABLE','error':{'code':e.code,'message':e.message}}])
        if p=='/api/v1/dynamic/devices':
            try:
                import asyncio
                return self.respond(200,asyncio.run(dynamic_manager().provider(name=parse_qs(urlparse(self.path).query).get('provider',['firebase_test_lab'])[0]).discover_devices()))
            except DynamicError as e:return self.respond(400,{'error':e.message,'code':e.code})
        if p=='/api/v1/providers/status':
            try:return self.respond(200,integrations.statuses())
            except integrations.IntegrationError as e:return self.respond(400,{'error':str(e)})
        if p=='/api/v1/scans':
            with connection() as c: reports=[json.loads(r[0]) for r in c.execute("SELECT report FROM scans WHERE archive_batch='' ORDER BY rowid DESC LIMIT 100")]
            reports=[{k:v for k,v in r.items() if k in ('id','filename','package','version','size','created','pipeline','state')} if r.get('pipeline',{}).get('state')=='RUNNING' else r for r in reports]
            return self.respond(200,reports)
        if p=='/api/v1/system/health': return self.respond(200,dict(status='healthy',version=VERSION,pipeline_version=PIPELINE_VERSION,vt_upload_supported=True,mode='Local',tools={'intake':True,'manifest':True,'byte_index':True,'jadx':False,'apksigner':False,'dynamic_provider':True,'sandbox':False,'ai':True,'threat_intel':True},disk_free=__import__('shutil').disk_usage(ROOT).free))
        m=re.fullmatch(r'/api/v1/scans/([a-f0-9]{12})(?:/(.*))?',p)
        if m:
            id,sub=m.groups(); job=jobs.get(id); scan=get_scan(id)
            if sub=='status':
                if job and job.get('state')=='FAILED':return self.respond(200,job)
                if scan and scan.get('pipeline',{}).get('state')=='RUNNING':return self.respond(200,dict(id=id,state='ANALYZING',progress=None,stage=job.get('stage',scan['pipeline']['stage']) if job else scan['pipeline']['stage'],pipeline=scan['pipeline']))
                if scan:return self.respond(200,dict(state=scan.get('analysis_completion',scan['state']),progress=100,stage='Report ready',report=scan,pipeline=scan.get('pipeline')))
                if job and not job.get('report'):return self.respond(200,job)
                return self.respond(404,{'error':'Scan not found or cleared from history'})
            if not scan:return self.respond(404,{'error':'Scan not found'})
            if sub=='dynamic':
                try:return self.respond(200,dynamic_manager().detail(id))
                except DynamicError as e:return self.respond(400,{'error':e.message,'code':e.code})
            if sub not in ('dynamic',) and scan.get('pipeline',{}).get('state')=='RUNNING':return self.respond(409,{'error':'Analysis is still running. The final report is not ready.'})
            if sub in ('report.json','report.html','report.sarif'):
                scan=export_report(scan,parse_qs(urlparse(self.path).query).get('include_screenshots',['false'])[0]=='true')
            if sub=='report.json':return self.respond(200,scan,extra={'Content-Disposition':f'attachment; filename="apktrust-{id}.json"'})
            if sub=='report.sarif':
                results=[dict(ruleId=f['rule'],level='error' if f['severity']=='high' else 'warning',message={'text':f['title']+': '+f['description']},locations=[{'physicalLocation':{'artifactLocation':{'uri':f['evidence'][0]['path']}}}],properties={'confidence':f['confidence'],'status':f['status']}) for f in scan['findings']]
                return self.respond(200,{'version':'2.1.0','$schema':'https://json.schemastore.org/sarif-2.1.0.json','runs':[{'tool':{'driver':{'name':'APKTrust','version':VERSION}},'results':results}]},extra={'Content-Disposition':f'attachment; filename="apktrust-{id}.sarif"'})
            if sub=='report.html':
                from reporting import html_report
                return self.respond(200,html_report(scan),'text/html; charset=utf-8',{'Content-Disposition':f'attachment; filename="apktrust-{id}.html"'})

            if sub in ('findings','coverage','inventory','endpoints','components','permissions','package_splits'):return self.respond(200,scan.get(sub,[]))
            return self.respond(200,scan)
        if p=='/favicon.ico':return self.respond(204,b'','image/x-icon')
        files={'/':'index.html','/app.js':'app.js','/style.css':'style.css','/dynamic.js':'dynamic.js'}
        if p in files:return self.respond(200,(ROOT/'web'/files[p]).read_bytes(),{'/':'text/html; charset=utf-8','/app.js':'text/javascript','/style.css':'text/css','/dynamic.js':'text/javascript'}[p])
        self.respond(404,{'error':'Not found'})
    def do_POST(self):
        # Same-origin + loopback Host prevent browser-based cross-site uploads / DNS rebinding.
        host=self.headers.get('Host','')
        if host not in (f'127.0.0.1:{self.server.server_port}',f'localhost:{self.server.server_port}') or self.headers.get('Origin') not in (None,f'http://{host}'):
            return self.respond(403,{'error':'Local same-origin requests only'})
        p=urlparse(self.path).path
        dynamic=re.fullmatch(r'/api/v1/scans/([a-f0-9]{12})/dynamic(?:/([a-f0-9]{32})/(cancel|artifact))?',p)
        if p=='/api/v1/dynamic/doctor':
            try:return self.respond(200,dynamic_manager().health(refresh=True))
            except DynamicError as e:return self.respond(400,{'error':e.message,'code':e.code})
        attach=re.fullmatch(r'/api/v1/scans/([a-f0-9]{12})/dynamic/artifact',p)
        if attach:
            scan=get_scan(attach[1])
            if not scan:return self.respond(404,{'error':'Scan not found'})
            try:length=int(self.headers.get('Content-Length','0'))
            except ValueError:return self.respond(400,{'error':'Invalid length'})
            if not 0<length<=MAX_UPLOAD:return self.respond(413,{'error':'APK must be at most 256 MiB'})
            DATA.mkdir(exist_ok=True);fd,path=tempfile.mkstemp(dir=DATA,suffix='.apk')
            try:
                self.connection.settimeout(30);remaining=length
                with os.fdopen(fd,'wb') as target:
                    while remaining:
                        chunk=self.rfile.read(min(1024*1024,remaining))
                        if not chunk:raise DynamicError('UPLOAD_FAILED','Local upload interrupted')
                        target.write(chunk);remaining-=len(chunk)
                dynamic_manager().attach(scan,path)
                return self.respond(200,{'retained_apk':True,'uploaded_to_cloud':False})
            except DynamicError as e:return self.respond(400,{'error':e.message,'code':e.code})
            finally:Path(path).unlink(missing_ok=True)
        if dynamic:
            id,job_id,operation=dynamic.groups()
            if not get_scan(id):return self.respond(404,{'error':'Scan not found'})
            try:
                n=int(self.headers.get('Content-Length','0'))
                if not 0<n<=4096:return self.respond(400,{'error':'Small JSON request required'})
                body=json.loads(self.rfile.read(n))
                if not isinstance(body,dict):raise ValueError()
                manager=dynamic_manager()
                if operation=='cancel':return self.respond(200,manager.cancel(job_id,id))
                if operation=='artifact':
                    artifact,raw,source_bytes=manager.read_artifact(id,job_id,body.get('artifact_id'),int(body.get('offset',0)),int(body.get('limit',65536)))
                    if artifact.type=='screenshot':
                        ctype='image/png' if raw.startswith(b'\x89PNG\r\n\x1a\n') else 'image/jpeg' if raw.startswith(b'\xff\xd8\xff') else None
                        if not ctype:raise DynamicError('RESULT_COLLECTION_FAILED','Unsupported screenshot encoding')
                        return self.respond(200,raw,ctype)
                    return self.respond(200,{'text':raw.decode('utf-8','replace'),'offset':int(body.get('offset',0)),'next_offset':int(body.get('offset',0))+source_bytes,'has_more':source_bytes>=min(int(body.get('limit',65536)),65536)})
                return self.respond(202,manager.start(id,body.get('provider','firebase_test_lab'),body.get('confirm_cloud_upload') is True))
            except DynamicError as e:return self.respond(400,{'error':e.message,'code':e.code,'static_analysis':'remains valid'})
            except (ValueError,TypeError):return self.respond(400,{'error':'Invalid dynamic request'})
        if p=='/api/v1/scans/clear-history':return self.respond(200,clear_history())
        restore=re.fullmatch(r'/api/v1/scans/restore-history/([a-f0-9]{32})',p)
        if restore:return self.respond(200,restore_history(restore[1]))
        test=re.fullmatch(r'/api/v1/providers/([a-z]+)/test',p)
        enrich=re.fullmatch(r'/api/v1/scans/([a-f0-9]{12})/(ai/explain|reputation|reputation/network)',p)
        if test or enrich:
            try:
                if test:return self.respond(200,integrations.test_provider(test[1]))
                scan=get_scan(enrich[1])
                if not scan:return self.respond(404,{'error':'Scan not found'})
                if scan.get('pipeline',{}).get('state')=='RUNNING':return self.respond(409,{'error':'Wait for the current investigation to finish before retrying enrichment'})
                field='ai_explanation' if enrich[2]=='ai/explain' else 'vt_network' if enrich[2]=='reputation/network' else 'reputation'
                result=integrations.explain(scan) if field=='ai_explanation' else integrations.vt_network(scan) if field=='vt_network' else integrations.reputation(scan)
                with connection() as c:
                    c.execute('BEGIN IMMEDIATE')
                    row=c.execute("SELECT report FROM scans WHERE id=? AND archive_batch=''",(scan['id'],)).fetchone()
                    if not row:return self.respond(404,{'error':'Scan was cleared during enrichment'})
                    current=json.loads(row[0])
                    current[field]=result
                    c.execute('UPDATE scans SET report=? WHERE id=?',(json.dumps(current),scan['id']))
                if field=='reputation' and any(row.get('provider')=='virustotal' and row.get('status')=='FOUND' for row in result.get('results',[])):
                    evidence=integrations.collect_vt_intelligence(get_scan(scan['id']))
                    update_scan(scan['id'],lambda r:r.update(vt_intelligence=evidence))
                return self.respond(200,result)
            except integrations.IntegrationError as e:return self.respond(400,{'error':str(e)})
        m=re.fullmatch(r'/api/v1/scans/([a-f0-9]{12})/findings/([A-Za-z0-9-]+)/review',p)
        if m:
            n=int(self.headers.get('Content-Length','0'))
            if n>4096:return self.respond(413,{'error':'Request too large'})
            try:body=json.loads(self.rfile.read(n))
            except Exception:return self.respond(400,{'error':'Invalid JSON'})
            scan=get_scan(m[1]); status=body.get('status')
            if not scan or status not in ('Needs review','Confirmed','Dismissed'):return self.respond(400,{'error':'Invalid review'})
            for f in scan['findings']:
                if f['id']==m[2]:f['status']=status;save(scan);return self.respond(200,f)
            return self.respond(404,{'error':'Finding not found'})
        if p!='/api/v1/scans':return self.respond(404,{'error':'Not found'})
        try:length=int(self.headers.get('Content-Length','0'))
        except ValueError:return self.respond(400,{'error':'Invalid length'})
        if length<=0 or length>MAX_UPLOAD:return self.respond(413,{'error':'Select a file up to 256 MiB'})
        query=parse_qs(urlparse(self.path).query)
        vt_upload=query.get('vt_upload',['false'])[0]=='true'
        if vt_upload and query.get('confirm_vt_upload',['false'])[0]!='true':return self.respond(400,{'error':'VirusTotal file upload requires explicit consent'})
        auto_dynamic=query.get('auto_dynamic',['false'])[0]=='true'
        if auto_dynamic and query.get('confirm_cloud_upload',['false'])[0]!='true':return self.respond(400,{'error':'Dynamic execution requires explicit cloud-upload consent'})
        filename=parse_qs(urlparse(self.path).query).get('filename',['sample.apk'])[0][:200]
        if Path(filename).suffix.lower() not in ('.apk','.xapk','.apks'):return self.respond(400,{'error':'Supported formats: APK, XAPK and APKS. AAB conversion is not supported yet'})
        if not slots.acquire(blocking=False):return self.respond(429,{'error':'Two scans are already running. Wait for a scan to finish.'})
        DATA.mkdir(exist_ok=True); fd,path=tempfile.mkstemp(suffix=Path(filename).suffix.lower(),dir=DATA)
        try:
            remaining=length; self.connection.settimeout(30)
            with os.fdopen(fd,'wb') as f:
                while remaining:
                    chunk=self.rfile.read(min(1024*1024,remaining))
                    if not chunk:raise ValueError('Upload interrupted')
                    f.write(chunk);remaining-=len(chunk)
        except Exception:
            Path(path).unlink(missing_ok=True);slots.release();return self.respond(400,{'error':'Upload interrupted'})
        id=uuid.uuid4().hex[:12];jobs[id]=dict(id=id,state='STATIC_ANALYSIS',stage='Intake & hashing',progress=10)
        retain=parse_qs(urlparse(self.path).query).get('retain_dynamic',['false'])[0]=='true'
        threading.Thread(target=worker,args=(id,path,filename,retain,parse_qs(urlparse(self.path).query).get("auto_ai",["false"])[0]=="true",parse_qs(urlparse(self.path).query).get("auto_reputation",["false"])[0]=="true",auto_dynamic,vt_upload),daemon=True).start();return self.respond(202,jobs[id])

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--port',type=int,default=8765);parser.add_argument('--worker');parser.add_argument('--filename',default='sample.apk');args=parser.parse_args()
    if args.worker:
        try:print(json.dumps(analyze(args.worker,args.filename)))
        except Exception as e:print(str(e),file=sys.stderr);sys.exit(1)
    else:
        connection().close();dynamic_manager().resume();recover_pipelines();print(f'APKTrust → http://127.0.0.1:{args.port}',flush=True)
        ThreadingHTTPServer(('127.0.0.1',args.port),Handler).serve_forever()
