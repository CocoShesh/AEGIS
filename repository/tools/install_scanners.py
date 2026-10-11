"""Install checksum-pinned official Linux x86_64 scanner binaries locally (no root)."""
import concurrent.futures,hashlib,io,json,os,platform,tarfile,urllib.request,time
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
LOCK=json.loads((ROOT/'tools/scanners.lock.json').read_text())
DEST=ROOT/'.tools/bin'
def install(item):
 name,spec=item;dest=DEST/spec['binary']
 if platform.machine() not in ('x86_64','amd64') or platform.system()!='Linux':raise RuntimeError('Pinned assets are Linux x86_64 only')
 req=urllib.request.Request(spec['url'],headers={'User-Agent':'AEGIS-local-scanner-setup'})
 deadline=time.monotonic()+180
 with urllib.request.urlopen(req,timeout=20) as r:
  data=bytearray()
  while True:
   if time.monotonic()>deadline:raise TimeoutError('Release download exceeded 180 seconds; retry setup')
   block=r.read(256*1024)
   if not block:break
   data.extend(block)
   if len(data)>200*1024*1024:raise RuntimeError('Release asset exceeds 200 MB')
 data=bytes(data)
 if len(data)>200*1024*1024:raise RuntimeError('Release asset exceeds 200 MB')
 if hashlib.sha256(data).hexdigest()!=spec['sha256']:raise RuntimeError('Checksum mismatch: '+name)
 if spec['url'].endswith('.tar.gz'):
  with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as tar:
   member=next(x for x in tar.getmembers() if x.isfile() and Path(x.name).name==spec['binary'])
   if member.size>400*1024*1024:raise RuntimeError('Binary exceeds size limit')
   data=tar.extractfile(member).read()
 DEST.mkdir(parents=True,exist_ok=True);temp=dest.with_suffix('.tmp');temp.write_bytes(data);temp.chmod(0o755);temp.replace(dest)
 return name+' '+spec['version']+' installed (SHA-256 verified)'
if __name__=='__main__':
 with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
  for result in pool.map(install,LOCK.items()):print(result,flush=True)
 (DEST.parent/'installed.json').write_text(json.dumps(LOCK,indent=2))
