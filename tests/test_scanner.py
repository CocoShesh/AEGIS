import importlib.util, tempfile, unittest, zipfile
from pathlib import Path
spec=importlib.util.spec_from_file_location('scanner',Path(__file__).resolve().parents[1]/'server.py');scanner=importlib.util.module_from_spec(spec);spec.loader.exec_module(scanner)
MANIFEST=b'''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="org.fixture.app" android:versionName="1.0"><uses-permission android:name="android.permission.INTERNET"/><application android:debuggable="true" android:usesCleartextTraffic="true"><activity android:name=".PublicActivity" android:exported="true"/></application></manifest>'''
class ScannerTests(unittest.TestCase):
 def run_sample(self,entries):
  with tempfile.TemporaryDirectory() as d:
   path=Path(d)/'fixture.apk'
   with zipfile.ZipFile(path,'w') as z:
    for name,body in entries:z.writestr(name,body)
   return scanner.analyze(str(path),'fixture.apk')
 def test_real_metadata_and_evidence(self):
  r=self.run_sample([('AndroidManifest.xml',MANIFEST),('classes.dex',b'dex\n035\x00DexClassLoader https://example.test/api')])
  self.assertEqual(r['package'],'org.fixture.app');self.assertEqual(r['state'],'PARTIAL');self.assertEqual(r['confidence'],'Low')
  self.assertEqual(r['risk'],'High');self.assertTrue(any(f['rule']=='debuggable' for f in r['findings']))
  f=next(f for f in r['findings'] if f['rule']=='dynamic-loader');self.assertEqual(f['confidence'],'Low');self.assertEqual(f['evidence'][0]['sha256'],r['sha256'])
  self.assertEqual(r['endpoints'][0]['host'],'example.test');self.assertTrue(any(c['status']=='Not run' for c in r['coverage']))
 def test_zip_slip_rejected(self):
  with self.assertRaisesRegex(ValueError,'Unsafe archive path'):self.run_sample([('AndroidManifest.xml',MANIFEST),('../escape',b'bad')])
 def test_duplicate_rejected(self):
  with self.assertRaisesRegex(ValueError,'Duplicate'):self.run_sample([('AndroidManifest.xml',MANIFEST),('classes.dex',b'a'),('classes.dex',b'b')])
 def test_no_manifest_rejected(self):
  with self.assertRaisesRegex(ValueError,'must contain'):self.run_sample([('payload.txt',b'a')])
 def test_failed_manifest_cannot_claim_complete(self):
  r=self.run_sample([('AndroidManifest.xml',b'bad binary data')]);self.assertEqual(r['risk'],'Inconclusive');self.assertTrue(any(c['name']=='Manifest & permissions' and c['status']=='Failed' for c in r['coverage']))
 def test_large_entry_recorded_as_skipped(self):
  r=self.run_sample([('AndroidManifest.xml',MANIFEST),('classes.dex',b'x'*(scanner.MAX_ENTRY+1))]);item=next(i for i in r['inventory'] if i['kind']=='DEX');self.assertEqual(item['status'],'Skipped');self.assertTrue(any(c['status']=='Partial' for c in r['coverage']))
 def test_hostile_manifest_strings_are_data(self):
  xml=MANIFEST.replace(b'org.fixture.app',b'&lt;script&gt;alert(1)&lt;/script&gt;');r=self.run_sample([('AndroidManifest.xml',xml)]);self.assertEqual(r['package'],'<script>alert(1)</script>')
 def test_compression_bomb_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   path=Path(d)/'bomb.apk'
   with zipfile.ZipFile(path,'w',compression=zipfile.ZIP_DEFLATED) as z:
    z.writestr('AndroidManifest.xml',MANIFEST);z.writestr('classes.dex',b'x'*(2*1024**2))
   with self.assertRaisesRegex(ValueError,'compression ratio'):scanner.analyze(str(path),'bomb.apk')
 def test_symlink_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   path=Path(d)/'link.apk'
   with zipfile.ZipFile(path,'w') as z:
    z.writestr('AndroidManifest.xml',MANIFEST)
    info=zipfile.ZipInfo('link');info.create_system=3;info.external_attr=(0o120777<<16);z.writestr(info,'/etc/passwd')
   with self.assertRaisesRegex(ValueError,'symlink'):scanner.analyze(str(path),'link.apk')
 def test_binary_manifest(self):
  import struct
  strings=['manifest','package','org.binary.fixture'];payload=b'';offsets=[]
  for s in strings:
   offsets.append(len(payload));raw=s.encode();payload+=bytes([len(s),len(raw)])+raw+b'\0'
  payload+=b'\0'*((-len(payload))%4)
  pool=struct.pack('<HHIIIIII',1,28,28+len(strings)*4+len(payload),len(strings),0,0x100,28+len(strings)*4,0)+struct.pack('<III',*offsets)+payload
  attr=struct.pack('<IIIHBBI',0xffffffff,1,2,8,0,3,2)
  start=struct.pack('<HHIII',0x102,16,56,1,0xffffffff)+struct.pack('<IIHHHHHH',0xffffffff,0,20,20,1,0,0,0)+attr
  end=struct.pack('<HHIIIII',0x103,16,24,1,0xffffffff,0xffffffff,0)
  data=struct.pack('<HHI',3,8,8+len(pool)+len(start)+len(end))+pool+start+end
  r=self.run_sample([('AndroidManifest.xml',data)]);self.assertEqual(r['package'],'org.binary.fixture');self.assertTrue(any(c['name']=='Manifest & permissions' and c['status']=='Complete' for c in r['coverage']))
if __name__=='__main__':unittest.main()
