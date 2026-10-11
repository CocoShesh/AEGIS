import io, tempfile, unittest, zipfile
from pathlib import Path
from unittest.mock import patch
from test_scanner import scanner, MANIFEST

def apk(manifest=MANIFEST, code=b''):
 b=io.BytesIO()
 with zipfile.ZipFile(b,'w') as z:
  z.writestr('AndroidManifest.xml',manifest)
  if code:z.writestr('classes.dex',code)
 return b.getvalue()

class PackageSetTests(unittest.TestCase):
 def run_container(self,entries,ext='xapk'):
  with tempfile.TemporaryDirectory() as d:
   path=Path(d)/('fixture.'+ext)
   with zipfile.ZipFile(path,'w') as z:
    for name,data in entries:z.writestr(name,data)
   return scanner.analyze(str(path),path.name)
 def test_base_split_and_obb_coverage(self):
  split=MANIFEST.replace(b'package="',b'split="config.arm64_v8a" package="').replace(b'android:debuggable="true"',b'android:debuggable="false"')
  r=self.run_container([('base.apk',apk()),('splits/arm64.apk',apk(split,b'DexClassLoader https://split.test/v1')),('Android/obb/main.1.org.fixture.app.obb',b'opaque'),('manifest.json',b'{"package_name":"not.authoritative"}')])
  self.assertEqual(r['package'],'org.fixture.app');self.assertEqual(r['format'],'XAPK');self.assertEqual(len(r['package_splits']),2)
  self.assertEqual(r['package_splits'][0]['role'],'Base');self.assertEqual(r['package_splits'][1]['role'],'Split')
  f=next(f for f in r['findings'] if f['rule']=='dynamic-loader');self.assertEqual(f['component'],'splits/arm64.apk');self.assertTrue(f['evidence'][0]['path'].startswith('splits/arm64.apk!/'))
  self.assertNotEqual(f['evidence'][0]['sha256'],r['sha256']);self.assertEqual(f['evidence'][0]['container_sha256'],r['sha256'])
  self.assertTrue(any(c['name']=='OBB / container asset content' and c['status']=='Not run' for c in r['coverage']))
  self.assertEqual(r['state'],'PARTIAL');self.assertEqual(len({f['id'] for f in r['findings']}),len(r['findings']))
 def test_apks(self):
  r=self.run_container([('standalones/base.apk',apk())],'apks');self.assertEqual(r['format'],'APKS');self.assertEqual(len(r['package_splits']),1)
 def test_corrupt_split_keeps_good_base(self):
  r=self.run_container([('base.apk',apk()),('bad.apk',b'not zip')]);self.assertEqual(r['package'],'org.fixture.app');self.assertEqual(r['package_splits'][1]['status'],'Failed');self.assertTrue(r['findings'])
  self.assertTrue(any(c['name']=='APK component intake' and c['status']=='Partial' for c in r['coverage']))
 def test_nested_traversal_is_failed_component(self):
  b=io.BytesIO()
  with zipfile.ZipFile(b,'w') as z:z.writestr('AndroidManifest.xml',MANIFEST);z.writestr('../evil',b'a')
  r=self.run_container([('bad.apk',b.getvalue())]);self.assertEqual(r['package_splits'][0]['status'],'Failed');self.assertIn('Unsafe archive path',r['package_splits'][0]['error'])
 def test_outer_traversal_rejected(self):
  with self.assertRaisesRegex(ValueError,'Unsafe archive path'):self.run_container([('../bad.apk',apk())])
 def test_no_apks_rejected(self):
  with self.assertRaisesRegex(ValueError,'no APK components'):self.run_container([('manifest.json',b'{}')])
 def test_mixed_packages_not_one_identity(self):
  r=self.run_container([('base.apk',apk()),('other.apk',apk(MANIFEST.replace(b'org.fixture.app',b'org.other.app')))])
  self.assertEqual(r['package'],'Unknown package');self.assertTrue(any('Mixed package' in l for l in r['limitations']))
 def test_shared_index_budget(self):
  cap=len(MANIFEST)+8
  with patch.object(scanner,'MAX_TOTAL',cap):r=self.run_container([('base.apk',apk(MANIFEST,b'DexClassLoader')),('split.apk',apk(MANIFEST,b'addJavascriptInterface'))])
  self.assertFalse(any(f['rule'] in ('dynamic-loader','webview-bridge') for f in r['findings']))
  self.assertTrue(any(i['status']=='Skipped' and i.get('component')=='split.apk' for i in r['inventory']))
 def test_apk_limit(self):
  with self.assertRaisesRegex(ValueError,'128 APK'):self.run_container([(f'{i}.apk',b'') for i in range(129)])
 def test_failed_manifest_preserves_unknown_role(self):
  r=self.run_container([('base.apk',apk(b'bad'))]);self.assertEqual(r['package_splits'][0]['role'],'Unknown');self.assertTrue(any(c['status']=='Failed' for c in r['coverage']))
if __name__=='__main__':unittest.main()
