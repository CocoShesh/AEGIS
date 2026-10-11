import json,sqlite3,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from test_scanner import scanner,MANIFEST
import zipfile
class HistoryTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.patch=patch.object(scanner,'DATA',self.root);self.patch.start()
  self.jobs=patch.object(scanner,'jobs',{});self.jobs.start()
 def tearDown(self):self.jobs.stop();self.patch.stop();self.temp.cleanup()
 def report(self,id):return {'id':id,'state':'PARTIAL','findings':[],'filename':'fixture.apk'}
 def test_migration_preserves_existing_reports(self):
  with sqlite3.connect(self.root/'scans.sqlite3') as c:c.execute('CREATE TABLE scans (id TEXT PRIMARY KEY,report TEXT NOT NULL)');c.execute('INSERT INTO scans VALUES (?,?)',('a',json.dumps(self.report('a'))))
  self.assertEqual(scanner.get_scan('a')['filename'],'fixture.apk')
 def test_clear_and_undo(self):
  scanner.save(self.report('a'));scanner.save(self.report('b'));result=scanner.clear_history()
  self.assertEqual(result['cleared'],2);self.assertIsNone(scanner.get_scan('a'));self.assertEqual(scanner.restore_history(result['undo_token'])['restored'],2);self.assertIsNotNone(scanner.get_scan('a'))
 def test_clear_keeps_new_scans_and_running_jobs(self):
  scanner.save(self.report('a'));scanner.jobs['running']={'progress':30};scanner.jobs['a']={'progress':100,'report':self.report('a')}
  result=scanner.clear_history();scanner.save(self.report('b'))
  self.assertIn('running',scanner.jobs);self.assertNotIn('a',scanner.jobs);self.assertIsNotNone(scanner.get_scan('b'))
  scanner.restore_history(result['undo_token']);self.assertIsNotNone(scanner.get_scan('b'))
 def test_save_does_not_resurrect_cleared_record(self):
  scanner.save(self.report('a'));scanner.clear_history();scanner.save(self.report('a'));self.assertIsNone(scanner.get_scan('a'))
 def test_undo_only_its_batch(self):
  scanner.save(self.report('a'));first=scanner.clear_history();scanner.save(self.report('b'));second=scanner.clear_history();scanner.restore_history(second['undo_token'])
  self.assertIsNone(scanner.get_scan('a'));self.assertIsNotNone(scanner.get_scan('b'))
 def test_identical_uploads_generate_different_runs(self):
  p=self.root/'fixture.apk'
  with zipfile.ZipFile(p,'w') as z:z.writestr('AndroidManifest.xml',MANIFEST)
  first=scanner.analyze(str(p),p.name);first['findings'][0]['status']='Dismissed';second=scanner.analyze(str(p),p.name)
  self.assertNotEqual(first['id'],second['id']);self.assertEqual(first['sha256'],second['sha256']);self.assertEqual(second['findings'][0]['status'],'Needs review')
 def test_worker_reanalyzes_same_bytes(self):
  reports=[]
  fixture=self.root/'fixture-source.apk'
  with zipfile.ZipFile(fixture,'w') as z:z.writestr('AndroidManifest.xml',MANIFEST)
  fixture_bytes=fixture.read_bytes()
  for id in ('111111111111','222222222222'):
   p=self.root/'upload.apk'
   p.write_bytes(fixture_bytes)
   scanner.jobs[id]={'progress':10,'state':'STATIC_ANALYSIS'}
   scanner.slots.acquire()
   scanner.worker(id,str(p),'upload.apk')
   r=scanner.get_scan(id)
   self.assertIsNotNone(r);self.assertFalse(r['cache_used']);self.assertEqual(r['execution'],'Fresh analyzer subprocess');self.assertFalse(p.exists());reports.append(r)
  self.assertEqual(reports[0]['sha256'],reports[1]['sha256']);self.assertNotEqual(reports[0]['id'],reports[1]['id']);self.assertGreater(reports[1]['analysis_started_at'],reports[0]['analysis_started_at'])
if __name__=='__main__':unittest.main()
