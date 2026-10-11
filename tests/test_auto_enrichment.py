import json,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from test_scanner import scanner

class AutomaticEnrichmentTests(unittest.TestCase):
 def run_worker(self,ai=True,intel=True,fail=False):
  with tempfile.TemporaryDirectory() as td,patch.object(scanner,'DATA',Path(td)),patch.object(scanner,'jobs',{}):
   path=Path(td)/'fixture.apk';path.write_bytes(b'fixture')
   scanid='123456789abc';scanner.jobs[scanid]={'progress':10}
   static={'findings':[{'id':'F-1','evidence':[{'source':'STATIC'}]}],'limitations':[]}
   with patch.object(scanner.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout=json.dumps(static))),patch.object(scanner.integrations,'explain',side_effect=RuntimeError('secret') if fail else None,return_value={'provider':'groq','summary':'Mock explanation','findings':[]}) as explain,patch.object(scanner.integrations,'reputation',return_value={'results':[{'provider':'virustotal','status':'NOT_FOUND'},{'provider':'urlhaus','status':'NOT_FOUND'}]}) as reputation:
    scanner.slots.acquire();scanner.worker(scanid,str(path),'fixture.apk',auto_ai=ai,auto_reputation=intel)
    report=scanner.get_scan(scanid)
    self.assertEqual(explain.call_count,int(ai));self.assertEqual(reputation.call_count,int(intel))
    self.assertEqual(report['findings'],static['findings']);self.assertEqual(scanner.jobs[scanid]['progress'],100)
    self.assertFalse(path.exists());return report
 def test_selected_requests_are_saved(self):
  r=self.run_worker();self.assertEqual(r['ai_explanation']['provider'],'groq');self.assertEqual(len(r['reputation']['results']),2)
 def test_opt_out_makes_no_external_requests(self):
  r=self.run_worker(False,False);self.assertNotIn('ai_explanation',r);self.assertNotIn('reputation',r)
 def test_ai_failure_does_not_stop_reputation_or_static(self):
  r=self.run_worker(fail=True);self.assertEqual(r['ai_explanation']['status'],'FAILED');self.assertIn('reputation',r);self.assertNotIn('secret',json.dumps(r))
