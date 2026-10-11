import unittest
from reporting import html_report
class ReportTests(unittest.TestCase):
 def test_untrusted_content_is_escaped(self):
  report=html_report({'package':'<script>alert(1)</script>','ai_explanation':{'provider':'local','summary':'<img src=x onerror=alert(1)>'},'findings':[{'id':'F-1','title':'<script>bad</script>','description':'unsafe <tag>'}]})
  self.assertNotIn('<script>',report);self.assertNotIn('<img',report);self.assertIn('&lt;script&gt;',report)
 def test_combined_sources_are_present_without_raw_json_dump(self):
  report=html_report({'package':'test','ai_explanation':{'provider':'groq','summary':'Combined intelligence','recommendations':['Review access checks']},'reputation':{'results':[{'provider':'virustotal','status':'FOUND','stats':{'undetected':66,'malicious':0}},{'provider':'urlhaus','status':'NOT_FOUND'}]},'dynamic_results':{'j':{'provider':'firebase_test_lab','status':'COMPLETED','coverage':'LIMITED','device':{'model':'virtual','version':'35'},'analysis_gaps':['Limited exploration']}}})
  for text in ('Combined intelligence','Review access checks','VirusTotal','URLhaus','firebase_test_lab','Limited exploration','0 / 66'):self.assertIn(text,report)
  self.assertNotIn('<pre>',report)

 def test_full_sections_and_vt_collection_export(self):
  report=html_report({'ai_explanation':{'sections':[{'title':'Detection assessment','text':'Escaped <script> evidence','evidence_ids':['VT-FILE']}]},'vt_intelligence':{'groups':[{'id':'VT-FILE','label':'File metadata','status':'AVAILABLE'}]}})
  self.assertIn('Detection assessment',report);self.assertIn('VT-FILE',report);self.assertIn('VirusTotal evidence collection',report);self.assertNotIn('<script>',report)
