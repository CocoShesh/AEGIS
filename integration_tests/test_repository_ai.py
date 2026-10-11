import json
import unittest
from unittest.mock import patch
from fastapi.testclient import TestClient
import sentinel
import repository_ai

class RepositoryAI(unittest.TestCase):
 def test_consent_and_session_required(self):
  client=TestClient(sentinel.app)
  self.assertEqual(client.post('/repository/api/scans/x/ai/explain',json={'consent':True}).status_code,403)
  token=client.get('/repository/api/session').json()['token']
  self.assertEqual(client.post('/repository/api/scans/x/ai/explain',json={'consent':False},headers={'X-Reposentinel-Token':token}).status_code,422)
 def test_bounded_summary_uses_shared_provider_without_source(self):
  r={'findings':[{'id':'f1','title':'Suspicious process execution','severity':'HIGH','path':'private/file.py','snippet':'PRIVATE_SOURCE'}],'files':[{'content':'PRIVATE_SOURCE'}],'coverage':{'percent':70},'limitations':['Static only']}
  response={'summary':'Review the process execution finding.','highlights':[],'recommendations':['Inspect the evidence.'],'uncertainties':['Runtime behavior unknown.']}
  with patch.object(repository_ai,'providers',return_value=[{'id':'groq','configured':True}]),patch.object(repository_ai.integrations,'ai_generate',return_value=(json.dumps(response),'test-model')) as generate:
   result=repository_ai.explain(r)
  prompt=generate.call_args.args[1]
  self.assertNotIn('PRIVATE_SOURCE',prompt)
  self.assertNotIn('private/file.py',prompt)
  self.assertEqual(result['provider'],'groq')
 def test_no_provider_preserves_clear_failure(self):
  with patch.object(repository_ai,'providers',return_value=[]):
   with self.assertRaisesRegex(ValueError,'No configured AI provider'):repository_ai.explain({})

 def test_assessment_confidence_is_validated_and_uses_full_counts(self):
  report={'findings':[{'id':str(i),'title':'Fixture','severity':'high'} for i in range(90)]}
  response={'assessment':'REVIEW_REQUIRED','confidence':'MEDIUM','confidence_reason':'Evidence is limited by static coverage.','summary':'Review these findings.','highlights':[],'recommendations':[],'uncertainties':[]}
  with patch.object(repository_ai,'providers',return_value=[{'id':'groq','configured':True}]),patch.object(repository_ai.integrations,'ai_generate',return_value=(json.dumps(response),'test-model')) as generate:
   result=repository_ai.explain(report)
  self.assertEqual(result['confidence'],'MEDIUM')
  evidence=json.loads(generate.call_args.args[1].split('Evidence: ',1)[1])
  self.assertEqual(evidence['finding_counts']['high'],90)
  self.assertEqual(evidence['findings_supplied'],80)
  response['confidence']='100%'
  with patch.object(repository_ai,'providers',return_value=[{'id':'groq','configured':True}]),patch.object(repository_ai.integrations,'ai_generate',return_value=(json.dumps(response),'test-model')):
   with self.assertRaises(ValueError):repository_ai.explain(report)

 def test_unsupported_text_review_redacts_and_keeps_gaps(self):
  report={'files':[{'id':'a','path':'private/index.html','status':'UNSUPPORTED','source':'<p>Hello</p>'},{'id':'b','path':'binary','status':'UNSUPPORTED','source':None},{'id':'c','path':'large.css','status':'UNSUPPORTED','source':'x'*9000}]}
  response={'files':[{'id':id,'assessment':'INCONCLUSIVE','confidence':'LOW','summary':'Static text purpose.','limitations':'Runtime unknown.'} for id in ('a','c')]}
  with patch.object(repository_ai,'providers',return_value=[{'id':'groq','configured':True}]),patch.object(repository_ai.integrations,'ai_generate',return_value=(json.dumps(response),'fixture')) as generate:
   result=repository_ai.review_unsupported(report)
  self.assertEqual([x['status'] for x in result],['COMPLETED','SKIPPED','PARTIAL'])
  self.assertNotIn('private/index.html',generate.call_args.args[1])
  self.assertIn('<p>Hello</p>',generate.call_args.args[1])
  self.assertEqual(report['files'][0]['status'],'UNSUPPORTED')
  response['files'][0]['id']='invented'
  with patch.object(repository_ai,'providers',return_value=[{'id':'groq','configured':True}]),patch.object(repository_ai.integrations,'ai_generate',return_value=(json.dumps(response),'fixture')):
   result=repository_ai.review_unsupported(report)
  self.assertEqual(result[0]['status'],'FAILED')

 def test_text_review_budget_accounts_for_every_object(self):
  report={'files':[{'id':str(i),'status':'UNSUPPORTED','source':'x'*8000} for i in range(30)]}
  with patch.object(repository_ai,'providers',return_value=[]):result=repository_ai.review_unsupported(report)
  self.assertEqual(len(result),30)
  self.assertEqual(sum(x['status']=='SKIPPED' for x in result),24)
