import json, tempfile, unittest, sys
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import integrations as m
CFG={'GROQ_API_KEY':'secret-g','OPENROUTER_API_KEY':'secret-o','GEMINI_API_KEY':'secret-m','URLHAUS_AUTH_KEY':'secret-u','VT_API_KEY':'secret-v'}
REPORT={'sha256':'a'*64,'coverage_percent':33,'coverage':[{'status':'Not run'}],'package':'PRIVATE_PACKAGE','findings':[{'id':'F-001','rule':'debuggable','severity':'high','confidence':'High','description':'Local explanation','evidence':[{'snippet':'SECRET_SNIPPET'}]}],'package_splits':[]}
class IntegrationsTests(unittest.TestCase):
 def setUp(self):m.circuits.clear();m.last.clear()
 def test_status_does_not_expose_keys(self):
  with patch.object(m,'config',return_value=CFG):data=json.dumps(m.statuses())
  self.assertNotIn('secret-',data);self.assertIn('GROQ_API_KEY',data)
 def test_env_file_no_shell_expansion(self):
  with tempfile.TemporaryDirectory() as td,patch.object(m,'ROOT',Path(td)),patch.dict(m.os.environ,{},clear=True):
   (Path(td)/'.env').write_text('GROQ_API_KEY="$(echo secret)"\nNOT_ALLOWED=bad\nGROQ_MODEL=some-model\n')
   self.assertEqual(m.config()['GROQ_API_KEY'],'$(echo secret)');self.assertNotIn('NOT_ALLOWED',m.config())
 def test_failover_and_minimal_payload(self):
  calls=[]
  def generate(id,prompt):
   calls.append((id,prompt))
   if id=='groq':raise m.IntegrationError('Quota')
   return json.dumps({'summary':'Review coverage','findings':[{'id':'F-001','explanation':'Review manifest'}]}),'model'
  with patch.object(m,'config',return_value=CFG),patch.object(m,'ai_generate',side_effect=generate),patch.object(m.time,'sleep'):r=m.explain(REPORT)
  self.assertEqual(r['provider'],'openrouter');self.assertEqual([c[0] for c in calls],['groq','groq','openrouter'])
  self.assertNotIn('PRIVATE_PACKAGE',calls[0][1]);self.assertNotIn('SECRET_SNIPPET',calls[0][1]);self.assertNotIn('secret-',calls[0][1])
 def test_all_failed_local_fallback(self):
  with patch.object(m,'config',return_value=CFG),patch.object(m,'ai_generate',side_effect=m.IntegrationError('fail')),patch.object(m.time,'sleep'):r=m.explain(REPORT)
  self.assertEqual(r['provider'],'local');self.assertEqual(len(r['errors']),3)
 def test_unknown_evidence_reference_rejected(self):
  with patch.object(m,'config',return_value=CFG),patch.object(m,'ai_generate',return_value=(json.dumps({'summary':'bad','findings':[{'id':'F-999','explanation':'invented'}]}),'model')),patch.object(m.time,'sleep'):r=m.explain(REPORT)
  self.assertEqual(r['provider'],'local')
 def test_token_exhaustion_not_success(self):
  with patch.object(m,'config',return_value=CFG),patch.object(m,'request_json',return_value={'choices':[{'message':{'content':''},'finish_reason':'length'}]}):
   with self.assertRaisesRegex(m.IntegrationError,'budget exhausted'):m.ai_generate('groq','test')
 def test_generation_probe_pass(self):
  with patch.object(m,'config',return_value=CFG),patch.object(m,'ai_generate',return_value=('APKTRUST_OK','model')):r=m.test_provider('groq')
  self.assertEqual(r['status'],'PASS')
 def test_vt_404_is_unconfirmed(self):
  with patch.object(m,'config',return_value=CFG),patch.object(m,'request_json',side_effect=m.IntegrationError('HTTP 404: not found')):r=m.test_provider('virustotal')
  self.assertEqual(r['status'],'UNCONFIRMED')
 def test_reputation_only_hash_no_submission(self):
  calls=[]
  def request(url,header,key,data=None,form=False):
   calls.append((url,header,key,data));return {'query_status':'no_results'} if 'urlhaus' in url else {'data':{'attributes':{'last_analysis_stats':{'malicious':0}}}}
  with patch.object(m,'config',return_value=CFG),patch.object(m,'request_json',side_effect=request):r=m.reputation(REPORT)
  self.assertIn('/api/v3/files/'+REPORT['sha256'],calls[0][0]);self.assertEqual(calls[1][3],{'sha256_hash':REPORT['sha256']});self.assertEqual(r['results'][1]['status'],'NOT_FOUND');self.assertNotIn('SECRET_SNIPPET',json.dumps(calls))
 def test_disabled_means_no_requests(self):
  with patch.object(m,'config',return_value={}),patch.object(m,'request_json') as request:m.reputation(REPORT);r=m.explain(REPORT);request.assert_not_called()
  self.assertEqual(r['provider'],'local')
 def test_circuit_skips_failed_provider(self):
  m.circuits['groq']={'failures':3,'until':m.time.time()+60}
  with patch.object(m,'config',return_value=CFG),patch.object(m,'ai_generate',return_value=('{"summary":"ok","findings":[]}','model')) as generate:r=m.explain(REPORT)
  self.assertEqual(r['provider'],'openrouter');self.assertEqual(generate.call_args.args[0],'openrouter')
 def test_provider_error_is_visible_and_secret_redacted(self):
  with patch.object(m,'config',return_value=CFG),patch.object(m,'ai_generate',side_effect=m.IntegrationError('HTTP 401: secret-g authentication rejected')),patch.object(m.time,'sleep'):
   r=m.explain(REPORT)
  self.assertIn('HTTP 401',r['errors'][0]['error']);self.assertNotIn('secret-g',json.dumps(r))
 def test_intelligence_combines_sources_without_private_content(self):
  import copy
  report=copy.deepcopy(REPORT)
  report['permissions']=['android.permission.RECORD_AUDIO','private.permission.SECRET']
  report['reputation']={'results':[{'provider':'virustotal','status':'FOUND','stats':{'malicious':2,'undetected':60},'detail':'SECRET_ERROR'}]}
  report['dynamic_results']={'job':{'status':'COMPLETED','coverage':'LIMITED','observations':[{'type':'APP_STARTED','summary':'PRIVATE_RUNTIME_TEXT'}],'analysis_gaps':['SECRET_GAP']}}
  data=m.intelligence_input(report);encoded=json.dumps(data)
  self.assertEqual(data['reputation'][0]['engine_counts']['malicious'],2);self.assertEqual(data['dynamic'][0]['observation_counts']['APP_STARTED'],1)
  for value in ('SECRET_ERROR','PRIVATE_RUNTIME_TEXT','SECRET_GAP','PRIVATE_PACKAGE','SECRET_SNIPPET','private.permission.SECRET'):self.assertNotIn(value,encoded)
 def test_inventory_and_network_scope_are_aggregated_without_identifiers(self):
  import copy
  report=copy.deepcopy(REPORT);report.update(format='APK',min_sdk=23,target_sdk=35,components=[{'name':'PRIVATE_ACTIVITY','exported':'true'}],endpoints=[{'scheme':'http','host':'PRIVATE_HOST','url':'http://PRIVATE_HOST/SECRET'}],inventory=[{'path':'PRIVATE_FILE','status':'Indexed'}])
  data=m.intelligence_input(report);encoded=json.dumps(data)
  self.assertEqual(data['static_metadata']['endpoint_scheme_counts'],{'http':1});self.assertEqual(data['static_metadata']['indexed_or_parsed_files'],1)
  for value in ('PRIVATE_ACTIVITY','PRIVATE_HOST','PRIVATE_FILE','SECRET'):self.assertNotIn(value,encoded)
 def test_structured_synthesis_sections_are_saved(self):
  value={'summary':'Combined intelligence','findings':[],'highlights':['Runtime coverage is limited'],'recommendations':['Review permissions'],'uncertainties':['Authentication not reached']}
  with patch.object(m,'config',return_value=CFG),patch.object(m,'ai_generate',return_value=(json.dumps(value),'model')):result=m.explain(REPORT)
  self.assertEqual(result['highlights'],value['highlights']);self.assertEqual(result['recommendations'],value['recommendations'])
if __name__=='__main__':unittest.main()
