import json,time,unittest
from unittest.mock import patch
import vt_intelligence as v
import integrations as m
class VTIntelligenceTests(unittest.TestCase):
 def test_collects_all_supported_categories_without_following_links(self):
  calls=[]
  def request(url,*args):
   calls.append(url)
   if url.endswith('/behaviour_summary'):return {'data':{'command_executions':['sh update.sh'],'mitre_attack_techniques':[{'id':'T1059'}],'password':'SECRET'}}
   if '/behaviours?' in url:return {'data':[{'attributes':{'sandbox_name':'Test sandbox','has_pcap':True}}]}
   if '?' in url:return {'data':[{'id':'example.invalid','type':'domain','attributes':{'last_analysis_stats':{'malicious':2}}}],'links':{'next':'https://attacker.invalid'}}
   return {'data':{'attributes':{'last_analysis_results':{'Engine':{'category':'malicious','result':'Example'}},'androguard':{'Package':'org.public.app'},'raw_source_code':'DO_NOT_SEND'}}}
  result=v.collect({'sha256':'a'*64},request,'KEY',interval=0)
  self.assertEqual(len(calls),11);self.assertEqual(len(result['groups']),11);self.assertEqual(result['status'],'COMPLETE');self.assertNotIn('attacker',json.dumps(calls));self.assertNotIn('SECRET',json.dumps(result));self.assertNotIn('DO_NOT_SEND',json.dumps(result));self.assertTrue(result['groups'][3]['truncated'])
 def test_rate_limit_stops_remaining_requests(self):
  def request(*_):raise m.IntegrationError('HTTP 429: limit')
  with patch('vt_intelligence.time.sleep') as sleep:result=v.collect({'sha256':'a'*64},request,'KEY',interval=16)
  sleep.assert_not_called();self.assertEqual(result['status'],'PARTIAL');self.assertEqual(result['groups'][0]['status'],'RATE_LIMITED');self.assertTrue(all(r['status']=='NOT_QUERIED' for r in result['groups'][1:]))
 def test_access_denied_keeps_other_evidence(self):
  def request(url,*_):
   if 'behaviour' in url:raise m.IntegrationError('HTTP 403: credential SECRET')
   return {'data':[] if '?' in url else {'attributes':{'tags':['android']}}}
  result=v.collect({'sha256':'a'*64},request,'KEY',interval=0)
  self.assertEqual(result['groups'][0]['status'],'AVAILABLE');self.assertEqual(result['groups'][1]['status'],'ACCESS_DENIED');self.assertNotIn('SECRET',json.dumps(result))
 def test_sanitizes_credentials_and_url_parameters(self):
  clean=v.sanitize({'url':'https://user:pass@example.invalid/path?token=private#fragment','command':'tool password=HIDDEN','headers':{'Authorization':'Bearer SECRET'},'known':'KEY'},['KEY'])
  encoded=json.dumps(clean);self.assertNotIn('HIDDEN',encoded);self.assertNotIn('Bearer',encoded);self.assertNotIn('private',encoded);self.assertNotIn('user:pass',encoded);self.assertEqual(clean['url'],'https://example.invalid/path')
 def test_ai_receives_every_category_with_sources_and_limits(self):
  collection={'groups':[{'id':'VT-FILE','label':'File','status':'AVAILABLE','data':{'androguard':{'Package':'org.public.app'},'names':['a.apk']*200}},{'id':'VT-BEHAVIOR-SUMMARY','label':'Behavior','status':'ACCESS_DENIED','data':{}}]}
  result=v.ai_evidence(collection)
  self.assertEqual(len(result['groups']),2);self.assertEqual(result['groups'][0]['source'],'VIRUSTOTAL_REPORT');self.assertTrue(result['groups'][0]['ai_detail_limited']);self.assertIn('org.public.app',json.dumps(result))
 def test_intelligence_report_sections_are_validated_and_saved(self):
  report={'findings':[],'coverage':[],'permissions':[],'vt_intelligence':{'groups':[{'id':'VT-FILE','label':'Metadata','status':'AVAILABLE','data':{'tags':['android']}}]}}
  response={'summary':'Limited evidence','findings':[],'sections':[{'title':'Detection assessment','text':'Collected VT metadata is available.','evidence_ids':['VT-FILE']}]}
  with patch.object(m,'config',return_value={'GROQ_API_KEY':'SECRET'}),patch.object(m,'ai_generate',return_value=(json.dumps(response),'model')) as generate:
   result=m.explain(report)
  self.assertEqual(result['sections'],response['sections']);self.assertTrue(result['input_scope']['vt_evidence']);self.assertIn('VT-FILE',generate.call_args.args[1]);self.assertIn('untrusted',generate.call_args.args[1])
