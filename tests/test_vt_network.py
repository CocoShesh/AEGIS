import unittest
from unittest.mock import patch
import integrations as m
class VTNetworkTests(unittest.TestCase):
 def test_bounded_read_only_relationships(self):
  responses={'data':[{'id':'example.invalid','attributes':{'last_analysis_stats':{'malicious':2},'country':'ZZ'}}]*45,'links':{'next':'https://untrusted.invalid'}}
  with patch.object(m,'config',return_value={'VT_API_KEY':'SECRET'}),patch.object(m,'request_json',return_value=responses) as request:
   result=m.vt_network({'sha256':'a'*64})
  self.assertEqual(request.call_count,3)
  self.assertEqual(len(result['relationships'][0]['items']),40)
  self.assertTrue(result['relationships'][0]['truncated'])
  self.assertNotIn('SECRET',str(result))
  for call in request.call_args_list:
   self.assertEqual(len(call.args),3);self.assertIn('/files/'+'a'*64+'/',call.args[0]);self.assertIn('?limit=40',call.args[0])
 def test_rate_limit_stops_requests(self):
  with patch.object(m,'config',return_value={'VT_API_KEY':'SECRET'}),patch.object(m,'request_json',side_effect=m.IntegrationError('HTTP 429: quota')) as request:
   result=m.vt_network({'sha256':'a'*64})
  self.assertEqual(request.call_count,1);self.assertEqual([r['status'] for r in result['relationships']],['RATE_LIMITED','NOT_QUERIED','NOT_QUERIED'])
 def test_denied_is_not_empty_or_clean(self):
  with patch.object(m,'config',return_value={'VT_API_KEY':'SECRET'}),patch.object(m,'request_json',side_effect=m.IntegrationError('HTTP 403: SECRET')):
   result=m.vt_network({'sha256':'a'*64})
  self.assertEqual(result['relationships'][0]['status'],'ACCESS_DENIED');self.assertNotIn('SECRET',str(result))
 def test_hash_validation_and_no_key(self):
  with patch.object(m,'request_json') as request:
   with self.assertRaises(m.IntegrationError):m.vt_network({'sha256':'../../escape'})
   with patch.object(m,'config',return_value={}):
    with self.assertRaises(m.IntegrationError):m.vt_network({'sha256':'a'*64})
   request.assert_not_called()
