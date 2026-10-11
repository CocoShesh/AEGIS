import json,unittest,tempfile
from pathlib import Path
from unittest.mock import patch,Mock
import integrations as m
from vt_keys import VTKeyPool,configured_keys

class VTKeyTests(unittest.TestCase):
 def setUp(self):self.now=1000;self.pool=VTKeyPool(lambda:self.now);self.cfg={'VT_API_KEY':'first-secret','VT_API_KEY_2':'second-secret','VT_API_KEY_3':'third-secret'}
 def test_quota_fallback_and_cooldown(self):
  calls=[]
  def call(key):
   calls.append(key)
   if key=='first-secret':raise m.IntegrationError('HTTP 429: quota',429,60)
   return 'ok'
  self.assertEqual(self.pool.run(configured_keys(self.cfg),call,m.IntegrationError),'ok')
  self.assertEqual(calls,['first-secret','second-secret']);calls.clear()
  self.pool.run(configured_keys(self.cfg),call,m.IntegrationError)
  self.assertEqual(calls,['second-secret']);self.assertEqual(self.pool.snapshot(configured_keys(self.cfg))[0]['status'],'COOLDOWN')
  self.now+=61;self.assertEqual(self.pool.snapshot(configured_keys(self.cfg))[0]['status'],'AVAILABLE')
 def test_duplicate_keys_do_not_multiply_quota(self):
  self.assertEqual(configured_keys({'VT_API_KEY':'same','VT_API_KEY_2':'same','VT_API_KEY_3':'same'}),['same'])
 def test_all_limited_is_bounded_and_redacted(self):
  call=Mock(side_effect=m.IntegrationError('HTTP 429: quota'))
  with self.assertRaisesRegex(m.IntegrationError,'HTTP 429') as error:self.pool.run(configured_keys(self.cfg),call,m.IntegrationError)
  self.assertEqual(call.call_count,3);self.assertNotIn('secret',str(error.exception));call.reset_mock()
  with self.assertRaises(m.IntegrationError):self.pool.run(configured_keys(self.cfg),call,m.IntegrationError)
  call.assert_not_called()
 def test_auth_fallback_but_access_and_missing_and_timeout_do_not_rotate(self):
  def auth(key):
   if key=='first-secret':raise m.IntegrationError('HTTP 401: rejected')
   return key
  self.assertEqual(self.pool.run(configured_keys(self.cfg),auth,m.IntegrationError),'second-secret')
  self.assertEqual(self.pool.snapshot(configured_keys(self.cfg))[0]['status'],'AUTH_REJECTED')
  for message in ['HTTP 403: permission denied','HTTP 404: missing','Connection failed or timed out']:
   call=Mock(side_effect=m.IntegrationError(message))
   with self.assertRaises(m.IntegrationError):VTKeyPool().run(configured_keys(self.cfg),call,m.IntegrationError)
   self.assertEqual(call.call_count,1)
 def test_reads_and_upload_share_fallback(self):
  with patch.object(m,'config',return_value=self.cfg),patch.object(m,'vt_pool',self.pool):
   calls=[]
   def raw(url,header,key,data=None,form=False):
    calls.append(key)
    if key=='first-secret':raise m.IntegrationError('HTTP 429: quota')
    return {'data':{}}
   with patch.object(m,'_request_json',side_effect=raw):m.request_json('https://www.virustotal.com/api/v3/files/hash','x-apikey','first-secret')
   with patch.object(m,'_vt_upload_file',return_value={'analysis_id':'already-submitted'}) as upload:
    self.assertEqual(m.vt_upload_file(None,None,None)['analysis_id'],'already-submitted')
    self.assertEqual(upload.call_args.args[-1],'second-secret');self.assertEqual(upload.call_count,1)
 def test_rejected_upload_fallback_but_ambiguous_failure_never_reuploads(self):
  with patch.object(m,'config',return_value=self.cfg),patch.object(m,'vt_pool',self.pool):
   with patch.object(m,'_vt_upload_file',side_effect=[m.IntegrationError('HTTP 429: rejected',429,60),{'analysis_id':'submitted'}]) as upload:
    self.assertEqual(m.vt_upload_file(None,None,None)['analysis_id'],'submitted');self.assertEqual(upload.call_count,2)
   with patch.object(m,'_vt_upload_file',side_effect=m.IntegrationError('VT upload connection failed or timed out')) as upload:
    with self.assertRaises(m.IntegrationError):m.vt_upload_file(None,None,None)
    self.assertEqual(upload.call_count,1)
 def test_resume_polling_never_uploads_during_fallback(self):
  import time
  report={'sha256':'a'*64,'vt_submission':{'analysis_id':'existing','uploaded_sha256':'a'*64,'submitted_at':time.time()}}
  def raw(url,header,key,data=None,form=False):
   if key=='first-secret':raise m.IntegrationError('HTTP 429: quota')
   return {'data':{'attributes':{'status':'completed','stats':{},'date':123}}}
  with patch.object(m,'config',return_value=self.cfg),patch.object(m,'vt_pool',self.pool),patch.object(m,'_request_json',side_effect=raw),patch.object(m,'vt_upload_file') as upload:
   self.assertTrue(m.vt_file_analysis(report,None,None,lambda _:None,lambda _:None)['fresh_analysis']);upload.assert_not_called()
 def test_secondary_only_config_and_status_never_expose_keys(self):
  with tempfile.TemporaryDirectory() as tmp,patch.object(m,'ROOT',Path(tmp)),patch.dict(m.os.environ,{},clear=True):
   (Path(tmp)/'.env').write_text('VT_API_KEY_2=second-secret\nVT_API_KEY_3=third-secret\n')
   self.assertEqual(m.primary_vt_key(),'second-secret')
   row=next(x for x in m.statuses() if x['id']=='virustotal')
   self.assertTrue(row['configured']);self.assertEqual(row['key_count'],2);self.assertNotIn('secret',json.dumps(row))
 def test_retry_after_respected(self):
  self.assertEqual(m.provider_http_error(429,{'Retry-After':'3600'}).retry_after,3600)
  self.assertIsNone(m.provider_http_error(429,{'Retry-After':'invalid'}).retry_after)

if __name__=='__main__':unittest.main()
