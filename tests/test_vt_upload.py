import hashlib,json,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch,MagicMock
import integrations as m
class VTUploadTests(unittest.TestCase):
 def test_official_large_upload_hosts(self):
  for host in ['www.virustotal.com','bigfiles.virustotal.com']:
   parts=m.vt_upload_destination('https://'+host+'/_ah/upload/one-use-token',True)
   self.assertEqual(parts.hostname,host)
 def test_destination_validation_keeps_boundary(self):
  for url in ['http://bigfiles.virustotal.com/_ah/upload/token','https://bigfiles.virustotal.com.attacker.invalid/_ah/upload/token','https://attacker.invalid/_ah/upload/token','https://bigfiles.virustotal.com:8443/_ah/upload/token','https://user:password@bigfiles.virustotal.com/_ah/upload/token','https://bigfiles.virustotal.com/other/token','https://bigfiles.virustotal.com/_ah/upload/token#fragment','https://bigfiles.virustotal.com/\n_ah/upload/token']:
   with self.assertRaisesRegex(m.IntegrationError,'Untrusted'):m.vt_upload_destination(url,True)
  with self.assertRaises(m.IntegrationError):m.vt_upload_destination('https://bigfiles.virustotal.com/api/v3/files')
 def test_large_file_streams_to_bigfiles_host(self):
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);p=root/'file.apk'
   with p.open('wb') as f:f.truncate(32*1024**2+1)
   digest=hashlib.sha256()
   with p.open('rb') as f:
    for chunk in iter(lambda:f.read(1024*1024),b''):digest.update(chunk)
   conn=MagicMock();conn.getresponse.return_value.status=200;conn.getresponse.return_value.read.return_value=b'{"data":{"id":"analysis-id"}}'
   with patch.object(m,'config',return_value={'VT_API_KEY':'SECRET'}),patch.object(m,'_request_json',return_value={'data':'https://bigfiles.virustotal.com/_ah/upload/one-use-token'}),patch('http.client.HTTPSConnection',return_value=conn) as connection:
    job=m.vt_upload_file(p,digest.hexdigest(),root)
   self.assertEqual(connection.call_args.args[0],'bigfiles.virustotal.com')
   self.assertEqual(conn.putrequest.call_args.args,('POST','/_ah/upload/one-use-token'))
   self.assertEqual(job['analysis_id'],'analysis-id')
 def test_exact_bytes_streamed_to_fixed_host_without_user_filename(self):
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);p=root/'app;$(secret).apk';p.write_bytes(b'APK BYTES');sha=hashlib.sha256(p.read_bytes()).hexdigest()
   conn=MagicMock();conn.getresponse.return_value.status=200;conn.getresponse.return_value.read.return_value=json.dumps({'data':{'id':'abc==:1'}}).encode()
   with patch.object(m,'config',return_value={'VT_API_KEY':'SECRET'}),patch('http.client.HTTPSConnection',return_value=conn) as connection:
    job=m.vt_upload_file(p,sha,root)
   self.assertEqual(connection.call_args.args[0],'www.virustotal.com');self.assertEqual(conn.putrequest.call_args.args,('POST','/api/v3/files'))
   payload=b''.join(c.args[0] for c in conn.send.call_args_list);self.assertIn(b'APK BYTES',payload);self.assertNotIn(b'secret',payload);self.assertNotIn(b'SECRET',payload);self.assertEqual(job['uploaded_sha256'],sha)
 def test_hash_and_path_validation(self):
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);p=root/'file.apk';p.write_bytes(b'bytes')
   with patch.object(m,'config',return_value={'VT_API_KEY':'SECRET'}),patch('http.client.HTTPSConnection') as connection:
    with self.assertRaisesRegex(m.IntegrationError,'SHA-256'):m.vt_upload_file(p,'a'*64,root)
    with self.assertRaisesRegex(m.IntegrationError,'outside'):m.vt_upload_file(p,'a'*64,root/'other')
    connection.assert_not_called()
 def test_large_file_uses_upload_url_and_rejects_untrusted_host(self):
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);p=root/'file.apk'
   with p.open('wb') as f:f.truncate(32*1024**2+1)
   digest=hashlib.sha256()
   with p.open('rb') as f:
    for chunk in iter(lambda:f.read(1024*1024),b''):digest.update(chunk)
   with patch.object(m,'config',return_value={'VT_API_KEY':'SECRET'}),patch.object(m,'_request_json',return_value={'data':'https://attacker.invalid/_ah/upload/test'}),patch('http.client.HTTPSConnection') as connection:
    with self.assertRaisesRegex(m.IntegrationError,'Untrusted'):m.vt_upload_file(p,digest.hexdigest(),root)
    connection.assert_not_called()
 def test_resume_analysis_without_reupload(self):
  report={'sha256':'a'*64,'vt_submission':{'analysis_id':'abc==','uploaded_sha256':'a'*64,'submitted_at':time.time()}}
  with patch.object(m,'config',return_value={'VT_API_KEY':'SECRET'}),patch.object(m,'vt_upload_file') as upload,patch.object(m,'request_json',return_value={'data':{'attributes':{'status':'completed','stats':{'malicious':2},'date':123}}}):
   result=m.vt_file_analysis(report,None,None,lambda _:None,lambda _:None)
  upload.assert_not_called();self.assertTrue(result['fresh_analysis']);self.assertEqual(result['stats']['malicious'],2)
 def test_timed_out_is_not_completed(self):
  report={'sha256':'a'*64,'vt_submission':{'analysis_id':'abc==','uploaded_sha256':'a'*64,'submitted_at':0}}
  saved=[]
  with patch.object(m,'config',return_value={'VT_API_KEY':'SECRET'}):
   with self.assertRaisesRegex(m.IntegrationError,'timed out'):m.vt_file_analysis(report,None,None,saved.append,lambda _:None)
  self.assertEqual(saved[0]['status'],'TIMED_OUT')

class VTLookupFirstTests(unittest.TestCase):
 def setUp(self):
  self.sha='a'*64;self.report={'sha256':self.sha};self.saved=[]
  self.found={'data':{'id':self.sha,'type':'file','attributes':{}}}
  self.descriptor={'data':{'type':'analysis','id':'new-analysis'}}
  self.completed={'data':{'attributes':{'status':'completed','stats':{'malicious':0},'date':123}}}
 def run_analysis(self):
  return m.vt_file_analysis(self.report,None,None,self.saved.append,lambda _:None)
 def test_existing_file_reanalyzed_without_upload(self):
  with patch.object(m,'primary_vt_key',return_value='mock'),patch.object(m,'vt_upload_file') as upload,patch.object(m,'request_json',side_effect=[self.found,self.descriptor,self.completed]) as request:
   result=self.run_analysis()
  upload.assert_not_called()
  self.assertEqual(request.call_args_list[1].args,('https://www.virustotal.com/api/v3/files/'+self.sha+'/analyse','x-apikey','mock',{}))
  self.assertEqual(self.saved[0]['analysis_mode'],'REANALYSIS');self.assertNotIn('uploaded_sha256',self.saved[0])
  self.assertFalse(result['file_uploaded']);self.assertTrue(result['fresh_analysis'])
 def test_not_found_uploads_and_persists_before_polling(self):
  job={'analysis_id':'new-analysis','uploaded_sha256':self.sha,'submitted_at':time.time()}
  def reply(*args):
   if args[0].endswith('/files/'+self.sha):raise m.IntegrationError('HTTP 404: not found',http_status=404)
   self.assertEqual(self.saved[0]['analysis_mode'],'UPLOAD')
   return self.completed
  with patch.object(m,'primary_vt_key',return_value='mock'),patch.object(m,'vt_upload_file',return_value=job) as upload,patch.object(m,'request_json',side_effect=reply):
   result=self.run_analysis()
  upload.assert_called_once_with(None,self.sha,None);self.assertTrue(result['file_uploaded']);self.assertEqual(result['analysis_mode'],'UPLOAD')
 def test_lookup_errors_never_upload(self):
  for code in (401,403,429,500,None):
   with self.subTest(code=code),patch.object(m,'primary_vt_key',return_value='mock'),patch.object(m,'vt_upload_file') as upload,patch.object(m,'request_json',side_effect=m.IntegrationError('lookup failed',http_status=code)):
    with self.assertRaises(m.IntegrationError):self.run_analysis()
    upload.assert_not_called()
 def test_invalid_lookup_does_not_upload_or_request_reanalysis(self):
  for reply in ({},{'data':{'id':'b'*64,'type':'file','attributes':{}}}):
   with patch.object(m,'primary_vt_key',return_value='mock'),patch.object(m,'vt_upload_file') as upload,patch.object(m,'request_json',return_value=reply) as request:
    with self.assertRaisesRegex(m.IntegrationError,'lookup response'):self.run_analysis()
    upload.assert_not_called();self.assertEqual(request.call_count,1)
 def test_reanalysis_rejection_does_not_fall_back_to_upload(self):
  with patch.object(m,'primary_vt_key',return_value='mock'),patch.object(m,'vt_upload_file') as upload,patch.object(m,'request_json',side_effect=[self.found,m.IntegrationError('reanalysis denied',http_status=403)]):
   with self.assertRaises(m.IntegrationError):self.run_analysis()
   upload.assert_not_called();self.assertEqual(self.saved,[])
 def test_resume_reanalysis_only_polls_saved_id(self):
  self.report['vt_submission']={'sha256':self.sha,'analysis_id':'saved-id','analysis_mode':'REANALYSIS','submitted_at':time.time()}
  with patch.object(m,'primary_vt_key',return_value='mock'),patch.object(m,'vt_upload_file') as upload,patch.object(m,'request_json',return_value=self.completed) as request:
   result=self.run_analysis()
  upload.assert_not_called();self.assertEqual(request.call_count,1);self.assertIn('/analyses/saved-id',request.call_args.args[0]);self.assertFalse(result['file_uploaded'])
 def test_wrong_scan_job_rejected_before_remote_request(self):
  self.report['vt_submission']={'sha256':'b'*64,'analysis_id':'saved-id','submitted_at':time.time()}
  with patch.object(m,'primary_vt_key',return_value='mock'),patch.object(m,'request_json') as request:
   with self.assertRaisesRegex(m.IntegrationError,'different scan'):self.run_analysis()
   request.assert_not_called()
 def test_invalid_reanalysis_id_not_persisted_or_polled(self):
  with patch.object(m,'primary_vt_key',return_value='mock'),patch.object(m,'vt_upload_file') as upload,patch.object(m,'request_json',side_effect=[self.found,{'data':{'id':'../bad'}}]) as request:
   with self.assertRaisesRegex(m.IntegrationError,'identifier'):self.run_analysis()
   upload.assert_not_called();self.assertEqual(request.call_count,2);self.assertEqual(self.saved,[])
