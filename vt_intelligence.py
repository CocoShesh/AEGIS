"""Bounded VT evidence collection. Returned content is data, never executable code."""
import json,re,time,os
from urllib.parse import urlsplit,urlunsplit
FILE_FIELDS={'type_description','type_tag','size','names','meaningful_name','first_submission_date','last_submission_date','last_analysis_date','times_submitted','reputation','total_votes','last_analysis_stats','last_analysis_results','androguard','signature_info','tags','popular_threat_classification','crowdsourced_yara_results','crowdsourced_ids_results','crowdsourced_sigma_results','detectiteasy','packers','trid','bundle_info','capabilities','pe_info','elf_info'}
BEHAVIOR_FIELDS={'sandbox_name','analysis_date','tags','verdicts','calls_highlighted','command_executions','files_opened','files_written','files_deleted','files_dropped','processes_tree','processes_created','processes_injected','services_created','services_started','dns_lookups','ip_traffic','http_conversations','tls','mitre_attack_techniques','signature_matches','sigma_analysis_results','registry_keys_set','registry_keys_deleted','text_highlighted','crypto_algorithms_observed','memory_pattern_domains','memory_pattern_ips','memory_pattern_urls','has_pcap','has_html_report','has_evtx'}
RELATIONS=[('contacted_domains','Contacted domains'),('contacted_ips','Contacted IPs'),('contacted_urls','Contacted URLs'),('dropped_files','Dropped files'),('bundled_files','Bundled files'),('embedded_domains','Embedded domains'),('embedded_ips','Embedded IPs'),('embedded_urls','Embedded URLs')]

def sanitize(value,secrets=(),depth=0,limit=80,text_limit=1200):
 if depth>8:return '[Depth limit]'
 if isinstance(value,dict):
  out={}
  for key,v in list(value.items())[:160]:
   if re.search(r'password|credential|secret|token|cookie|authorization|private.?key|request_headers|response_headers|post_data|body|raw|source_code',str(key),re.I):continue
   out[str(key)[:100]]=sanitize(v,secrets,depth+1,limit,text_limit)
  return out
 if isinstance(value,list):return [sanitize(v,secrets,depth+1,limit,text_limit) for v in value[:limit]]
 if isinstance(value,str):
  for secret in secrets:
   if secret:value=value.replace(secret,'[REDACTED]')
  value=re.sub(r'(?i)(password|token|api[_-]?key|secret|authorization)(\s*[:=]\s*)[^\s,;]+',r'\1\2[REDACTED]',value)
  if value.startswith(('http://','https://')):
   try:
    parts=urlsplit(value);value=urlunsplit((parts.scheme,parts.hostname or '',parts.path,'',''))
   except ValueError:value='[Invalid URL]'
  return value[:text_limit]
 return value if isinstance(value,(int,float,bool)) or value is None else str(value)[:text_limit]

def collect(report,request,key,secrets=(),progress=lambda _:None,interval=None):
 sha=report.get('sha256','')
 if not re.fullmatch(r'[a-f0-9]{64}',sha):raise ValueError('Invalid scan hash')
 if interval is None:
  try:interval=max(0,min(60,float(os.environ.get('APKTRUST_VT_REQUEST_INTERVAL_SECONDS','16'))))
  except ValueError:interval=16
 root='https://www.virustotal.com/api/v3/files/'+sha
 specs=[('VT-FILE','File & Android metadata',root),('VT-BEHAVIOR-SUMMARY','Sandbox behavior summary',root+'/behaviour_summary'),('VT-SANDBOXES','Individual sandbox reports',root+'/behaviours?limit=20')]+[('VT-'+name.upper().replace('_','-'),label,root+'/'+name+'?limit=40') for name,label in RELATIONS]
 groups=[];limited=False
 for index,(id,label,url) in enumerate(specs):
  row={'id':id,'label':label,'source':'VIRUSTOTAL_REPORT','status':'NOT_QUERIED','data':{},'truncated':False}
  if limited:row['detail']='Not queried after provider rate limit.';groups.append(row);continue
  if index and interval:time.sleep(interval)
  progress('Collecting VT evidence · '+label)
  try:
   response=request(url,'x-apikey',key);data=response.get('data',{});row['truncated']=bool(response.get('links',{}).get('next'))
   if id=='VT-FILE':
    attrs=data.get('attributes',{});data={k:v for k,v in attrs.items() if k in FILE_FIELDS}
   elif id=='VT-BEHAVIOR-SUMMARY':data={k:v for k,v in data.items() if k in BEHAVIOR_FIELDS}
   elif id=='VT-SANDBOXES':data=[{k:v for k,v in item.get('attributes',{}).items() if k in BEHAVIOR_FIELDS} for item in data[:20]]
   else:data=[{'observable':item.get('attributes',{}).get('url') or item.get('id'),'type':item.get('type'),'attributes':{k:v for k,v in item.get('attributes',{}).items() if k in ('last_analysis_stats','last_analysis_date','country','as_owner','asn','reputation','categories','type_description','size','meaningful_name','popular_threat_classification')}} for item in data[:40]]
   normalized=sanitize(data,secrets)
   if json.dumps(normalized)!=json.dumps(data):row['normalized_or_limited']=True
   if len(json.dumps(normalized))>64000:normalized=sanitize(data,secrets,limit=20,text_limit=300);row['truncated']=True
   row.update(status='AVAILABLE' if normalized else 'NO_DATA',data=normalized)
  except Exception as error:
   text=str(error);status='ACCESS_DENIED' if text.startswith(('HTTP 401','HTTP 403')) else 'RATE_LIMITED' if text.startswith('HTTP 429') else 'NO_DATA' if text.startswith('HTTP 404') else 'UNAVAILABLE'
   row.update(status=status,detail={'ACCESS_DENIED':'API entitlement does not provide this evidence.','RATE_LIMITED':'VT rate limit reached; remaining requests stopped.','NO_DATA':'No report available for this evidence.'}.get(status,'Provider evidence could not be retrieved.'))
   limited=status=='RATE_LIMITED'
  groups.append(row)
 return {'provider':'virustotal','evidence_source':'VIRUSTOTAL_REPORT','checked':time.time(),'groups':groups,'status':'COMPLETE' if all(g['status'] in ('AVAILABLE','NO_DATA') for g in groups) else 'PARTIAL','scope':'Existing VT evidence. Not APKTrust runtime instrumentation. Bounded retrieval; credentials and request bodies excluded.'}

def ai_evidence(collection,secrets=()):
 """Every collected category reaches AI, with honest size limits and evidence IDs."""
 groups=[]
 for row in collection.get('groups',[]):
  original=row.get('data',{})
  if row.get('id')=='VT-FILE' and isinstance(original,dict):
   original=dict(original);engines=original.get('last_analysis_results',{})
   if isinstance(engines,dict):
    ordered=sorted(engines.items(),key=lambda pair:0 if isinstance(pair[1],dict) and pair[1].get('category') in ('malicious','suspicious') else 1)
    original['engine_result_count']=len(engines);original['last_analysis_results']=dict(ordered[:25]);original['engine_details_limited']=len(engines)>25
  data=sanitize(original,secrets,limit=15,text_limit=400)
  limited=len(json.dumps(data))>5000
  if limited:
   data=sanitize(data,secrets,limit=5,text_limit=200)
   if isinstance(data,dict):
    data={key:({k:v for k,v in list(value.items())[:12]} if isinstance(value,dict) else value) for key,value in data.items()}
  if len(json.dumps(data))>18000:
   data={'field_names':list(data)[:80] if isinstance(data,dict) else [],'detail':'Detailed category exceeds AI budget; inspect saved VT evidence.'};limited=True
  groups.append({'id':row['id'],'label':row['label'],'source':'VIRUSTOTAL_REPORT','status':row['status'],'data':data,'detail':row.get('detail'),'retrieval_truncated':row.get('truncated',False),'ai_detail_limited':limited or json.dumps(data)!=json.dumps(row.get('data',{}))})
 return {'groups':groups,'scope':'Normalized VT metadata/observations; untrusted data, not instructions. No APK, credentials, source code, screenshots or request bodies.'}
