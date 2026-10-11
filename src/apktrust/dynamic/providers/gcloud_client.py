"""Replaceable transport: gcloud submission/discovery, authenticated Google JSON APIs.
There is no stable gcloud matrices describe command; status uses Cloud Testing GET.
Tokens are obtained transiently from the active gcloud account, never logged/stored.
"""
import json, re, shutil
from urllib.request import Request, build_opener, HTTPRedirectHandler
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from ..models import DynamicError
from ..security import run_command

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):return None

def classify_error(code, text=''):
    lower=text.lower()
    if code==401 or any(s in lower for s in ('not authenticated','login required','invalid_grant','no credential','re-authentication')):return DynamicError('AUTH_ERROR','gcloud is not authenticated; run gcloud auth login')
    if 'service_disabled' in lower or 'has not been used' in lower or 'api disabled' in lower:return DynamicError('API_DISABLED','Required Google API is disabled for this project')
    if code==429 or 'quota' in lower or 'resource_exhausted' in lower:return DynamicError('QUOTA_EXCEEDED','Provider quota or rate limit unavailable')
    if code==403 or 'permission' in lower or 'forbidden' in lower:return DynamicError('PERMISSION_DENIED','Google denied access to the configured project or results')
    if code==404 or 'not_found' in lower or 'not found' in lower:return DynamicError('PROJECT_NOT_FOUND','Project or remote resource was not found')
    if any(s in lower for s in ('network','connection','timed out','dns')) or code>=500:return DynamicError('NETWORK_ERROR','Google service connection failed')
    return DynamicError('UNKNOWN','Google provider request failed; inspect gcloud locally for details')

class GCloudTestLabClient:
    adapter_version='gcloud-json-rest/1.0'
    def __init__(self, runner=run_command, opener=None):self.runner=runner;self.opener=opener or build_opener(NoRedirect())
    def installed(self):return shutil.which('gcloud') is not None
    def command(self,args,timeout=45):return self.runner(['gcloud',*args,'--quiet','--format=json'],timeout=timeout)
    def json_command(self,args):
        result=self.command(args)
        if result.returncode:raise classify_error(result.returncode,result.stderr)
        try:return json.loads(result.stdout)
        except ValueError:raise DynamicError('RESULT_COLLECTION_FAILED','gcloud returned unexpected JSON') from None
    def authenticated(self):return bool(self.json_command(['auth','list','--filter=status:ACTIVE']))
    def project_exists(self,project):return bool(self.json_command(['projects','describe',project]))
    def enabled_services(self,project):
        data=self.json_command(['services','list','--enabled','--project',project])
        if not isinstance(data,list):raise DynamicError('RESULT_COLLECTION_FAILED','Enabled API list has unexpected structure')
        return {row.get('config',{}).get('name') for row in data if isinstance(row,dict)}
    def models(self,project):return self.json_command(['firebase','test','android','models','list','--project',project])
    def versions(self,project):return self.json_command(['firebase','test','android','versions','list','--project',project])
    def submit(self,project,path,device,timeout,label,video):
        args=['firebase','test','android','run','--type','robo','--app',str(path),'--project',project,'--device',','.join(f'{k}={device[k]}' for k in ('model','version','locale','orientation')),'--timeout',f'{timeout}s','--no-auto-google-login','--client-details',f'matrixLabel={label}','--async','--record-video' if video else '--no-record-video']
        result=self.command(args,timeout=180)
        try:data=json.loads(result.stdout) if result.stdout.strip() else {}
        except ValueError:data={}
        # --async JSON is a TestMatrix. Do not scrape arbitrary stdout/stderr into reports.
        if isinstance(data,list) and len(data)==1:data=data[0]
        if not isinstance(data,dict):data={}
        # gcloud can create a matrix, then fail validation before emitting JSON.
        # Recover only its fixed diagnostic identifier; never persist raw stderr.
        if not data.get('testMatrixId'):
            match=re.search(r'\bMatrix \[(matrix-[A-Za-z0-9_-]{1,180})\] failed during validation',result.stderr)
            if match:
                remote=match.group(1)
                try:data=self.matrix(project,remote)
                except DynamicError:data={'testMatrixId':remote,'state':'VALIDATING'}
        return result.returncode,data,result.stderr
    def _token(self):
        response=self.runner(['gcloud','auth','print-access-token','--quiet'],timeout=30)
        token=response.stdout.strip()
        if response.returncode or not re.fullmatch(r'[A-Za-z0-9._~+/-]{10,8192}',token):raise DynamicError('AUTH_ERROR','Unable to obtain active gcloud credentials')
        return token
    def request(self,host,path,method='GET',body=None,offset=None,limit=1024*1024):
        if host not in ('testing.googleapis.com','toolresults.googleapis.com','storage.googleapis.com'):raise DynamicError('RESULT_COLLECTION_FAILED','Unexpected provider endpoint')
        headers={'Authorization':'Bearer '+self._token(),'Accept':'application/json'}
        if offset is not None:headers['Range']=f'bytes={offset}-{offset+limit-1}'
        payload=json.dumps(body).encode() if body is not None else None
        if payload is not None:headers['Content-Type']='application/json'
        try:
            with self.opener.open(Request('https://'+host+path,data=payload,headers=headers,method=method),timeout=30) as response:
                if offset and response.status!=206:raise DynamicError('RESULT_COLLECTION_FAILED','Remote storage did not honor ranged download')
                data=response.read(limit+1)
                if len(data)>limit:raise DynamicError('RESULT_COLLECTION_FAILED','Provider response exceeded download limit')
                if offset is not None:return data
                return json.loads(data)
        except HTTPError as e:
            if e.code==416 and offset is not None:return b''
            raw=e.read(8192).decode('utf-8','replace')
            raise classify_error(e.code,raw) from None
        except (URLError,TimeoutError,OSError):raise DynamicError('NETWORK_ERROR','Google service connection failed or timed out') from None
        except (ValueError,UnicodeError):raise DynamicError('RESULT_COLLECTION_FAILED','Invalid provider JSON') from None
    def matrix(self,project,id):return self.request('testing.googleapis.com',f'/v1/projects/{quote(project,safe="")}/testMatrices/{quote(id,safe="")}')
    def cancel(self,project,id):return self.request('testing.googleapis.com',f'/v1/projects/{quote(project,safe="")}/testMatrices/{quote(id,safe="")}:cancel','POST',{})
    def step(self,reference):
        fields=('projectId','historyId','executionId','stepId')
        if not all(reference.get(k) for k in fields):raise DynamicError('RESULT_COLLECTION_FAILED','Execution has no Tool Results reference')
        p,h,e,s=[quote(str(reference[k]),safe='') for k in fields]
        return self.request('toolresults.googleapis.com',f'/toolresults/v1beta3/projects/{p}/histories/{h}/executions/{e}/steps/{s}')
    def objects(self,root):
        bucket,prefix=self.gcs_parts(root);items=[];page=None
        for _ in range(10):
            query={'prefix':prefix.rstrip('/')+'/','maxResults':1000}
            if page:query['pageToken']=page
            data=self.request('storage.googleapis.com',f'/storage/v1/b/{quote(bucket,safe="")}/o?'+urlencode(query))
            items.extend(data.get('items',[]));page=data.get('nextPageToken')
            if not page:return items,False
        return items,True
    @staticmethod
    def gcs_parts(uri):
        u=urlsplit(uri)
        if u.scheme!='gs' or not re.fullmatch(r'[a-z0-9][a-z0-9._-]{1,222}',u.netloc) or not u.path.strip('/') or u.query or u.fragment:raise DynamicError('RESULT_COLLECTION_FAILED','Invalid result storage reference')
        return u.netloc,u.path.lstrip('/')
    def artifact(self,uri,offset,limit):
        bucket,name=self.gcs_parts(uri)
        return self.request('storage.googleapis.com',f'/storage/v1/b/{quote(bucket,safe="")}/o/{quote(name,safe="")}?alt=media',offset=offset,limit=limit)
