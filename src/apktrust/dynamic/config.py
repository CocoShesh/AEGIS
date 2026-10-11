"""JSON configuration plus whitelisted environment overrides; credentials stay in gcloud."""
import json, os, re
from pathlib import Path
from .models import DynamicError
DEFAULT={'enabled':False,'provider':'firebase_test_lab','firebase_test_lab':{'project_id':None,'device':{'model':None,'version':None,'locale':'en','orientation':'portrait'},'timeout_seconds':300,'job_timeout_seconds':900,'no_auto_google_login':True,'collect':{'logs':True,'screenshots':True,'video':True},'retain_remote_results':True}}
ENV={'APKTRUST_DYNAMIC_ENABLED','APKTRUST_FTL_PROJECT_ID','APKTRUST_FTL_DEVICE_MODEL','APKTRUST_FTL_ANDROID_VERSION','APKTRUST_FTL_TIMEOUT_SECONDS','APKTRUST_FTL_JOB_TIMEOUT_SECONDS'}
def load_config(root):
    cfg=json.loads(json.dumps(DEFAULT)); path=Path(root)/'dynamic-config.json'
    if path.exists():
        if path.stat().st_size>65536: raise DynamicError('UNKNOWN','Dynamic configuration exceeds 64 KiB')
        try:
            data=json.loads(path.read_text()).get('dynamic',{})
            if not isinstance(data,dict): raise ValueError()
            for key in ('enabled','provider'):
                if key in data:cfg[key]=data[key]
            f=data.get('firebase_test_lab',{})
            for key in cfg['firebase_test_lab']:
                if key in f:
                    if isinstance(cfg['firebase_test_lab'][key],dict):
                        if not isinstance(f[key],dict) or set(f[key])-set(cfg['firebase_test_lab'][key]):raise ValueError()
                        cfg['firebase_test_lab'][key].update(f[key])
                    else: cfg['firebase_test_lab'][key]=f[key]
        except (ValueError,TypeError,AttributeError):raise DynamicError('UNKNOWN','Invalid dynamic-config.json') from None
    env={}; dotenv=Path(root)/'.env'
    if dotenv.exists() and dotenv.stat().st_size<=65536:
        for line in dotenv.read_text().splitlines():
            key,sep,value=line.strip().partition('=')
            if sep and key in ENV:env[key]=value.strip().strip('\"\'')
    env.update({key:os.environ[key] for key in ENV if key in os.environ})
    f=cfg['firebase_test_lab']
    if 'APKTRUST_DYNAMIC_ENABLED' in env:cfg['enabled']=env['APKTRUST_DYNAMIC_ENABLED'].lower() in ('true','1','yes')
    for name,key in [('APKTRUST_FTL_PROJECT_ID','project_id'),('APKTRUST_FTL_TIMEOUT_SECONDS','timeout_seconds'),('APKTRUST_FTL_JOB_TIMEOUT_SECONDS','job_timeout_seconds')]:
        if env.get(name):f[key]=env[name]
    for name,key in [('APKTRUST_FTL_DEVICE_MODEL','model'),('APKTRUST_FTL_ANDROID_VERSION','version')]:
        if env.get(name):f['device'][key]=env[name]
    try:
        f['timeout_seconds']=int(f['timeout_seconds']);f['job_timeout_seconds']=int(f['job_timeout_seconds'])
        if not 60<=f['timeout_seconds']<=3600 or not f['timeout_seconds']+120<=f['job_timeout_seconds']<=7200:raise ValueError()
        if not isinstance(cfg['enabled'],bool) or not isinstance(cfg['provider'],str) or not re.fullmatch(r'[a-z][a-z0-9_]{1,63}',cfg['provider']):raise ValueError()
        if f['no_auto_google_login'] is not True or f['retain_remote_results'] is not True:raise ValueError()
        if any(not isinstance(f['collect'].get(k),bool) for k in ('logs','screenshots','video')):raise ValueError()
        for key,val in [('project_id',f['project_id']),*f['device'].items()]:
            pattern=r'[A-Za-z0-9][A-Za-z0-9._-]{0,99}' if key=='model' else r'[A-Za-z0-9_-]{1,100}'
            if val is not None and not re.fullmatch(pattern,str(val)):raise ValueError()
        if f['device']['orientation'] not in ('portrait','landscape'):raise ValueError()
    except (TypeError,ValueError):raise DynamicError('UNKNOWN','Invalid dynamic settings: check identifiers, boolean flags and timeout bounds. Automatic Google login must be disabled; remote deletion is not supported.') from None
    return cfg
