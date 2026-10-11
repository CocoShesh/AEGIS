"""Bounded subprocess and artifact validation. Raw provider errors are never persisted."""
import hashlib, os, re, selectors, subprocess, time
from dataclasses import dataclass
from pathlib import Path
from .models import DynamicError
CAP=1024*1024
@dataclass
class CommandResult:
    returncode: int
    stdout: str
    stderr: str

def redact(text):
    text=re.sub(r'(?i)(bearer\s+|access_token[\"\s:=]+|token[\"\s:=]+)[\w.~/+-]+',r'\1[REDACTED]',text)
    text=re.sub(r'ya29\.[\w.-]+|AIza[\w-]+|-----BEGIN[^-]*PRIVATE KEY-----[\s\S]*?-----END[^-]*PRIVATE KEY-----','[REDACTED]',text)
    return text

def run_command(args, timeout=45):
    # Do not forward APKTrust AI keys or arbitrary environment secrets to gcloud.
    env={k:os.environ[k] for k in ('PATH','HOME','LANG','LC_ALL','CLOUDSDK_CONFIG','GOOGLE_APPLICATION_CREDENTIALS','SYSTEMROOT') if k in os.environ}
    env.update(CLOUDSDK_CORE_DISABLE_PROMPTS='1',CLOUDSDK_CORE_DISABLE_USAGE_REPORTING='true')
    try:
        process=subprocess.Popen(list(args),shell=False,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)
    except OSError:raise DynamicError('UNAVAILABLE','gcloud could not be started') from None
    output={};size=0; deadline=time.monotonic()+timeout
    try:
        with selectors.DefaultSelector() as selector:
            for stream in (process.stdout,process.stderr):selector.register(stream,selectors.EVENT_READ);output[stream]=bytearray()
            while selector.get_map():
                remaining=deadline-time.monotonic()
                if remaining<=0:raise DynamicError('TEST_TIMEOUT','Provider command timed out')
                for key,_ in selector.select(min(remaining,.5)):
                    block=os.read(key.fileobj.fileno(),65536)
                    if not block:selector.unregister(key.fileobj);continue
                    size+=len(block)
                    if size>CAP:raise DynamicError('RESULT_COLLECTION_FAILED','Provider output exceeded 1 MiB capture limit')
                    output[key.fileobj].extend(block)
        code=process.wait(timeout=max(.1,deadline-time.monotonic()))
        return CommandResult(code,bytes(output[process.stdout]).decode('utf-8','replace'),bytes(output[process.stderr]).decode('utf-8','replace'))
    except subprocess.TimeoutExpired:raise DynamicError('TEST_TIMEOUT','Provider command timed out') from None
    finally:
        if process.poll() is None:process.kill();process.wait()
        process.stdout.close();process.stderr.close()

def verified_apk(request):
    if request.confirm_cloud_upload is not True:raise DynamicError('UPLOAD_FAILED','Cloud upload requires explicit consent')
    if not re.fullmatch(r'[a-f0-9]{12}',request.scan_id):raise DynamicError('APK_INCOMPATIBLE','Invalid scan identifier')
    workspace=Path(request.workspace).resolve(); supplied=Path(request.apk_path)
    # Only a single immutable managed path per scan is accepted, even for shell-like filenames.
    expected=workspace/'inputs'/request.scan_id/'app.apk'
    if supplied.is_symlink() or supplied.absolute()!=expected or supplied.resolve()!=expected:raise DynamicError('APK_INCOMPATIBLE','APK must be the exact artifact in the scan workspace')
    if not expected.is_file() or expected.stat().st_size>256*1024**2:raise DynamicError('APK_INCOMPATIBLE','Retained APK missing or too large; attach the original APK again')
    digest=hashlib.sha256()
    with expected.open('rb') as stream:
        for block in iter(lambda:stream.read(1024*1024),b''):digest.update(block)
    if digest.hexdigest()!=request.sha256:raise DynamicError('APK_INCOMPATIBLE','APK SHA-256 does not match this static scan')
    return expected
