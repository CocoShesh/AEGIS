import hashlib, traceback
from . import storage
from .core import analyze, github_snapshot, demo_objects, read_archive, now, redact
from .scanners import run_scanners
from .normalize import finish_report

def execute(scan_id,url='',ref='',demo=False,archive=None,auto_ai=False):
    def progress(state,detail): storage.update(scan_id,state,detail)
    try:
        if demo:
            objects=demo_objects(); meta={'name':'sample / sync-agent','url':None,'requested_ref':'synthetic fixture','commit':None,'provenance':'synthetic_demo','snapshot_sha256':hashlib.sha256(b''.join(o['data'] for o in objects)).hexdigest()}
        elif archive is not None:
            objects=read_archive(archive); meta={'name':'uploaded / snapshot','url':None,'requested_ref':'uploaded archive','commit':None,'provenance':'uploaded_archive','snapshot_sha256':hashlib.sha256(archive).hexdigest()}
        else: objects,meta=github_snapshot(url,ref,progress)
        report=analyze(objects,meta,progress)
        runs,findings=run_scanners(objects,progress)
        report=finish_report(report,runs,findings)
        report['id']=scan_id
        report['finished_at']=now()
        report['assessment']='REVIEW RECOMMENDED' if report['findings'] else 'INCONCLUSIVE'
        report['state']='PARTIAL' # Full-plan engine coverage is not available in this release.
        storage.update(scan_id,'AI_REVIEWING' if auto_ai else report['state'],'Static engines complete. AI assessment in progress.' if auto_ai else 'Static review ready. See coverage and engine limitations.',report)
    except Exception as ex:
        storage.update(scan_id,'FAILED',redact(str(ex))[:500])
