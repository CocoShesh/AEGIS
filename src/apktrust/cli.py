import argparse, asyncio, json, sys, time, uuid
from pathlib import Path
from .dynamic.models import DynamicError, TERMINAL, DynamicJobStatus

def consent(args):
    if args.confirm_cloud_upload:return True
    if not sys.stdin.isatty():raise DynamicError('UPLOAD_FAILED','Cloud upload requires explicit --confirm-cloud-upload.')
    print('Firebase Test Lab requires uploading this APK to Google.')
    return input('Continue? [y/N] ').strip().lower()=='y'

def main(argv=None):
    root=Path(__file__).resolve().parents[2];sys.path.insert(0,str(root))
    import server
    parser=argparse.ArgumentParser(prog='apktrust');commands=parser.add_subparsers(dest='command',required=True)
    config=commands.add_parser('config');config.add_subparsers(dest='action',required=True).add_parser('doctor')
    dynamic=commands.add_parser('dynamic');actions=dynamic.add_subparsers(dest='action',required=True)
    actions.add_parser('providers');devices=actions.add_parser('devices');devices.add_argument('--provider',default='firebase_test_lab')
    run=actions.add_parser('run');run.add_argument('scan_id');run.add_argument('--provider',default='firebase_test_lab');run.add_argument('--confirm-cloud-upload',action='store_true');run.add_argument('--apk',help='Reattach the exact original APK locally for an older scan')
    scan=commands.add_parser('scan');scan.add_argument('apk');scan.add_argument('--dynamic',choices=['firebase_test_lab']);scan.add_argument('--confirm-cloud-upload',action='store_true');scan.add_argument('--retain-dynamic',action='store_true')
    args=parser.parse_args(argv)
    try:
        manager=server.dynamic_manager()
        if args.command=='config':
            health=manager.health(refresh=True);print('Dynamic Analysis\n\nFirebase Test Lab')
            for check,ok in health['checks'].items():print(f'  {check:<24} '+('YES' if ok else 'NO'))
            print('\nStatus: '+health['status']);print('Quota status: '+health['quota_status'])
            if health['error']:print('Reason: '+health['error']['code']+' — '+health['error']['message'])
            return 0 if health['status']=='READY' else 1
        if args.command=='dynamic' and args.action=='providers':
            health=manager.health();print(health['provider']+'   '+health['status']);return 0
        if args.command=='dynamic' and args.action=='devices':
            print(json.dumps(asyncio.run(manager.provider(name=args.provider).discover_devices()),indent=2));return 0
        if args.command=='scan':
            path=Path(args.apk).resolve()
            if not path.is_file() or path.suffix.lower() not in ('.apk','.xapk','.apks') or path.stat().st_size>server.MAX_UPLOAD:raise DynamicError('APK_INCOMPATIBLE','Select an APK/XAPK/APKS file up to 256 MiB')
            import tempfile, shutil, os
            id=uuid.uuid4().hex[:12];fd,temp=tempfile.mkstemp(dir=server.DATA,suffix=path.suffix)
            with os.fdopen(fd,'wb') as dst,path.open('rb') as src:shutil.copyfileobj(src,dst,1024*1024)
            server.jobs[id]={'progress':10,'state':'STATIC_ANALYSIS'};server.slots.acquire()
            server.worker(id,temp,path.name,bool(args.dynamic or args.retain_dynamic))
            report=server.get_scan(id)
            if not report:raise DynamicError('APK_INCOMPATIBLE','Static scan failed: '+server.jobs[id].get('error','unknown'))
            print('Static scan: '+id+' · '+report['state']+' · '+report['sha256'])
            if not args.dynamic:return 0
            provider=args.dynamic
        else:
            id=args.scan_id;provider=args.provider
            if args.apk:
                report=server.get_scan(id)
                if not report:raise DynamicError('APK_INCOMPATIBLE','Scan not found')
                manager.attach(report,Path(args.apk).resolve())
        if not consent(args):print('Cloud upload cancelled. Static analysis remains valid.');return 0
        job=manager.start(id,provider,True);print('Dynamic job: '+job['id'])
        previous=None
        while True:
            current=manager.store.get(job['id'])
            if current.stage!=previous:print(current.status+' · '+current.stage,flush=True);previous=current.stage
            if current.status in TERMINAL and manager.store.result(current.id):
                print('Result: '+current.status+' · Dynamic coverage: LIMITED')
                if current.error:print(current.error.code+': '+current.error.message)
                if current.provider_result_url:print(current.provider_result_url)
                print('Robo execution does not guarantee the APK is safe.')
                return 0 if current.status==DynamicJobStatus.COMPLETED else 1
            time.sleep(1)
    except (DynamicError,KeyboardInterrupt) as error:
        print('ERROR: '+str(error),file=sys.stderr);return 1
if __name__=='__main__':raise SystemExit(main())
