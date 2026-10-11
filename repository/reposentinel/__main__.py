import argparse,json,uuid
from pathlib import Path
from .core import analyze,github_snapshot,demo_objects,read_archive
from .scanners import status,run_scanners
from .reporting import html_report,sbom
from .normalize import finish_report

def main():
    parser=argparse.ArgumentParser(prog='reposentinel',description='Static repository review; target code is never run.')
    sub=parser.add_subparsers(dest='command',required=True)
    serve=sub.add_parser('serve'); serve.add_argument('--port',type=int,default=8765)
    scan=sub.add_parser('scan'); scan.add_argument('url',nargs='?'); scan.add_argument('--ref',default=''); scan.add_argument('--demo',action='store_true'); scan.add_argument('--archive'); scan.add_argument('--out',default='reports')
    sub.add_parser('scanners')
    args=parser.parse_args()
    if args.command=='serve':
        import uvicorn
        uvicorn.run('reposentinel.api:app',host='127.0.0.1',port=args.port)
    elif args.command=='scanners': print(json.dumps(status(),indent=2))
    else:
        progress=lambda state,detail:print(f'{state}: {detail}')
        if args.demo: objects=demo_objects(); meta={'name':'sample/sync-agent','commit':None,'provenance':'synthetic_demo'}
        elif args.archive: objects=read_archive(Path(args.archive).read_bytes()); meta={'name':'uploaded/snapshot','commit':None,'provenance':'uploaded_archive'}
        elif args.url: objects,meta=github_snapshot(args.url,args.ref,progress)
        else: parser.error('Provide a GitHub URL, --demo, or --archive')
        report=analyze(objects,meta,progress); runs,findings=run_scanners(objects,progress); report=finish_report(report,runs,findings)
        out=Path(args.out); out.mkdir(parents=True,exist_ok=True)
        for name,obj in [('report',report),('manifest',report['files']),('findings',report['findings']),('behavior-graph',report['graph']),('sbom.cdx',sbom(report))]: (out/(name+'.json')).write_text(json.dumps(obj,indent=2))
        (out/'report.html').write_text(html_report(report)); print(f'Report written to {out.resolve()}')
if __name__=='__main__': main()
