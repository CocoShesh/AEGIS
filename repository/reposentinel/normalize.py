"""Evidence-preserving correlation of matching scanner observations."""
from collections import Counter
from .core import sha
SEMANTICS={'RS-EXEC-001':'dynamic_execution','rs-python-exec':'dynamic_execution','rs-js-exec':'dynamic_execution','B307':'dynamic_execution','RS-SHELL-002':'shell_enabled','rs-python-shell':'shell_enabled','B602':'shell_enabled'}
def finish_report(report,runs,extra):
    for run in runs:
        for package in run.pop('inventory',[]):
            key=(package['name'],package['version'],package['path'])
            if not any((p['name'],p['version'],p['path'])==key for p in report['dependencies']):report['dependencies'].append(package)
    report['scanner_runs'].extend(runs)
    grouped={}
    for f in report['findings']+extra:
        semantic=SEMANTICS.get(f['rule_id'],f['rule_id'])
        key=(f['path'],f['start_line'],semantic,f.get('derived_id'))
        observation={'engine':f['engine'],'engine_version':f.get('engine_version'),'rule_id':f['rule_id'],'finding_id':f['id']}
        if key not in grouped:
            grouped[key]={**f,'provenance':[observation]}
        else:
            existing=grouped[key]
            if observation not in existing['provenance']:existing['provenance'].append(observation)
            order={'critical':4,'high':3,'medium':2,'low':1,'info':0}
            if order.get(f['severity'],0)>order.get(existing['severity'],0):existing['severity']=f['severity']
            existing['related_files']=sorted(set(existing['related_files']+f['related_files']))
    findings=list(grouped.values())
    for f in findings:
        f['engine']=' + '.join(dict.fromkeys(p['engine'] for p in f['provenance']))
    findings.sort(key=lambda f:({'critical':0,'high':1,'medium':2,'low':3}.get(f['severity'],4),f['path'],f['start_line']))
    report['findings']=findings
    counts=Counter(f['path'] for f in findings)
    for item in report['files']:item['finding_count']=counts[item['path']]
    for category in report['risk']:
        report['risk'][category]=next((s for s in ('critical','high','medium','low') if any(f['category']==category and f['severity']==s for f in findings)),'unknown')
    report['assessment']='REVIEW RECOMMENDED' if findings else 'INCONCLUSIVE'
    report['state']='PARTIAL'
    return report
