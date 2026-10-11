from reposentinel.core import analyze,demo_objects,finding
from reposentinel.normalize import finish_report

def test_same_semantic_observation_is_deduplicated_without_losing_provenance():
    report=analyze(demo_objects(),{'name':'fixture'})
    existing=next(f for f in report['findings'] if f['path']=='src/encoded.js' and f['rule_id']=='RS-EXEC-001' and not f.get('derived_id'))
    duplicate=finding(existing['path'],existing['start_line'],'rs-js-exec','Eval','high','medium','vulnerability','Review eval',existing['evidence'])
    duplicate['engine']='Semgrep';duplicate['engine_version']='1.180.0'
    before=len(report['findings'])
    result=finish_report(report,[],[duplicate])
    assert len(result['findings'])==before
    merged=next(f for f in result['findings'] if f['id']==existing['id'])
    assert {p['engine'] for p in merged['provenance']}=={'Semgrep','RepoSentinel'}
    assert merged['evidence']==existing['evidence']
    assert sum(f['finding_count'] for f in result['files'])==len(result['findings'])
