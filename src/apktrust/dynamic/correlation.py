"""Append runtime evidence without mutating deterministic static findings or verdicts."""
import copy

def correlate(report,result):
    report=copy.deepcopy(report); links=[]
    for observation in result.get('observations',[]):
        attrs=observation.get('attributes',{}); related=[]
        if observation['type']=='PERMISSION_DIALOG' and attrs.get('permission'):
            permission=attrs['permission']
            if permission in report.get('permissions',[]):
                links.append({'capability':permission,'static_evidence':'Declared in manifest','runtime_evidence':'Permission requested during execution','relationship':'supports','confidence':'Increased for permission request only','observation_id':observation['id'],'evidence_source':observation['evidence_source']})
        for finding in report.get('findings',[]):
            if finding.get('origin','Static')!='Static':continue
            relationship=None
            if observation['type']=='ACTIVITY_OBSERVED' and attrs.get('action')=='android.intent.action.INSTALL_PACKAGE' and finding.get('rule')=='installer':relationship='supports'
            if finding.get('rule') in attrs.get('related_static_rules',[]):relationship=attrs.get('relationship','unresolved')
            if relationship in ('supports','contradicts','unresolved'):
                evidence={'job_id':result['job_id'],'observation_id':observation['id'],'relationship':relationship,'evidence_source':observation['evidence_source'],'source_label':observation['source_label'],'summary':observation['summary'],'device':result['device'],'timestamp':observation.get('timestamp'),'artifact_ids':observation.get('artifact_ids',[])}
                existing=finding.setdefault('runtime_evidence',[])
                if not any(e['job_id']==evidence['job_id'] and e['observation_id']==evidence['observation_id'] for e in existing):existing.append(evidence)
                related.append(finding['id'])
        if observation['type'] in ('APP_CRASHED','TEST_FAILURE'):
            fid='D-'+result['job_id'][:8]+'-'+observation['id']
            if not any(f['id']==fid for f in report.get('findings',[])):
                report.setdefault('findings',[]).append({'id':fid,'rule':'runtime-'+observation['type'].lower(),'title':'Runtime crash observed' if observation['type']=='APP_CRASHED' else 'Remote execution failure','severity':'info','category':'Runtime','confidence':'Medium','status':'Needs review','description':observation['summary'],'origin':'Dynamic','source_label':observation['source_label'],'evidence_source':observation['evidence_source'],'runtime':{'job_id':result['job_id'],'device':result['device'],'test_duration':result.get('provider_metadata',{}).get('run_durations',[]),'timestamp':observation.get('timestamp'),'related_static_evidence':related,'artifacts':observation.get('artifact_ids',[])},'evidence':[{'id':observation['id'],'path':'Remote execution '+result['job_id'],'location':observation.get('timestamp') or 'Execution metadata','snippet':observation['summary'],'analyzer':observation['evidence_source'],'sha256':report.get('sha256'),'evidence_source':observation['evidence_source']}],'benign':'A test or crash failure alone does not establish malware.','remediation':'Inspect the remote artifacts and reproduce the observed failure.'})
    report.setdefault('dynamic_correlations',{})[result['job_id']]=links
    report.setdefault('dynamic_results',{})[result['job_id']]=result
    coverage='NOT_RUN' if result['status']=='NOT_RUN' else result.get('coverage','LIMITED')
    report['dynamic_coverage']={'status':coverage,'provider':result['provider'],'job_id':result['job_id'],'analysis_gaps':result['analysis_gaps']}
    for stage in report.get('coverage',[]):
        if stage['name']=='Dynamic sandbox':
            detail='No runtime execution; dynamic verification was not completed' if coverage=='NOT_RUN' else 'LIMITED runtime coverage; full instrumentation unavailable'
            stage.update(status='Partial' if result['status']=='COMPLETED' else 'Not run' if result['status']=='NOT_RUN' else 'Failed',detail=result['provider']+' · '+result['status']+' · '+detail,analyzed=1 if result['status']=='COMPLETED' else 0,total=1)
    report['analysis_completion']='COMPLETED_WITH_GAPS'
    return report
