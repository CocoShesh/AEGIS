import html,json

def sbom(report):
    components=[]; seen=set()
    for d in report['dependencies']:
        key=(d['ecosystem'],d['name'],d['version'])
        if key in seen: continue
        seen.add(key)
        components.append({'type':'library','name':d['name'],'version':d['version'],'properties':[{'name':'reposentinel:version-resolution','value':'locked' if d['resolved'] else 'declared-only'},{'name':'reposentinel:source','value':d['path']}]})
    return {'bomFormat':'CycloneDX','specVersion':'1.5','version':1,'metadata':{'timestamp':report['created_at'],'tools':[{'vendor':'RepoSentinel','name':'manifest-inventory','version':report['version']}]},'components':components}

def sarif(report):
    return {'version':'2.1.0','$schema':'https://json.schemastore.org/sarif-2.1.0.json','runs':[{'tool':{'driver':{'name':'RepoSentinel','version':report['version']}},'results':[{'ruleId':f['rule_id'],'level':{'critical':'error','high':'error','medium':'warning'}.get(f['severity'],'note'),'message':{'text':f['message']},'locations':[{'physicalLocation':{'artifactLocation':{'uri':f['path']},'region':{'startLine':f['start_line']}}}],'properties':{'confidence':f['confidence'],'engine':f['engine']}} for f in report['findings']]}]}

def html_report(report):
    e=html.escape; repo=report['repository']; rows=''.join(f'<article><h2>{e(f["severity"].upper())} · {e(f["title"])}</h2><p>{e(f["path"])}:{f["start_line"]} · {e(f["engine"])} · {e(f["confidence"])} confidence</p><p>{e(f["message"])}</p><pre>{e(f["evidence"])}</pre><p>Review: {e((f.get("review") or {}).get("disposition","Unreviewed"))}</p><p>{e((f.get("review") or {}).get("note",""))}</p></article>' for f in report['findings'])
    return f'<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>RepoSentinel report</title><style>body{{font:16px/1.6 system-ui;max-width:960px;margin:40px auto;padding:24px;color:#17283d;background:#f5f7fb}}article{{border-top:1px solid #cad3df;padding:18px 0}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:white;padding:16px}}h1{{font-size:32px}}h2{{font-size:20px}}@media print{{body{{background:white;margin:0}}}}</style><h1>RepoSentinel · {e(repo["name"])}</h1><p>{e(report["assessment"])} · {e(report["state"])}</p><p>Provenance: {e(repo["provenance"])} · Commit: {e(repo.get("commit") or "No Git commit asserted")}</p><p>{report["coverage"]["accounted"]} objects accounted for · {report["coverage"]["unresolved"]} unresolved or limited · {report["coverage"]["percent"]}% content inspection</p><p>Static evidence supports human review; it does not certify safety.</p>{rows}<h2>Limitations</h2><ul>'+''.join('<li>'+e(x)+'</li>' for x in report['limitations'])+'</ul><h2>Scanner runs</h2><pre>'+e(json.dumps(report['scanner_runs'],indent=2))+'</pre></html>'
