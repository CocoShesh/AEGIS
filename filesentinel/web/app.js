const $ = (s, root=document) => root.querySelector(s);
let token = '', currentId = '';
const historyEl = $('#history'), resultsEl = $('#results'), formError = $('#form-error');
const esc = (value='') => String(value).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function api(path, options={}) {
  const response = await fetch(path, {...options, headers:{...(options.headers||{}), ...(token?{'X-FileSentinel-Token':token}:{})}});
  if (!response.ok) { const body=await response.json().catch(()=>({})); throw new Error(body.detail||body.error||`Request failed (${response.status})`); }
  return response.status===204 ? null : response.json();
}
function niceDate(ts) { return new Date(ts*1000).toLocaleString(undefined,{month:'short',day:'numeric',hour:'numeric',minute:'2-digit'}); }
async function refreshHistory() {
  try {
    const rows=await api('./api/scans');
    if(!rows.length){historyEl.innerHTML='<p class="quiet">No scans yet. Add a file to begin.</p>';return;}
    historyEl.replaceChildren(...rows.map(item=>{
      const b=document.createElement('button'); b.className='history-item'+(item.id===currentId?' selected':''); b.type='button';
      b.innerHTML=`<span class="history-name">${esc(item.name)}</span><span class="history-meta">${esc(item.family||item.state)} · ${niceDate(item.created)}</span>${item.assessment?`<span class="history-assessment">${esc(item.assessment)}</span>`:''}`;
      b.addEventListener('click',()=>openScan(item.id)); return b;
    }));
  } catch(e) { historyEl.innerHTML=`<p class="quiet">${esc(e.message)}</p>`; }
}
function metric(label,value,extra=''){return `<div class="metric"><span>${esc(label)}</span><strong class="${extra}">${esc(value??'—')}</strong></div>`;}
function reportMarkup(scan) {
 const r=scan.report, id=r?.identity||{}, structure=r?.structure||{};
 if(!r) return `<div class="card"><div class="result-head"><div><span class="eyebrow">${esc(scan.state)}</span><h3>${esc(scan.name)}</h3><p>${esc(scan.detail)}</p></div><span class="state-pill">${esc(scan.state)}</span></div><div class="progress-line"><span></span></div></div>`;
 const structureRows=Object.entries(structure).filter(([k,v])=>k!=='sample_names'&&(['string','number','boolean'].includes(typeof v))).map(([k,v])=>`<div class="kv"><span>${esc(k.replaceAll('_',' '))}</span><strong>${esc(v)}</strong></div>`).join('')||'<p class="quiet">No additional structure fields for this format.</p>';
 const engines=(r.engine_runs||[]).map(x=>`<div class="engine-row"><strong>${esc(x.engine)}</strong><span>${esc(x.status)}${x.isolation?` · ${esc(x.isolation)}`:''}</span></div>`).join('');
 const limitations=(r.limitations||[]).map(x=>`<li>${esc(x)}</li>`).join('');
 const aiRun=(r.engine_runs||[]).find(x=>x.engine==='Shared AI assessment');
 const aiMessage=aiRun?.status==='NOT_CONFIGURED'?'No AI provider is configured. Static metadata remains available.':aiRun?.status==='FAILED'?'AI assessment is unavailable. Static metadata remains available.':'AI assessment was not run.';
 const ai=scan.ai?`<div class="result-section"><h4>AI assessment · opinion, not a verdict</h4><div class="ai-box"><span class="ai-assessment">${esc(scan.ai.assessment)} · ${esc(scan.ai.confidence)} CONFIDENCE</span><p>${esc(scan.ai.summary)}</p>${scan.ai.confidence_reason?`<p><strong>Confidence:</strong> ${esc(scan.ai.confidence_reason)}</p>`:''}${scan.ai.recommendations?.length?`<ul>${scan.ai.recommendations.map(x=>`<li>${esc(x)}</li>`).join('')}</ul>`:''}<p class="quiet">Provider: ${esc(scan.ai.provider||'configured AEGIS provider')}${scan.ai.model?` · ${esc(scan.ai.model)}`:''}. Based on bounded metadata and structure flags. No file bytes or original filename were sent.</p></div></div>`:`<div class="result-section"><h4>AI assessment</h4><p class="quiet">${esc(aiMessage)}</p></div>`;
 return `<div class="card"><div class="result-head"><div><span class="eyebrow">INVESTIGATION · ${niceDate(scan.created)}</span><h3>${esc(scan.name)}</h3><p>${esc(scan.detail)}</p></div><span class="state-pill">${esc(r.coverage?.status||'PARTIAL')} · ${esc(r.coverage?.meaning||'')}</span></div>
 <div class="metric-grid">${metric('File family',id.family)}${metric('Size',`${(id.size_bytes/1024/1024).toFixed(id.size_bytes<1048576?3:1)} MiB`)}${metric('MIME type',id.mime)}${metric('SHA-256',id.sha256,'hash')}</div>
 <div class="result-section"><h4>Structure observed</h4><div class="kv-grid">${structureRows}</div></div>
 ${ai}<div class="result-section"><h4>Engine coverage</h4>${engines}</div>
 <div class="result-section"><h4>Limits and unresolved questions</h4><ul class="limits">${limitations}</ul></div>
 <div class="result-section result-actions"><button id="copy-hash" class="button" type="button">Copy SHA-256</button><button id="delete-scan" class="button danger" type="button">Delete report</button></div></div>`;
}
async function openScan(id) {
 currentId=id; resultsEl.hidden=false; resultsEl.innerHTML='<div class="card"><p>Loading investigation…</p></div>';
 try {
  let scan=await api(`./api/scans/${id}`); resultsEl.innerHTML=reportMarkup(scan); await refreshHistory();
  if(!scan.report&&['QUEUED','ANALYZING','AI_REVIEWING'].includes(scan.state)) setTimeout(()=>openScan(id),1000);
  $('#delete-scan')?.addEventListener('click',async()=>{if(!confirm('Delete this saved report and its AI assessment? The file itself has already been removed.'))return;try{await api(`./api/scans/${id}`,{method:'DELETE'});currentId='';resultsEl.hidden=true;await refreshHistory();}catch(e){alert(e.message);}});
  $('#copy-hash')?.addEventListener('click',async()=>{await navigator.clipboard.writeText(scan.report.identity.sha256);$('#copy-hash').textContent='Copied';});
 } catch(e) {resultsEl.innerHTML=`<div class="card form-error">${esc(e.message)}</div>`;}
}
async function start(file) {
 formError.hidden=true; if(!file)return;
 if(file.size>64*1024*1024){formError.textContent='This file exceeds the 64 MiB limit.';formError.hidden=false;return;}
 const zone=$('#dropzone'), old=zone.querySelector('.drop-title').textContent; zone.querySelector('.drop-title').textContent=`Preparing ${file.name}…`;
 try {
  const created=await api('./api/scans',{method:'POST',headers:{'Content-Type':'application/octet-stream','X-Filename':file.name},body:file});
  resultsEl.hidden=false; await openScan(created.id); resultsEl.scrollIntoView({behavior:matchMedia('(prefers-reduced-motion: reduce)').matches?'auto':'smooth',block:'start'});
 } catch(e) {formError.textContent=e.message;formError.hidden=false;}
 finally {zone.querySelector('.drop-title').textContent=old;$('#file-input').value='';}
}
$('#file-input').addEventListener('change',e=>start(e.target.files[0]));
$('#refresh-history').addEventListener('click',refreshHistory);
const dz=$('#dropzone'); dz.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();$('#file-input').click();}});
for(const event of ['dragenter','dragover'])dz.addEventListener(event,e=>{e.preventDefault();dz.classList.add('drag');});
for(const event of ['dragleave','drop'])dz.addEventListener(event,e=>{e.preventDefault();dz.classList.remove('drag');});
dz.addEventListener('drop',e=>start(e.dataTransfer.files[0]));
(async()=>{try{const s=await api('./api/session');token=s.token;$('#ai-chip').textContent=s.ai_configured?'AI · AUTO AFTER SCAN':'AI · NOT CONFIGURED';$('#ai-chip').title=s.ai_configured?'Configured shared AEGIS providers receive bounded file metadata only.':'Static triage still works; add AI provider keys in the APKTrust .env configuration.';await refreshHistory();const id=new URLSearchParams(location.search).get('scan');if(id)openScan(id);}catch(e){formError.textContent=e.message;formError.hidden=false;}})();
