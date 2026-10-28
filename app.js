const $ = (id) => document.getElementById(id);
const severityOrder = ['Critical','High','Medium','Low'];
let pollTimer = null;
function setStatus(message, type='info') { const el=$('status'); el.textContent=message; el.className=`status ${type}`; }
function getAssessment(report){return report?.risk_assessment||report?.assessment||{}}
function getFindings(report){const a=getAssessment(report);return a.enriched_findings||a.findings||[]}
function severityClass(s){return String(s||'Medium').toLowerCase()}
function render(report){
 if(!report||report.status==='baseline'){ $('score').textContent='—';$('findings').textContent='0';$('critical').textContent='0';$('high').textContent='0';$('medium').textContent='0';$('riskText').textContent='No scan';$('progressFill').style.width='0%';$('findingsTable').innerHTML='<tr><td colspan="5" class="empty">No findings yet. Run a scan.</td></tr>';return; }
 const a=getAssessment(report), fs=getFindings(report), b=a.severity_breakdown||{}, score=Number(a.overall_risk_score||0);
 $('score').textContent=`${score}/100`;$('findings').textContent=fs.length;$('critical').textContent=b.Critical||0;$('high').textContent=b.High||0;$('medium').textContent=b.Medium||0;$('riskText').textContent=`${score}/100`;$('progressFill').style.width=`${Math.max(0,Math.min(100,score))}%`;$('targetLabel').textContent=report.target_url||'';
 const max=Math.max(1,...severityOrder.map(s=>Number(b[s]||0))); $('severityChart').className='bars'; $('severityChart').innerHTML=severityOrder.map(s=>{const n=Number(b[s]||0),h=Math.max(4,n/max*160);return `<div class="bar-item"><b>${n}</b><div class="bar ${severityClass(s)}" style="height:${h}px"></div><small>${s}</small></div>`}).join('');
 $('composition').innerHTML=severityOrder.filter(s=>Number(b[s]||0)>0).map(s=>`<div class="pill"><b>${s}</b>${b[s]}</div>`).join('')||'<div class="empty">No findings.</div>';
 $('findingsTable').innerHTML=fs.length?fs.map(f=>{const sev=f.ml_predicted_severity||f.severity||'Medium',conf=Number(f.confidence??0);return `<tr><td class="sev ${severityClass(sev)}">${sev}</td><td>${f.endpoint||''}</td><td>${f.method||''}</td><td>${f.vulnerability_type||f.type||'Finding'}</td><td>${(conf*100).toFixed(0)}%</td></tr>`}).join(''):'<tr><td colspan="5" class="empty">No findings.</td></tr>';
}
async function loadReport(){try{const r=await fetch('/api/reports/latest',{cache:'no-store'});const d=await r.json();render(d);if(d.status==='baseline')setStatus('Ready. Start the local vulnerable API, then run a scan.');else setStatus('Latest assessment loaded.','ok')}catch(e){setStatus(`Could not load report: ${e.message}`,'error')}}
async function runScan(){
 const target=$('targetUrl').value.trim();if(!target)return setStatus('Enter a target API URL.','error');
 $('scanBtn').disabled=true;$('scanBtn').textContent='Scanning...';$('liveBox').classList.add('active');$('liveProgress').style.width='0%';setStatus('Starting live scan...');
 try{
  const start=await fetch('/api/pipeline/full-scan/start',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target_url:target})});
  const job=await start.json();if(!start.ok)throw new Error(job.detail||'Could not start scan');
  pollTimer=setInterval(()=>pollJob(job.job_id),400);
 }catch(e){setStatus(`Scan failed: ${e.message}`,'error');$('scanBtn').disabled=false;$('scanBtn').textContent='Run Full Scan'}
}
async function pollJob(id){try{const r=await fetch(`/api/pipeline/full-scan/status/${id}`,{cache:'no-store'}),j=await r.json();if(!r.ok)throw new Error(j.detail||'Status error');$('livePhase').textContent=j.phase||'Running';$('liveMessage').textContent=j.message||'';$('liveProgress').style.width=`${j.progress||0}%`;setStatus(`${j.phase}: ${j.message||''}`);if(j.status==='completed'){clearInterval(pollTimer);render(j.report);setStatus('Full scan completed successfully.','ok');$('scanBtn').disabled=false;$('scanBtn').textContent='Run Full Scan';}else if(j.status==='failed'){clearInterval(pollTimer);setStatus(`Scan failed: ${j.error||j.message}`,'error');$('scanBtn').disabled=false;$('scanBtn').textContent='Run Full Scan'}}catch(e){clearInterval(pollTimer);setStatus(`Live update failed: ${e.message}`,'error');$('scanBtn').disabled=false;$('scanBtn').textContent='Run Full Scan'}}
$('reloadBtn').addEventListener('click',loadReport);$('scanBtn').addEventListener('click',runScan);
$('pdfBtn').addEventListener('click',async()=>{try{const r=await fetch('/api/reports/pdf');if(!r.ok){const d=await r.json();throw new Error(d.detail||'No report available')}const blob=await r.blob(),a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='API_Security_Report.pdf';a.click();URL.revokeObjectURL(a.href);setStatus('PDF report generated.','ok')}catch(e){setStatus(e.message,'error')}});
loadReport();
