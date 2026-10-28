import json
import os
import sys
import streamlit as st
import pandas as pd
import plotly.express as px
from core.ai_risk.risk_engine import AIRiskAssessmentEngine

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from reports.report_generator import generate_report

st.set_page_config(page_title='API Sentinel | AI Risk Dashboard', page_icon='🛡️', layout='wide')

st.markdown('''<style>
[data-testid="stAppViewContainer"]{background:linear-gradient(135deg,#07111f,#0d1b2a 55%,#102a43);color:#eaf4ff}
[data-testid="stMetric"]{background:rgba(255,255,255,.07);padding:18px;border-radius:16px;border:1px solid #24445e}
.hero{padding:28px;border-radius:20px;background:linear-gradient(100deg,#123b5d,#1c6e8c);box-shadow:0 0 30px #0ea5e955}
</style>''', unsafe_allow_html=True)
st.markdown('<div class="hero"><h1>🛡️ API Sentinel</h1><p>AI-Driven Adaptive API Security Scanner • Risk Intelligence Console</p></div>', unsafe_allow_html=True)

REPORT_PATH = os.path.join(BASE_DIR, 'data', 'final_assessment_report.json')


def load_assessment():
    if os.path.exists(REPORT_PATH):
        with open(REPORT_PATH, encoding='utf-8-sig') as f:
            report = json.load(f)
        return report.get('assessment', report), report

    findings = [
        {'id':'VULN-001','vulnerability_type':'SQL Injection','severity':'Critical','endpoint':'/api/users/search','method':'GET','parameter':'query','evidence':'Safe local demo finding','confidence':.95},
        {'id':'VULN-002','vulnerability_type':'Missing Security Header','severity':'Low','endpoint':'/health','method':'GET','parameter':'CSP','evidence':'Header missing','confidence':.90}
    ]
    assessment = AIRiskAssessmentEngine().assess_findings(findings)
    return assessment, {'target_url':'Demo data'}

assessment, complete_report = load_assessment()
score = assessment.get('overall_risk_score', 0)
breakdown = assessment.get('severity_breakdown', {})
findings = assessment.get('enriched_findings', [])

cols = st.columns(5)
for c, label, val in zip(
    cols,
    ['Risk Score','Findings','Critical','High','Medium'],
    [f'{score}/100', len(findings), breakdown.get('Critical',0), breakdown.get('High',0), breakdown.get('Medium',0)]
):
    c.metric(label, val)

st.progress(min(100, max(0, int(score))) / 100, text=f'Overall API Risk: {score}/100')

left, right = st.columns(2)
with left:
    st.subheader('Severity Distribution')
    df = pd.DataFrame({'Severity': list(breakdown.keys()), 'Count': list(breakdown.values())})
    if not df.empty:
        st.plotly_chart(px.bar(df, x='Severity', y='Count', color='Severity', template='plotly_dark'), use_container_width=True)

with right:
    st.subheader('Risk Composition')
    if not df.empty:
        st.plotly_chart(px.pie(df, names='Severity', values='Count', hole=.45, template='plotly_dark'), use_container_width=True)

st.subheader('Endpoint-wise Findings')
if findings:
    table = pd.DataFrame(findings)
    st.dataframe(table, use_container_width=True)
    for f in findings:
        severity = f.get('ml_predicted_severity', f.get('severity', 'Medium'))
        with st.expander(f"{severity} • {f.get('vulnerability_type', f.get('type', 'Finding'))} • {f.get('endpoint', '')}"):
            st.write(f.get('explanation', {}))
            st.caption(f"Confidence: {f.get('confidence', 0)}")
else:
    st.info('No findings available. Run the pipeline first.')

st.divider()
st.subheader('Security Report')
st.write('Generate a formatted PDF summary of the current assessment.')
if st.button('Generate PDF Security Report'):
    with st.spinner('Generating report...'):
        report_path = generate_report(complete_report)
    with open(report_path, 'rb') as pdf_file:
        st.download_button('⬇ Download Security Report (PDF)', data=pdf_file.read(), file_name='API_Security_Report.pdf', mime='application/pdf')
    st.success('Report generated successfully.')

with st.sidebar:
    st.header('Controls')
    if st.button('🔄 Reload report'):
        st.rerun()
    st.write('Report source:', REPORT_PATH if os.path.exists(REPORT_PATH) else 'Safe demo data')
