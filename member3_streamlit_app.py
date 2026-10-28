"""
AI/ML & Risk Assessment Module — Interactive demo UI.

This is separate from dashboard.py (that one is the final, integrated
project dashboard). This app exists to demo / test / screenshot this
module on its own: the dataset, the trained model's evaluation graphs, a
live "run risk assessment on a finding" demo, and the adaptive attack plans.

Run:
    streamlit run member3_app.py
"""

import os
import json
import time
import subprocess
import sys

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px

from core.ai_risk.risk_engine import AIRiskAssessmentEngine
from core.discovery.api_discovery import APIDiscovery
from core.scanner.vuln_scanner import APIVulnerabilityScanner

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
GRAPHS_DIR = os.path.join(DATA_DIR, "graphs")
CSV_PATH = os.path.join(DATA_DIR, "training_data.csv")
MODEL_PATH = os.path.join(DATA_DIR, "severity_model.joblib")
METRICS_PATH = os.path.join(DATA_DIR, "model_metrics.json")
REPORT_PATH = os.path.join(DATA_DIR, "final_assessment_report.json")

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]

# ---------------------------------------------------------------------------
# Page config + cyber theme
# ---------------------------------------------------------------------------
st.set_page_config(page_title="AI Risk Engine | API Sentinel", page_icon="🧠", layout="wide")

CYBER_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@600;800&display=swap');

html, body, [class*="css"] { font-family: 'Share Tech Mono', monospace; }

[data-testid="stAppViewContainer"]{
    background:
        linear-gradient(rgba(4,8,16,0.94), rgba(4,8,16,0.97)),
        repeating-linear-gradient(0deg, rgba(0,245,255,0.05) 0px, rgba(0,245,255,0.05) 1px, transparent 1px, transparent 32px),
        repeating-linear-gradient(90deg, rgba(0,245,255,0.05) 0px, rgba(0,245,255,0.05) 1px, transparent 1px, transparent 32px),
        #05070d;
    color: #d7f8ff;
}
[data-testid="stSidebar"]{
    background: linear-gradient(180deg, #060a13 0%, #0a1420 60%, #060a13 100%);
    border-right: 1px solid #123049;
}
[data-testid="stHeader"]{ background: rgba(0,0,0,0); }

/* ---------- Hero ---------- */
.hero{
    padding: 26px 30px; border-radius: 14px; margin-bottom: 18px;
    background: linear-gradient(120deg, #050b16, #081c2e 55%, #1a0b2e 100%);
    border: 1px solid #0ff3ff55;
    box-shadow: 0 0 12px #00f5ff33, inset 0 0 40px #00f5ff11;
    position: relative; overflow: hidden;
}
.hero::after{
    content:""; position:absolute; top:-50%; left:-20%; width:60%; height:200%;
    background: linear-gradient(120deg, transparent, rgba(0,245,255,0.08), transparent);
    animation: sheen 6s ease-in-out infinite;
}
@keyframes sheen{ 0%{transform:translateX(-100%);} 100%{transform:translateX(250%);} }
.hero h1{
    font-family: 'Orbitron', sans-serif; font-weight: 800; letter-spacing: 1px;
    color: #6dfcff; text-shadow: 0 0 10px #00f5ffaa, 0 0 24px #00f5ff55; margin: 0;
    font-size: 30px;
}
.hero p{ color: #8fd9e8; margin: 6px 0 0 0; font-size: 14px; }

/* ---------- Badges ---------- */
.badge{
    display:inline-block; padding: 4px 12px; border-radius: 20px; font-size: 12px;
    border: 1px solid currentColor; margin-right: 6px; letter-spacing: 0.5px;
}
.badge-critical{ color:#ff3d6e; text-shadow:0 0 8px #ff3d6e88; }
.badge-high{ color:#ff9d3d; text-shadow:0 0 8px #ff9d3d88; }
.badge-medium{ color:#f6ff00; text-shadow:0 0 8px #f6ff0088; }
.badge-low{ color:#39ff14; text-shadow:0 0 8px #39ff1488; }
.badge-info{ color:#8dd6ff; text-shadow:0 0 8px #8dd6ff66; }
.badge-purple{ color:#c58bff; text-shadow:0 0 8px #c58bff66; }

[data-testid="stMetric"]{
    background: rgba(0,245,255,0.05); border: 1px solid #123049; border-radius: 12px;
    padding: 14px 10px; box-shadow: 0 0 14px #00f5ff11;
    transition: box-shadow .25s ease, transform .25s ease;
}
[data-testid="stMetric"]:hover{ box-shadow: 0 0 20px #00f5ff44; transform: translateY(-2px); }
[data-testid="stMetricLabel"]{ color: #7fdcec !important; }
[data-testid="stMetricValue"]{ color: #baffff !important; text-shadow: 0 0 8px #00f5ff55; }

.term-box{
    background: #030509; border: 1px solid #113049; border-radius: 10px;
    padding: 16px; color: #6dffb0; font-family: 'Share Tech Mono', monospace;
    white-space: pre-wrap; box-shadow: inset 0 0 20px #00ff8811;
}

/* ---------- Feature cards (Overview) ---------- */
@keyframes fadeInUp{
    from{ opacity:0; transform: translateY(14px); }
    to{ opacity:1; transform: translateY(0); }
}
.feature-card{
    border-radius: 14px; padding: 18px 18px 16px 18px; height: 100%;
    background: rgba(255,255,255,0.03);
    border-left: 3px solid var(--accent, #00f5ff);
    box-shadow: 0 0 16px var(--glow, rgba(0,245,255,0.12));
    animation: fadeInUp .55s ease both;
    transition: transform .2s ease, box-shadow .2s ease;
}
.feature-card:hover{ transform: translateY(-3px); box-shadow: 0 0 24px var(--glow, rgba(0,245,255,0.25)); }
.feature-card h4{ margin: 0 0 6px 0; color: var(--accent, #6dfcff); font-size: 15px; letter-spacing: .3px; }
.feature-card p{ margin: 0; color: #b9d9e6; font-size: 12.5px; line-height: 1.5; }
.feature-icon{ font-size: 22px; margin-bottom: 6px; display:block; }

.stat-strip{
    display:flex; gap:14px; flex-wrap:wrap; margin: 6px 0 18px 0;
}
.stat-chip{
    background: rgba(0,245,255,0.05); border: 1px solid #123049; border-radius: 10px;
    padding: 8px 16px; font-size: 12.5px; color:#a9e7f5;
}
.stat-chip b{ color:#6dfcff; }

/* ---------- Sidebar logo ---------- */
.sidebar-logo{
    text-align:center; padding: 6px 0 14px 0; margin-bottom: 6px;
    border-bottom: 1px solid #123049;
}
.sidebar-logo .icon{
    font-size: 40px; display:inline-block;
    animation: pulseGlow 2.4s ease-in-out infinite;
    filter: drop-shadow(0 0 8px #00f5ffaa);
}
@keyframes pulseGlow{
    0%,100%{ transform: scale(1); filter: drop-shadow(0 0 6px #00f5ff88); }
    50%{ transform: scale(1.08); filter: drop-shadow(0 0 16px #00f5ffdd); }
}
.sidebar-logo .brand{
    font-family:'Orbitron', sans-serif; font-weight:800; font-size:17px; letter-spacing:1px;
    background: linear-gradient(90deg,#6dfcff,#c58bff,#6dfcff);
    background-size: 200% auto;
    -webkit-background-clip: text; -webkit-text-fill-color: transparent;
    animation: shimmer 4s linear infinite;
    margin-top: 4px;
}
@keyframes shimmer{ 0%{background-position:0% center;} 100%{background-position:200% center;} }
.sidebar-logo .tag{ color:#6f93a6; font-size:10.5px; letter-spacing:.5px; margin-top:2px; }

.sev-legend{ display:flex; flex-direction:column; gap:6px; margin-top:10px; }
.sev-legend .row{ display:flex; align-items:center; gap:8px; font-size:11.5px; color:#a9e7f5; }
.sev-dot{ width:9px; height:9px; border-radius:50%; display:inline-block; box-shadow:0 0 6px currentColor; }

section[data-testid="stSidebar"] .stRadio label{ color: #baffff; }
::-webkit-scrollbar{ width: 10px; }
::-webkit-scrollbar-thumb{ background:#0ff3ff55; border-radius: 10px; }

/* ---------- Adaptive attack payload cards ---------- */
@keyframes cardIn{
    from{ opacity:0; transform: translateX(-10px); }
    to{ opacity:1; transform: translateX(0); }
}
@keyframes pulseBorder{
    0%,100%{ box-shadow: 0 0 10px #ff2ec422; }
    50%{ box-shadow: 0 0 18px #ff2ec455; }
}
.payload-card{
    background: #050b14; border: 1px solid #ff2ec455; border-radius: 10px;
    padding: 14px 16px; margin-bottom: 12px;
    animation: cardIn .45s ease both, pulseBorder 3s ease-in-out infinite;
}
.payload-card code{ color: #ff8dd6; }
.phase-badge{
    display:inline-block; padding:2px 10px; border-radius:12px; font-size:10.5px;
    background: rgba(197,139,255,0.12); color:#c58bff; border:1px solid #c58bff55; margin-left:8px;
}
.db-badge{
    display:inline-block; padding:2px 10px; border-radius:12px; font-size:10.5px;
    background: rgba(109,252,255,0.1); color:#6dfcff; border:1px solid #6dfcff55; margin-left:6px;
}

/* ---------- Graph entrance animation (applies to every Plotly chart) ---------- */
.js-plotly-plot{ animation: chartFadeIn .6s ease both; }
@keyframes chartFadeIn{
    from{ opacity:0; transform: scale(.94) translateY(8px); }
    to{ opacity:1; transform: scale(1) translateY(0); }
}
</style>
"""
st.markdown(CYBER_CSS, unsafe_allow_html=True)

st.markdown(
    """<div class="hero">
    <h1>🧠 AI / ML &amp; RISK ASSESSMENT ENGINE</h1>
    <p>Automated severity prediction, dynamic risk scoring, explainability and adaptive attack planning
    &mdash; part of the API Sentinel security platform.</p>
    </div>""",
    unsafe_allow_html=True,
)

PLOTLY_DARK = dict(
    template="plotly_dark",
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font=dict(family="Share Tech Mono, monospace", color="#d7f8ff"),
)
NEON_SEVERITY_COLORS = {"Critical": "#ff2ec4", "High": "#ff9d3d", "Medium": "#f6ff00", "Low": "#39ff14"}

SAMPLE_FINDINGS = [
    {"id": "VULN-001", "vulnerability_type": "SQL Injection", "severity": "Critical",
     "endpoint": "/api/users/search", "method": "GET", "parameter": "query",
     "payload_used": "' OR '1'='1", "evidence": "sqlite3.OperationalError: syntax error near '1'",
     "confidence": 0.98, "cwe_id": "CWE-89"},
    {"id": "VULN-002", "vulnerability_type": "Reflected Cross-Site Scripting (XSS)", "severity": "High",
     "endpoint": "/api/comments", "method": "POST", "parameter": "comment",
     "payload_used": "<script>alert('XSS')</script>", "evidence": "Payload reflected unescaped in rendered_html",
     "confidence": 0.95, "cwe_id": "CWE-79"},
    {"id": "VULN-003", "vulnerability_type": "Broken Object Level Authorization (IDOR)", "severity": "High",
     "endpoint": "/api/orders/{id}", "method": "GET", "parameter": "id",
     "payload_used": "id=1042 (not owned by caller)", "evidence": "Returned another user's order record",
     "confidence": 0.9, "cwe_id": "CWE-639"},
    {"id": "VULN-004", "vulnerability_type": "Missing Security Header", "severity": "Low",
     "endpoint": "/health", "method": "GET", "parameter": "-",
     "payload_used": "-", "evidence": "Content-Security-Policy header absent",
     "confidence": 0.92, "cwe_id": "CWE-1021"},
    {"id": "VULN-005", "vulnerability_type": "Missing Rate Limiting", "severity": "Medium",
     "endpoint": "/api/auth/login", "method": "POST", "parameter": "-",
     "payload_used": "500 requests / 10s", "evidence": "No 429 response after repeated login attempts",
     "confidence": 0.88, "cwe_id": "CWE-799"},
]


@st.cache_resource(show_spinner=False)
def get_engine():
    return AIRiskAssessmentEngine()


def load_metrics():
    if os.path.exists(METRICS_PATH):
        with open(METRICS_PATH, encoding="utf-8") as f:
            return json.load(f)
    return None


def gauge_chart(score, title):
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        number={"suffix": "/100", "font": {"color": "#baffff", "size": 34}},
        title={"text": title, "font": {"color": "#6dfcff", "size": 16}},
        gauge={
            "axis": {"range": [0, 100], "tickcolor": "#6dfcff"},
            "bar": {"color": "#00f5ff"},
            "bgcolor": "rgba(0,0,0,0)",
            "borderwidth": 1, "bordercolor": "#123049",
            "steps": [
                {"range": [0, 20], "color": "#0f3d1a"},
                {"range": [20, 45], "color": "#4a4a0f"},
                {"range": [45, 70], "color": "#4a2a0f"},
                {"range": [70, 100], "color": "#4a0f24"},
            ],
        },
    ))
    fig.update_layout(**PLOTLY_DARK, height=280, margin=dict(l=20, r=20, t=50, b=10))
    return fig


def severity_bar_chart(counts: dict, title: str):
    """Bar chart that always shows all four severity classes, in a fixed
    order and color, with the count labeled on every bar (even zero) so a
    class is never silently missing from the chart."""
    values = [int(counts.get(s, 0)) for s in SEVERITY_ORDER]
    df = pd.DataFrame({"Severity": SEVERITY_ORDER, "Count": values})
    fig = px.bar(
        df, x="Severity", y="Count", color="Severity",
        color_discrete_map=NEON_SEVERITY_COLORS,
        category_orders={"Severity": SEVERITY_ORDER},
        title=title, text="Count",
    )
    fig.update_traces(textposition="outside", cliponaxis=False, marker_line_width=1,
                       marker_line_color="rgba(255,255,255,0.25)")
    top = max(values) if values else 0
    fig.update_layout(**PLOTLY_DARK, showlegend=False, yaxis_range=[0, max(top * 1.25, 1)])
    return fig


def animate_gauge(container, final_score: float, title: str, key: str, steps: int = 18, delay: float = 0.02):
    """Renders the gauge growing from 0 up to its final value."""
    for i in range(1, steps + 1):
        t = i / steps
        container.plotly_chart(gauge_chart(final_score * t, title),
                                use_container_width=True, key=f"{key}_{i}")
        if i < steps:
            time.sleep(delay)


def animate_bars(container, counts: dict, title: str, key: str, steps: int = 14, delay: float = 0.025):
    """Renders the severity bar chart with bars growing up from 0 to their final counts."""
    for i in range(1, steps + 1):
        t = i / steps
        scaled = {s: counts.get(s, 0) * t for s in SEVERITY_ORDER}
        container.plotly_chart(severity_bar_chart(scaled, title),
                                use_container_width=True, key=f"{key}_{i}")
        if i < steps:
            time.sleep(delay)


def severity_legend_row(counts: dict):
    st.markdown(
        "".join(
            f'<span class="badge badge-{s.lower()}">{s.upper()} {int(counts.get(s, 0))}</span>'
            for s in SEVERITY_ORDER
        ),
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Sidebar navigation
# ---------------------------------------------------------------------------
with st.sidebar:
    st.markdown(
        """<div class="sidebar-logo">
            <span class="icon">🛡️</span>
            <div class="brand">API SENTINEL</div>
            <div class="tag">AI RISK &amp; ADAPTIVE DEFENSE CONSOLE</div>
        </div>""",
        unsafe_allow_html=True,
    )

    st.markdown("### ⚙️ Control Panel")
    page = st.radio(
        "Navigate",
        ["🏠 Overview", "📊 Dataset & Model", "🩻 Live Risk Assessment", "⚡ Adaptive Attacks"],
    )

    st.markdown("---")
    st.caption("Severity color key")
    st.markdown(
        '<div class="sev-legend">'
        + "".join(
            f'<div class="row"><span class="sev-dot" style="color:{NEON_SEVERITY_COLORS[s]}"></span>{s}</div>'
            for s in SEVERITY_ORDER
        )
        + "</div>",
        unsafe_allow_html=True,
    )

    st.markdown("---")
    st.caption("Retrain from scratch (regenerates dataset + model + graphs):")
    if st.button("🔁 Regenerate dataset & retrain model"):
        with st.spinner("Running dataset_generator.py and train_model.py ..."):
            r1 = subprocess.run([sys.executable, "-m", "core.ai_risk.dataset_generator"],
                                 cwd=BASE_DIR, capture_output=True, text=True)
            r2 = subprocess.run([sys.executable, "-m", "core.ai_risk.train_model"],
                                 cwd=BASE_DIR, capture_output=True, text=True)
        st.code((r1.stdout + "\n" + r2.stdout)[-1500:] or "(no output)")
        if r1.returncode != 0 or r2.returncode != 0:
            st.error("Training failed — see log above.")
        else:
            st.success("Dataset regenerated and model retrained.")
            get_engine.clear()
            st.rerun()

    st.markdown("---")
    st.caption("Module: **AI/ML & Risk Assessment**\nPart of a 4-module API Sentinel pipeline.")

metrics = load_metrics()

# ---------------------------------------------------------------------------
# Overview
# ---------------------------------------------------------------------------
if page == "🏠 Overview":

    stat_bits = []
    if metrics:
        stat_bits.append(f'<div class="stat-chip">Model accuracy&nbsp;<b>{metrics["test_accuracy"]*100:.1f}%</b></div>')
        stat_bits.append(f'<div class="stat-chip">Training samples&nbsp;<b>{metrics["total_samples"]}</b></div>')
    if os.path.exists(MODEL_PATH):
        trained_at = time.strftime("%d %b %Y, %H:%M", time.localtime(os.path.getmtime(MODEL_PATH)))
        stat_bits.append(f'<div class="stat-chip">Model last trained&nbsp;<b>{trained_at}</b></div>')
    if os.path.exists(REPORT_PATH):
        with open(REPORT_PATH, encoding="utf-8") as f:
            _rep = json.load(f)
        _assess = _rep.get("assessment", _rep)
        if "total_findings" in _assess:
            stat_bits.append(f'<div class="stat-chip">Last run findings&nbsp;<b>{_assess["total_findings"]}</b></div>')
        if "overall_risk_score" in _assess:
            stat_bits.append(f'<div class="stat-chip">Last risk score&nbsp;<b>{_assess["overall_risk_score"]}/100</b></div>')

    if stat_bits:
        st.markdown('<div class="stat-strip">' + "".join(stat_bits) + "</div>", unsafe_allow_html=True)

    st.markdown("#### What this module does")

    features = [
        ("🧬", "Severity Prediction", "A trained ML classifier scores every incoming finding as "
         "Critical, High, Medium or Low based on its real-world characteristics.", "#ff2ec4", "rgba(255,46,196,0.18)"),
        ("📈", "Dynamic Risk Scoring", "Combines endpoint sensitivity, data exposure and confidence "
         "into a single 0-100 API-wide risk score.", "#00f5ff", "rgba(0,245,255,0.18)"),
        ("🎯", "CVSS 3.1 Estimation", "Derives an estimated CVSS base score so findings map cleanly "
         "onto an industry-standard severity scale.", "#ff9d3d", "rgba(255,157,61,0.18)"),
        ("📝", "Explainability & Fixes", "Every finding gets a plain-language explanation, CWE/OWASP "
         "mapping, and a ready-to-use remediation code sample.", "#39ff14", "rgba(57,255,20,0.18)"),
        ("⚡", "Adaptive Attack Planning", "Suggests context-aware, next-step attack payloads for "
         "safe, authorized local testing only.", "#c58bff", "rgba(197,139,255,0.18)"),
        ("🔄", "Continuous Retraining", "The dataset, model and evaluation graphs can be regenerated "
         "on demand straight from the control panel.", "#f6ff00", "rgba(246,255,0,0.18)"),
    ]

    cols = st.columns(3)
    for i, (icon, title, desc, accent, glow) in enumerate(features):
        with cols[i % 3]:
            st.markdown(
                f'<div class="feature-card" style="--accent:{accent}; --glow:{glow}; '
                f'animation-delay:{i*0.08}s;">'
                f'<span class="feature-icon">{icon}</span>'
                f'<h4>{title}</h4><p>{desc}</p></div>',
                unsafe_allow_html=True,
            )
        if i % 3 == 2 and i != len(features) - 1:
            st.write("")

    st.write("")
    if metrics:
        st.markdown("#### Current model at a glance")
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Test accuracy", f"{metrics['test_accuracy']*100:.1f}%")
        c2.metric("5-fold CV accuracy", f"{metrics['cv_mean_accuracy']*100:.1f}%")
        c3.metric("Training samples", metrics["total_samples"])
        c4.metric("Classes", len(metrics["class_order"]))
    else:
        st.warning("No trained model found yet — click **Regenerate dataset & retrain model** in the sidebar.")

# ---------------------------------------------------------------------------
# Dataset & Model
# ---------------------------------------------------------------------------
elif page == "📊 Dataset & Model":
    st.markdown("#### Training dataset")
    st.caption(
        "There's no public dataset for 'API finding metadata → severity label', so this dataset is "
        "simulated using a CVSS-3.1-style scoring rule (vuln type + endpoint sensitivity + data exposure "
        "+ auth context + confidence → continuous risk score → severity band), plus ~6% controlled label "
        "noise so the model faces realistic, slightly ambiguous cases instead of a trivial lookup table."
    )
    if os.path.exists(CSV_PATH):
        df = pd.read_csv(CSV_PATH)
        st.dataframe(df.head(25), use_container_width=True, height=280)

        col1, col2 = st.columns(2)
        with col1:
            counts = df["severity"].value_counts().reindex(SEVERITY_ORDER).fillna(0)
            animate_bars(st.empty(), counts.to_dict(), "Severity Class Distribution", key="dist_bar")
            severity_legend_row(counts.to_dict())
        with col2:
            fig2 = px.pie(df, names="vuln_type", title="Vulnerability Type Mix", hole=0.45)
            fig2.update_layout(**PLOTLY_DARK)
            st.plotly_chart(fig2, use_container_width=True)
    else:
        st.info("Dataset not generated yet — use the sidebar button.")

    st.markdown("#### Model evaluation")
    if metrics:
        c1, c2, c3 = st.columns(3)
        c1.metric("Held-out test accuracy", f"{metrics['test_accuracy']*100:.1f}%")
        c2.metric("5-fold CV mean", f"{metrics['cv_mean_accuracy']*100:.1f}%")
        c3.metric("CV std dev", f"±{metrics['cv_std_accuracy']*100:.1f}%")

        g1, g2 = st.columns(2)
        for col, fname in zip([g1, g2], ["confusion_matrix.png", "feature_importance.png"]):
            p = os.path.join(GRAPHS_DIR, fname)
            if os.path.exists(p):
                col.image(p, use_container_width=True)
        g3, g4 = st.columns(2)
        for col, fname in zip([g3, g4], ["cv_scores.png", "correlation_heatmap.png"]):
            p = os.path.join(GRAPHS_DIR, fname)
            if os.path.exists(p):
                col.image(p, use_container_width=True)

        with st.expander("Full classification report (per-class precision / recall / F1)"):
            rep = pd.DataFrame(metrics["classification_report"]).T
            st.dataframe(rep, use_container_width=True)
    else:
        st.info("No metrics yet — train the model from the sidebar.")

# ---------------------------------------------------------------------------
# Live Risk Assessment
# ---------------------------------------------------------------------------
elif page == "🩻 Live Risk Assessment":
    st.markdown("#### Run the AI risk engine on real findings")
    src = st.radio(
        "Findings source",
        ["Use built-in sample findings", "Upload scan_results.json (from scanner module)", "Scan a live target API now"],
        horizontal=True,
    )

    findings = None
    if src == "Use built-in sample findings":
        findings = SAMPLE_FINDINGS
        st.caption(f"Using {len(findings)} built-in sample findings.")

    elif src == "Upload scan_results.json (from scanner module)":
        up = st.file_uploader("Upload the scanner module's vulnerability scan JSON", type=["json"])
        if up is not None:
            data = json.load(up)
            findings = data.get("findings", data if isinstance(data, list) else [])
            st.caption(f"Loaded {len(findings)} findings from upload.")

    else:  # Scan a live target API now
        st.caption("Runs discovery + the vulnerability scanner directly against a target you own or "
                    "are authorized to test, then scores the results here.")
        target_url = st.text_input("Target API base URL", placeholder="http://127.0.0.1:5000")
        spec_url = st.text_input("Optional: OpenAPI/Swagger spec URL", placeholder="leave blank to auto-probe")
        run_scan = st.button("🚀 Discover & scan this API")

        if run_scan:
            if not target_url.strip():
                st.error("Enter a target API base URL first.")
            else:
                with st.spinner("Phase 1/2 — Discovering endpoints..."):
                    discovery = APIDiscovery()
                    try:
                        if spec_url.strip():
                            disc_res = discovery.load_spec_from_url(spec_url.strip())
                        else:
                            disc_res = discovery.probe_live_api(target_url.strip())
                    except Exception as e:
                        st.error(f"Discovery failed: {e}")
                        disc_res = None

                if disc_res:
                    st.success(f"Discovered {disc_res['total_endpoints']} endpoint(s).")
                    with st.spinner("Phase 2/2 — Running vulnerability scan..."):
                        try:
                            scanner = APIVulnerabilityScanner(base_url=target_url.strip())
                            scan_res = scanner.run_full_scan(disc_res["endpoints"])
                            st.session_state["live_scan_findings"] = scan_res["findings"]
                            st.success(f"Scan complete — {scan_res['total_vulnerabilities']} finding(s) detected.")
                        except Exception as e:
                            st.error(f"Scan failed: {e}")

        findings = st.session_state.get("live_scan_findings")
        if findings:
            st.caption(f"Using {len(findings)} finding(s) from the live scan above.")

    if findings:
        engine = get_engine()
        with st.spinner("Scoring findings..."):
            result = engine.assess_findings(findings)

        c1, c2, c3 = st.columns([1.1, 1, 1])
        with c1:
            animate_gauge(st.empty(), result["overall_risk_score"], "Overall API Risk Score", key="risk_gauge")
        with c2:
            st.metric("Threat level", result["threat_level"])
            st.metric("Estimated CVSS base score", f"{result['cvss_base_score']} / 10.0")
        with c3:
            st.metric("Total findings", result["total_findings"])
            bd = {s: result["severity_breakdown"].get(s, 0) for s in SEVERITY_ORDER}
            severity_legend_row(bd)

        animate_bars(st.empty(), bd, "Severity Breakdown (this run)", key="breakdown_bar")

        st.markdown("#### Executive summary")
        st.markdown(f'<div class="term-box">{result["executive_summary"]}</div>', unsafe_allow_html=True)

        st.markdown("#### Findings — ML-predicted severity, explanation & fix")
        for f in result["enriched_findings"]:
            sev = f.get("ml_predicted_severity", "Medium")
            with st.expander(f"[{sev}] {f['vulnerability_type']}  —  {f['method']} {f['endpoint']}"):
                exp = f["explanation"]
                st.write(f"**CWE:** {exp['cwe_reference']}")
                st.write(f"**OWASP category:** {exp['owasp_category']}")
                st.write(f"**Why it matters:** {exp['technical_description']}")
                st.write(f"**Impact:** {exp['attack_impact']}")
                st.write(f"**Fix:** {exp['remediation_guidance']}")
                st.code(exp["secure_code_example"], language="python")
                st.caption(f"Model confidence used: {f['confidence']} · "
                           f"endpoint sensitivity: {f['factors']['endpoint_sensitivity_score']}/5 · "
                           f"data exposure: {f['factors']['data_exposure_score']}/5")
    else:
        st.info("Choose a findings source above to run the engine.")

# ---------------------------------------------------------------------------
# Adaptive Attacks
# ---------------------------------------------------------------------------
elif page == "⚡ Adaptive Attacks":
    st.markdown("#### Adaptive attack / payload recommendations")
    st.caption(
        "For research/testing on systems you own or are authorized to test only "
        "(e.g. OWASP Juice Shop, DVWA, your own lab API)."
    )
    engine = get_engine()
    plan = engine.adaptive_selector.analyze_and_adapt(SAMPLE_FINDINGS)
    st.metric("Adaptive plans generated", plan["total_adaptive_plans"])

    for i, p in enumerate(plan["adaptive_attack_plans"]):
        badges = f'<span class="phase-badge">{p.get("attack_phase", "Adaptive Phase")}</span>'
        if p.get("target_db") and p.get("target_db") != "N/A":
            badges += f'<span class="db-badge">{p["target_db"]}</span>'
        st.markdown(
            f'<div class="payload-card" style="animation-delay:{i*0.1}s">'
            f'<b>{p["method"]} {p["endpoint"]}</b> &mdash; {p["strategy"]}{badges}<br>'
            f'<span style="color:#8fd9e8">{p["rationale"]}</span><br><br>'
            + "<br>".join(f"<code>{pl}</code>" for pl in p["adaptive_payloads"]) +
            "</div>",
            unsafe_allow_html=True,
        )
