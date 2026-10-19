import json
import streamlit as st
from scam_engine import investigate

st.set_page_config(page_title="ScamShield AI", page_icon="🛡️", layout="wide")

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Space+Grotesk:wght@400;500;600;700&display=swap');
:root{--bg:#07111f;--panel:#0c1b2b;--line:rgba(148,177,205,.17);--muted:#91a6bb;--text:#edf5ff;--cyan:#57e3d0}
html,body,[class*="css"]{font-family:'DM Sans',sans-serif}
.stApp{background:radial-gradient(ellipse at 12% 0%,rgba(29,111,143,.19),transparent 34%),radial-gradient(ellipse at 92% 8%,rgba(62,91,180,.15),transparent 30%),var(--bg);color:var(--text)}
[data-testid="stHeader"]{background:transparent}
[data-testid="stSidebar"]{background:#091725;border-right:1px solid var(--line)}
[data-testid="stSidebar"] *{color:var(--text)}
.block-container{padding-top:1.8rem;padding-bottom:3rem;max-width:1450px}
h1,h2,h3{font-family:'Space Grotesk',sans-serif!important;color:var(--text)!important;letter-spacing:-.025em}
p,li,label{color:#c4d3e2}
.hero{padding:1.6rem 1.7rem;border:1px solid rgba(87,227,208,.22);border-radius:22px;background:linear-gradient(115deg,rgba(17,49,65,.96),rgba(13,27,48,.96) 68%,rgba(23,35,70,.95));margin-bottom:1.2rem}
.eyebrow,.section-kicker{color:var(--cyan);text-transform:uppercase;letter-spacing:.14em;font-size:.72rem;font-weight:700}
.hero-title{font-family:'Space Grotesk',sans-serif;font-size:clamp(2rem,3.5vw,3.2rem);font-weight:700;line-height:1.06;color:#f2f8ff;margin-top:.5rem}
.hero-title span{color:var(--cyan)}
.hero-sub{color:#a9bfd2;font-size:1rem;max-width:760px;margin-top:.75rem;line-height:1.6}
.pill{display:inline-block;border:1px solid rgba(87,227,208,.27);color:#aaf6e9;background:rgba(87,227,208,.07);padding:.35rem .65rem;border-radius:999px;font-size:.72rem;margin:.8rem .3rem 0 0}
.panel{background:linear-gradient(145deg,rgba(14,32,50,.98),rgba(10,25,41,.98));border:1px solid var(--line);border-radius:17px;padding:1.1rem 1.2rem}
.metric{background:linear-gradient(145deg,#10253a,#0b1b2d);border:1px solid var(--line);border-radius:15px;padding:1rem 1.1rem;min-height:100px;margin-bottom:.5rem}
.metric-label{color:#8ea9c1;font-size:.75rem;margin-bottom:.45rem}
.metric-value{font-family:'Space Grotesk',sans-serif;font-size:1.7rem;font-weight:700;color:#f3f8ff}
.metric-note,.small-note{color:#829ab0;font-size:.78rem;line-height:1.5}
.status{border-radius:14px;padding:1.1rem 1.25rem;border:1px solid var(--line);background:#102337;margin:.6rem 0 1rem}
.status-high{border-color:rgba(255,102,125,.45);background:linear-gradient(100deg,rgba(113,30,49,.35),rgba(18,35,54,.92))}
.status-suspicious{border-color:rgba(255,190,92,.4);background:linear-gradient(100deg,rgba(111,72,22,.27),rgba(18,35,54,.92))}
.status-clear{border-color:rgba(87,227,208,.3);background:linear-gradient(100deg,rgba(18,91,86,.23),rgba(18,35,54,.92))}
.status-title{font-family:'Space Grotesk',sans-serif;font-size:1.25rem;font-weight:700;color:#f5f9ff}
.status-copy{color:#a9bfd2;font-size:.88rem;margin-top:.3rem}
.finding{background:rgba(16,35,55,.82);border:1px solid var(--line);border-radius:12px;padding:.8rem .9rem;margin:.45rem 0}
.finding-title{color:#e7f1fb;font-weight:600}.finding-evidence{color:#90a9c0;font-size:.82rem;margin-top:.25rem}
div.stButton>button{border-radius:11px;border:1px solid rgba(87,227,208,.35);background:linear-gradient(100deg,#58e1cf,#6bb8f6);color:#061521;font-weight:700;padding:.65rem 1rem;min-height:2.7rem}
div.stButton>button:hover{border-color:#a4fff2;color:#061521;filter:brightness(1.04)}
div[data-testid="stTextArea"] textarea{background:#091827!important;color:#edf5ff!important;border:1px solid rgba(148,177,205,.25)!important;border-radius:13px!important}
[data-testid="stExpander"]{border:1px solid var(--line);border-radius:12px;background:rgba(12,27,43,.65)}
hr{border-color:var(--line)!important} footer{visibility:hidden}
</style>
""", unsafe_allow_html=True)

with st.sidebar:
    st.markdown("## 🛡️ ScamShield")
    st.markdown("<div class='small-note'>THREAT TRIAGE CONSOLE</div>", unsafe_allow_html=True)
    st.divider()
    st.markdown("### Investigation flow")
    for n, label in [("01","Message signals"),("02","URL structure"),("03","Evidence summary"),("04","Protective actions")]:
        st.markdown(f"<div style='display:flex;gap:.7rem;align-items:center;margin:.7rem 0'><span style='color:#57e3d0;font-size:.75rem;font-weight:700'>{n}</span><span style='color:#c4d3e2'>{label}</span></div>", unsafe_allow_html=True)
    st.divider()
    st.markdown("### System status")
    st.markdown("🟢 Local analysis engine")
    st.markdown("⚪ Live URL reputation: not connected")
    st.markdown("⚪ ASI:One / ACP: integration pending")
    st.divider()
    st.markdown("<div class='small-note'>Submitted URLs are parsed locally and are not opened. Avoid pasting personal or confidential information.</div>", unsafe_allow_html=True)

st.markdown("""
<div class="hero">
 <div class="eyebrow">AI-powered threat investigation</div>
 <div class="hero-title">Stay one step ahead<br>of <span>digital scams.</span></div>
 <div class="hero-sub">Investigate suspicious messages, surface the signals that matter, and get practical next steps. Evidence first. No false promises of certainty.</div>
 <span class="pill">EXPLAINABLE ANALYSIS</span><span class="pill">URL STRUCTURE CHECK</span><span class="pill">SAFETY RECOMMENDATIONS</span>
</div>
""", unsafe_allow_html=True)

left, right = st.columns([1.35,.75], gap="large")
samples = {
 "Prize / fee scam":"Congratulations! You have won a reward. Claim your prize immediately and pay a processing fee at https://reward-example.invalid/claim",
 "Account urgency":"URGENT: Your account will be blocked within 10 minutes. Verify your bank account now.",
 "Everyday message":"Hi, are we still meeting at the library at 4 PM? Please let me know."
}
with left:
    st.markdown("<div class='section-kicker'>01 / New investigation</div>", unsafe_allow_html=True)
    st.subheader("Analyze a message")
    st.write("Paste suspicious text, or load a sample scenario.")
    choice = st.selectbox("Load a sample scenario", ["Choose a sample…",*samples.keys()])
    message = st.text_area("Message content", value=samples.get(choice,""), height=190, placeholder="Paste SMS, email text, or a suspicious URL here…")
    analyze_clicked = st.button("🛡️  Run investigation", use_container_width=True)
with right:
    st.markdown("<div class='section-kicker'>02 / What gets checked</div>", unsafe_allow_html=True)
    st.subheader("Investigation modules")
    st.markdown("""
    <div class="panel">
      <div style="display:flex;gap:12px;margin-bottom:1rem"><div style="color:#57e3d0;font-size:1.3rem">◈</div><div><b style="color:#edf5ff">Message intelligence</b><div class="small-note">Urgency, payment requests, credential prompts and suspicious wording.</div></div></div>
      <div style="display:flex;gap:12px;margin-bottom:1rem"><div style="color:#57e3d0;font-size:1.3rem">⌁</div><div><b style="color:#edf5ff">URL inspection</b><div class="small-note">Hostname and URL structure checks without visiting the link.</div></div></div>
      <div style="display:flex;gap:12px;margin-bottom:1rem"><div style="color:#57e3d0;font-size:1.3rem">◇</div><div><b style="color:#edf5ff">Evidence summary</b><div class="small-note">Findings are explicit; unknowns remain unknown.</div></div></div>
      <div style="display:flex;gap:12px"><div style="color:#57e3d0;font-size:1.3rem">✓</div><div><b style="color:#edf5ff">Protection guidance</b><div class="small-note">Practical actions to reduce exposure to potential scams.</div></div></div>
    </div>
    """, unsafe_allow_html=True)
    st.write("")
    st.markdown("<div class='small-note'>Current prototype uses configurable rules. Live domain reputation, advanced classification, and Fetch.ai chat integration are not enabled yet.</div>", unsafe_allow_html=True)

if analyze_clicked:
    if not message.strip():
        st.error("Enter a message or choose a sample before running an investigation.")
    else:
        report = investigate(message)
        st.divider()
        st.markdown("<div class='section-kicker'>03 / Investigation report</div>", unsafe_allow_html=True)
        risk = report["risk"]
        cls = {"HIGH":"status-high","SUSPICIOUS":"status-suspicious","NO SIGNALS DETECTED":"status-clear"}.get(risk,"")
        desc = {
          "HIGH":"Multiple configured warning signals were found. Treat this message cautiously and verify independently.",
          "SUSPICIOUS":"One or more warning signals were found. Investigate further before taking action.",
          "NO SIGNALS DETECTED":"No configured warning patterns were found. This does not establish that the message is safe."
        }.get(risk,"")
        st.markdown(f"<div class='status {cls}'><div class='section-kicker'>PRELIMINARY ASSESSMENT</div><div class='status-title'>{risk}</div><div class='status-copy'>{desc}</div></div>", unsafe_allow_html=True)
        m1,m2,m3=st.columns(3)
        metrics=[
          ("MESSAGE SIGNALS",report["summary"]["message_signals"],"Configured phrase matches"),
          ("URL SIGNALS",report["summary"]["url_signals"],"Structural indicators"),
          ("URLS IDENTIFIED",report["summary"]["urls_found"],"Not opened or visited"),
        ]
        for col,(label,value,note) in zip((m1,m2,m3),metrics):
            with col:
                st.markdown(f"<div class='metric'><div class='metric-label'>{label}</div><div class='metric-value'>{value:02d}</div><div class='metric-note'>{note}</div></div>",unsafe_allow_html=True)
        tab_evidence,tab_urls,tab_actions=st.tabs(["Evidence","URL inspection","Recommended actions"])
        with tab_evidence:
            st.markdown("#### Message signals")
            if report["message_findings"]:
                for f in report["message_findings"]:
                    st.markdown(f"<div class='finding'><div class='finding-title'>{f['category'].title()}</div><div class='finding-evidence'>Matched phrase: <code>{f['evidence']}</code></div><div class='finding-evidence'>{f['explanation']}</div></div>",unsafe_allow_html=True)
            else: st.info("No configured message patterns matched.")
        with tab_urls:
            if report["url_findings"]:
                for item in report["url_findings"]:
                    st.markdown(f"**`{item['url']}`**")
                    c1,c2=st.columns(2)
                    c1.markdown(f"<div class='metric'><div class='metric-label'>HOSTNAME</div><div style='color:#edf5ff;overflow-wrap:anywhere'>{item.get('hostname','Unavailable')}</div></div>",unsafe_allow_html=True)
                    c2.markdown("<div class='metric'><div class='metric-label'>REPUTATION</div><div style='color:#edf5ff'>Not checked</div></div>",unsafe_allow_html=True)
                    for finding in item["findings"]:
                        if isinstance(finding,dict): st.markdown(f"- **{finding['signal']}** — {finding['detail']}")
                        else: st.markdown(f"- {finding}")
            else: st.info("No candidate URLs were detected.")
        with tab_actions:
            for i,action in enumerate(report["recommended_actions"],1):
                st.markdown(f"<div class='finding'><span style='color:#57e3d0;font-weight:700;margin-right:.5rem'>{i:02d}</span><span style='color:#e7f1fb'>{action}</span></div>",unsafe_allow_html=True)
        with st.expander("Technical details and limitations"):
            for limitation in report["limitations"]: st.markdown(f"- {limitation}")
            st.download_button("Download report as JSON",data=json.dumps(report,indent=2,ensure_ascii=False),file_name="scamshield-report.json",mime="application/json")

st.divider()
st.markdown("<div class='small-note' style='text-align:center'>SCAMSHIELD AI · HACKATHON PROTOTYPE · Rule-based triage is not proof of malicious activity. Verify unexpected requests through official channels.</div>",unsafe_allow_html=True)
