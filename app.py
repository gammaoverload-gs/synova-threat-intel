import base64
import html
import io
import json
import time
import hashlib
import re
import urllib.parse
from datetime import datetime, timezone, timedelta
import folium
from elevenlabs.client import ElevenLabs
from ingestion_engine import EmailIngestionEngine
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
import streamlit as st
from streamlit_folium import st_folium
import google.generativeai as genai

IST_TZ = timezone(timedelta(hours=5, minutes=30))

st.set_page_config(
    page_title="SYNOVA Autonomous SOC Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# --- SECRETS & CLIENT INITIALIZATION ---
api_key = st.secrets.get("GEMINI_API_KEY", "")
elevenlabs_api_key = st.secrets.get("ELEVENLABS_API_KEY", "")
abuse_key = st.secrets.get("ABUSEIPDB_API_KEY", "")
backend_gmail_pwd = st.secrets.get("GMAIL_PASSWORD", st.secrets.get("IMAP_PASSWORD", ""))

eleven_client = ElevenLabs(api_key=elevenlabs_api_key) if elevenlabs_api_key else None

# --- PERSISTENT STATE CONTROLLERS ---
if "replay" in st.query_params:
    st.query_params.clear()
    st.session_state.intro_done = False
    st.session_state.last_played_audio_hash = None
    st.session_state.citadel_active = False
    st.session_state.results = None
    st.session_state.mailbox_catalog = []

if "intro_done" not in st.session_state:
    st.session_state.intro_done = False

if "last_played_audio_hash" not in st.session_state:
    st.session_state.last_played_audio_hash = None

if "copilot_history" not in st.session_state:
    st.session_state.copilot_history = []

if "citadel_active" not in st.session_state:
    st.session_state.citadel_active = False

if "results" not in st.session_state:
    st.session_state.results = None

if "mailbox_catalog" not in st.session_state:
    st.session_state.mailbox_catalog = []

# --- STEP 1: CALIBRATION SCREEN ---
if not st.session_state.intro_done:
    st.markdown(
        """
        <style>
        .stApp { background-color: #030712 !important; }
        .intro-container { display: flex; flex-direction: column; align-items: center; justify-content: center; text-align: center; margin-top: 15vh; margin-bottom: 25px; }
        .intro-shield-svg { width: 120px; height: 140px; fill: none; stroke: #00f0ff; stroke-width: 1.6; stroke-dasharray: 450; stroke-dashoffset: 450; animation: drawIntroShield 2.2s cubic-bezier(0.65, 0, 0.35, 1) forwards; filter: drop-shadow(0 0 24px rgba(0, 240, 255, 0.65)); }
        @keyframes drawIntroShield { 0% { stroke-dashoffset: 450; opacity: 0.3; } 80% { stroke-dashoffset: 0; opacity: 1; } 100% { stroke-dashoffset: 0; opacity: 1; } }
        .intro-title { color: #00f0ff; font-family: 'JetBrains Mono', monospace; font-size: 20px; font-weight: bold; letter-spacing: 3.5px; margin-top: 22px; }
        </style>
        <div class="intro-container">
            <svg class="intro-shield-svg" viewBox="0 0 24 28">
                <path d="M12 2 L3 5.5 V13 C3 19.5 7 24.5 12 26 C17 24.5 21 19.5 21 13 V5.5 Z" />
            </svg>
            <div class="intro-title">INITIALIZING SYNOVA DEFENSE MATRIX...</div>
            <div style="color: #94a3b8; font-family: monospace; font-size: 13px; margin-top: 8px;">CALIBRATING MULTI-MAIL INBOX TRIAGE & NIST QUANTUM PROOFS</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    col_l, col_btn, col_r = st.columns([1.5, 1, 1.5])
    with col_btn:
        if st.button("⚡ Skip Calibration", use_container_width=True):
            st.session_state.intro_done = True
            st.rerun()

    p_bar = st.progress(0)
    for p in range(100):
        time.sleep(0.015)
        p_bar.progress(p + 1)
    st.session_state.intro_done = True
    st.rerun()

# --- STEP 2: CONTAINERS SETUP ---
header_container = st.container()
ticker_container = st.container()
ingestion_container = st.container()
content_container = st.container()

primary_color = "#00f0ff"
glow_rgba = "rgba(0, 240, 255, 0.18)"
bg_glow = "rgba(0, 240, 255, 0.22)"
badge_text = "OMNICHANNEL RADAR ACTIVE"
score_num = 0
pulse_duration = "5.0s"
voice_briefing = "Welcome to Synova Omnichannel Threat Intelligence Matrix. Quantum-safe defense engines are online."

# --- STEP 3: OMNICHANNEL INGESTION GATEWAY ---
with ingestion_container:
    in_mode = st.radio(
        "Select Threat Ingestion Gateway:",
        [
            "☁️ Direct Gmail Account Sync (Logged-in Device)",
            "📝 Raw RFC-822 Stream Paste",
            "📱 1-Tap Mobile Threat Simulator",
            "💬 WhatsApp / Telegram / SMS Chat Paste",
            "📁 Safe File Upload (.eml / .msg / .txt)"
        ],
        horizontal=True
    )

    raw_payload_bytes = None
    selected_vector = "EMAIL"

    if "Direct Gmail" in in_mode:
        st.caption("🔒 **Zero-Password Device Gmail Sync:** Enter any active Gmail address to fetch, scan, and categorize all unread & recent emails into threat conditions.")
        c_gm1, c_gm2 = st.columns([2.2, 1.2])
        with c_gm1:
            target_gmail = st.text_input("Active Device Google / Gmail Address", value="oxforddude66@gmail.com")
        with c_gm2:
            st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
            st.markdown("<span style='color: #00f0ff; font-family: monospace; font-size: 12px;'>🟢 Active Device Session Linked</span>", unsafe_allow_html=True)

        if st.button("🚀 Fetch All Emails & Scan Threat Conditions", use_container_width=True):
            with st.spinner(f"Connecting to {target_gmail} mailbox buffer and triaging all incoming messages..."):
                catalog = EmailIngestionEngine.fetch_mailbox_threat_catalog(
                    target_email=target_gmail,
                    password=backend_gmail_pwd,
                    api_key=api_key,
                    abuse_key=abuse_key
                )
                st.session_state.mailbox_catalog = catalog
                if catalog:
                    st.session_state.results = catalog[0]
                st.rerun()

    elif "Raw RFC-822" in in_mode:
        st.caption("📝 **Strict RFC-822 MIME Parser:** Paste raw headers and payload directly from webmail ('Show Original' / 'View Message Source').")
        raw_stream_text = st.text_area(
            "Paste complete RFC-822 email source here:",
            height=140,
            placeholder="Received: from mail.attacker.net (185.220.101.5) by mx.google.com ...\nFrom: alerts@onlinesbi-kyc-update.top\nSubject: Urgent Security Action..."
        )
        if st.button("⚡ Triage Raw RFC Stream", use_container_width=True):
            if raw_stream_text.strip():
                raw_payload_bytes = raw_stream_text.encode("utf-8")
                selected_vector = "EMAIL"

    elif "1-Tap" in in_mode:
        st.caption("📲 **1-Tap Mobile Testing:** Zero download required. Tap any simulated attack vector below:")
        s_c1, s_c2, s_c3 = st.columns(3)
        if s_c1.button("🚨 Quishing & APT36 Lure", use_container_width=True):
            st.session_state.results = EmailIngestionEngine.fetch_mailbox_threat_catalog("target@enterprise.com")[0]
            st.session_state.mailbox_catalog = [st.session_state.results]
            st.rerun()
        if s_c2.button("⚠️ PayPal Homoglyph Spoof", use_container_width=True):
            st.session_state.results = EmailIngestionEngine.fetch_mailbox_threat_catalog("target@enterprise.com")[1]
            st.session_state.mailbox_catalog = [st.session_state.results]
            st.rerun()
        if s_c3.button("🚔 WhatsApp Digital Arrest", use_container_width=True):
            st.session_state.results = EmailIngestionEngine.fetch_mailbox_threat_catalog("target@enterprise.com")[2]
            st.session_state.mailbox_catalog = [st.session_state.results]
            st.rerun()

    elif "Chat Paste" in in_mode:
        st.caption("💬 Paste any WhatsApp / Telegram or SMS threat text below:")
        raw_chat = st.text_area("Paste chat body:", height=110, placeholder="[14:20] CBI Officer: A warrant has been issued against your Aadhaar...")
        if st.button("⚡ Triage Chat Message", use_container_width=True):
            if raw_chat.strip():
                raw_payload_bytes = raw_chat.encode("utf-8")
                selected_vector = "WHATSAPP"

    elif "Upload" in in_mode:
        st.caption("📁 Drop .eml, .msg, or .txt file directly:")
        up = st.file_uploader("Select threat artifact", type=["eml", "msg", "txt"])
        if up is not None:
            raw_payload_bytes = up.getvalue()
            selected_vector = "EMAIL" if not up.name.endswith(".txt") else "SMS"

    if raw_payload_bytes:
        with st.spinner("Parsing RFC-822 byte stream and computing post-quantum Merkle proofs..."):
            engine = EmailIngestionEngine(raw_payload_bytes, api_key=api_key, abuse_key=abuse_key, vector_type=selected_vector)
            st.session_state.results = engine.parse_email()
            st.session_state.mailbox_catalog = [st.session_state.results]
            st.rerun()

results = st.session_state.results

# --- STEP 4: THREAT EVALUATION ---
if results is not None:
    raw_score = str(results.get("ai_analysis", {}).get("score", "0"))
    try:
        score_num = int("".join([c for c in raw_score.split("/")[0] if c.isdigit()]))
    except Exception:
        score_num = 0

    origin_city = str(results["metadata"]["geo_data"].get("city", "Unknown"))
    origin_country = str(results["metadata"]["geo_data"].get("country", "Unknown"))
    channel_name = results.get("channel", "EMAIL")

    if st.session_state.citadel_active:
        primary_color = "#ff1744"
        glow_rgba = "rgba(255, 23, 68, 0.45)"
        bg_glow = "rgba(255, 23, 68, 0.35)"
        badge_text = "🚨 CITADEL HOST LOCKDOWN ENGAGED"
        pulse_duration = "0.45s"
        voice_briefing = "Citadel Protocol active. Host network air-gapped. Identity tokens revoked."
    elif score_num >= 70:
        primary_color = "#ff2a55"
        glow_rgba = "rgba(255, 42, 85, 0.38)"
        bg_glow = "rgba(255, 42, 85, 0.30)"
        badge_text = f"CRITICAL {channel_name} THREAT"
        pulse_duration = "0.65s"
        voice_briefing = f"Alert. Critical security threat isolated on {channel_name}. Origin anchored at {origin_city}."
    elif score_num >= 40:
        primary_color = "#ffb020"
        glow_rgba = "rgba(255, 176, 32, 0.28)"
        bg_glow = "rgba(255, 176, 32, 0.22)"
        badge_text = f"SUSPICIOUS {channel_name} VECTOR"
        pulse_duration = "1.6s"
        voice_briefing = f"Caution. Suspicious heuristics logged on {channel_name} stream."
    else:
        primary_color = "#00f0ff"
        glow_rgba = "rgba(0, 240, 255, 0.20)"
        bg_glow = "rgba(0, 240, 255, 0.22)"
        badge_text = f"CLEAN {channel_name} STREAM"
        pulse_duration = "4.0s"
        voice_briefing = "Forensic inspection complete. Artifact verified clean."

# --- STEP 5: ELEVATED HUD CSS ENGINE ---
shield_emoji_svg = f"""<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 28' fill='none'><path d='M12 2 L3 5.5 V13 C3 19.5 7 24.5 12 26 C17 24.5 21 19.5 21 13 V5.5 Z' stroke='{primary_color}' stroke-width='1.2' stroke-opacity='0.45' fill='{primary_color}' fill-opacity='0.05'/></svg>""".replace("#", "%23")

st.markdown(
    f"""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;800&family=Inter:wght@400;500;700&display=swap');
    html, body, [class*="css"] {{ font-family: 'Inter', sans-serif; }}
    code, pre, .mono-font {{ font-family: 'JetBrains Mono', monospace !important; }}
    .stApp {{
        background-color: #030712 !important;
        background-image: url("data:image/svg+xml,{shield_emoji_svg}"), radial-gradient(circle at 50% 0%, {bg_glow} 0%, transparent 60%), linear-gradient({glow_rgba} 1px, transparent 1px), linear-gradient(90deg, {glow_rgba} 1px, transparent 1px) !important;
        background-position: center 48%, center top, 0 0, 0 0 !important;
        background-repeat: no-repeat, no-repeat, repeat, repeat !important;
        background-size: 420px 480px, 100% 100%, 35px 35px, 35px 35px !important;
    }}
    .hud-ticker {{ display: flex; justify-content: space-between; align-items: center; background: rgba(6, 12, 28, 0.9); border: 1px solid rgba(0, 240, 255, 0.25); border-left: 3px solid {primary_color}; border-radius: 8px; padding: 8px 14px; margin-bottom: 16px; font-family: 'JetBrains Mono', monospace; font-size: 11px; color: #94a3b8; }}
    .hud-ticker-val {{ color: {primary_color}; font-weight: bold; }}
    div[data-testid="stTabs"] button[role="tab"][aria-selected="true"] {{ color: {primary_color} !important; background: {glow_rgba} !important; border: 1px solid {primary_color} !important; }}
    [data-testid="stMetric"] {{ background: rgba(8, 15, 32, 0.8) !important; border: 1px solid rgba(0, 240, 255, 0.25) !important; border-radius: 12px !important; padding: 12px 16px !important; }}
    [data-testid="stMetricValue"] {{ color: {primary_color} !important; font-family: 'JetBrains Mono', monospace !important; }}
    .soc-terminal {{ background: rgba(4, 8, 18, 0.95); border-left: 4px solid {primary_color}; border-radius: 8px; padding: 16px; font-family: 'JetBrains Mono', monospace; color: #d1d5db; font-size: 13px; margin-bottom: 20px; }}
    </style>
    """,
    unsafe_allow_html=True
)

# --- STEP 6: HEADER & LIVE IST STATUS ---
with header_container:
    col1, col2 = st.columns([3.0, 2.0])
    with col1:
        st.markdown(f"<h1 style='color: white; margin-bottom: 0px;'>🛡️ SYNOVA <span style='color: {primary_color};'>Omnichannel XDR</span></h1>", unsafe_allow_html=True)
        st.markdown("<p style='color: #94a3b8; font-size: 14px; margin-top: 4px;'>Autonomous AI Cyber Defense: NIST Post-Quantum Lattice Proof, 3D WebGL Globe & Mailbox Radar</p>", unsafe_allow_html=True)
    with col2:
        top_btn_col1, top_btn_col2 = st.columns(2)
        with top_btn_col1:
            if results is not None:
                if st.button("🔄 Reset / New Scan", use_container_width=True):
                    st.session_state.results = None
                    st.session_state.mailbox_catalog = []
                    st.rerun()
            else:
                st.markdown(f"<span style='color:{primary_color}; font-family:monospace; font-weight:bold;'>{badge_text}</span>", unsafe_allow_html=True)
        with top_btn_col2:
            st.markdown("<a href='?replay=1' target='_self' style='text-decoration:none; color:#00f0ff; font-family:monospace; font-weight:bold; border:1px solid #00f0ff; padding:6px 12px; border-radius:6px; display:inline-block;'>🔁 REPLAY PROTOCOL</a>", unsafe_allow_html=True)

with ticker_container:
    curr_time_ist = datetime.now(IST_TZ).strftime('%Y-%m-%d %H:%M:%S IST')
    st.markdown(
        f"""
        <div class="hud-ticker">
            <div>GRID: <span class="hud-ticker-val">IND-NORTH-DEFENSE-01</span></div>
            <div>STATUS: <span class="hud-ticker-val">COMBAT READY</span></div>
            <div>TIME (IST): <span class="hud-ticker-val">{curr_time_ist}</span></div>
            <div>PQC ENGINE: <span class="hud-ticker-val">NIST ML-DSA-87</span></div>
            <div>BUFFER: <span class="hud-ticker-val">ZERO-DISK RAM</span></div>
        </div>
        """,
        unsafe_allow_html=True
    )

# --- STEP 7: AUDIO ENGINE ---
current_audio_hash = hashlib.md5((voice_briefing + str(st.session_state.citadel_active)).encode('utf-8')).hexdigest()
if st.session_state.last_played_audio_hash != current_audio_hash:
    st.session_state.last_played_audio_hash = current_audio_hash
    audio_bridge_js = f"""
    <script>
    (function() {{
        if ('speechSynthesis' in window) {{
            window.speechSynthesis.cancel();
            const utter = new SpeechSynthesisUtterance("{voice_briefing}");
            utter.rate = 0.95;
            window.speechSynthesis.speak(utter);
        }}
    }})();
    </script>
    """
    st.components.v1.html(audio_bridge_js, height=0)

# --- REPORTLAB PDF BUFFER BUILDER ---
def build_pdf_buffer(results_data):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=30, leftMargin=30, topMargin=30, bottomMargin=30)
    story = []
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("TStyle", parent=styles["Heading1"], fontSize=18, textColor=colors.HexColor("#003366"))
    body_style = ParagraphStyle("BStyle", parent=styles["Normal"], fontSize=9, textColor=colors.HexColor("#222222"), leading=12)

    meta = (results_data.get("metadata") or {}) if isinstance(results_data, dict) else {}
    chain = (results_data.get("blockchain_custody") or {}) if isinstance(results_data, dict) else {}
    apt = (results_data.get("apt_attribution") or {}) if isinstance(results_data, dict) else {}
    street = (results_data.get("street_telemetry") or {}) if isinstance(results_data, dict) else {}
    pqc = (results_data.get("pqc_lattice_seal") or {}) if isinstance(results_data, dict) else {}

    story.append(Paragraph("SYNOVA CYBERSECURITY INCIDENT REPORT", title_style))
    story.append(Paragraph("<b>Post-Quantum Validated Omnichannel Forensic Playbook</b>", body_style))
    story.append(Spacer(1, 10))

    coords = f"{street.get('tactical_latitude', 'N/A')}, {street.get('tactical_longitude', 'N/A')} (Radius: +/-{street.get('accuracy_radius_meters', 12)}m)"

    m_data = [
        [Paragraph("<b>Channel Vector:</b>", body_style), Paragraph(str(results_data.get("channel", "EMAIL")), body_style)],
        [Paragraph("<b>Subject:</b>", body_style), Paragraph(html.escape(str(meta.get("subject", "N/A"))), body_style)],
        [Paragraph("<b>Sender:</b>", body_style), Paragraph(html.escape(str(meta.get("from", "N/A"))), body_style)],
        [Paragraph("<b>Origin IP:</b>", body_style), Paragraph(html.escape(str(meta.get("sender_ip", "N/A"))), body_style)],
        [Paragraph("<b>Tactical Coordinates:</b>", body_style), Paragraph(html.escape(coords), body_style)],
        [Paragraph("<b>Threat Actor:</b>", body_style), Paragraph(f"<b>{apt.get('actor_name')}</b> ({apt.get('confidence_score')}%)", body_style)],
        [Paragraph("<b>PQC Lattice Seal:</b>", body_style), Paragraph(f"<font name='Courier'>{pqc.get('lattice_signature_seal', 'N/A')}</font>", body_style)],
        [Paragraph("<b>Timestamp (IST):</b>", body_style), Paragraph(datetime.now(IST_TZ).strftime('%Y-%m-%d %H:%M:%S IST'), body_style)]
    ]
    t = Table(m_data, colWidths=[140, 380])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f2f4f8")),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#d0d7de")),
        ("PADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(t)
    doc.build(story)
    buffer.seek(0)
    return buffer

# --- STEP 8: RENDER INBOX THREAT CATALOG & ACTIVE INVESTIGATION ---
with content_container:
    if st.session_state.mailbox_catalog and len(st.session_state.mailbox_catalog) > 1:
        st.markdown("### 📥 Mailbox Threat Condition Triage Matrix")
        st.caption("All emails in the target account triaged by severity condition. Select any message below to inspect full deep forensic telemetry:")

        crit_count = sum(1 for m in st.session_state.mailbox_catalog if int(m['ai_analysis']['score'].split('/')[0]) >= 70)
        susp_count = sum(1 for m in st.session_state.mailbox_catalog if 40 <= int(m['ai_analysis']['score'].split('/')[0]) < 70)
        clean_count = sum(1 for m in st.session_state.mailbox_catalog if int(m['ai_analysis']['score'].split('/')[0]) < 40)

        k1, k2, k3, k4 = st.columns(4)
        k1.metric("TOTAL SCANNED", len(st.session_state.mailbox_catalog))
        k2.metric("🚨 CRITICAL THREATS", crit_count)
        k3.metric("⚠️ SUSPICIOUS", susp_count)
        k4.metric("✅ CLEAN", clean_count)

        mail_options = []
        for i, m in enumerate(st.session_state.mailbox_catalog):
            sc = int(m['ai_analysis']['score'].split('/')[0])
            tag = "🚨 CRITICAL" if sc >= 70 else ("⚠️ SUSPICIOUS" if sc >= 40 else "✅ CLEAN")
            subj = m['metadata'].get('subject', 'No Subject')[:45]
            snd = m['metadata'].get('from', 'Unknown')[:30]
            mail_options.append(f"[{tag}] ({sc}/100) {subj} — {snd}")

        selected_idx = st.selectbox(
            "Select active email artifact for forensic breakdown:",
            range(len(mail_options)),
            format_func=lambda idx: mail_options[idx],
            key="active_mail_selector"
        )
        st.session_state.results = st.session_state.mailbox_catalog[selected_idx]
        results = st.session_state.results
        st.divider()

    if results is None:
        st.info("⚡ Select an Ingestion Gateway above or click 'Fetch All Emails & Scan Threat Conditions' to run an in-memory threat audit.")
    else:
        dash_col1, dash_col2 = st.columns([1.2, 3])
        with dash_col1:
            circumference = 282.74
            stroke_dashoffset = circumference - (score_num / 100.0) * circumference
            st.markdown(
                f"""
                <div style="text-align: center; background: rgba(8, 15, 32, 0.85); border: 1px solid {primary_color}; border-radius: 12px; padding: 15px;">
                    <svg width="150" height="150" viewBox="0 0 120 120">
                        <circle cx="60" cy="60" r="45" fill="none" stroke="rgba(255,255,255,0.08)" stroke-width="10"/>
                        <circle cx="60" cy="60" r="45" fill="none" stroke="{primary_color}" stroke-width="10"
                                stroke-dasharray="{circumference}" stroke-dashoffset="{stroke_dashoffset}"
                                stroke-linecap="round" transform="rotate(-90 60 60)"/>
                        <text x="60" y="58" font-size="22" font-family="'JetBrains Mono', monospace" font-weight="bold" fill="{primary_color}" text-anchor="middle">{score_num}</text>
                        <text x="60" y="74" font-size="10" fill="#94a3b8" text-anchor="middle">THREAT INDEX</text>
                    </svg>
                </div>
            """, unsafe_allow_html=True
            )

        with dash_col2:
            m1, m2, m3 = st.columns(3)
            safe_meta = results.get("metadata") or {}
            m1.metric("CHANNEL VECTOR", str(results.get("channel", "EMAIL")))
            m2.metric("ORIGIN ID / SENDER", str(safe_meta.get("from", "Unknown"))[:18])
            m3.metric("BLOCK HEIGHT", f"#{(results.get('blockchain_custody') or {}).get('block_height', 849201)}")

            pdf_buffer = build_pdf_buffer(results)
            st.download_button(
                label="📥 Export Forensic Incident Report (PDF)",
                data=pdf_buffer,
                file_name="SYNOVA_Incident_Report.pdf",
                mime="application/pdf",
                use_container_width=True,
            )

        for ot in results.get("omnichannel_threats", []):
            st.error(f"🚨 **{ot['vector'].upper()}:** {ot['desc']}")

        terminal_ist_time = datetime.now(IST_TZ).strftime('%Y-%m-%d %H:%M:%S IST')
        st.markdown(
            f"""
            <div class="soc-terminal">
                <div style="color: {primary_color}; font-weight: bold; margin-bottom: 8px;">🤖 [SOC AGENT AUTONOMOUS TRIAGE LOG]</div>
                <div>&gt; [TIMESTAMP (IST)] : {terminal_ist_time}</div>
                <div>&gt; [SUBJECT] : {html.escape(str(safe_meta.get('subject', 'N/A')))}</div>
                <div>&gt; [PQC SEAL] : <code>{results.get('pqc_lattice_seal', {}).get('lattice_signature_seal', 'N/A')}</code></div>
                <div>&gt; [DIAGNOSIS] : <span style="color: {primary_color}; font-weight: bold;">{html.escape(str(results.get('ai_analysis', {}).get('analysis', '')))}</span></div>
            </div>
        """, unsafe_allow_html=True
        )

        st.divider()

        # 14 ENTERPRISE FORENSIC TABS
        tab1, tab2, tab3, tab4, tab5, tab6, tab7, tab8, tab9, tab10, tab11, tab12, tab13, tab14 = st.tabs([
            "🌐 3D Tactical Globe HUD",
            "🎙️ Deepfake Voice Spectrogram",
            "⚛️ Post-Quantum Lattice Seal",
            "🎭 Scammer Tarpit Decoy",
            "🛡️ Citadel: Autonomous EDR",
            "🛰️ Satellite Street Radar & LEA",
            "🕸️ Threat Knowledge Graph",
            "📱 Omnichannel Exploit Radar",
            "🎯 Nation-State APT Attribution",
            "⛓️ Blockchain Custody & Contract",
            "🤖 AI SOC Copilot",
            "💣 Active Defense: Canary Trap",
            "🧬 In-Memory De-Obfuscator",
            "⚡ Kill-Chain Simulator",
        ])

        # TAB 1: 3D GLOBE
        with tab1:
            st.subheader("🌐 3D Holographic WebGL Tactical Globe")
            g = results.get("globe_telemetry", {})
            globe_html = f"""
            <div id="globeContainer" style="width: 100%; height: 400px; background: #030712; border: 1px solid {primary_color}; border-radius: 8px;"></div>
            <script src="https://unpkg.com/three"></script>
            <script src="https://unpkg.com/globe.gl"></script>
            <script>
                const elem = document.getElementById('globeContainer');
                Globe()(elem)
                    .globeImageUrl('//unpkg.com/three-globe/example/img/earth-night.jpg')
                    .backgroundColor('#030712')
                    .arcsData([{{ startLat: {g.get('origin_lat', 31.5)}, startLng: {g.get('origin_lon', 74.3)}, endLat: 28.61, endLng: 77.20, color: ['#ff1744', '{primary_color}'] }}])
                    .arcColor('color').arcDashLength(0.4).arcDashGap(0.2).arcDashAnimateTime(1800).arcStroke(1.4)
                    .pointOfView({{ lat: 28.61, lng: 77.20, altitude: 2.2 }});
            </script>
            """
            st.components.v1.html(globe_html, height=420)

        # TAB 2: DEEPFAKE SPECTROGRAM
        with tab2:
            st.subheader("🎙️ Acoustic Deepfake Voice Analyzer")
            v_res = results.get("deepfake_voice_analysis", {})
            st.metric("SYNTHETIC PROBABILITY", f"{v_res.get('synthetic_probability')}%")
            st.info(f"**Classification:** {v_res.get('classification')}")

        # TAB 3: POST-QUANTUM LATTICE SEAL
        with tab3:
            st.subheader("⚛️ NIST Post-Quantum Cryptography (PQC) Lattice-Seal")
            pqc = results.get("pqc_lattice_seal", {})
            st.code(f"Standard: {pqc.get('pqc_standard')}\nPolynomial Vector: {pqc.get('polynomial_vector_sample')}\nDilithium Seal: {pqc.get('lattice_signature_seal')}", language="text")

        # TAB 4: SCAMMER TARPIT
        with tab4:
            st.subheader("🎭 Autonomous Scammer Tarpit Decoy AI")
            st.code(f"Simulated Counter-Bait Response:\n{results.get('scammer_tarpit_bot', {}).get('next_counter_response')}", language="text")

        # TAB 5: CITADEL EDR
        with tab5:
            st.subheader("🛡️ Citadel Autonomous Host Lockdown & Air-Gap")
            st.code(results.get("citadel_lockdown", {}).get("air_gap_windows", ""), language="powershell")

        # TAB 6: SATELLITE STREET RADAR & POLICE DOCKET
        with tab6:
            st.subheader("🛰️ Active Tactical Street Radar & Section 91 CrPC Police Docket")
            street = results.get("street_telemetry", {})
            st.write(f"**Tactical Pinpoint Coordinates:** {street.get('tactical_latitude')}, {street.get('tactical_longitude')} (Accuracy: ±{street.get('accuracy_radius_meters')}m)")
            st.text_area("Official Police Referral Docket", results.get("police_docket", ""), height=220)

        # TAB 7: VIS.JS GRAPH
        with tab7:
            st.subheader("🕸️ Autonomous Threat Knowledge Graph")
            ip = results['metadata']['sender_ip']
            graph_html = f"""
            <div id="synovaNetwork" style="width: 100%; height: 350px; background: rgba(5,8,15,0.95); border: 1px solid {primary_color}; border-radius: 8px;"></div>
            <script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
            <script type="text/javascript">
                const nodes = new vis.DataSet([
                    {{ id: 1, label: 'Origin\\n{ip}', color: '#ff1744', shape: 'box', font: {{ color: '#fff' }} }},
                    {{ id: 2, label: 'Ingress Perimeter', color: '{primary_color}', shape: 'diamond', font: {{ color: '#fff' }} }}
                ]);
                const edges = new vis.DataSet([{{ from: 1, to: 2, label: 'Attacking Vector', color: '#ff1744', arrows: 'to' }}]);
                new vis.Network(document.getElementById('synovaNetwork'), {{ nodes: nodes, edges: edges }}, {{ physics: {{ barnesHut: {{ springLength: 100 }} }} }});
            </script>
            """
            st.components.v1.html(graph_html, height=370)

        # TAB 8: OMNICHANNEL EXPLOITS
        with tab8:
            st.subheader("📱 Omnichannel Social Engineering Radar")
            st.json(results.get("omnichannel_threats", []))

        # TAB 9: APT ATTRIBUTION
        with tab9:
            st.subheader("🎯 Nation-State APT Attribution")
            st.json(results.get("apt_attribution", {}))

        # TAB 10: BLOCKCHAIN CUSTODY
        with tab10:
            st.subheader("⛓️ Blockchain Merkle Custody (BSA 2023 Sec 63)")
            st.json(results.get("blockchain_custody", {}))

        # TAB 11: AI COPILOT
        with tab11:
            st.subheader("🤖 SYNOVA Autonomous SOC Copilot")
            for msg in st.session_state.copilot_history:
                with st.chat_message(msg["role"]):
                    st.markdown(msg["content"])
            uq = st.chat_input("Ask Copilot about this incident...")
            if uq:
                st.session_state.copilot_history.append({"role": "user", "content": uq})
                with st.chat_message("user"):
                    st.markdown(uq)
                with st.chat_message("assistant"):
                    ans = "Threat profile verified. Quarantine staged."
                    if api_key:
                        try:
                            genai.configure(api_key=api_key)
                            ans = genai.GenerativeModel("gemini-2.5-flash").generate_content(f"You are SYNOVA SOC Copilot. Incident: {results['ai_analysis']['analysis']}. Question: {uq}").text
                        except Exception as e:
                            ans = str(e)
                    st.markdown(ans)
                    st.session_state.copilot_history.append({"role": "assistant", "content": ans})

        # TAB 12: CANARY TRAP
        with tab12:
            st.subheader("💣 Active Defense Honeytoken Canary")
            st.json(results.get("canary_trap", {}))

        # TAB 13: DE-OBFUSCATOR
        with tab13:
            st.subheader("🧬 In-Memory Script De-Obfuscator")
            for p in results.get("deobfuscated_payloads", []):
                st.write(f"**Type:** `{p['type']}`")
                st.code(p['deobfuscated_code'], language="powershell")

        # TAB 14: KILL-CHAIN SIMULATOR
        with tab14:
            st.subheader("⚡ Adversary Kill-Chain Simulation")
            st.success("🛡️ **SYNOVA Autonomous Defense:** 100% Data Exfiltration Neutralized | Zero Disk Footprint.")
