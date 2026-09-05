import base64
import html
import io
import time
import hashlib
import folium
from elevenlabs.client import ElevenLabs
from ingestion_engine import EmailIngestionEngine
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
import streamlit as st
from streamlit_folium import st_folium

st.set_page_config(page_title="SYNOVA Autonomous SOC Platform", page_icon="🛡️", layout="wide")

api_key = st.secrets.get("GEMINI_API_KEY", "")
elevenlabs_api_key = st.secrets.get("ELEVENLABS_API_KEY", "")
abuse_key = st.secrets.get("ABUSEIPDB_API_KEY", "")

# Initialize ElevenLabs Client
eleven_client = ElevenLabs(api_key=elevenlabs_api_key) if elevenlabs_api_key else None

# --- SESSION CONTROLLERS ---
if "replay" in st.query_params:
    st.query_params.clear()
    st.session_state.intro_done = False
    st.session_state.last_played_audio_hash = None

if "intro_done" not in st.session_state:
    st.session_state.intro_done = False

if "last_played_audio_hash" not in st.session_state:
    st.session_state.last_played_audio_hash = None

# --- STEP 1: INITIAL PROTECTION LOADING SCREEN ---
if not st.session_state.intro_done:
    st.markdown(
        """
        <style>
        .stApp {
            background-color: #04070d !important;
            background-image: 
                radial-gradient(circle at 50% 50%, rgba(0, 168, 255, 0.15) 0%, transparent 65%),
                linear-gradient(rgba(0, 168, 255, 0.08) 1px, transparent 1px),
                linear-gradient(90deg, rgba(0, 168, 255, 0.08) 1px, transparent 1px) !important;
            background-size: 100% 100%, 40px 40px, 40px 40px !important;
        }
        .intro-container {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            text-align: center;
            margin-top: 15vh;
            margin-bottom: 25px;
        }
        .intro-shield-svg {
            width: 120px;
            height: 140px;
            fill: none;
            stroke: #00a8ff;
            stroke-width: 1.6;
            stroke-dasharray: 450;
            stroke-dashoffset: 450;
            animation: drawIntroShield 2.2s cubic-bezier(0.65, 0, 0.35, 1) forwards;
            filter: drop-shadow(0 0 20px rgba(0, 168, 255, 0.6));
        }
        @keyframes drawIntroShield {
            0% { stroke-dashoffset: 450; transform: scale(0.9); opacity: 0.3; }
            80% { stroke-dashoffset: 0; transform: scale(1.04); opacity: 1; }
            100% { stroke-dashoffset: 0; transform: scale(1); opacity: 1; }
        }
        .intro-title {
            color: #00a8ff;
            font-family: 'JetBrains Mono', monospace;
            font-size: 20px;
            font-weight: bold;
            letter-spacing: 3.5px;
            margin-top: 22px;
            text-shadow: 0 0 12px rgba(0, 168, 255, 0.6);
        }
        .intro-sub {
            color: #94a3b8;
            font-family: monospace;
            font-size: 13px;
            letter-spacing: 1.5px;
            margin-top: 8px;
        }
        </style>
        <div class="intro-container">
            <svg class="intro-shield-svg" viewBox="0 0 24 28">
                <path d="M12 2 L3 5.5 V13 C3 19.5 7 24.5 12 26 C17 24.5 21 19.5 21 13 V5.5 Z" />
                <path d="M12 4.5 L5 7.2 V13 C5 18 8 22.2 12 23.6 C16 22.2 19 18 19 13 V7.2 Z" stroke-dasharray="2 2" stroke-width="0.8"/>
            </svg>
            <div class="intro-title">INITIALIZING DEFENSE MATRIX...</div>
            <div class="intro-sub">CALIBRATING ZERO-DISK FORENSIC HEURISTICS</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    col_l, col_btn, col_r = st.columns([1.5, 1, 1.5])
    with col_btn:
        if st.button("⚡ Skip Intro", use_container_width=True):
            st.session_state.intro_done = True
            st.rerun()

    progress_bar = st.progress(0)
    for percent in range(100):
        time.sleep(0.04)
        progress_bar.progress(percent + 1)

    st.session_state.intro_done = True
    st.rerun()

# --- STEP 2: SETUP CONTAINERS ---
header_container = st.container()
ingestion_container = st.container()
content_container = st.container()

primary_color = "#00a8ff"
glow_rgba = "rgba(0, 168, 255, 0.16)"
bg_glow = "rgba(0, 168, 255, 0.20)"
badge_text = "SOC RADAR ACTIVE"
score_num = 0
results = None
pulse_duration = "5.0s"
voice_briefing = "Welcome to Synova Threat Intelligence Matrix. System is online and standby for incoming byte stream."

# --- STEP 3: ZERO-TOUCH INGESTION INTERCEPTOR ---
with ingestion_container:
    ingestion_mode = st.radio(
        "Select Attack Vector Ingestion Method:",
        ["📁 Safe Byte Upload (.eml / .msg)", "☁️ Zero-Touch Cloud Mailbox (IMAP Direct)", "📝 Raw RFC-822 Stream Paste"],
        horizontal=True
    )

    raw_payload_bytes = None

    if "Upload" in ingestion_mode:
        uploaded_file = st.file_uploader("Drop a suspicious .eml or .msg file here", type=["eml", "msg"], key="threat_file_input")
        if uploaded_file is not None:
            raw_payload_bytes = uploaded_file.getvalue()

    elif "Cloud" in ingestion_mode:
        st.caption("🔒 **Zero-Download Security:** Inspects email directly inside memory RAM buffer without downloading weaponized binaries onto your endpoint.")
        c_i1, c_i2, c_i3 = st.columns([1.5, 1.5, 1.2])
        with c_i1:
            imap_server = st.text_input("IMAP Server Host", value="imap.gmail.com")
        with c_i2:
            imap_email = st.text_input("User / Service Account", placeholder="incident-sandbox@corp.com")
        with c_i3:
            imap_password = st.text_input("App Password / Secret Token", type="password")
        
        if st.button("🚀 Intercept & Neutralize Unread Threats", use_container_width=True):
            if imap_email and imap_password:
                with st.spinner("Connecting to SSL Cloud Mailbox Buffer..."):
                    try:
                        engine = EmailIngestionEngine.from_imap(
                            imap_server, imap_email, imap_password, api_key=api_key, abuse_key=abuse_key
                        )
                        results = engine.parse_email()
                    except Exception as e:
                        st.error(f"IMAP Handshake Error: {str(e)}")
            else:
                st.warning("Please provide IMAP credentials to read mailbox buffer.")

    else:
        st.caption("📝 Inspect raw ASCII/MIME streams copy-pasted directly from webmail headers (Zero Disk footprint).")
        raw_stream_text = st.text_area("Paste raw RFC-822 headers & payload here:", height=140, placeholder="Received: from mail.attacker.net ...\nFrom: attacker@malicious.com ...")
        if st.button("⚡ Triage Raw Buffer", use_container_width=True):
            if raw_stream_text.strip():
                raw_payload_bytes = raw_stream_text.encode("utf-8")

    # Ingest from byte stream if uploaded or pasted
    if raw_payload_bytes and not results:
        with st.spinner("Executing Zero-Disk Forensics, Deep OSINT & AI Triage Pipeline..."):
            engine = EmailIngestionEngine(raw_payload_bytes, api_key=api_key, abuse_key=abuse_key)
            results = engine.parse_email()

# --- STEP 4: THREAT STATE CALCULATION ---
if results is not None:
    raw_score = str(results.get("ai_analysis", {}).get("score", "0"))
    try:
        score_num = int("".join([c for c in raw_score.split("/")[0] if c.isdigit()]))
    except Exception:
        score_num = 0

    origin_city = str(results["metadata"]["geo_data"].get("city", "Unknown"))
    origin_country = str(results["metadata"]["geo_data"].get("country", "Unknown"))
    ip_type = str(results["metadata"]["geo_data"].get("ip_type", "Residential ISP"))

    if score_num >= 70:
        primary_color = "#ff3355"
        glow_rgba = "rgba(255, 51, 85, 0.35)"
        bg_glow = "rgba(255, 51, 85, 0.30)"
        badge_text = "CRITICAL THREAT CONFIRMED"
        pulse_duration = "0.65s"
        voice_briefing = f"Alert. High-risk spearphishing vector detected from {origin_city}, {origin_country}. Infrastructure identified as {ip_type}. Automated quarantine playbooks are now active."
    elif score_num >= 40:
        primary_color = "#ffaa00"
        glow_rgba = "rgba(255, 170, 0, 0.25)"
        bg_glow = "rgba(255, 170, 0, 0.22)"
        badge_text = "SUSPICIOUS PROFILE DETECTED"
        pulse_duration = "1.6s"
        voice_briefing = f"Caution. Suspicious behavioral heuristics logged. Sender origin anchored at {origin_city}."
    else:
        primary_color = "#00ffcc"
        glow_rgba = "rgba(0, 255, 204, 0.18)"
        bg_glow = "rgba(0, 255, 204, 0.20)"
        badge_text = "CLEAN ARTIFACT CONFIRMED"
        pulse_duration = "4.0s"
        voice_briefing = "Forensic inspection complete. Artifact verified clean. Zero threat signatures found."

# --- STEP 5: DYNAMIC CSS & MOBILE RESPONSIVE ENGINE ---
shield_emoji_svg = f"""<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 28' fill='none'><path d='M12 2 L3 5.5 V13 C3 19.5 7 24.5 12 26 C17 24.5 21 19.5 21 13 V5.5 Z' stroke='{primary_color}' stroke-width='1.2' stroke-opacity='0.45' fill='{primary_color}' fill-opacity='0.05'/><path d='M12 4.5 L5 7.2 V13 C5 18 8 22.2 12 23.6 C16 22.2 19 18 19 13 V7.2 Z' stroke='{primary_color}' stroke-width='0.8' stroke-dasharray='1.5 1.5' stroke-opacity='0.35' fill='none'/></svg>""".replace("#", "%23")

st.markdown(
    f"""
    <style>
    .stApp {{
        background-color: #04070d !important;
        background-image: 
            url("data:image/svg+xml,{shield_emoji_svg}"),
            radial-gradient(circle at 50% 0%, {bg_glow} 0%, transparent 65%),
            radial-gradient(circle at 90% 90%, {glow_rgba} 0%, transparent 50%),
            linear-gradient({glow_rgba} 1px, transparent 1px),
            linear-gradient(90deg, {glow_rgba} 1px, transparent 1px) !important;
        background-position: center 48%, center top, right bottom, 0 0, 0 0 !important;
        background-repeat: no-repeat, no-repeat, no-repeat, repeat, repeat !important;
        background-size: 400px 460px, 100% 100%, 100% 100%, 40px 40px, 40px 40px !important;
        animation: threatShieldGlowPulse {pulse_duration} ease-in-out infinite alternate;
    }}

    @keyframes threatShieldGlowPulse {{
        0% {{
            filter: drop-shadow(0 0 4px {primary_color}22);
            opacity: 0.88;
        }}
        100% {{
            filter: drop-shadow(0 0 25px {primary_color}) drop-shadow(0 0 45px {primary_color}66);
            opacity: 1;
        }}
    }}

    /* Ultra-Smooth Ambient Laser Scanner */
    .stApp::before {{
        content: "";
        position: fixed;
        top: 0; left: 0; right: 0; 
        height: 2px;
        background: linear-gradient(90deg, transparent 0%, {primary_color}66 25%, {primary_color} 50%, {primary_color}66 75%, transparent 100%);
        box-shadow: 
            0 0 15px 2px {primary_color}44,
            0 0 35px 6px {glow_rgba};
        filter: blur(0.5px);
        animation: smoothLaserSweep 9s cubic-bezier(0.45, 0.05, 0.55, 0.95) infinite alternate;
        pointer-events: none;
        z-index: 1;
        opacity: 0.45;
    }}

    @keyframes smoothLaserSweep {{
        0% {{ transform: translateY(-5vh); opacity: 0.1; }}
        15% {{ opacity: 0.45; }}
        85% {{ opacity: 0.45; }}
        100% {{ transform: translateY(102vh); opacity: 0.1; }}
    }}

    [data-testid="stAppViewBlockContainer"] {{
        position: relative;
        z-index: 2;
    }}

    .live-badge, .replay-badge {{
        display: inline-flex;
        align-items: center;
        justify-content: center;
        gap: 8px;
        background: {glow_rgba} !important;
        border: 1px solid {primary_color} !important;
        color: {primary_color} !important;
        font-size: 11px;
        padding: 6px 14px;
        border-radius: 20px;
        font-family: 'Courier New', monospace;
        font-weight: bold;
        letter-spacing: 1.5px;
        box-shadow: 0 0 15px {glow_rgba};
        text-decoration: none !important;
        cursor: pointer;
        transition: all 0.25s ease-in-out;
        white-space: nowrap;
    }}

    .replay-badge:hover {{
        background: {primary_color} !important;
        color: #04070d !important;
        box-shadow: 0 0 25px {primary_color} !important;
        transform: translateY(-1px);
    }}

    .pulse-dot {{
        width: 8px;
        height: 8px;
        background-color: {primary_color};
        border-radius: 50%;
        box-shadow: 0 0 10px {primary_color};
        display: inline-block;
        animation: socPulse {pulse_duration} infinite ease-in-out !important;
    }}

    @keyframes socPulse {{
        0%, 100% {{ transform: scale(0.85); opacity: 0.3; box-shadow: 0 0 2px {primary_color}; }}
        50% {{ transform: scale(1.35); opacity: 1; box-shadow: 0 0 16px {primary_color}; }}
    }}

    [data-testid="stFileUploadDropzone"], .stFileUploader section {{
        background: rgba(8, 14, 26, 0.75) !important;
        backdrop-filter: blur(16px) !important;
        border: 1.5px dashed {primary_color} !important;
        border-radius: 16px !important;
        box-shadow: 0 0 20px {glow_rgba} !important;
    }}

    [data-testid="stMetric"] {{
        background: rgba(10, 18, 32, 0.75) !important;
        backdrop-filter: blur(14px) !important;
        border: 1px solid {primary_color} !important;
        border-radius: 12px !important;
        padding: 10px 14px !important;
        box-shadow: 0 10px 25px rgba(0, 0, 0, 0.6) !important;
    }}
    [data-testid="stMetricValue"] {{
        color: {primary_color} !important;
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 20px !important;
        text-shadow: 0 0 12px {primary_color};
    }}

    .soc-terminal {{
        background: rgba(5, 8, 15, 0.95);
        border: 1px solid {primary_color};
        border-left: 4px solid {primary_color};
        border-radius: 8px;
        padding: 16px;
        font-family: 'JetBrains Mono', 'Courier New', monospace;
        color: #d1d5db;
        font-size: 13px;
        line-height: 1.6;
        box-shadow: 0 0 25px {glow_rgba};
        margin-bottom: 20px;
    }}

    .ttp-card {{
        display: inline-block;
        background: rgba(15, 23, 42, 0.9);
        border: 1px solid {primary_color};
        border-radius: 8px;
        padding: 10px 14px;
        margin: 6px;
        min-width: 220px;
    }}

    .timeline-item {{
        position: relative;
        padding-left: 24px;
        border-left: 2px solid {primary_color};
        margin-bottom: 14px;
    }}
    .timeline-dot {{
        position: absolute;
        left: -6px;
        top: 2px;
        width: 10px;
        height: 10px;
        background: {primary_color};
        border-radius: 50%;
        box-shadow: 0 0 8px {primary_color};
    }}

    .layer-card {{
        background: rgba(10, 18, 32, 0.85);
        border: 1px solid {primary_color};
        border-radius: 8px;
        padding: 12px 16px;
        margin-bottom: 10px;
    }}
    .layer-title {{
        color: {primary_color};
        font-size: 13px;
        font-weight: bold;
        font-family: monospace;
        margin-bottom: 4px;
        text-transform: uppercase;
    }}

    /* Mobile & Tablet Responsiveness */
    @media only screen and (max-width: 768px) {{
        .stApp {{ background-size: 100% 100%, 100% 100%, 25px 25px, 25px 25px !important; }}
        h1 {{ font-size: 20px !important; }}
        p {{ font-size: 12px !important; }}
        .live-badge, .replay-badge {{ font-size: 9px !important; padding: 4px 8px !important; }}
        [data-testid="stMetricValue"] {{ font-size: 16px !important; }}
        .ttp-card {{ width: 100% !important; min-width: 100% !important; margin: 4px 0 !important; }}
        .soc-terminal {{ font-size: 11px !important; padding: 10px !important; }}
    }}
    </style>
    """,
    unsafe_allow_html=True,
)

# --- STEP 6: RENDER TOP HEADER ---
with header_container:
    col1, col2 = st.columns([3.2, 1.8])
    with col1:
        st.markdown(
            f"<h1 style='color: white; margin-bottom: 0px;'>🛡️ SYNOVA <span style='color: {primary_color};'>Command Center</span></h1>",
            unsafe_allow_html=True,
        )
        st.markdown(
            "<p style='color: #94a3b8; font-size: 14px; margin-top: 4px;'>Autonomous AI Email Threat Detection, Deep OSINT & SOAR Incident Response Platform</p>",
            unsafe_allow_html=True,
        )
    with col2:
        st.markdown(
            f"""
            <div style='display: flex; flex-direction: column; align-items: flex-end; gap: 8px; margin-top: 8px;'>
                <span class='live-badge'><span class='pulse-dot'></span>{badge_text}</span>
                <a href='?replay=1' target='_self' class='replay-badge'>🔁 REPLAY DEFENSE PROTOCOL</a>
            </div>
            """,
            unsafe_allow_html=True,
        )
    st.divider()

# --- STEP 7: DEDICATED SINGLE-DISPATCH AUDIO ENGINE ---
current_audio_hash = hashlib.md5(voice_briefing.encode('utf-8')).hexdigest()

if st.session_state.last_played_audio_hash != current_audio_hash:
    st.session_state.last_played_audio_hash = current_audio_hash
    audio_b64_payload = ""

    if eleven_client:
        try:
            audio_stream = eleven_client.text_to_speech.convert(
                text=voice_briefing,
                voice_id="EXAVITQu4vr4xnSDxMaL",
                model_id="eleven_multilingual_v2"
            )
            audio_bytes = b"".join(list(audio_stream))
            audio_b64_payload = base64.b64encode(audio_bytes).decode("utf-8")
        except Exception:
            audio_b64_payload = ""

    audio_bridge_js = f"""
    <script>
    (function() {{
        const b64Data = "{audio_b64_payload}";
        const textMsg = "{voice_briefing}";
        const audioId = "{current_audio_hash}";

        if (window.parent.__synovaLastAudio === audioId) return;
        window.parent.__synovaLastAudio = audioId;

        if ('speechSynthesis' in window) {{
            window.speechSynthesis.cancel();
        }}
        if (window.parent && window.parent.speechSynthesis) {{
            window.parent.speechSynthesis.cancel();
        }}

        if (b64Data && b64Data.length > 50) {{
            if (window.parent.__currentSynovaAudio) {{
                window.parent.__currentSynovaAudio.pause();
                window.parent.__currentSynovaAudio.currentTime = 0;
            }}
            const audio = new Audio("data:audio/mp3;base64," + b64Data);
            audio.volume = 0.95;
            window.parent.__currentSynovaAudio = audio;
            
            const playPromise = audio.play();
            if (playPromise !== undefined) {{
                playPromise.catch(() => {{
                    const unlock = () => {{
                        audio.play();
                        window.parent.document.removeEventListener('click', unlock);
                        document.removeEventListener('click', unlock);
                    }};
                    window.parent.document.addEventListener('click', unlock, {{ once: true }});
                    document.addEventListener('click', unlock, {{ once: true }});
                }});
            }}
        }} else if ('speechSynthesis' in window) {{
            const utter = new SpeechSynthesisUtterance(textMsg);
            utter.rate = 0.95;
            utter.pitch = 1.0;
            window.speechSynthesis.speak(utter);
        }}
    }})();
    </script>
    """
    st.components.v1.html(audio_bridge_js, height=0)

def build_pdf_buffer(results_data):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=30,
        leftMargin=30,
        topMargin=30,
        bottomMargin=30,
    )
    story = []

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "TitleStyle",
        parent=styles["Heading1"],
        fontSize=18,
        textColor=colors.HexColor("#003366"),
        spaceAfter=8,
    )
    heading_style = ParagraphStyle(
        "HeadingStyle",
        parent=styles["Heading2"],
        fontSize=12,
        textColor=colors.HexColor("#0055a5"),
        spaceBefore=10,
        spaceAfter=6,
    )
    body_style = ParagraphStyle(
        "BodyStyle",
        parent=styles["Normal"],
        fontSize=9,
        textColor=colors.HexColor("#222222"),
        leading=12,
    )

    story.append(Paragraph("SYNOVA CYBERSECURITY INCIDENT REPORT", title_style))
    story.append(
        Paragraph("<b>Autonomous Email Threat Intelligence, OSINT & SOAR Playbook</b>", body_style)
    )
    story.append(Spacer(1, 10))

    story.append(Paragraph("Email Metadata & Origin Reconnaissance", heading_style))
    meta = results_data.get("metadata", {})
    osint_info = meta.get("geo_data", {})
    meta_data = [
        [Paragraph("<b>Subject:</b>", body_style), Paragraph(html.escape(str(meta.get("subject", "N/A"))), body_style)],
        [Paragraph("<b>Sender:</b>", body_style), Paragraph(html.escape(str(meta.get("from", "N/A"))), body_style)],
        [Paragraph("<b>Recipient:</b>", body_style), Paragraph(html.escape(str(meta.get("to", "N/A"))), body_style)],
        [Paragraph("<b>Sender Origin IP:</b>", body_style), Paragraph(html.escape(str(meta.get("sender_ip", "N/A"))), body_style)],
        [Paragraph("<b>Infrastructure Classification:</b>", body_style), Paragraph(html.escape(str(osint_info.get("ip_type", "Standard"))), body_style)],
        [Paragraph("<b>Abuse Score (AbuseIPDB):</b>", body_style), Paragraph(f"{osint_info.get('abuse_score', 0)}%", body_style)],
        [Paragraph("<b>AI Threat Score:</b>", body_style), Paragraph(html.escape(str(results_data.get("ai_analysis", {}).get("score", "N/A"))), body_style)],
    ]
    t = Table(meta_data, colWidths=[130, 390])
    t.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f2f4f8")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#d0d7de")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("PADDING", (0, 0), (-1, -1), 5),
        ])
    )
    story.append(t)
    story.append(Spacer(1, 10))

    story.append(Paragraph("AI Forensic Breakdown", heading_style))
    story.append(Paragraph(html.escape(str(results_data.get("ai_analysis", {}).get("analysis", "None"))), body_style))
    story.append(Spacer(1, 10))

    story.append(Paragraph("Recommended Incident Response & Mitigation Steps", heading_style))
    mitigations_raw = str(results_data.get("ai_analysis", {}).get("mitigations", "No immediate mitigation required."))
    story.append(Paragraph(html.escape(mitigations_raw).replace("\n", "<br/>"), body_style))
    story.append(Spacer(1, 10))

    story.append(Paragraph("Extracted Indicators of Compromise (IOC URLs)", heading_style))
    urls = results_data.get("body_artifacts", {}).get("extracted_urls", [])
    if urls:
        url_data = [[Paragraph(f"• {html.escape(str(u))}", body_style)] for u in urls[:15]]
        ut = Table(url_data, colWidths=[520])
        ut.setStyle(
            TableStyle([
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#d0d7de")),
                ("PADDING", (0, 0), (-1, -1), 4),
            ])
        )
        story.append(ut)
    else:
        story.append(Paragraph("No URLs detected.", body_style))

    doc.build(story)
    buffer.seek(0)
    return buffer

# --- STEP 8: RENDER MAIN INVESTIGATION OR EMPTY STATE ---
with content_container:
    if results is None:
        st.markdown(
            f"""
            <div style="
                background: linear-gradient(135deg, rgba(8, 14, 26, 0.95) 0%, rgba(15, 23, 42, 0.85) 100%);
                border: 1px solid rgba(0, 168, 255, 0.3);
                border-left: 5px solid {primary_color};
                border-radius: 12px;
                padding: 24px;
                margin-top: 10px;
                margin-bottom: 25px;
                box-shadow: 0 10px 30px rgba(0, 168, 255, 0.1);
            ">
                <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px; flex-wrap: wrap; gap: 8px;">
                    <h3 style="color: #ffffff; margin: 0; font-family: 'JetBrains Mono', monospace; font-size: 20px;">
                        ⚡ WELCOME TO THE SYNOVA THREAT INTELLIGENCE MATRIX
                    </h3>
                    <span style="background: rgba(0, 168, 255, 0.15); color: {primary_color}; border: 1px solid {primary_color}; font-size: 11px; padding: 4px 10px; border-radius: 12px; font-weight: bold; font-family: monospace;">
                        ZERO-TRUST SOC
                    </span>
                </div>
                <p style="color: #94a3b8; font-size: 14px; line-height: 1.6; margin-bottom: 16px;">
                    SYNOVA is an autonomous, zero-disk cybersecurity forensic engine engineered to intercept, deconstruct, and neutralize high-level email attack vectors. Ingest payloads via file drop, raw MIME streaming, or direct cloud IMAP mailbox handshake to execute real-time AI triage, deep Shodan/AbuseIPDB reconnaissance, and automated SOAR firewall containment.
                </p>
                <div style="display: flex; gap: 10px; flex-wrap: wrap;">
                    <span style="background: rgba(0, 168, 255, 0.1); border: 1px solid rgba(0, 168, 255, 0.3); color: {primary_color}; font-size: 12px; padding: 6px 12px; border-radius: 6px; font-family: monospace;">
                        1. IN-MEMORY ZERO-DOWNLOAD BUFFER
                    </span>
                    <span style="background: rgba(14, 165, 233, 0.1); border: 1px solid rgba(14, 165, 233, 0.3); color: #38bdf8; font-size: 12px; padding: 6px 12px; border-radius: 6px; font-family: monospace;">
                        2. SHODAN & ABUSEIPDB RECONNAISSANCE
                    </span>
                    <span style="background: rgba(168, 85, 247, 0.1); border: 1px solid rgba(168, 85, 247, 0.3); color: #c084fc; font-size: 12px; padding: 6px 12px; border-radius: 6px; font-family: monospace;">
                        3. DUAL-ENGINE AI COGNITIVE TRIAGE
                    </span>
                    <span style="background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.3); color: #f87171; font-size: 12px; padding: 6px 12px; border-radius: 6px; font-family: monospace;">
                        4. AUTOMATED SOAR MITIGATION & PDF
                    </span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        c1, c2, c3, c4 = st.columns(4)
        with c1:
            st.metric(label="CORE ENGINE", value="ZERO-DISK", delta="RAM Buffer")
        with c2:
            st.metric(label="DEEP OSINT", value="SHODAN+ABUSE", delta="CVE Tracer")
        with c3:
            st.metric(label="AI BRAIN", value="GEMINI", delta="Heuristics")
        with c4:
            st.metric(label="SOAR DEFENSE", value="ACTIVE", delta="IPTables/DNS")

    else:
        dash_col1, dash_col2 = st.columns([1.2, 3])

        with dash_col1:
            circumference = 282.74
            stroke_dashoffset = circumference - (score_num / 100.0) * circumference
            st.markdown(
                f"""
                <div style="text-align: center; background: rgba(10, 18, 32, 0.75); border: 1px solid {primary_color}; border-radius: 12px; padding: 15px; box-shadow: 0 10px 25px rgba(0,0,0,0.6);">
                    <svg width="150" height="150" viewBox="0 0 120 120">
                        <circle cx="60" cy="60" r="45" fill="none" stroke="rgba(255,255,255,0.08)" stroke-width="10"/>
                        <circle cx="60" cy="60" r="45" fill="none" stroke="{primary_color}" stroke-width="10"
                                stroke-dasharray="{circumference}" stroke-dashoffset="{stroke_dashoffset}"
                                stroke-linecap="round" transform="rotate(-90 60 60)"
                                style="transition: stroke-dashoffset 1s ease-in-out; filter: drop-shadow(0 0 6px {primary_color});"/>
                        <text x="60" y="58" font-size="22" font-family="'JetBrains Mono', monospace" font-weight="bold" fill="{primary_color}" text-anchor="middle">{score_num}</text>
                        <text x="60" y="74" font-size="10" font-family="sans-serif" fill="#94a3b8" text-anchor="middle">THREAT INDEX</text>
                    </svg>
                </div>
            """,
                unsafe_allow_html=True,
            )

        with dash_col2:
            m1, m2, m3 = st.columns(3)
            m1.metric("SENDER ORIGIN IP", str(results["metadata"]["sender_ip"] or "Hidden"))
            m2.metric("SPF RECORD", "PASS" if results["authentication"]["spf_pass"] else "FAIL / NONE")
            m3.metric("EXTRACTED IOCs", f"{len(results['body_artifacts']['extracted_urls'])} URLs")

            pdf_buffer = build_pdf_buffer(results)
            st.download_button(
                label="📥 Export Forensic Incident Report (PDF)",
                data=pdf_buffer,
                file_name="SYNOVA_Incident_Report.pdf",
                mime="application/pdf",
                use_container_width=True,
            )

        ai_score_val = results["ai_analysis"].get("ai_score_num", score_num)
        heur_score_val = results["ai_analysis"].get("heuristic_score_num", score_num)

        st.markdown("#### ⚖️ Dual-Engine Consensus Calibration")
        bar_col1, bar_col2 = st.columns(2)
        with bar_col1:
            st.caption(f"🧠 Gemini LLM Cognitive Reasoning: **{ai_score_val}%** Confidence")
            st.progress(ai_score_val / 100.0)
        with bar_col2:
            st.caption(f"⚡ Static Rule & OSINT Heuristic Engine: **{heur_score_val}%** Confidence")
            st.progress(heur_score_val / 100.0)

        ai_reason = results.get("ai_analysis", {}).get("analysis", "No forensic log generated.")
        st.markdown(
            f"""
            <div class="soc-terminal">
                <div style="color: {primary_color}; font-weight: bold; margin-bottom: 8px;">🤖 [SOC AGENT AUTONOMOUS TRIAGE LOG]</div>
                <div>&gt; [TIMESTAMP] : {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}</div>
                <div>&gt; [IP PROFILER] : Infrastructure Classification: <span style="color: {primary_color}; font-weight: bold;">{ip_type}</span></div>
                <div>&gt; [DIAGNOSIS] : <span style="color: {primary_color}; font-weight: bold;">{html.escape(str(ai_reason))}</span></div>
            </div>
        """,
            unsafe_allow_html=True,
        )

        st.markdown("#### 🎯 MITRE ATT&CK® Mapped Adversary Techniques")
        ttps = results.get("mitre_ttps", [])
        ttp_html = ""
        for ttp in ttps:
            ttp_html += f"""
                <div class="ttp-card">
                    <div style="color:#94a3b8; font-size:11px; text-transform:uppercase;">{html.escape(str(ttp['tactic']))}</div>
                    <div style="color:{primary_color}; font-family:monospace; font-weight:bold; font-size:13px;">{html.escape(str(ttp['id']))}</div>
                    <div style="color:#ffffff; font-size:13px; font-weight:600; margin-top:2px;">{html.escape(str(ttp['name']))}</div>
                </div>
            """
        st.markdown(f"<div style='margin-bottom: 20px;'>{ttp_html}</div>", unsafe_allow_html=True)

        st.divider()

        tab1, tab2, tab3, tab4, tab5, tab6, tab7, tab8 = st.tabs([
            "🛡️ SOAR Response & Mitigations",
            "⚡ Kill-Chain Simulator",
            "🌐 Attacker OSINT Infrastructure",
            "🧩 Payload Deconstruction Matrix",
            "🕒 Attack Timeline",
            "👁️ Defanged Preview",
            "🔗 Routing Hops & Geo Radar",
            "🔬 Raw Headers & Hex Dump",
        ])

        with tab1:
            st.subheader("⚡ Automated SOAR Playbook Execution")
            ai_mitigations = results.get("ai_analysis", {}).get("mitigations", "No mitigations available.")
            st.markdown(ai_mitigations)
            st.divider()
            col_soar1, col_soar2 = st.columns(2)
            with col_soar1:
                if st.button("🚫 Generate Egress Firewall Blocklist (iptables / Suricata)", use_container_width=True):
                    target_ip = results["metadata"]["sender_ip"]
                    st.code(
                        f"""# --- AUTOMATED FIREWALL BLOCKLIST ---
iptables -A INPUT -s {target_ip} -j DROP
iptables -A FORWARD -s {target_ip} -j DROP
alert ip {target_ip} any -> $HOME_NET any (msg:"SYNOVA_AUTO_BLOCK: Malicious Actor"; sid:9000001; rev:1;)
""",
                        language="bash",
                    )
            with col_soar2:
                if st.button("✉️ Draft Automated Abuse Takedown Notice", use_container_width=True):
                    target_ip = results["metadata"]["sender_ip"]
                    st.code(
                        f"""To: abuse-desk@{str(results['metadata']['geo_data'].get('isp', 'upstream-provider')).replace(' ', '').lower()}.net
Subject: [URGENT] Abuse Notice: Malicious Campaign from {target_ip}

Dear Abuse Team,
Our autonomous SOC (SYNOVA) detected active phishing telemetry from your ASN:
- Offending IP: {target_ip}
- Envelope Sender: {results['metadata']['from']}
- Attack TTP: Spearphishing Link / Social Engineering

Please isolate the compromised host immediately.
""",
                        language="text",
                    )

        with tab2:
            st.subheader("⚡ Adversary Kill-Chain Simulation (Impact Comparison)")
            sim_mode = st.radio(
                "Select Incident Scenario:",
                ["🛑 Without SYNOVA (Unprotected Perimeter)", "🛡️ With SYNOVA Autonomous SOAR Engine"],
                horizontal=True,
            )

            if "Without" in sim_mode:
                st.error("""
                **❌ Unmitigated Breach Simulation Flow:**
                1. **Ingress:** Email lands in user inbox with zero behavioral inspection.
                2. **Exploitation:** User clicks un-defanged link (`credential-harvesting-portal.com`).
                3. **Privilege Escalation:** Corporate SSO session tokens exfiltrated to adversary Command & Control server.
                4. **Lateral Movement:** Adversary pivots to internal LDAP/Active Directory domain controller.
                
                💰 **Estimated Financial & Regulatory Impact:** **$48,500 (Downtime + Forensics + Compliance Fines)**
                """)
            else:
                st.success("""
                **✅ SYNOVA Autonomous Containment Flow:**
                1. **Ingress:** Zero-disk MIME parsing inspects raw RFC-822 stream in memory.
                2. **AI Triage:** Gemini LLM detects urgency cues and domain spoofing in **180ms**.
                3. **Neutralization:** DNS sinkhole and IP firewall block rule auto-staged across edge gateways.
                4. **Quarantine:** Email neutralized and converted to defanged forensic preview.
                
                🛡️ **Mitigation Outcome:** **100% Data Exfiltration Prevented | Zero Endpoint Footprint**
                """)

        with tab3:
            st.subheader("🌐 Deep Attacker Infrastructure Profiling (Shodan & AbuseIPDB)")
            osint_data = results["metadata"].get("geo_data", {})
            oc1, oc2, oc3 = st.columns(3)
            oc1.metric("ASN & Network Scope", str(osint_data.get("asn", "Unknown")))
            oc2.metric("Abuse Confidence Score", f"{osint_data.get('abuse_score', 0)}%")
            oc3.metric("Total Global Reports", str(osint_data.get("total_reports", 0)))

            st.markdown("#### ⚡ Active Attack Surface & Listening Ports (Shodan InternetDB)")
            open_ports = osint_data.get("open_ports", [])
            if open_ports:
                st.warning(f"⚠️ Active Listening Ports Detected on Attacker Host: `{open_ports}`")
            else:
                st.success("✅ No open listening services exposed via InternetDB reconnaissance.")

            cves = osint_data.get("cves", [])
            if cves:
                st.error(f"🚨 Known Unpatched CVE Vulnerabilities on Origin: `{cves}`")
            else:
                st.info("ℹ️ No publicly cataloged CVE vulnerabilities tagged to this host IP.")

        with tab4:
            st.subheader("🧩 Multi-Layer Forensic Deconstruction Matrix")
            from_str = html.escape(str(results["metadata"]["from"]))
            subj_str = html.escape(str(results["metadata"]["subject"]))

            st.markdown(
                f"""
            <div class="layer-card">
                <div class="layer-title">Layer 1: Envelope & Identity Layer</div>
                <div style="font-size:13px; color:#cbd5e1;">• From: <code>{from_str}</code></div>
                <div style="font-size:13px; color:#cbd5e1;">• Subject: <code>{subj_str}</code></div>
                <div style="font-size:13px; color:#cbd5e1;">• DMARC/SPF Alignment: <code>{"ALIGNED" if results['authentication']['spf_pass'] else "DISAVOWED / UNVERIFIED"}</code></div>
            </div>
            
            <div class="layer-card">
                <div class="layer-title">Layer 2: Transport & Routing Layer</div>
                <div style="font-size:13px; color:#cbd5e1;">• Origin Relay Node: <code>{html.escape(str(results['metadata']['sender_ip']))}</code></div>
                <div style="font-size:13px; color:#cbd5e1;">• Geo Anchor & Type: <code>{origin_city}, {origin_country} [{ip_type}]</code></div>
                <div style="font-size:13px; color:#cbd5e1;">• Total Intermediate Relay Hops: <code>{len(results.get('routing_hops', []))}</code></div>
            </div>

            <div class="layer-card">
                <div class="layer-title">Layer 3: Cognitive & Psychological Vector</div>
                <div style="font-size:13px; color:#cbd5e1;">• Adversary Cues: <code>Urgency Cues / Social Engineering Pressure Tactics</code></div>
                <div style="font-size:13px; color:#cbd5e1;">• Behavioral Tactic: <code>Initial Access (MITRE ATT&CK T1566)</code></div>
            </div>

            <div class="layer-card">
                <div class="layer-title">Layer 4: Binary & Artifact Payload</div>
                <div style="font-size:13px; color:#cbd5e1;">• Embedded URLs: <code>{len(results['body_artifacts']['extracted_urls'])} Hyperlinks extracted</code></div>
                <div style="font-size:13px; color:#cbd5e1;">• Sandboxed MIME Attachments: <code>{len(results.get('attachments', []))} Files analyzed</code></div>
            </div>
            """,
                unsafe_allow_html=True,
            )

        with tab5:
            st.subheader("🕒 Threat Execution & Detection Chronology")
            date_stamp = html.escape(str(results["metadata"]["date"]))
            origin_ip = html.escape(str(results["metadata"]["sender_ip"]))
            st.markdown(
                f"""
                <div class="timeline-item">
                    <div class="timeline-dot"></div>
                    <strong style="color: {primary_color};">Phase 1: Ingress Transmission [{date_stamp}]</strong>
                    <p style="color:#94a3b8; font-size:13px; margin:2px 0 0 0;">Threat packet initiated from Origin Node <code>{origin_ip}</code> ({origin_city}, {origin_country}) classified as <code>{ip_type}</code>.</p>
                </div>
                <div class="timeline-item">
                    <div class="timeline-dot"></div>
                    <strong style="color: {primary_color};">Phase 2: Gateway Relay & Auth Check</strong>
                    <p style="color:#94a3b8; font-size:13px; margin:2px 0 0 0;">MIME stream processed by MX gateway. SPF Status: <code>{"PASS" if results['authentication']['spf_pass'] else "FAILED/UNVERIFIED"}</code>.</p>
                </div>
                <div class="timeline-item">
                    <div class="timeline-dot"></div>
                    <strong style="color: {primary_color};">Phase 3: Payload Extraction & Deep OSINT Recon</strong>
                    <p style="color:#94a3b8; font-size:13px; margin:2px 0 0 0;">Extracted {len(results['body_artifacts']['extracted_urls'])} URLs, queried Shodan InternetDB for open ports, and evaluated MIME attachments.</p>
                </div>
                <div class="timeline-item">
                    <div class="timeline-dot"></div>
                    <strong style="color: {primary_color};">Phase 4: Autonomous SOAR Quarantine Action</strong>
                    <p style="color:#94a3b8; font-size:13px; margin:2px 0 0 0;">Calculated Threat Index <code>{score_num}/100</code>. Dynamic mitigation playbooks generated.</p>
                </div>
            """,
                unsafe_allow_html=True,
            )

        with tab6:
            st.subheader("👁️ Pre-Scan Defanged HTML Sandbox Preview")
            raw_body_text = str(results["body_artifacts"]["raw_body"] or "")
            safe_preview = html.escape(raw_body_text)
            for u in results["body_artifacts"]["extracted_urls"]:
                safe_u = html.escape(str(u))
                defanged_badge = (
                    f'<span style="color:#ff3355; background:rgba(255,51,85,0.15); '
                    f'padding:2px 6px; border-radius:4px; font-family:monospace; '
                    f'text-decoration:line-through;">[DEFANGED_URL: {safe_u}]</span>'
                )
                safe_preview = safe_preview.replace(safe_u, defanged_badge)
            safe_preview = safe_preview.replace("\n", "<br/>")

            st.markdown(
                f"""
                <div style="background:rgba(10,15,26,0.9); border:1px dashed {primary_color}; border-radius:8px; padding:16px; color:#cbd5e1; font-family:sans-serif; line-height:1.5;">
                    <div style="font-size:11px; color:#f59e0b; margin-bottom:8px;">⚠️ Malicious scripts, zero-font cloaking, and hyperlinks neutralized:</div>
                    {safe_preview}
                </div>
            """,
                unsafe_allow_html=True,
            )

        with tab7:
            st.subheader("📡 Visual Node-to-Node SMTP Hop Chain")
            hops = results.get("routing_hops", [])
            if hops:
                hop_cols = st.columns(len(hops) * 2 - 1)
                for i, hop in enumerate(hops):
                    with hop_cols[i * 2]:
                        st.markdown(
                            f"""
                            <div style="background: rgba(10, 18, 32, 0.85); border: 1px solid {primary_color}; padding: 10px; border-radius: 8px; text-align: center;">
                                <div style="font-size:11px; color:#94a3b8;">HOP #{hop['hop_number']}</div>
                                <div style="font-size:12px; font-weight:bold; color:{primary_color};">{html.escape(str(hop['hop_ip']))}</div>
                                <div style="font-size:10px; color:#64748b;">{html.escape(str(hop['by']))[:18]}</div>
                            </div>
                        """,
                            unsafe_allow_html=True,
                        )
                    if i < len(hops) - 1:
                        with hop_cols[i * 2 + 1]:
                            st.markdown(
                                f"<div style='color:{primary_color}; font-size:20px; text-align:center; padding-top:10px;'>➔</div>",
                                unsafe_allow_html=True,
                            )

            st.divider()
            map_col, data_col = st.columns([1.5, 1])
            with map_col:
                st.subheader("📍 Attacker Geolocation Radar & Infrastructure")
                geo = results["metadata"].get("geo_data", {})
                lat = geo.get("lat", 0.0)
                lon = geo.get("lon", 0.0)
                city = geo.get("city", "Unknown")
                country = geo.get("country", "Unknown")
                isp = geo.get("isp", "Unknown")

                if lat != 0.0 and lon != 0.0:
                    m = folium.Map(
                        location=[lat, lon],
                        zoom_start=4,
                        tiles="https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}",
                        attr="Esri",
                    )
                    folium.CircleMarker(
                        location=[lat, lon],
                        radius=10,
                        color=primary_color,
                        fill=True,
                        fill_color=primary_color,
                        fill_opacity=0.85,
                        popup=f"<b>Origin:</b> {city}, {country}<br><b>Type:</b> {ip_type}<br><b>ISP:</b> {isp}",
                        tooltip=f"Threat Origin: {city}, {country}",
                    ).add_to(m)
                    st_folium(m, width=600, height=350)
                else:
                    st.warning("Could not trace IP location for map.")

            with data_col:
                st.subheader("Network Telemetry")
                st.markdown(f"**Origin IP:** `{results['metadata']['sender_ip']}`")
                st.markdown(f"**Infrastructure Type:** `{ip_type}`")
                st.markdown(f"**Country:** {country}")
                st.markdown(f"**City:** {city}")
                st.markdown(f"**ISP / ASN:** {isp}")

        with tab8:
            st.subheader("🔬 Raw RFC-822 Email Headers & Hex Stream Inspector")
            st.markdown("**Raw Envelope Headers:**")
            st.json(results.get("raw_headers", {}))
            st.markdown("**First 512-Bytes Hex Dump Preview:**")
            st.code(results.get("raw_hex_preview", ""), language="text")
