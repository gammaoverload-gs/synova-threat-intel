import streamlit as st
import time
import io
import html
import folium
from streamlit_folium import st_folium
from ingestion_engine import EmailIngestionEngine

# ReportLab in-memory PDF generation
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

# Set Streamlit Page Config
st.set_page_config(page_title="SYNOVA SOC Command Center", page_icon="🛡️", layout="wide")

# Read key securely
api_key = st.secrets.get("GEMINI_API_KEY", "")

# --- State Management & Ingestion ---
uploaded_file = st.file_uploader("Drop a suspicious .eml or .msg file here", type=['eml', 'msg'])

primary_color = "#00ffcc"
glow_rgba = "rgba(0, 255, 204, 0.15)"
bg_glow = "rgba(0, 255, 204, 0.18)"
badge_text = "SOC RADAR ACTIVE"
score_num = 0
results = None

if uploaded_file is not None:
    with st.spinner("Executing Zero-Disk Forensics & AI Triage Pipeline..."):
        raw_bytes = uploaded_file.getvalue()
        engine = EmailIngestionEngine(raw_bytes, api_key=api_key)
        results = engine.parse_email()

    raw_score = str(results.get("ai_analysis", {}).get("score", "0"))
    try:
        score_num = int("".join([c for c in raw_score.split("/")[0] if c.isdigit()]))
    except Exception:
        score_num = 0

    if score_num >= 70:
        primary_color = "#ff3355"  # CRITICAL RED
        glow_rgba = "rgba(255, 51, 85, 0.25)"
        bg_glow = "rgba(255, 51, 85, 0.25)"
        badge_text = "CRITICAL THREAT CONFIRMED"
    elif score_num >= 40:
        primary_color = "#ffaa00"  # AMBER WARNING
        glow_rgba = "rgba(255, 170, 0, 0.25)"
        bg_glow = "rgba(255, 170, 0, 0.22)"
        badge_text = "SUSPICIOUS PROFILE DETECTED"
    else:
        primary_color = "#00ffcc"  # GREEN SECURE
        glow_rgba = "rgba(0, 255, 204, 0.15)"
        bg_glow = "rgba(0, 255, 204, 0.18)"
        badge_text = "CLEAN ARTIFACT CONFIRMED"

# --- Injectable Cyber CSS Styling ---
st.markdown(f"""
    <style>
    /* 1. FAINT CYBER SCANLINE & HUD OVERLAY */
    .stApp::before {{
        content: " ";
        display: block;
        position: fixed;
        top: 0; left: 0; bottom: 0; right: 0;
        background: linear-gradient(rgba(18, 16, 16, 0) 50%, {glow_rgba} 50%), 
                    linear-gradient(90deg, rgba(255, 0, 0, 0.01), rgba(0, 255, 0, 0.01), rgba(0, 0, 255, 0.01));
        z-index: 99999;
        background-size: 100% 3px, 3px 100%;
        pointer-events: none;
        opacity: 0.65;
    }}

    .stApp::after {{
        content: "";
        position: fixed;
        top: 0; left: 0; right: 0; height: 100vh;
        background: linear-gradient(180deg, transparent 0%, {glow_rgba} 50%, transparent 100%);
        animation: radarSweep 5s ease-in-out infinite;
        pointer-events: none;
        z-index: 99998;
    }}

    @keyframes radarSweep {{
        0% {{ transform: translateY(-100%); }}
        100% {{ transform: translateY(100%); }}
    }}

    .stApp {{
        background-color: #04070d !important;
        background-image: 
            radial-gradient(circle at 50% 0%, {bg_glow} 0%, transparent 70%),
            radial-gradient(circle at 90% 90%, rgba(14, 165, 233, 0.1) 0%, transparent 50%),
            linear-gradient({glow_rgba} 1px, transparent 1px),
            linear-gradient(90deg, {glow_rgba} 1px, transparent 1px) !important;
        background-size: 100% 100%, 100% 100%, 40px 40px, 40px 40px !important;
    }}

    .live-badge {{
        display: inline-flex;
        align-items: center;
        gap: 8px;
        background: {glow_rgba};
        border: 1px solid {primary_color};
        color: {primary_color};
        font-size: 11px;
        padding: 6px 14px;
        border-radius: 20px;
        font-family: 'Courier New', monospace;
        font-weight: bold;
        letter-spacing: 1.5px;
        box-shadow: 0 0 15px {glow_rgba};
    }}

    .pulse-dot {{
        width: 8px;
        height: 8px;
        background-color: {primary_color};
        border-radius: 50%;
        box-shadow: 0 0 10px {primary_color};
        display: inline-block;
        animation: socPulse 1.2s infinite ease-in-out !important;
    }}

    @keyframes socPulse {{
        0%, 100% {{ transform: scale(0.85); opacity: 0.3; box-shadow: 0 0 2px {primary_color}; }}
        50% {{ transform: scale(1.35); opacity: 1; box-shadow: 0 0 14px {primary_color}; }}
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

    /* Cyber Terminal Box */
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

    .terminal-header {{
        color: {primary_color};
        font-weight: bold;
        font-size: 12px;
        margin-bottom: 8px;
        text-transform: uppercase;
        letter-spacing: 1px;
    }}

    /* MITRE TTP Badges */
    .ttp-card {{
        display: inline-block;
        background: rgba(15, 23, 42, 0.9);
        border: 1px solid {primary_color};
        border-radius: 8px;
        padding: 10px 14px;
        margin: 6px;
        min-width: 220px;
    }}
    .ttp-id {{
        color: {primary_color};
        font-family: monospace;
        font-weight: bold;
        font-size: 13px;
    }}
    .ttp-name {{
        color: #ffffff;
        font-size: 13px;
        font-weight: 600;
        margin-top: 2px;
    }}
    .ttp-tactic {{
        color: #94a3b8;
        font-size: 11px;
        text-transform: uppercase;
    }}

    /* Hop Chain Visual */
    .hop-node {{
        background: rgba(10, 18, 32, 0.85);
        border: 1px solid {primary_color};
        padding: 10px 16px;
        border-radius: 8px;
        text-align: center;
        min-width: 140px;
    }}
    .hop-arrow {{
        color: {primary_color};
        font-size: 22px;
        font-weight: bold;
        display: flex;
        align-items: center;
        justify-content: center;
    }}
    </style>
""", unsafe_allow_html=True)

# --- Header Section ---
col1, col2 = st.columns([3.5, 1.5])
with col1:
    st.markdown(f"<h1 style='color: white; margin-bottom: 0px;'>🛡️ SYNOVA <span style='color: {primary_color};'>Command Center</span></h1>", unsafe_allow_html=True)
    st.markdown("<p style='color: #94a3b8; font-size: 14px; margin-top: 4px;'>Autonomous AI Email Threat Detection & SOAR Incident Response Platform</p>", unsafe_allow_html=True)
with col2:
    st.markdown(f"<div style='text-align: right; margin-top: 15px;'><span class='live-badge'><span class='pulse-dot'></span>{badge_text}</span></div>", unsafe_allow_html=True)

st.divider()

# --- PDF Builder ---
def build_pdf_buffer(results_data):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=30, leftMargin=30, topMargin=30, bottomMargin=30)
    story = []
    
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle('TitleStyle', parent=styles['Heading1'], fontSize=18, textColor=colors.HexColor('#003366'), spaceAfter=8)
    heading_style = ParagraphStyle('HeadingStyle', parent=styles['Heading2'], fontSize=12, textColor=colors.HexColor('#0055a5'), spaceBefore=10, spaceAfter=6)
    body_style = ParagraphStyle('BodyStyle', parent=styles['Normal'], fontSize=9, textColor=colors.HexColor('#222222'), leading=12)
    
    story.append(Paragraph("SYNOVA CYBERSECURITY INCIDENT REPORT", title_style))
    story.append(Paragraph("<b>Autonomous Email Threat Intelligence & SOAR Playbook</b>", body_style))
    story.append(Spacer(1, 10))
    
    story.append(Paragraph("Email Metadata", heading_style))
    meta = results_data.get("metadata", {})
    meta_data = [
        [Paragraph("<b>Subject:</b>", body_style), Paragraph(html.escape(str(meta.get('subject', 'N/A'))), body_style)],
        [Paragraph("<b>Sender:</b>", body_style), Paragraph(html.escape(str(meta.get('from', 'N/A'))), body_style)],
        [Paragraph("<b>Recipient:</b>", body_style), Paragraph(html.escape(str(meta.get('to', 'N/A'))), body_style)],
        [Paragraph("<b>Sender IP:</b>", body_style), Paragraph(html.escape(str(meta.get('sender_ip', 'N/A'))), body_style)],
        [Paragraph("<b>AI Threat Score:</b>", body_style), Paragraph(html.escape(str(results_data.get('ai_analysis', {}).get('score', 'N/A'))), body_style)]
    ]
    t = Table(meta_data, colWidths=[110, 410])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f2f4f8')),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#d0d7de')),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('PADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(t)
    story.append(Spacer(1, 10))
    
    story.append(Paragraph("AI Forensic Breakdown", heading_style))
    story.append(Paragraph(html.escape(str(results_data.get('ai_analysis', {}).get('analysis', 'None'))), body_style))
    story.append(Spacer(1, 10))

    story.append(Paragraph("Recommended Incident Response & Mitigation Steps", heading_style))
    mitigations_raw = str(results_data.get('ai_analysis', {}).get('mitigations', 'No immediate mitigation required.'))
    story.append(Paragraph(html.escape(mitigations_raw).replace("\n", "<br/>"), body_style))
    story.append(Spacer(1, 10))
    
    story.append(Paragraph("Extracted Indicators of Compromise (IOC URLs)", heading_style))
    urls = results_data.get("body_artifacts", {}).get("extracted_urls", [])
    if urls:
        url_data = [[Paragraph(f"• {html.escape(str(u))}", body_style)] for u in urls[:15]]
        ut = Table(url_data, colWidths=[520])
        ut.setStyle(TableStyle([('BOX', (0,0), (-1,-1), 1, colors.HexColor('#d0d7de')), ('PADDING', (0,0), (-1,-1), 4)]))
        story.append(ut)
    else:
        story.append(Paragraph("No URLs detected.", body_style))
        
    doc.build(story)
    buffer.seek(0)
    return buffer

# --- Empty State Landing View ---
if not uploaded_file:
    st.markdown("<br>", unsafe_allow_html=True)
    c1, c2, c3, c4 = st.columns(4)
    with c1: st.metric(label="CORE ENGINE", value="ZERO-DISK", delta="RAM Buffer")
    with c2: st.metric(label="GEO RADAR", value="LIVE IP", delta="Hop Tracer")
    with c3: st.metric(label="AI BRAIN", value="GEMINI", delta="Heuristics")
    with c4: st.metric(label="SOAR DEFENSE", value="ACTIVE", delta="IPTables/DNS")

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown(f"""
        <div style="background: rgba(6, 11, 21, 0.9); border: 1px solid {glow_rgba}; border-left: 4px solid {primary_color}; border-radius: 8px; padding: 14px 20px; font-family: 'Courier New', monospace; font-size: 13px; color: #94a3b8; box-shadow: 0 4px 20px rgba(0,0,0,0.5);">
            <span style="color: {primary_color}; font-weight: bold;">[SOC RADAR READY]</span> Awaiting forensic byte stream... | Drop any raw .eml or .msg to trigger autonomous triage.
        </div>
    """, unsafe_allow_html=True)

# --- Active Threat Investigation View ---
else:
    # 1. Circular SVG Threat Gauge & Telemetry Metrics
    dash_col1, dash_col2 = st.columns([1.2, 3])
    
    with dash_col1:
        # Animated SVG Radial Dial Calculation
        circumference = 282.74  # 2 * pi * 45
        stroke_dashoffset = circumference - (score_num / 100.0) * circumference
        st.markdown(f"""
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
        """, unsafe_allow_html=True)

    with dash_col2:
        m1, m2, m3 = st.columns(3)
        m1.metric("SENDER ORIGIN IP", results["metadata"]["sender_ip"] or "Hidden")
        m2.metric("SPF RECORD", "PASS" if results["authentication"]["spf_pass"] else "FAIL / NONE")
        m3.metric("EXTRACTED IOCs", f"{len(results['body_artifacts']['extracted_urls'])} URLs")
        
        # Download Report Bar
        pdf_buffer = build_pdf_buffer(results)
        st.download_button(
            label="📥 Export Forensic Incident Report (PDF)",
            data=pdf_buffer,
            file_name="SYNOVA_Incident_Report.pdf",
            mime="application/pdf",
            use_container_width=True
        )

    # 2. Cyber Terminal Box (Typewriter Simulation)
    ai_reason = results.get("ai_analysis", {}).get("analysis", "No forensic log generated.")
    st.markdown(f"""
        <div class="soc-terminal">
            <div class="terminal-header">🤖 [SOC AGENT AUTONOMOUS TRIAGE LOG]</div>
            <div>&gt; [TIMESTAMP] : {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}</div>
            <div>&gt; [PARSER]    : Zero-Disk MIME Byte Reconstruction complete.</div>
            <div>&gt; [DIAGNOSIS] : <span style="color: {primary_color}; font-weight: bold;">{ai_reason}</span></div>
        </div>
    """, unsafe_allow_html=True)

    # 3. MITRE ATT&CK Matrix TTP Heatmap Badges
    st.markdown("#### 🎯 MITRE ATT&CK® Mapped Adversary Techniques")
    ttps = results.get("mitre_ttps", [])
    ttp_html = ""
    for ttp in ttps:
        ttp_html += f"""
            <div class="ttp-card">
                <div class="ttp-tactic">{ttp['tactic']}</div>
                <div class="ttp-id">{ttp['id']}</div>
                <div class="ttp-name">{ttp['name']}</div>
            </div>
        """
    st.markdown(f"<div style='margin-bottom: 20px;'>{ttp_html}</div>", unsafe_allow_html=True)

    st.divider()

    # 4. Forensic Deep Dive Investigation Tabs
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "🛡️ SOAR Response & Mitigations", 
        "🌐 IOC Extraction", 
        "🔗 Routing Hop Chain & Geolocation", 
        "📦 Attachment Sandbox", 
        "🔬 Raw RFC-822 & Hex Inspector"
    ])

    # TAB 1: SOAR Defense Playbooks
    with tab1:
        st.subheader("⚡ Automated SOAR Playbook Execution")
        ai_mitigations = results.get("ai_analysis", {}).get("mitigations", "No mitigations available.")
        st.markdown(ai_mitigations)
        st.divider()
        
        st.subheader("Interactive Quick Defensive Responses")
        col_soar1, col_soar2 = st.columns(2)
        
        with col_soar1:
            if st.button("🚫 Generate Egress Firewall Blocklist (iptables / Suricata)", use_container_width=True):
                target_ip = results['metadata']['sender_ip']
                st.code(f"""# --- AUTOMATED FIREWALL BLOCKLIST ---
# Drop Inbound from Threat Actor IP
iptables -A INPUT -s {target_ip} -j DROP
iptables -A FORWARD -s {target_ip} -j DROP

# Suricata Threat Rule
alert ip {target_ip} any -> $HOME_NET any (msg:"SYNOVA_AUTO_BLOCK: Malicious Actor"; sid:9000001; rev:1;)
""", language="bash")

        with col_soar2:
            if st.button("✉️ Draft Automated Abuse Takedown Notice", use_container_width=True):
                target_ip = results['metadata']['sender_ip']
                sender = results['metadata']['from']
                st.code(f"""To: abuse-desk@{results['metadata']['geo_data'].get('isp', 'upstream-provider').replace(' ', '').lower()}.net
Subject: [URGENT] Abuse Notice: Malicious Phishing Campaign originating from {target_ip}

Dear Abuse / Security Incident Response Team,

Our autonomous SOC monitoring system (SYNOVA) has detected active phishing & credential harvesting telemetry originating from your autonomous network:

- Offending Origin IP: {target_ip}
- Associated ISP / ASN: {results['metadata']['geo_data'].get('isp', 'N/A')}
- Originating Envelope Sender: {sender}
- Attack TTP: Spearphishing Link / Social Engineering

Please immediately isolate the compromised host and revoke outbound SMTP permissions.

Regards,
Security Operations Center (SOC) Automated Dispatch
""", language="text")

    # TAB 2: Extracted URLs (IOCs)
    with tab2:
        st.subheader("Extracted Indicators of Compromise (URLs)")
        urls = results["body_artifacts"]["extracted_urls"]
        if urls:
            for u in urls:
                st.code(u, language="text")
        else:
            st.success("Zero suspicious hyperlinks detected in body.")

    # TAB 3: Visual Hop Chain & Geolocation Map
    with tab3:
        st.subheader("📡 Visual Node-to-Node SMTP Hop Chain")
        hops = results.get("routing_hops", [])
        if hops:
            hop_cols = st.columns(len(hops) * 2 - 1)
            for i, hop in enumerate(hops):
                with hop_cols[i * 2]:
                    st.markdown(f"""
                        <div class="hop-node">
                            <div style="font-size:11px; color:#94a3b8;">HOP #{hop['hop_number']}</div>
                            <div style="font-size:12px; font-weight:bold; color:{primary_color};">{hop['hop_ip']}</div>
                            <div style="font-size:10px; color:#64748b;">{hop['by'][:18]}</div>
                        </div>
                    """, unsafe_allow_html=True)
                if i < len(hops) - 1:
                    with hop_cols[i * 2 + 1]:
                        st.markdown(f"<div class='hop-arrow'>➔</div>", unsafe_allow_html=True)
        else:
            st.info("Single hop transmission.")

        st.divider()

        map_col, data_col = st.columns([1.5, 1])
        with map_col:
            st.subheader("📍 Attacker Geolocation Radar")
            geo = results["metadata"].get("geo_data", {})
            lat = geo.get("lat", 0.0)
            lon = geo.get("lon", 0.0)
            city = geo.get("city", "Unknown")
            country = geo.get("country", "Unknown")
            isp = geo.get("isp", "Unknown")
            
            if lat != 0.0 and lon != 0.0:
                m = folium.Map(location=[lat, lon], zoom_start=4, tiles="https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}", attr="Esri")
                folium.CircleMarker(
                    location=[lat, lon],
                    radius=10,
                    color=primary_color,
                    fill=True,
                    fill_color=primary_color,
                    fill_opacity=0.85,
                    popup=f"<b>Origin:</b> {city}, {country}<br><b>ISP:</b> {isp}",
                    tooltip=f"Threat Origin: {city}, {country}"
                ).add_to(m)
                st_folium(m, width=600, height=350)
            else:
                st.warning("Could not trace IP location for map.")

        with data_col:
            st.subheader("Network Telemetry")
            st.markdown(f"**Origin IP:** `{results['metadata']['sender_ip']}`")
            st.markdown(f"**Country:** {country}")
            st.markdown(f"**City:** {city}")
            st.markdown(f"**ISP / ASN:** {isp}")

    # TAB 4: Attachments
    with tab4:
        st.subheader("Attachment Heuristic Sandbox Check")
        atts = results["attachments"]
        if atts:
            for att in atts:
                st.write(f"**File Name:** {att['filename']}")
                st.code(f"SHA-256: {att['sha256_hash']}", language="text")
                if "Suspicious" in att['sandbox_status']:
                    st.error(f"Status: {att['sandbox_status']}")
                else:
                    st.success(f"Status: {att['sandbox_status']}")
        else:
            st.info("No attachments present in this email container.")

    # TAB 5: Raw RFC-822 & Hex Inspector
    with tab5:
        st.subheader("🔬 Raw RFC-822 Email Headers & Hex Stream Inspector")
        st.markdown("**Raw Envelope Headers:**")
        st.json(results.get("raw_headers", {}))
        
        st.markdown("**First 512-Bytes Hex Dump Preview:**")
        st.code(results.get("raw_hex_preview", ""), language="text")
