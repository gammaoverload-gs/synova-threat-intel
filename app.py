import streamlit as st
import time
import io
import folium
from streamlit_folium import st_folium
from ingestion_engine import EmailIngestionEngine

# ReportLab in-memory PDF generation
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

st.set_page_config(page_title="SYNOVA | Threat Intel", page_icon="🕷️", layout="wide")

st.markdown("""
    <style>
    /* 1. Cyber Grid + Deep Ambient Radial Background */
    .stApp {
        background-color: #080b10;
        background-image: 
            radial-gradient(circle at 50% 0%, rgba(0, 255, 204, 0.08) 0%, transparent 50%),
            radial-gradient(circle at 90% 90%, rgba(31, 111, 235, 0.06) 0%, transparent 40%),
            linear-gradient(rgba(255, 255, 255, 0.02) 1px, transparent 1px),
            linear-gradient(90deg, rgba(255, 255, 255, 0.02) 1px, transparent 1px);
        background-size: 100% 100%, 100% 100%, 30px 30px, 30px 30px;
    }

    /* 2. Frosted Glassmorphism File Uploader */
    [data-testid="stFileUploadDropzone"] {
        background: rgba(18, 22, 34, 0.65) !important;
        backdrop-filter: blur(12px) !important;
        border: 1px dashed rgba(0, 255, 204, 0.35) !important;
        border-radius: 14px !important;
        transition: all 0.3s ease;
    }
    [data-testid="stFileUploadDropzone"]:hover {
        border-color: #00ffcc !important;
        box-shadow: 0 0 20px rgba(0, 255, 204, 0.2);
    }

    /* 3. Metric Cards Styling & Neon Glow */
    [data-testid="stMetric"] {
        background: rgba(17, 24, 39, 0.7);
        backdrop-filter: blur(8px);
        border: 1px solid rgba(56, 189, 248, 0.15);
        border-radius: 12px;
        padding: 12px 18px;
        box-shadow: 0 4px 15px rgba(0, 0, 0, 0.3);
    }
    [data-testid="stMetricValue"] {
        color: #00ffcc !important;
        font-family: 'Courier New', monospace;
        font-size: 28px !important;
        text-shadow: 0 0 10px rgba(0, 255, 204, 0.4);
    }
    [data-testid="stMetricLabel"] {
        color: #94a3b8 !important;
        font-size: 13px !important;
        text-transform: uppercase;
        letter-spacing: 1px;
    }

    /* 4. Tab Navigation Styling */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        background-color: transparent;
    }
    .stTabs [data-baseweb="tab"] {
        background: rgba(15, 23, 42, 0.6);
        border: 1px solid #1e293b;
        border-radius: 8px 8px 0px 0px;
        color: #94a3b8;
        padding: 8px 18px;
    }
    .stTabs [aria-selected="true"] {
        background: rgba(0, 255, 204, 0.1) !important;
        border-bottom: 2px solid #00ffcc !important;
        color: #00ffcc !important;
    }

    /* 5. Live Radar Pulsing Beacon */
    .live-badge {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        background: rgba(0, 255, 204, 0.1);
        border: 1px solid #00ffcc;
        color: #00ffcc;
        font-size: 11px;
        padding: 4px 10px;
        border-radius: 20px;
        font-weight: bold;
        letter-spacing: 0.5px;
    }
    .pulse-dot {
        width: 7px;
        height: 7px;
        background-color: #00ffcc;
        border-radius: 50%;
        box-shadow: 0 0 8px #00ffcc;
        animation: pulse 1.5s infinite;
    }
    @keyframes pulse {
        0% { transform: scale(0.9); opacity: 1; }
        50% { transform: scale(1.4); opacity: 0.4; }
        100% { transform: scale(0.9); opacity: 1; }
    }
    </style>
    """, unsafe_allow_html=True)

# Hardcoded API Key (Insert your Gemini API key here)
# Read key from Streamlit Secrets securely
api_key = st.secrets.get("GEMINI_API_KEY", "")

# --- NAYA UPGRADED HEADER WITH PULSING LIVE BEACON ---
col1, col2 = st.columns([3.5, 1.5])
with col1:
    st.markdown("<h1 style='color: white; margin-bottom: 0px;'>🛡️ SYNOVA <span style='color: #00ffcc;'>Zero-Code</span></h1>", unsafe_allow_html=True)
    st.markdown("<p style='color: #94a3b8; font-size: 15px; margin-top: 4px;'>Autonomous AI Email Threat Detection & Forensic Intelligence Platform</p>", unsafe_allow_html=True)
with col2:
    st.markdown("<div style='text-align: right; margin-top: 15px;'><span class='live-badge'><span class='pulse-dot'></span>SOC ENGINE ACTIVE</span></div>", unsafe_allow_html=True)

st.divider()

st.divider()

uploaded_file = st.file_uploader("Drop a suspicious .eml or .msg file here", type=['eml', 'msg'])

def build_pdf_buffer(results):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=30, leftMargin=30, topMargin=30, bottomMargin=30)
    story = []
    
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle('TitleStyle', parent=styles['Heading1'], fontSize=20, textColor=colors.HexColor('#003366'), spaceAfter=8)
    heading_style = ParagraphStyle('HeadingStyle', parent=styles['Heading2'], fontSize=13, textColor=colors.HexColor('#0055a5'), spaceBefore=10, spaceAfter=6)
    body_style = ParagraphStyle('BodyStyle', parent=styles['Normal'], fontSize=9, textColor=colors.HexColor('#222222'), leading=12)
    
    story.append(Paragraph("SYNOVA CYBERSECURITY INCIDENT REPORT", title_style))
    story.append(Paragraph("<b>Automated Email Threat Intelligence & Incident Response</b>", body_style))
    story.append(Spacer(1, 10))
    
    story.append(Paragraph("Email Metadata", heading_style))
    meta = results.get("metadata", {})
    meta_data = [
        [Paragraph("<b>Subject:</b>", body_style), Paragraph(str(meta.get('subject', 'N/A')), body_style)],
        [Paragraph("<b>Sender:</b>", body_style), Paragraph(str(meta.get('from', 'N/A')), body_style)],
        [Paragraph("<b>Recipient:</b>", body_style), Paragraph(str(meta.get('to', 'N/A')), body_style)],
        [Paragraph("<b>Sender IP:</b>", body_style), Paragraph(str(meta.get('sender_ip', 'N/A')), body_style)],
        [Paragraph("<b>AI Threat Score:</b>", body_style), Paragraph(str(results.get('ai_analysis', {}).get('score', 'N/A')), body_style)]
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
    story.append(Paragraph(str(results.get('ai_analysis', {}).get('analysis', 'None')), body_style))
    story.append(Spacer(1, 10))

    story.append(Paragraph("Recommended Incident Response & Mitigation Steps", heading_style))
    story.append(Paragraph(str(results.get('ai_analysis', {}).get('mitigations', 'No immediate mitigation required.')).replace("\n", "<br/>"), body_style))
    story.append(Spacer(1, 10))
    
    story.append(Paragraph("Extracted Indicators of Compromise (IOC URLs)", heading_style))
    urls = results.get("body_artifacts", {}).get("extracted_urls", [])
    if urls:
        url_data = [[Paragraph(f"• {u}", body_style)] for u in urls[:15]]
        ut = Table(url_data, colWidths=[520])
        ut.setStyle(TableStyle([('BOX', (0,0), (-1,-1), 1, colors.HexColor('#d0d7de')), ('PADDING', (0,0), (-1,-1), 4)]))
        story.append(ut)
    else:
        story.append(Paragraph("No URLs detected.", body_style))
        
    doc.build(story)
    buffer.seek(0)
    return buffer

if uploaded_file is not None:
    with st.spinner("Analyzing email payloads and generating mitigation playbooks..."):
        raw_bytes = uploaded_file.getvalue()
        engine = EmailIngestionEngine(raw_bytes, api_key=api_key)
        results = engine.parse_email()
    
    st.success("Target acquired. Forensic breakdown complete.")
    st.divider()
    
    st.markdown("<h3 style='color: white;'>Threat Intelligence Overview</h3>", unsafe_allow_html=True)
    
    ai_score = results.get("ai_analysis", {}).get("score", "N/A")
    ai_reason = results.get("ai_analysis", {}).get("analysis", "No AI analysis performed.")
    ai_mitigations = results.get("ai_analysis", {}).get("mitigations", "No mitigations available.")
    
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("🧠 AI Threat Score", ai_score)
    m2.metric("Sender IP", results["metadata"]["sender_ip"] or "Hidden")
    m3.metric("SPF Check", "Pass" if results["authentication"]["spf_pass"] else "Fail/None")
    m4.metric("Extracted URLs", f"{len(results['body_artifacts']['extracted_urls'])} Detected")
    
    st.info(f"**AI Forensic Analysis:** {ai_reason}")
    st.divider()
    
    col_pdf1, col_pdf2 = st.columns([3, 1])
    with col_pdf1:
        st.markdown("### 📊 Comprehensive Forensic Investigation Panel")
    with col_pdf2:
        pdf_buffer = build_pdf_buffer(results)
        st.download_button(
            label="📥 Download PDF Report",
            data=pdf_buffer,
            file_name="SYNOVA_Threat_Report.pdf",
            mime="application/pdf"
        )
            
    tab1, tab2, tab3, tab4 = st.tabs([
        "🛡️ Defense & Mitigation", 
        "🌐 Extracted URLs (IOCs)", 
        "📦 Attachment Sandbox", 
        "🗺️ Routing & Network"
    ])
    
    with tab1:
        st.subheader("⚡ Automated Incident Response Playbook")
        st.markdown(ai_mitigations)
        st.divider()
        st.subheader("Quick Defensive Actions")
        col_act1, col_act2 = st.columns(2)
        with col_act1:
            st.button("🚫 Export Blocklist for Firewall (iptables / Suricata)")
        with col_act2:
            st.button("✉️ Draft Automated Takedown Request")
            
    with tab2:
        st.subheader("Suspicious Links Identified")
        urls = results["body_artifacts"]["extracted_urls"]
        if urls:
            for u in urls:
                st.code(u, language="text")
        else:
            st.success("No external URLs found.")
            
    with tab3:
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
            
    with tab4:
        map_col, data_col = st.columns([1.5, 1])
        with map_col:
            st.subheader("📍 Attacker Geolocation")
            lat = results["metadata"]["geo_data"]["lat"]
            lon = results["metadata"]["geo_data"]["lon"]
            city = results["metadata"]["geo_data"]["city"]
            country = results["metadata"]["geo_data"]["country"]
            isp = results["metadata"]["geo_data"]["isp"]
            
            if lat != 0.0 and lon != 0.0:
                m = folium.Map(location=[lat, lon], zoom_start=4, tiles="https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}", attr="Esri")
                folium.Marker([lat, lon], popup=f"ISP: {isp}", tooltip=f"{city}, {country}", icon=folium.Icon(color="red", icon="info-sign")).add_to(m)
                st_folium(m, width=600, height=350)
            else:
                st.warning("Could not trace IP location for map.")
                
        with data_col:
            st.subheader("Network Details")
            st.markdown(f"**Country:** {country}")
            st.markdown(f"**City:** {city}")
            st.markdown(f"**ISP:** {isp}")
            st.subheader("Routing Hops")
            st.json(results["routing_hops"])
