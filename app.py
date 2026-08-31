import html
import io
import time
import folium
from ingestion_engine import EmailIngestionEngine
from reportlab.lib import colors

# ReportLab in-memory PDF generation
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
import streamlit as st
from streamlit_folium import st_folium

st.markdown(
    """
    <style>
    /* Live SOC Radar Pulse */
    .live-badge {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        background: rgba(0, 255, 204, 0.1);
        border: 1px solid #00ffcc;
        color: #00ffcc;
        font-size: 11px;
        padding: 5px 14px;
        border-radius: 20px;
        font-family: 'Courier New', monospace;
        font-weight: bold;
        letter-spacing: 1.5px;
        box-shadow: 0 0 12px rgba(0, 255, 204, 0.3);
    }

    .pulse-dot {
        width: 8px;
        height: 8px;
        background-color: #00ffcc;
        border-radius: 50%;
        box-shadow: 0 0 10px #00ffcc;
        display: inline-block;
        animation: socPulse 1.2s infinite ease-in-out !important;
    }

    @keyframes socPulse {
        0% {
            transform: scale(0.85);
            opacity: 0.3;
            box-shadow: 0 0 2px #00ffcc;
        }
        50% {
            transform: scale(1.35);
            opacity: 1;
            box-shadow: 0 0 14px #00ffcc;
        }
        100% {
            transform: scale(0.85);
            opacity: 0.3;
            box-shadow: 0 0 2px #00ffcc;
        }
    }

    /* 1. Base Grid & Viewport Ambience */
    .stApp {
        background-color: #06090e !important;
        background-image: 
            radial-gradient(circle at 50% 0%, rgba(0, 255, 204, 0.15) 0%, transparent 60%),
            radial-gradient(circle at 85% 85%, rgba(14, 165, 233, 0.1) 0%, transparent 40%),
            linear-gradient(rgba(0, 255, 204, 0.04) 1px, transparent 1px),
            linear-gradient(90deg, rgba(0, 255, 204, 0.04) 1px, transparent 1px) !important;
        background-size: 100% 100%, 100% 100%, 35px 35px, 35px 35px !important;
    }

    /* 2. Responsive Radar Dropzone */
    [data-testid="stFileUploadDropzone"], .stFileUploader section {
        background: rgba(10, 15, 26, 0.85) !important;
        backdrop-filter: blur(16px) !important;
        border: 2px dashed #00ffcc !important;
        border-radius: 16px !important;
        animation: cyberRadar 2.5s infinite ease-in-out !important;
    }
    @keyframes cyberRadar {
        0%, 100% { border-color: rgba(0, 255, 204, 0.3); box-shadow: 0 0 10px rgba(0, 255, 204, 0.1); }
        50% { border-color: rgba(0, 255, 204, 1); box-shadow: 0 0 25px rgba(0, 255, 204, 0.4); }
    }

    /* 3. Metric Containers */
    [data-testid="stMetric"] {
        background: rgba(13, 20, 36, 0.8) !important;
        backdrop-filter: blur(12px) !important;
        border: 1px solid rgba(0, 255, 204, 0.25) !important;
        border-radius: 12px !important;
        padding: 10px 14px !important;
        box-shadow: 0 8px 30px rgba(0, 0, 0, 0.5);
    }
    [data-testid="stMetricValue"] {
        color: #00ffcc !important;
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 22px !important;
        text-shadow: 0 0 10px rgba(0, 255, 204, 0.5);
    }
    [data-testid="stMetricLabel"] {
        font-size: 11px !important;
        letter-spacing: 1px;
    }

    /* 4. Glassmorphism IOC Table & Terminal Wrapper */
    div[data-testid="stExpander"], div.stDataFrame {
        border: 1px solid rgba(0, 255, 204, 0.2) !important;
        border-radius: 10px !important;
        background: rgba(10, 15, 26, 0.6) !important;
        backdrop-filter: blur(10px) !important;
    }

    /* 5. Custom Quick-Action Demo Badges */
    .demo-chip {
        display: inline-block;
        padding: 4px 12px;
        background: rgba(56, 189, 248, 0.1);
        border: 1px solid rgba(56, 189, 248, 0.3);
        border-radius: 6px;
        color: #38bdf8;
        font-size: 12px;
        font-family: monospace;
        margin-right: 6px;
    }
    </style>
""",
    unsafe_allow_html=True,
)

# Read key from Streamlit Secrets securely
api_key = st.secrets.get("GEMINI_API_KEY", "")

# --- HEADER WITH PULSING LIVE BEACON ---
col1, col2 = st.columns([3.5, 1.5])
with col1:
    st.markdown(
        "<h1 style='color: white; margin-bottom: 0px;'>🛡️ SYNOVA <span"
        " style='color: #00ffcc;'>Zero-Code</span></h1>",
        unsafe_allow_html=True,
    )
    st.markdown(
        "<p style='color: #94a3b8; font-size: 15px; margin-top:"
        " 4px;'>Autonomous AI Email Threat Detection & Forensic Intelligence"
        " Platform</p>",
        unsafe_allow_html=True,
    )
with col2:
    st.markdown(
        "<div style='text-align: right; margin-top: 15px;'><span"
        " class='live-badge'><span class='pulse-dot'></span>SOC ENGINE"
        " ACTIVE</span></div>",
        unsafe_allow_html=True,
    )

st.divider()

uploaded_file = st.file_uploader(
    "Drop a suspicious .eml or .msg file here", type=["eml", "msg"]
)

# Agar koi file upload nahi hui hai, toh Live Threat Intelligence Dashboard dikhega
if not uploaded_file:
    st.markdown("<br>", unsafe_allow_html=True)

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.metric(label="CORE ENGINE", value="ZERO-DISK", delta="RAM Buffer")
    with c2:
        st.metric(label="GEO RADAR", value="LIVE IP", delta="Hop Tracer")
    with c3:
        st.metric(label="AI BRAIN", value="GEMINI", delta="Heuristics")
    with c4:
        st.metric(label="SOAR DEFENSE", value="ACTIVE", delta="IPTables/DNS")

    st.markdown("<br>", unsafe_allow_html=True)

    st.markdown(
        """
        <div style="
            background: rgba(6, 11, 21, 0.9);
            border: 1px solid rgba(0, 255, 204, 0.2);
            border-left: 4px solid #00ffcc;
            border-radius: 8px;
            padding: 14px 20px;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            color: #94a3b8;
            box-shadow: 0 4px 20px rgba(0,0,0,0.5);
        ">
            <span style="color: #00ffcc; font-weight: bold;">[SOC RADAR LIVE]</span> 
            Awaiting forensic byte stream... | 
            <span class="demo-chip">DRAG & DROP .EML</span>
            <span class="demo-chip">DEEP RELAY PARSE</span>
            <span class="demo-chip">PDF READY</span>
        </div>
    """,
        unsafe_allow_html=True,
    )


def build_pdf_buffer(results):
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
        fontSize=20,
        textColor=colors.HexColor("#003366"),
        spaceAfter=8,
    )
    heading_style = ParagraphStyle(
        "HeadingStyle",
        parent=styles["Heading2"],
        fontSize=13,
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

    story.append(
        Paragraph("SYNOVA CYBERSECURITY INCIDENT REPORT", title_style)
    )
    story.append(
        Paragraph(
            "<b>Automated Email Threat Intelligence & Incident Response</b>",
            body_style,
        )
    )
    story.append(Spacer(1, 10))

    story.append(Paragraph("Email Metadata", heading_style))
    meta = results.get("metadata", {})
    meta_data = [
        [
            Paragraph("<b>Subject:</b>", body_style),
            Paragraph(
                html.escape(str(meta.get("subject", "N/A"))), body_style
            ),
        ],
        [
            Paragraph("<b>Sender:</b>", body_style),
            Paragraph(html.escape(str(meta.get("from", "N/A"))), body_style),
        ],
        [
            Paragraph("<b>Recipient:</b>", body_style),
            Paragraph(html.escape(str(meta.get("to", "N/A"))), body_style),
        ],
        [
            Paragraph("<b>Sender IP:</b>", body_style),
            Paragraph(
                html.escape(str(meta.get("sender_ip", "N/A"))), body_style
            ),
        ],
        [
            Paragraph("<b>AI Threat Score:</b>", body_style),
            Paragraph(
                html.escape(
                    str(results.get("ai_analysis", {}).get("score", "N/A"))
                ),
                body_style,
            ),
        ],
    ]
    t = Table(meta_data, colWidths=[110, 410])
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
    ai_analysis_text = html.escape(
        str(results.get("ai_analysis", {}).get("analysis", "None"))
    )
    story.append(Paragraph(ai_analysis_text, body_style))
    story.append(Spacer(1, 10))

    story.append(
        Paragraph(
            "Recommended Incident Response & Mitigation Steps", heading_style
        )
    )
    mitigations_raw = str(
        results.get("ai_analysis", {}).get(
            "mitigations", "No immediate mitigation required."
        )
    )
    sanitized_mitigations = html.escape(mitigations_raw).replace("\n", "<br/>")
    story.append(Paragraph(sanitized_mitigations, body_style))
    story.append(Spacer(1, 10))

    story.append(
        Paragraph("Extracted Indicators of Compromise (IOC URLs)", heading_style)
    )
    urls = results.get("body_artifacts", {}).get("extracted_urls", [])
    if urls:
        url_data = [
            [Paragraph(f"• {html.escape(str(u))}", body_style)]
            for u in urls[:15]
        ]
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


if uploaded_file is not None:
    with st.spinner(
        "Analyzing email payloads and generating mitigation playbooks..."
    ):
        raw_bytes = uploaded_file.getvalue()
        engine = EmailIngestionEngine(raw_bytes, api_key=api_key)
        results = engine.parse_email()

    st.success("Target acquired. Forensic breakdown complete.")
    st.divider()

    st.markdown(
        "<h3 style='color: white;'>Threat Intelligence Overview</h3>",
        unsafe_allow_html=True,
    )

    ai_score = results.get("ai_analysis", {}).get("score", "N/A")
    ai_reason = results.get("ai_analysis", {}).get(
        "analysis", "No AI analysis performed."
    )
    ai_mitigations = results.get("ai_analysis", {}).get(
        "mitigations", "No mitigations available."
    )

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("🧠 AI Threat Score", ai_score)
    m2.metric("Sender IP", results["metadata"]["sender_ip"] or "Hidden")
    m3.metric(
        "SPF Check",
        "Pass" if results["authentication"]["spf_pass"] else "Fail/None",
    )
    m4.metric(
        "Extracted URLs",
        f"{len(results['body_artifacts']['extracted_urls'])} Detected",
    )

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
            mime="application/pdf",
        )

    tab1, tab2, tab3, tab4 = st.tabs([
        "🛡️ Defense & Mitigation",
        "🌐 Extracted URLs (IOCs)",
        "📦 Attachment Sandbox",
        "🗺️ Routing & Network",
    ])

    with tab1:
        st.subheader("⚡ Automated Incident Response Playbook")
        st.markdown(ai_mitigations)
        st.divider()
        st.subheader("Quick Defensive Actions")
        col_act1, col_act2 = st.columns(2)
        with col_act1:
            st.button(
                "🚫 Export Blocklist for Firewall (iptables / Suricata)"
            )
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
                if "Suspicious" in att["sandbox_status"]:
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
                m = folium.Map(
                    location=[lat, lon],
                    zoom_start=4,
                    tiles="https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}",
                    attr="Esri",
                )
                folium.Marker(
                    [lat, lon],
                    popup=f"ISP: {isp}",
                    tooltip=f"{city}, {country}",
                    icon=folium.Icon(color="red", icon="info-sign"),
                ).add_to(m)
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
