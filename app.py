import streamlit as st
import folium
from streamlit_folium import st_folium
from parser_engine import parse_eml, extract_ip_hops, geolocate_ip, verify_email_auth
from threat_engine import analyze_email_intent, extract_and_analyze_urls, compute_threat_score

st.set_page_config(page_title="Forensic Email Threat Intelligence", layout="wide")

st.title("🛡️ AI-Powered Email Threat Detection & Forensic Intelligence")
st.markdown("Automated forensic investigation pipeline: Header verification, IP hop geolocation mapping, and NLP threat detection.")

uploaded_file = st.file_uploader("Upload an email file (.eml)", type=["eml"])

if uploaded_file:
    file_bytes = uploaded_file.read()
    headers, body, raw_msg = parse_eml(file_bytes)
    
    sender = headers.get('From', 'Unknown')
    return_path = headers.get('Return-Path', 'Unknown')
    subject = headers.get('Subject', 'No Subject')
    date = headers.get('Date', 'Unknown')
    
    # Check domain mismatch
    domain_mismatch = False
    if "@" in sender and "@" in return_path:
        sender_domain = sender.split("@")[-1].replace(">", "").strip()
        return_domain = return_path.split("@")[-1].replace(">", "").strip()
        domain_mismatch = sender_domain.lower() != return_domain.lower()

    # Run engines
    auth_data = verify_email_auth(headers)
    intents = analyze_email_intent(body, subject)
    urls = extract_and_analyze_urls(body)
    score, risk_level, flags = compute_threat_score(auth_data, intents, urls, domain_mismatch)
    
    # Metric Summary Row
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Risk Level", risk_level)
    c2.metric("Threat Score", f"{score}/100")
    c3.metric("SPF Status", auth_data["SPF"])
    c4.metric("DKIM Status", auth_data["DKIM"])
    
    st.divider()
    
    # Main Tabs
    tab1, tab2, tab3, tab4 = st.tabs(["🌍 GeoLocation Journey", "🔍 Forensic Breakdown", "🔗 URL & Intent Analysis", "📄 Raw Headers"])
    
    with tab1:
        st.subheader("Hop-by-Hop Email Relay Route")
        hops = extract_ip_hops(headers)
        
        geo_points = []
        for ip in hops:
            geo = geolocate_ip(ip)
            if geo:
                geo_points.append(geo)
                
        if geo_points:
            m = folium.Map(location=[geo_points[0]['lat'], geo_points[0]['lon']], zoom_start=3)
            coords = []
            
            for idx, pt in enumerate(geo_points):
                coords.append([pt['lat'], pt['lon']])
                folium.Marker(
                    [pt['lat'], pt['lon']],
                    popup=f"Hop {idx+1}: {pt['query']} ({pt['city']}, {pt['country']}) - ISP: {pt['isp']}",
                    tooltip=f"Hop {idx+1}: {pt['country']}",
                    icon=folium.Icon(color="red" if idx == 0 else "blue", icon="info-sign")
                ).add_to(m)
                
            if len(coords) > 1:
                folium.PolyLine(coords, color="red", weight=2.5, opacity=0.8).add_to(m)
                
            st_folium(m, width=1100, height=450)
            
            # Hop detail table
            st.table([{
                "Hop": i + 1,
                "IP": g["query"],
                "Location": f"{g['city']}, {g['country']}",
                "ISP / Org": g["isp"]
            } for i, g in enumerate(geo_points)])
        else:
            st.info("No public relay IP hops found in the Received headers.")

    with tab2:
        st.subheader("Forensic Flags & Indicators")
        if flags:
            for flag in flags:
                st.warning(f"⚠️ {flag}")
        else:
            st.success("No anomalous forensic indicators detected.")
            
        st.markdown(f"**From:** `{sender}`")
        st.markdown(f"**Return-Path:** `{return_path}`")
        st.markdown(f"**Subject:** {subject}")
        st.markdown(f"**Date:** {date}")

    with tab3:
        st.subheader("Intent Triggers Detected")
        st.write(intents if intents else "No social engineering keywords triggered.")
        
        st.subheader("Extracted URLs")
        if urls:
            st.json(urls)
        else:
            st.write("No URLs found in the email body.")

    with tab4:
        st.text_area("Full Header Dump", str(headers), height=300)
