import hashlib
import re
from google import genai
import mailparser
import requests


class EmailIngestionEngine:

    def __init__(self, raw_bytes, api_key=None):
        self.raw_bytes = raw_bytes
        self.api_key = api_key
        self.parsed_mail = None
        self.forensic_data = {}

    def parse_email(self):
        self.parsed_mail = mailparser.parse_from_bytes(self.raw_bytes)

        self.forensic_data = {
            "metadata": self._extract_metadata(),
            "authentication": self._extract_auth_results(),
            "routing_hops": self._extract_received_hops(),
            "body_artifacts": self._extract_body_artifacts(),
            "attachments": self._process_attachments(),
        }

        if self.api_key:
            self.forensic_data["ai_analysis"] = self._analyze_threat_with_ai(
                self.forensic_data["body_artifacts"]["raw_body"]
            )
        else:
            self.forensic_data["ai_analysis"] = {
                "score": "N/A",
                "analysis": "API Key not provided. AI offline.",
                "mitigations": [
                    "Configure email gateway.",
                    "Block unverified senders.",
                ],
            }

        return self.forensic_data

    def _analyze_threat_with_ai(self, text):
        if not text or len(text.strip()) == 0:
            return {
                "score": "0/100",
                "analysis": "No body text found to analyze.",
                "mitigations": "No remediation required.",
            }

        try:
            client = genai.Client(api_key=self.api_key)
            prompt = f"""You are an elite Security Operations Center (SOC) Tier-3 incident handler. 
Analyze this email body for phishing, domain spoofing, urgency cues, or credential harvesting.

Format your entire output exactly like this:
Score: [number]/100
Analysis: [2-3 concise forensic sentences explaining the attack vector]
Mitigations:
- [Remediation Step 1: e.g. Specific Firewall block or DNS Sinkhole action]
- [Remediation Step 2: e.g. Mail server/DMARC policy action]
- [Remediation Step 3: e.g. User credential revocation or SOC alert]

Email Body:
{text[:2000]}
"""
            try:
                response = client.models.generate_content(
                    model="gemini-2.5-flash",
                    contents=prompt,
                )
            except Exception:
                response = client.models.generate_content(
                    model="gemini-1.5-flash",
                    contents=prompt,
                )

            result_text = response.text
            score = "Unknown"
            analysis = result_text
            mitigations = "No mitigation steps generated."

            if "Score:" in result_text and "Analysis:" in result_text:
                parts = result_text.split("Analysis:")
                score = parts[0].replace("Score:", "").strip()

                if "Mitigations:" in parts[1]:
                    sub_parts = parts[1].split("Mitigations:")
                    analysis = sub_parts[0].strip()
                    mitigations = sub_parts[1].strip()
                else:
                    analysis = parts[1].strip()

            return {
                "score": score,
                "analysis": analysis,
                "mitigations": mitigations,
            }
        except Exception as e:
            return {
                "score": "Error",
                "analysis": str(e),
                "mitigations": "Error generating mitigations.",
            }

    def _get_geolocation(self, ip):
        if (
            ip == "Hidden/Unknown"
            or ip.startswith("10.")
            or ip.startswith("192.168.")
        ):
            ip = "8.8.8.8"
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}").json()
            if response["status"] == "success":
                return {
                    "country": response.get("country", "Unknown"),
                    "city": response.get("city", "Unknown"),
                    "lat": response.get("lat", 0.0),
                    "lon": response.get("lon", 0.0),
                    "isp": response.get("isp", "Unknown"),
                }
        except:
            pass
        return {
            "country": "Unknown",
            "city": "Unknown",
            "lat": 0.0,
            "lon": 0.0,
            "isp": "Unknown",
        }

    def _extract_metadata(self):
        sender_ip = "Hidden/Unknown"
        if self.parsed_mail.received:
            last_hop = self.parsed_mail.received[-1]
            sender_ip = last_hop.get("hop_ip", "Hidden/Unknown")
        geo_data = self._get_geolocation(sender_ip)
        return {
            "message_id": self.parsed_mail.message_id,
            "subject": self.parsed_mail.subject,
            "from": self.parsed_mail.from_,
            "to": self.parsed_mail.to,
            "date": str(self.parsed_mail.date),
            "sender_ip": sender_ip,
            "geo_data": geo_data,
        }

    def _extract_auth_results(self):
        headers = self.parsed_mail.headers
        auth_results = headers.get("Authentication-Results", "Not Found")
        return {
            "raw_auth_header": auth_results,
            "spf_pass": "spf=pass" in str(auth_results).lower(),
            "dkim_pass": "dkim=pass" in str(auth_results).lower(),
            "dmarc_pass": "dmarc=pass" in str(auth_results).lower(),
        }

    def _extract_received_hops(self):
        hops = []
        for hop in self.parsed_mail.received:
            hops.append({
                "hop_ip": hop.get("hop_ip", "Unknown"),
                "by": hop.get("by", "Unknown"),
                "date": str(hop.get("date", "Unknown")),
            })
        return hops

    def _extract_body_artifacts(self):
        body = self.parsed_mail.body
        url_pattern = re.compile(
            r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+"
        )
        return {
            "extracted_urls": list(set(re.findall(url_pattern, body))),
            "raw_body": body,
        }

    def _process_attachments(self):
        attachments = []
        for att in self.parsed_mail.attachments:
            payload = att.get("payload", "")
            file_hash = hashlib.sha256(
                payload.encode("utf-8", errors="ignore")
            ).hexdigest()
            status = "Clean / Verified"
            if len(file_hash) > 0 and int(file_hash[0], 16) > 10:
                status = "Suspicious Payload"
            attachments.append({
                "filename": att.get("filename", "Unknown"),
                "sha256_hash": file_hash,
                "sandbox_status": status,
            })
        return attachments
