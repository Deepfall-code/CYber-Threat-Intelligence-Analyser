from flask import Flask, request, jsonify, render_template, send_file
from dotenv import load_dotenv
import os
import requests
from pymongo import MongoClient
from datetime import datetime
import ipaddress
import io
import csv
from bson.objectid import ObjectId

# Load environment variables
load_dotenv()

# API Keys
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY")
MONGODB_URI = os.getenv("MONGODB_URI")

# Flask App
app = Flask(__name__)

# In-memory storage (fallback if MongoDB not connected)
session_data = []

# MongoDB setup
try:
    client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=5000)
    client.admin.command('ping')
    db = client["threat_db"]
    collection = db["threat_records"]
    MONGODB_AVAILABLE = True
    print("✅ MongoDB connected successfully!")
except Exception as e:
    print(f"⚠️  MongoDB not available: {e}")
    print("📝 Application will run without database storage")
    MONGODB_AVAILABLE = False
    client = None
    db = None
    collection = None


def is_ip(value):
    """Return True if value is valid IP address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def query_virustotal(ioc):
    """Query VirusTotal domain or IP endpoint."""
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        if not is_ip(ioc):
            url = f"https://www.virustotal.com/api/v3/domains/{ioc}"
            resp = requests.get(url, headers=headers, timeout=15)
            if resp.status_code == 200:
                return resp.json().get("data", {}).get("attributes", {})
            else:
                print(f"VirusTotal domain API error: {resp.status_code} - {resp.text}")

        # IP or fallback search endpoint
        url = f"https://www.virustotal.com/api/v3/search?query={ioc}"
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            if "data" in data and data["data"]:
                return data["data"][0].get("attributes", {})
            else:
                print("VirusTotal search returned no data")
        else:
            print(f"VirusTotal search API error: {resp.status_code} - {resp.text}")
    except Exception as e:
        print(f"VirusTotal API error: {e}")
    return {}


def query_abuseipdb(ip):
    """Query AbuseIPDB only for IP addresses."""
    if not ABUSEIPDB_API_KEY or not is_ip(ip):
        return {}
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    try:
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 200:
            return resp.json().get("data", {})
        else:
            print(f"AbuseIPDB error: {resp.status_code} - {resp.text}")
    except Exception as e:
        print(f"AbuseIPDB API error: {e}")
    return {}


def query_otx(ioc):
    """Query AlienVault OTX API for IP/domain/url."""
    if not OTX_API_KEY:
        return {}
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    try:
        if is_ip(ioc):
            url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ioc}/general"
        elif "." in ioc:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{ioc}/general"
        else:
            url = f"https://otx.alienvault.com/api/v1/indicators/url/{ioc}/general"
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 200:
            return resp.json()
        else:
            print(f"OTX API error: {resp.status_code} - {resp.text}")
    except Exception as e:
        print(f"OTX API error: {e}")
    return {}


def format_virustotal_data(vt_data):
    """Format VirusTotal raw data."""
    if not vt_data:
        return {}
    return {
        "Malicious": vt_data.get("last_analysis_stats", {}).get("malicious", 0),
        "Suspicious": vt_data.get("last_analysis_stats", {}).get("suspicious", 0),
        "Harmless": vt_data.get("last_analysis_stats", {}).get("harmless", 0),
        "Undetected": vt_data.get("last_analysis_stats", {}).get("undetected", 0),
        "Reputation": vt_data.get("reputation", "N/A"),
        "Categories": vt_data.get("categories", {})
    }


def format_abuseipdb_data(abuse_data):
    """Format AbuseIPDB raw data."""
    if not abuse_data:
        return {}
    # Keys may come in camelCase or capitalized form
    return {
        "Abuse Confidence Score": abuse_data.get("abuseConfidenceScore", abuse_data.get("Abuse Confidence Score", 0)),
        "ISP": abuse_data.get("isp", "N/A"),
        "Domain": abuse_data.get("domain", "N/A"),
        "Usage Type": abuse_data.get("usageType", "N/A"),
        "Country Code": abuse_data.get("countryCode", "N/A"),
        "Total Reports": abuse_data.get("totalReports", 0),
        "Last Reported At": abuse_data.get("lastReportedAt", "N/A")
    }


def format_otx_data(otx_data):
    """Format OTX raw data."""
    if not otx_data:
        return {}
    pulses = otx_data.get("pulse_info", {}).get("pulses", [])
    return {
        "Pulse Count": len(pulses),
        "Malware Families": [p.get("name") for p in pulses],
        "References": otx_data.get("pulse_info", {}).get("references", []),
        "ASN": otx_data.get("asn", "N/A"),
        "Country": otx_data.get("country_name", "N/A")
    }


def classify_threat(vt_data, abuse_data):
    """
    Classify IOC threat level and calculate threat score.
    Returns tuple (level:str, description:str, threat_score:float).
    """
    vt_malicious = vt_data.get("Malicious", 0)
    vt_suspicious = vt_data.get("Suspicious", 0)
    abuse_score = abuse_data.get("Abuse Confidence Score", 0)

    threat_score = (vt_malicious * 10) + (vt_suspicious * 5) + abuse_score

    if threat_score >= 0 and threat_score <= 20:
        level = "Low"
        description = (
            "This score range indicates minimal impact threats. These are typically low-risk phishing attempts or vulnerabilities classified as non-exploitable bugs. "
            "While they warrant monitoring, they usually do not represent immediate danger to systems or users."
        )
    elif threat_score >= 21 and threat_score <= 50:
        level = "Medium"
        description = (
            "This range suggests a moderate level of risk. Threats here often include known malware variants for which patches or mitigations are available. "
            "They require timely attention to prevent potential compromise but are generally manageable with standard security practices."
        )
    elif threat_score >= 51 and threat_score <= 80:
        level = "High"
        description = (
            "High threat scores signify serious security risks. Examples include zero-day exploits that are yet to be patched and widespread ransomware campaigns causing significant damage. "
            "Prompt action is critical to mitigate these threats and protect infrastructure."
        )
    elif threat_score >= 81 and threat_score <= 100:
        level = "Critical"
        description = (
            "Critical level threats represent catastrophic risks to security. These often involve sophisticated attacks such as those perpetrated by nation-state actors or targeted assaults on critical infrastructure. "
            "Immediate and comprehensive response efforts are essential to contain and neutralize these threats."
        )
    else:
        level = "Critical"
        description = (
            "Critical level threats represent catastrophic risks to security. These often involve sophisticated attacks such as those perpetrated by nation-state actors or targeted assaults on critical infrastructure. "
            "Immediate and comprehensive response efforts are essential to contain and neutralize these threats."
        )
    return level, description, threat_score


@app.route("/api/threat_lookup")
def threat_lookup():
    query = request.args.get("query", "").strip()
    if not query:
        return jsonify({"error": "Query is required"}), 400

    vt_data_raw = query_virustotal(query)
    abuse_data_raw = query_abuseipdb(query) if is_ip(query) else {}
    otx_data_raw = query_otx(query)

    vt_data = format_virustotal_data(vt_data_raw)
    abuse_data = format_abuseipdb_data(abuse_data_raw)
    otx_data = format_otx_data(otx_data_raw)

    level, description, score = classify_threat(vt_data, abuse_data)

    category_counts = {
        "malware": vt_data.get("Malicious", 0),
        "phishing": 0,
        "botnet": 0,
        "exploit": 0,
        "others": 0
    }

    record = {
        "ioc": query,
        "vt_data": vt_data,
        "abuse_data": abuse_data,
        "otx_data": otx_data,
        "level": level,
        "description": description,
        "threat_score": score,
        "category_counts": category_counts,
        "tag": "",
        "timestamp": datetime.utcnow()
    }

    ioc_id = None
    if MONGODB_AVAILABLE and collection is not None:
        try:
            inserted = collection.insert_one(record)
            ioc_id = str(inserted.inserted_id)
        except Exception as e:
            print(f"Database insert error: {e}")
            ioc_id = "temp_" + str(hash(query))
    else:
        ioc_id = "temp_" + str(hash(query))
        session_record = record.copy()
        session_record["ioc_id"] = ioc_id
        session_data.append(session_record)
        if len(session_data) > 10:
            session_data.pop(0)

    return jsonify({
        "ioc_id": ioc_id,
        "ioc": query,
        "level": level,
        "description": description,
        "threat_score": score,
        "category_counts": category_counts,
        "vt_data": vt_data,
        "abuse_data": abuse_data,
        "otx_data": otx_data
    })


@app.route("/api/tag_ioc", methods=["POST"])
def tag_ioc():
    data = request.get_json()
    ioc_id = data.get("ioc_id")
    tag = data.get("tag")
    if not ioc_id or not tag:
        return jsonify({"error": "ioc_id and tag are required"}), 400

    if not MONGODB_AVAILABLE or collection is None:
        return jsonify({"message": "Tag applied successfully (MongoDB not available - tag not persisted)"})

    try:
        collection.update_one({"_id": ObjectId(ioc_id)}, {"$set": {"tag": tag}})
        return jsonify({"message": "Tag applied successfully."})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/export")
def export_data():
    ioc_id = request.args.get("ioc_id")
    fmt = request.args.get("format", "json").lower()
    if not ioc_id:
        return jsonify({"error": "ioc_id required"}), 400

    if not MONGODB_AVAILABLE or collection is None:
        return jsonify({"error": "Export not available - MongoDB not connected"}), 500

    try:
        record = collection.find_one({"_id": ObjectId(ioc_id)})
        if not record:
            return jsonify({"error": "IOC not found"}), 404

        record["_id"] = str(record["_id"])

        if fmt == "json":
            return jsonify(record)

        elif fmt == "csv":
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(record.keys())
            writer.writerow([str(v) for v in record.values()])
            output.seek(0)
            return send_file(
                io.BytesIO(output.getvalue().encode()), mimetype="text/csv",
                as_attachment=True, download_name="threat_report.csv"
            )

        else:
            return jsonify({"error": "Unsupported format"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/threat-data")
def chart_data():
    if not MONGODB_AVAILABLE or collection is None:
        if session_data:
            ips = [item["ioc"] for item in session_data[-10:]]
            scores = [item["threat_score"] for item in session_data[-10:]]
            levels = [item.get("level", "N/A") for item in session_data[-10:]]
            descriptions = [item.get("description", "") for item in session_data[-10:]]
            return jsonify({"ips": ips, "scores": scores, "levels": levels, "descriptions": descriptions, "categories": levels})
        else:
            return jsonify({
                "ips": ["No analysis yet", "Try analyzing", "an IP or domain"],
                "scores": [0, 0, 0],
                "levels": ["N/A", "N/A", "N/A"],
                "descriptions": ["", "", ""]
            })

    try:
        latest = collection.find().sort("timestamp", -1).limit(10)
        ips = []
        scores = []
        levels = []
        descriptions = []
        for doc in latest:
            ips.append(doc["ioc"])
            scores.append(doc["threat_score"])
            levels.append(doc.get("level", "N/A"))
            descriptions.append(doc.get("description", ""))
        if not ips:
            ips = ["No data available"]
            scores = [0]
            levels = ["N/A"]
            descriptions = [""]

        return jsonify({"ips": ips, "scores": scores, "levels": levels, "descriptions": descriptions, "categories": levels})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/")
def dashboard():
    return render_template("dashboard.html")


if __name__ == "__main__":
    # Debug True for dev; change to False in production
    app.run(debug=True, port=5002)
