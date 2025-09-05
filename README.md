# 🛡️ Cyber Threat Intelligence (CTI) Analyzer

A **real-time Cyber Threat Intelligence Dashboard** that aggregates data from multiple threat feeds (AlienVault OTX, VirusTotal, AbuseIPDB) and visualizes Indicators of Compromise (IOCs) for security analysis.  
Built with **Flask, MongoDB, and Chart.js**, this project is designed to help SOC Analysts, researchers, and cybersecurity enthusiasts monitor and analyze threats effectively.

---

## 🚀 Features
- Collects **threat intelligence from APIs** (AlienVault OTX, VirusTotal, AbuseIPDB).
- Stores threat data securely in **MongoDB**.
- **Real-time visualization** of IOCs with interactive charts.
- IOC **classification and tagging** for better analysis.
- Supports **CVSS scoring** for threat prioritization.
- Export threat intelligence reports in **CSV/JSON** format.
- Simple **Flask-based web interface** for usability.

---

## 📂 Project Structure
CTI-Analyzer/
├── app.py # Main Flask application
├── requirements.txt # Python dependencies
├── README.md # Project documentation
├── .gitignore # Ignored files
├── static/ # CSS, JS, Images
└── templates/ # HTML templates   

Note- create your own .env file consisting of  API KEYS  virustotal.abuseIPdb,OTX and install mongodb in your system 
OTX_API_KEY=your_otx_key
VIRUSTOTAL_API_KEY=your_virustotal_key
ABUSEIPDB_API_KEY=your_abuseipdb_key

pip install -r requirements.txt
python app.py- run



## ⚡ Installation & Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/username/CTI-Analyzer.git
   cd CTI-Analyzer


   Future Enhancements

Integration with MISP or TheHive for automated threat sharing.

Add support for more threat feeds.

Advanced ML-based IOC risk scoring.




