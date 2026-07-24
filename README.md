# 🦖 [NET-ZiLLA]
/__\ ADVANCED THREAT INTELLIGENCE & DETECTION PLATFORM
(o.o) SEC_ONLINE :: V 1.0.0
/--\
⚡ NET-ZiLLA ⚡
Modular Cybersecurity & Threat Intelligence Engine
Powered by FJ™ Cybertronic Systems®
Python 3.14+
License: MIT
FastAPI
Rich CLI
</div>
🧭 Overview
Net-ZiLLA is a high-performance, modular Python cybersecurity framework engineered for
deep threat intelligence analysis, URL parsing, domain reconnaissance, and multi-vector threat
detection. Featuring a vintage MS-DOS CRT command-line interface, real-time progress ETAs,
and a robust FastAPI backend, Net-ZiLLA is built for security analysts, automated pipelines, and
SOC teams looking for lightweight yet powerful threat correlation.
📂 Project Architecture
Net-ZiLLA/
├── main.py # CLI and application entry point
├── pyproject.toml # Project metadata and dependencies (uv
compatible)
├── uv.lock # Dependency lockfile
├── netzilla/
│ ├── api/ # FastAPI backend server modules
│ ├── cli/ # Vintage MS-DOS Rich terminal interface
│ ├── core/ # Core analysis, correlation, and
enrichment engines
│ │ ├── analyzer.py
│ │ ├── content_analyzer.py
│ │ ├── correlation_analyzer.py
│ │ ├── data_enricher.py
│ │ ├── domain_analyzer.py
│ │ ├── pattern_engine.py
│ │ └── url_parser.py
│ ├── detectors/ # Modular threat detection suite
│ │ ├── base.py │ │ ├── brand_impersonation.py
│ │ ├── malware.py
│ │ ├── phishing.py
│ │ ├── sms_scam.py
│ │ └── url_shortener.py
│ ├── models/ # Pydantic & DNS data models
│ ├── network/ # DNS client & network request handlers
│ ├── reports/ # Report generation engine
│ ├── tests/ # Pytest suite
│ └── utils/ # Configuration & logging utilities
🛡️ Core Detection Modules
Net-ZiLLA utilizes a plug-and-play detection architecture across 5 primary threat vectors:
1. Phishing Detector (phishing.py): Identifies heuristic indicators, deceptive URL
structures, and known phishing patterns.
2. Malware Signatures (malware.py): Scans payloads and target endpoints against known
malicious binary and script signatures.
3. Brand Impersonation (brand_impersonation.py): Evaluates domain typosquatting,
homograph attacks, and unauthorized brand spoofing.
4. SMS Scam Vector (sms_scam.py): Analyzes text message bodies for smishing,
financial fraud, and credential harvesting lures.
5. URL Shortener Resolver (url_shortener.py): Unrolls shortened links (e.g., bit.ly, t.co) to
inspect the ultimate destination safely.
⚙️ Technology Stack
● Language: Python 3.14+
● Package Manager: uv for lightning-fast dependency resolution
● CLI Framework: rich for terminal UI, tables, panels, and live progress bars
● API Backend: FastAPI / Uvicorn for high-throughput microservice deployment
● Testing: pytest for unit and integration validation
🚀 Installation & Setup
Prerequisites
Ensure you have Python 3.14+ and uv installed on your system.
1. Clone the Repository
git clone
[https://github.com/your-username/Net-ZiLLA.git](https://github.com/yo
ur-username/Net-ZiLLA.git)
cd Net-ZiLLA 2. Install Dependencies using uv
uv sync
💻 Usage Guide
Launching the Vintage MS-DOS Command Center
Net-ZiLLA features an interactive CRT-style terminal control panel complete with live progress
metrics and risk evaluations:
python main.py
(Or if entry points are configured in pyproject.toml, run netzilla directly).
Running the FastAPI Backend
To spin up the Net-ZiLLA REST API server for external integrations:
uvicorn netzilla.api.server:app --reload --host 127.0.0.1 --port 8000
Navigate to http://127.0.0.1:8000/docs to access the interactive Swagger documentation.
🧪 Testing
Run the test suite using pytest:
pytest
🗺️ Roadmap
● [ ] Integration with external threat feeds (AbuseIPDB, VirusTotal, URLhaus)
● [ ] SQLite/Redis caching layer for rapid DNS & domain age checks
● [ ] Docker containerization (Dockerfile and docker-compose.yml)
● [ ] Webhook support for asynchronous batch queue scans
📜 License
Distributed under the MIT License. See LICENSE for more information.
<div align="center"> <p><b>FJ™ Cybertronic Systems®</b> © 2026. All Rights Reserved.</p>
</div>
