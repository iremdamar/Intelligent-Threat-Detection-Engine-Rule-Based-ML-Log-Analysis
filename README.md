# 🛡 Intelligent Threat Detection Engine  

Hybrid **Rule-Based + Machine Learning** powered log analysis engine designed to detect anomalous and suspicious activities across multiple log formats.

---

## 🚀 Features

- Universal log format support (raw / JSON logs)
- IP-based rate anomaly detection
- DNS entropy analysis (DGA detection)
- Suspicious keyword detection (SQL injection, brute-force, traversal attacks)
- GeoIP enrichment
- ML anomaly scoring using IsolationForest
- JSON & CSV export
- Optional Splunk HEC integration

---

## 🧠 Detection Architecture

The engine combines:

1. Deterministic rule-based detection  
2. Behavioral anomaly detection  
3. Machine learning anomaly scoring  

Alert generation is rule-driven.  
Machine learning is used to score anomaly severity.

---

## 📦 Installation

```bash
git clone https://github.com/YOUR_USERNAME/intelligent-threat-detection-engine.git
cd intelligent-threat-detection-engine
pip install -r requirements.txt

Usage
python analyzer.py
Outputs:
alerts.json
alerts.csv

📊 Detection Methods

Rate-based anomaly detection

Entropy-based DNS anomaly detection

Signature-based keyword detection

ML-based anomaly scoring (Isolation Forest)

🔒 Future Improvements

Risk scoring system

Severity classification

MITRE ATT&CK mapping

Real-time streaming mode

Dashboard integration
👩‍💻 Author

Developed as a practical threat detection engine combining traditional detection engineering with machine learning.

