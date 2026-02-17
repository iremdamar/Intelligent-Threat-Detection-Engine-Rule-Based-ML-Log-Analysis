import re
import json
import csv
import time
import math
import ipaddress
import numpy as np
import requests
from datetime import datetime, timezone  # timezone'u direkt içeri alıyoruz 
from collections import defaultdict, deque
from colorama import Fore, init
from sklearn.ensemble import IsolationForest
import geoip2.database

init(autoreset=True)

# ==============================
# CONFIG
# ==============================

INPUT_FILE = "input.log"
JSON_OUTPUT_FILE = "alerts.json"
CSV_OUTPUT_FILE = "alerts.csv"

TIME_WINDOW = 60
ANOMALY_THRESHOLD = 5
HEC_ENABLED = False

HEC_URL = "https://your-splunk-server:8088/services/collector"
HEC_TOKEN = "YOUR_HEC_TOKEN"
GEOIP_DB_PATH = "GeoLite2-City.mmdb"

# ==============================
# GLOBAL STORAGE
# ==============================

alerts = []
stats = defaultdict(int)
ip_tracker = defaultdict(lambda: deque())
ml_features = []

try:
    geo_reader = geoip2.database.Reader(GEOIP_DB_PATH)
except:
    geo_reader = None


# ==============================
# UTIL FUNCTIONS
# ==============================

def extract_ip(line):
    match = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", line)
    return match.group() if match else None


def extract_domain(line):
    match = re.search(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", line)
    return match.group() if match else None


def extract_url(line):
    match = re.search(r"(\/[a-zA-Z0-9_\-\/\.]+)", line)
    return match.group() if match else None


def calculate_entropy(data):
    if not data:
        return 0
    prob = [float(data.count(c)) / len(data) for c in set(data)]
    return -sum([p * math.log2(p) for p in prob])


def geoip_lookup(ip):
    if not geo_reader:
        return {"country": "unknown", "city": "unknown"}
    try:
        response = geo_reader.city(ip)
        return {
            "country": response.country.name,
            "city": response.city.name
        }
    except:
        return {"country": "unknown", "city": "unknown"}


def detect_suspicious_keywords(line):
    keywords = [
        "SELECT", "UNION", "DROP", "INSERT",
        "../", "..\\", "cmd=", "/admin",
        "Failed password", "404", "500"
    ]
    for word in keywords:
        if word.lower() in line.lower():
            return True
    return False


def is_json(line):
    try:
        json.loads(line)
        return True
    except:
        return False


def send_to_hec(event):
    if not HEC_ENABLED:
        return
    headers = {"Authorization": f"Splunk {HEC_TOKEN}"}
    payload = {"event": event}
    requests.post(HEC_URL, headers=headers, json=payload, verify=False)


def run_ml():
    if not ml_features:
        return
    model = IsolationForest(contamination=0.05)
    X = np.array(ml_features)
    model.fit(X)
    scores = model.decision_function(X)
    preds = model.predict(X)

    for i in range(len(alerts)):
        alerts[i]["ml_score"] = float(scores[i])
        alerts[i]["ml_anomaly"] = True if preds[i] == -1 else False


def save_results():
    if alerts:
        # JSON Kayıt
        with open(JSON_OUTPUT_FILE, "w") as jf:
            json.dump(alerts, jf, indent=4)

        # CSV Kayıt - Dinamik Sütun Tespiti
        # Tüm alarmları gez ve var olan tüm farklı key'leri (sütun isimlerini) topla
        fieldnames = set()
        for alert in alerts:
            fieldnames.update(alert.keys())
        
        with open(CSV_OUTPUT_FILE, "w", newline="", encoding="utf-8") as cf:
            writer = csv.DictWriter(cf, fieldnames=sorted(list(fieldnames)))
            writer.writeheader()
            writer.writerows(alerts)
        print(f"{Fore.GREEN}[+] Kayit başarili: {CSV_OUTPUT_FILE}")

# ==============================
# MAIN ANALYSIS ENGINE
# ==============================

def analyze(file_path):
    print(f"{Fore.CYAN}[*] Universal Log Analyzer Started")
    print("=" * 70)

    try:
        with open(file_path, "r") as f:
            for line in f:
                line = line.strip()
                now = time.time()

                if not line:
                    continue

                event = {
                    "time": datetime.now(timezone.utc).isoformat(),
                    "raw": line,
                    "alert": False
                }

                # JSON handling
                if is_json(line):
                    parsed = json.loads(line)
                    event.update(parsed)

                ip = extract_ip(line)
                domain = extract_domain(line)
                url = extract_url(line)

                if ip:
                    ip_tracker[ip].append(now)
                    while ip_tracker[ip] and now - ip_tracker[ip][0] > TIME_WINDOW:
                        ip_tracker[ip].popleft()

                    rate = len(ip_tracker[ip])
                    event["source_ip"] = ip
                    event["rate_per_min"] = rate

                    geo = geoip_lookup(ip)
                    event.update(geo)

                    if rate >= ANOMALY_THRESHOLD:
                        event["rate_anomaly"] = True
                        event["alert"] = True

                if domain:
                    entropy = calculate_entropy(domain)
                    event["domain_entropy"] = entropy

                    if entropy > 4.0:
                        event["dns_entropy_flag"] = True
                        event["alert"] = True

                if url:
                    event["uri"] = url

                if detect_suspicious_keywords(line):
                    event["keyword_flag"] = True
                    event["alert"] = True

                # ✅ ML feature ve alert handling (DOĞRU YER)
                if event["alert"]:
                    ml_features.append([
                        event.get("rate_per_min", 0),
                        event.get("domain_entropy", 0)
                    ])

                    alerts.append(event)
                    stats["alerts"] += 1

                    print(f"{Fore.RED}[ALERT]")
                    print(json.dumps(event, indent=2))
                    print()

                    send_to_hec(event)

                else:
                    stats["normal"] += 1

    except FileNotFoundError:
        print(f"{Fore.RED}[!] File not found.")
        return

    run_ml()
    save_results()
    summary()


def summary():
    print("\n" + "=" * 70)
    print(f"{Fore.CYAN}Summary")
    print("=" * 70)
    print(f"{Fore.GREEN}Alerts: {stats['alerts']}")
    print(f"{Fore.GREEN}Normal: {stats['normal']}")
    print(f"{Fore.CYAN}JSON saved: {JSON_OUTPUT_FILE}")
    print(f"{Fore.CYAN}CSV saved: {CSV_OUTPUT_FILE}")
    print("=" * 70)


# ==============================
# ENTRY
# ==============================

if __name__ == "__main__":
    analyze(INPUT_FILE)
