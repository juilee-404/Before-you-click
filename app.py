from flask import Flask, render_template, request, jsonify
from urllib.parse import urlparse
import sqlite3
import re
import ipaddress
from datetime import datetime
from pathlib import Path

app = Flask(__name__)
DB_PATH = Path(__file__).with_name("scan_history.db")

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "cutt.ly", "rb.gy", "shorturl.at"
}

SUSPICIOUS_TLDS = {
    "zip", "mov", "click", "top", "xyz", "tk", "ml", "ga",
    "cf", "gq", "work", "country", "stream"
}

SUSPICIOUS_KEYWORDS = {
    "login", "signin", "verify", "verification", "secure", "security",
    "account", "password", "passwd", "otp", "wallet", "claim",
    "reward", "prize", "winner", "urgent", "update", "confirm",
    "bank", "payment", "refund", "free", "gift", "bonus"
}

BRANDS = {
    "paypal", "google", "microsoft", "apple", "amazon", "instagram",
    "facebook", "netflix", "whatsapp", "telegram", "flipkart",
    "sbi", "hdfc", "icici", "phonepe", "paytm"
}


def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                scanned_at TEXT NOT NULL
            )
        """)
        conn.commit()


def add_scan(url, score, level):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO scans (url, risk_score, risk_level, scanned_at) VALUES (?, ?, ?, ?)",
            (url, score, level, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        )
        conn.commit()


def get_history(limit=10):
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT url, risk_score, risk_level, scanned_at "
            "FROM scans ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(row) for row in rows]


def normalize_url(raw):
    raw = raw.strip()
    if not raw:
        return ""
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
        raw = "https://" + raw
    return raw


def is_ip_address(host):
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def analyze_url(raw_url):
    url = normalize_url(raw_url)
    findings = []
    score = 0

    if not url:
        return {"error": "Please enter a URL."}

    if len(url) > 120:
        score += 10
        findings.append({
            "type": "warning",
            "title": "Very long URL",
            "detail": "Long URLs can hide important parts of the destination."
        })

    try:
        parsed = urlparse(url)
    except ValueError:
        return {"error": "The URL could not be parsed."}

    if parsed.scheme.lower() not in {"http", "https"}:
        score += 20
        findings.append({
            "type": "danger",
            "title": "Unusual protocol",
            "detail": f"The link uses '{parsed.scheme}', not HTTP/HTTPS."
        })

    if parsed.scheme.lower() == "https":
        findings.append({
            "type": "good",
            "title": "HTTPS is present",
            "detail": "The connection is intended to use HTTPS. HTTPS alone does not prove a site is trustworthy."
        })
    else:
        score += 10
        findings.append({
            "type": "warning",
            "title": "HTTPS is not used",
            "detail": "The link does not use HTTPS."
        })

    host = (parsed.hostname or "").lower()

    if not host:
        score += 25
        findings.append({
            "type": "danger",
            "title": "Missing domain",
            "detail": "No normal domain name was found in the URL."
        })
    else:
        if is_ip_address(host):
            score += 25
            findings.append({
                "type": "danger",
                "title": "IP address used as destination",
                "detail": "The URL points directly to an IP address instead of a normal domain."
            })

        if "xn--" in host:
            score += 20
            findings.append({
                "type": "danger",
                "title": "Punycode domain detected",
                "detail": "Punycode can be legitimate, but it is also used in some look-alike domain attacks."
            })

        labels = host.split(".")
        if len(labels) >= 5:
            score += 10
            findings.append({
                "type": "warning",
                "title": "Many subdomains",
                "detail": "The destination contains an unusually large number of domain labels."
            })

        tld = labels[-1] if len(labels) > 1 else ""
        if tld in SUSPICIOUS_TLDS:
            score += 10
            findings.append({
                "type": "warning",
                "title": "Uncommon/suspicious TLD",
                "detail": f".{tld} appears in the project's heuristic watchlist."
            })

        if host in SHORTENERS or any(host.endswith("." + s) for s in SHORTENERS):
            score += 15
            findings.append({
                "type": "warning",
                "title": "URL shortener detected",
                "detail": "The final destination is hidden behind a URL-shortening service."
            })

        hyphens = host.count("-")
        if hyphens >= 3:
            score += 8
            findings.append({
                "type": "warning",
                "title": "Many hyphens in domain",
                "detail": "Multiple hyphens can occur in legitimate domains, but are worth checking carefully."
            })

        compact_host = re.sub(r"[^a-z0-9]", "", host)
        for brand in BRANDS:
            if brand in compact_host and brand not in host.replace("-", ""):
                score += 12
                findings.append({
                    "type": "danger",
                    "title": "Possible brand look-alike",
                    "detail": f"The domain contains text resembling '{brand}'. Check the exact domain carefully."
                })
                break

    if parsed.username:
        score += 15
        findings.append({
            "type": "danger",
            "title": "Username information in URL",
            "detail": "The URL contains a username before the domain, which can be used to make links look misleading."
        })

    if "@" in url:
        score += 15
        findings.append({
            "type": "danger",
            "title": "'@' symbol detected",
            "detail": "Everything before @ can be misleading; the actual host is after it."
        })

    path_and_query = f"{parsed.path} {parsed.query}".lower()
    keyword_hits = sorted({k for k in SUSPICIOUS_KEYWORDS if k in path_and_query})
    if keyword_hits:
        score += min(20, 5 * len(keyword_hits))
        findings.append({
            "type": "warning",
            "title": "Sensitive/action keywords found",
            "detail": "Detected: " + ", ".join(keyword_hits[:6])
        })

    if len(parsed.query) > 180:
        score += 8
        findings.append({
            "type": "warning",
            "title": "Large query string",
            "detail": "The URL contains a large amount of query data."
        })

    if re.search(r"%[0-9a-fA-F]{2}", url):
        findings.append({
            "type": "warning",
            "title": "Encoded characters present",
            "detail": "URL encoding is normal on the web, but encoded text can make a link harder to read."
        })

    score = min(score, 100)

    if score >= 70:
        level = "High Risk"
        color = "danger"
    elif score >= 40:
        level = "Caution"
        color = "warning"
    else:
        level = "Lower Risk"
        color = "good"

    if not findings:
        findings.append({
            "type": "good",
            "title": "No obvious heuristic red flags",
            "detail": "This tool did not find the patterns it is designed to detect."
        })

    return {
        "url": url,
        "host": host,
        "score": score,
        "level": level,
        "color": color,
        "findings": findings,
        "disclaimer": "This is a heuristic checker, not a guarantee that a website is safe or malicious."
    }


@app.route("/")
def index():
    return render_template("index.html")


@app.post("/api/analyze")
def api_analyze():
    data = request.get_json(silent=True) or {}
    raw_url = data.get("url", "")

    result = analyze_url(raw_url)
    if "error" in result:
        return jsonify(result), 400

    add_scan(result["url"], result["score"], result["level"])
    result["history"] = get_history()
    return jsonify(result)


@app.get("/api/history")
def api_history():
    return jsonify(get_history())


@app.post("/api/clear-history")
def api_clear_history():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM scans")
        conn.commit()
    return jsonify({"success": True})


init_db()

if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
