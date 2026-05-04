from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
import requests
import tldextract
import whois
import re
import math
from datetime import datetime
from collections import Counter
import urllib.parse

app = FastAPI()
templates = Jinja2Templates(directory="templates")

# -------------------------
# Helper functions
# -------------------------
def calc_entropy(s):
    if not s:
        return 0
    freq = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())

def analyze_url(url):
    score = 0
    reasons = []

    if not url.startswith("http"):
        url = "http://" + url

    ext = tldextract.extract(url)
    domain = ext.domain

    headers = {"User-Agent": "Mozilla/5.0"}

    # HTTPS
    if not url.startswith("https"):
        score += 10
        reasons.append("No HTTPS encryption")

    # IP check
    if re.match(r"https?://\d+\.\d+\.\d+\.\d+", url):
        score += 25
        reasons.append("IP address used instead of domain")

    # Keywords
    if any(k in url.lower() for k in ["login", "verify", "bank", "secure"]):
        score += 10
        reasons.append("Suspicious keywords in URL")

    # Entropy
    if calc_entropy(domain) > 3.5:
        score += 10
        reasons.append("Random-looking domain")

    # WHOIS
    try:
        w = whois.whois(ext.registered_domain)
        if w.creation_date:
            creation = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
            age = (datetime.now() - creation).days
            if age < 30:
                score += 20
                reasons.append("Newly registered domain")
    except:
        pass

    # Request check
    try:
        r = requests.get(url, headers=headers, timeout=5)
        if r.status_code >= 400:
            score += 5
            reasons.append("Suspicious server response")
    except:
        score += 5
        reasons.append("Connection issue or blocked request")

    # Verdict
    if score >= 60:
        verdict = "Malicious"
    elif score >= 30:
        verdict = "Suspicious"
    else:
        verdict = "Safe"

    return {"url": url, "score": score, "verdict": verdict, "reasons": reasons}

# -------------------------
# Routes
# -------------------------

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/scan", response_class=HTMLResponse)
def scan(request: Request, url: str = Form(...)):
    result = analyze_url(url)
    return templates.TemplateResponse("index.html", {
        "request": request,
        "result": result
    })