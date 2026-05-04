# 🔐 PhishGuard — AI-Powered Phishing Detection Tool

PhishGuard is a web-based cybersecurity tool that analyzes URLs to detect potential phishing and malicious behavior using heuristic-based analysis and domain intelligence.

---


## 📌 Features

- 🔍 URL-based phishing detection
- 📊 Risk scoring system (0–100)
- ⚠️ Classification:
  - Safe
  - Suspicious
  - Malicious
- 🧠 Explainable results (why a URL is flagged)
- ⏳ Real-time scanning with loading indicator
- 🌐 Clean and simple web interface

---

## ⚙️ How It Works

PhishGuard analyzes URLs using multiple security checks:

1. **HTTPS Check**  
   Detects if the website uses secure encryption.

2. **Keyword Detection**  
   Flags suspicious terms like *login, verify, bank*.

3. **Domain Analysis**  
   Identifies random-looking or suspicious domains.

4. **WHOIS Lookup**  
   Checks domain age — newly registered domains are high risk.

5. **Server Behavior Check**  
   Sends a request to analyze response reliability.

---

## 📊 Risk Scoring

| Score Range | Verdict |
|------------|--------|
| 0–29       | ✅ Safe |
| 30–59      | ⚠️ Suspicious |
| 60–100     | ❌ Malicious |

---

## 🧱 Tech Stack

- **Backend:** FastAPI  
- **Frontend:** HTML, CSS (Jinja Templates)  
- **Libraries:**
  - requests  
  - tldextract  
  - python-whois  

---

## 🖥️ Project Structure
