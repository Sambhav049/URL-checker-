# 🔍 URL Safety Checker

**An offline, heuristic-based command-line tool that tells you whether a URL is safe, suspicious, or dangerous — before you click it.**

No API keys. No internet connection. No dependencies. Just Python.

<p align="center">
  <img src="https://img.shields.io/badge/python-3.7%2B-blue?style=flat-square&logo=python&logoColor=white" alt="Python 3.7+" />
  <img src="https://img.shields.io/badge/dependencies-none-brightgreen?style=flat-square" alt="No dependencies" />
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey?style=flat-square" alt="Cross platform" />
  <img src="https://img.shields.io/badge/license-MIT-yellow?style=flat-square" alt="MIT License" />
</p>

---

## ✨ What it does

Paste in any URL and the tool runs it through a series of red-flag checks commonly used in real phishing/scam detection — then gives you a clear verdict with a breakdown of exactly *why*.

```
=======================================================
           URL SAFETY CHECKER (offline heuristics)
=======================================================

URL analyzed : http://paypal-secure-login.verify-account.tk/update
Risk score   : 14
Verdict      : DANGEROUS

Red flags detected:
  [-2] Uses HTTP instead of HTTPS (no encryption)
  [-2] Multiple hyphens in domain name (often used to mimic real brands)
  [-3] Uses a top-level domain often abused for spam/phishing (.tk)
  [-4] Mentions brand 'paypal' but domain doesn't match its official site
  [-3] Contains urgency/phishing-style keywords: verify

-------------------------------------------------------
Note: This is a heuristic offline check, not a guarantee.
When in doubt, don't click, and verify through official channels.
-------------------------------------------------------
```

---

## 🚩 What it checks for

| # | Check | Why it matters |
|---|-------|-----------------|
| 1 | HTTP vs HTTPS | Unencrypted connections are a red flag for sensitive sites |
| 2 | Raw IP address instead of domain | Legit sites almost never link via IP |
| 3 | `@` symbol in URL | Classic trick — browsers ignore everything before it |
| 4 | Excessive URL length | Long, messy URLs often hide malicious redirects |
| 5 | Excessive subdomains | `login.security.paypal.verify.example.com` is a warning sign |
| 6 | Multiple hyphens in domain | Common in typosquatting (`paypal-secure-login.com`) |
| 7 | Suspicious top-level domains | `.tk`, `.zip`, `.xyz`, `.click`, etc. are heavily abused |
| 8 | Known URL shorteners | Hides the real destination |
| 9 | Brand name mismatch | Mentions "paypal" but isn't actually paypal.com |
| 10 | Urgency/phishing keywords | "verify", "suspend", "act-now", etc. |
| 11 | Punycode / homograph domains | Masks lookalike domains using special characters |
| 12 | Excessive URL parameters | Can indicate tracking or redirect abuse |
| 13 | Unparsable hostname | Malformed or obfuscated input |

Each check adds weighted points to a **risk score**, which maps to a final verdict:

| Score | Verdict |
|-------|---------|
| 0 | ✅ SAFE |
| 1–4 | 🟢 LOW RISK |
| 5–8 | 🟡 SUSPICIOUS |
| 9+ | 🔴 DANGEROUS |

---

## 🚀 Getting started

### Requirements
- Python 3.7 or later (no external packages required)

### Installation
```bash
git clone https://github.com/your-username/url-safety-checker.git
cd url-safety-checker
```

### Usage

**Interactive mode** — check as many URLs as you want in one session:
```bash
python url_checker.py
```
```
Enter a URL to check (or 'exit' to quit).

URL> https://www.google.com
```

**One-shot mode** — pass a URL directly as an argument:
```bash
python url_checker.py https://suspicious-link.tk/login
```

---

## 🧠 How it works

The tool has **no internet dependency** — it doesn't call any external API or database. Instead, it parses the URL's structure (scheme, hostname, path, query string) and scores it against a set of pattern-based rules drawn from common phishing and scam techniques. This makes it:

- ⚡ Instant — no network latency
- 🔒 Private — nothing is ever sent anywhere
- 🪶 Lightweight — a single `.py` file, zero dependencies

> **Disclaimer:** This is a heuristic tool, not a substitute for a full threat-intelligence service. A low score doesn't guarantee a URL is safe, and a high score doesn't guarantee malicious intent. Always use good judgment.

---

## 🛠️ Roadmap

- [ ] Web-based version with visual red-flag breakdown
- [ ] Integration with live threat-intel APIs (VirusTotal / Google Safe Browsing)
- [ ] Batch scanning from a file of URLs
- [ ] Export results to CSV/JSON

---

## 🤝 Contributing

Contributions, issue reports, and feature suggestions are welcome! Feel free to open a PR or an issue.

## 📄 License

Licensed under the [MIT License](LICENSE).

---

<p align="center">Made to help people think twice before they click. 🛡️</p>
