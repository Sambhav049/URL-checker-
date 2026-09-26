#!/usr/bin/env python3
"""
URL Safety Checker
-------------------
A command-line tool that analyzes a URL using a set of heuristics commonly
used in phishing/scam detection, and gives a verdict: SAFE, SUSPICIOUS, or
DANGEROUS — along with the specific red flags it found.

No internet connection or API key required. Just standard Python 3.

USAGE:
    python url_checker.py
    python url_checker.py https://example.com
"""

import re
import sys
from urllib.parse import urlparse

# ----------------------------- Config data ------------------------------ #

SUSPICIOUS_TLDS = {
    "zip", "review", "country", "kim", "cricket", "science", "work",
    "party", "gq", "link", "xyz", "tk", "ml", "ga", "cf", "top", "click",
    "loan", "win", "bid", "download", "men", "date", "stream", "racing"
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "shorte.st", "bc.vc", "rb.gy", "cutt.ly", "shorturl.at"
}

URGENCY_KEYWORDS = [
    "verify", "urgent", "suspend", "locked", "limited", "confirm",
    "update-account", "security-alert", "unusual-activity", "expire",
    "restricted", "click-here", "act-now", "immediately"
]

BRAND_KEYWORDS = [
    "paypal", "amazon", "apple", "microsoft", "netflix", "bankofamerica",
    "google", "facebook", "instagram", "whatsapp", "chase", "wellsfargo",
    "irs", "dhl", "fedex", "outlook", "office365"
]

IP_PATTERN = re.compile(
    r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$"
)


class Flag:
    def __init__(self, message, weight):
        self.message = message
        self.weight = weight  # points added to the risk score


def analyze_url(raw_url: str):
    flags = []
    score = 0

    url = raw_url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url_for_parse = "http://" + url
        flags.append(Flag("No scheme (http/https) specified — assumed 'http://' for analysis", 1))
        score += 1
    else:
        url_for_parse = url

    parsed = urlparse(url_for_parse)
    hostname = (parsed.hostname or "").lower()
    full_url_lower = url.lower()

    # 1. Protocol check
    if parsed.scheme == "http":
        flags.append(Flag("Uses HTTP instead of HTTPS (no encryption)", 2))
        score += 2

    # 2. IP address instead of domain name
    if hostname and IP_PATTERN.match(hostname):
        flags.append(Flag("Uses a raw IP address instead of a domain name", 4))
        score += 4

    # 3. '@' symbol in URL (classic redirect trick)
    if "@" in url:
        flags.append(Flag("Contains '@' symbol — browsers ignore everything before it, a classic redirect trick", 5))
        score += 5

    # 4. Excessive length
    if len(url) > 90:
        flags.append(Flag(f"Unusually long URL ({len(url)} characters)", 2))
        score += 2

    # 5. Excessive subdomains
    if hostname:
        subdomain_count = hostname.count(".")
        if subdomain_count >= 4:
            flags.append(Flag(f"Excessive number of subdomains ({subdomain_count})", 3))
            score += 3

    # 6. Hyphens in domain (often used to mimic brands, e.g. paypal-secure-login.com)
    if hostname and hostname.count("-") >= 2:
        flags.append(Flag("Multiple hyphens in domain name (often used to mimic real brands)", 2))
        score += 2

    # 7. Suspicious TLD
    tld = hostname.split(".")[-1] if hostname and "." in hostname else ""
    if tld in SUSPICIOUS_TLDS:
        flags.append(Flag(f"Uses a top-level domain often abused for spam/phishing (.{tld})", 3))
        score += 3

    # 8. Known URL shortener (hides real destination)
    if hostname in URL_SHORTENERS:
        flags.append(Flag("Uses a URL shortener — real destination is hidden", 3))
        score += 3

    # 9. Brand name present but NOT as the actual registered domain
    for brand in BRAND_KEYWORDS:
        if brand in full_url_lower and hostname and not hostname.endswith(f"{brand}.com"):
            flags.append(Flag(f"Mentions brand '{brand}' but domain doesn't match its official site", 4))
            score += 4
            break

    # 10. Urgency / phishing-style keywords in the URL itself
    found_urgency = [kw for kw in URGENCY_KEYWORDS if kw in full_url_lower]
    if found_urgency:
        flags.append(Flag(f"Contains urgency/phishing-style keywords: {', '.join(found_urgency)}", 3))
        score += 3

    # 11. Punycode / IDN homograph attack indicator
    if hostname.startswith("xn--") or "xn--" in hostname:
        flags.append(Flag("Uses Punycode encoding — can mask lookalike/homograph domains", 5))
        score += 5

    # 12. Too many query parameters (can indicate tracking/redirect abuse)
    if parsed.query and parsed.query.count("=") >= 6:
        flags.append(Flag("Unusually large number of URL parameters", 1))
        score += 1

    # 13. No hostname could be parsed at all
    if not hostname:
        flags.append(Flag("Could not parse a valid hostname from this input", 5))
        score += 5

    return score, flags, url_for_parse


def verdict_from_score(score: int):
    if score == 0:
        return "SAFE", "\033[92m"      # green
    elif score <= 4:
        return "LOW RISK", "\033[92m"  # green
    elif score <= 8:
        return "SUSPICIOUS", "\033[93m"  # yellow
    else:
        return "DANGEROUS", "\033[91m"   # red


RESET = "\033[0m"
BOLD = "\033[1m"


def print_banner():
    print(BOLD + "=" * 55)
    print("           URL SAFETY CHECKER (offline heuristics)")
    print("=" * 55 + RESET)


def check_and_report(raw_url: str):
    score, flags, normalized = analyze_url(raw_url)
    verdict, color = verdict_from_score(score)

    print(f"\nURL analyzed : {raw_url}")
    print(f"Risk score   : {score}")
    print(f"Verdict      : {color}{BOLD}{verdict}{RESET}\n")

    if flags:
        print("Red flags detected:")
        for f in flags:
            print(f"  [-{f.weight}] {f.message}")
    else:
        print("No red flags detected by heuristic checks.")

    print("\n" + "-" * 55)
    print("Note: This is a heuristic offline check, not a guarantee.")
    print("When in doubt, don't click, and verify through official channels.")
    print("-" * 55)


def main():
    print_banner()

    if len(sys.argv) > 1:
        url = " ".join(sys.argv[1:])
        check_and_report(url)
        return

    print("\nEnter a URL to check (or 'exit' to quit).")
    while True:
        try:
            url = input("\nURL> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break

        if not url:
            continue
        if url.lower() in ("exit", "quit", "q"):
            print("Exiting.")
            break

        check_and_report(url)


if __name__ == "__main__":
    main()
