import re

URGENCY_PHRASES = [
    "urgent", "immediately", "act now", "verify your identity",
    "account has been suspended", "permanently closed", "click the link",
    "failure to act", "within 24 hours", "confirm your account"
]

SUSPICIOUS_TLDS = [".xyz", ".top", ".click", ".info", ".biz"]

def read_email(filename):
    with open(filename, 'r') as f:
        content = f.read()
    return content

def find_urgency_language(content):
    found = []
    lower_content = content.lower()
    for phrase in URGENCY_PHRASES:
        if phrase in lower_content:
            found.append(phrase)
    return found

def find_links(content):
    url_pattern = r'https?://[^\s]+'
    return re.findall(url_pattern, content)

def extract_sender(content):
    match = re.search(r'From:\s*(.+)', content)
    return match.group(1).strip() if match else "Unknown"

def check_suspicious_domain(sender):
    has_digit_swap = bool(re.search(r'[a-z]+\d[a-z]*\.(com|net|org)', sender.lower()))
    has_suspicious_tld = any(tld in sender.lower() for tld in SUSPICIOUS_TLDS)
    return has_digit_swap or has_suspicious_tld

def calculate_risk_score(urgency_hits, links, suspicious_sender):
    score = 0
    score += len(urgency_hits) * 10
    score += len(links) * 5
    if suspicious_sender:
        score += 40
    
    score = min(score, 100)
    
    if score >= 60:
        verdict = "LIKELY PHISHING"
    elif score >= 30:
        verdict = "SUSPICIOUS - Review manually"
    else:
        verdict = "LOOKS SAFE"
    
    return score, verdict

def write_report(filename, sender, urgency_hits, links, suspicious_sender, score, verdict, output_file="phishing_report.txt"):
    with open(output_file, 'w') as f:
        f.write(f"=== Phishing Analysis Report: {filename} ===\n\n")
        f.write(f"Sender: {sender}\n")
        f.write(f"Suspicious sender domain: {suspicious_sender}\n\n")
        f.write(f"Urgency phrases found ({len(urgency_hits)}):\n")
        for phrase in urgency_hits:
            f.write(f"  - {phrase}\n")
        f.write(f"\nLinks found ({len(links)}):\n")
        for link in links:
            f.write(f"  - {link}\n")
        f.write(f"\nRisk Score: {score}/100\n")
        f.write(f"Verdict: {verdict}\n")
    print(f"Report saved to {output_file}")

filename = 'sample_phishing.eml'
email_content = read_email(filename)

sender = extract_sender(email_content)
urgency_hits = find_urgency_language(email_content)
links = find_links(email_content)
suspicious_sender = check_suspicious_domain(sender)

score, verdict = calculate_risk_score(urgency_hits, links, suspicious_sender)

print(f"Risk Score: {score}/100 — {verdict}")
write_report(filename, sender, urgency_hits, links, suspicious_sender, score, verdict)
