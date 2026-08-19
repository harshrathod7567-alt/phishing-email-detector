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
    # look for lookalike tricks: digits replacing letters (e.g. paypa1 instead of paypal)
    has_digit_swap = bool(re.search(r'[a-z]+\d[a-z]*\.(com|net|org)', sender.lower()))
    has_suspicious_tld = any(tld in sender.lower() for tld in SUSPICIOUS_TLDS)
    return has_digit_swap or has_suspicious_tld

def calculate_risk_score(urgency_hits, links, suspicious_sender):
    score = 0
    score += len(urgency_hits) * 10  # each urgency phrase adds risk
    score += len(links) * 5          # each link adds a bit of risk
    if suspicious_sender:
        score += 40                  # spoofed-looking domain is a big red flag
    
    score = min(score, 100)  # cap at 100
    
    if score >= 60:
        verdict = "LIKELY PHISHING"
    elif score >= 30:
        verdict = "SUSPICIOUS - Review manually"
    else:
        verdict = "LOOKS SAFE"
    
    return score, verdict

email_content = read_email('sample_phishing.eml')

sender = extract_sender(email_content)
urgency_hits = find_urgency_language(email_content)
links = find_links(email_content)
suspicious_sender = check_suspicious_domain(sender)

score, verdict = calculate_risk_score(urgency_hits, links, suspicious_sender)

print(f"Sender: {sender}")
print(f"Suspicious sender domain: {suspicious_sender}")
print(f"Urgency phrases found: {len(urgency_hits)}")
print(f"Links found: {len(links)}")
print(f"\nRisk Score: {score}/100")
print(f"Verdict: {verdict}")
