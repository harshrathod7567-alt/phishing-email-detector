import re

URGENCY_PHRASES = [
    "urgent", "immediately", "act now", "verify your identity",
    "account has been suspended", "permanently closed", "click the link",
    "failure to act", "within 24 hours", "confirm your account"
]

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
    # simple regex to find URLs in the email
    url_pattern = r'https?://[^\s]+'
    return re.findall(url_pattern, content)

def extract_sender(content):
    match = re.search(r'From:\s*(.+)', content)
    return match.group(1).strip() if match else "Unknown"

email_content = read_email('sample_phishing.eml')

sender = extract_sender(email_content)
urgency_hits = find_urgency_language(email_content)
links = find_links(email_content)

print(f"Sender: {sender}")
print(f"\nUrgency/pressure phrases found ({len(urgency_hits)}):")
for phrase in urgency_hits:
    print(f"  - {phrase}")

print(f"\nLinks found ({len(links)}):")
for link in links:
    print(f"  - {link}")
