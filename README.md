# Phishing Email Detector

A beginner Python project that analyzes `.eml` email files for common phishing 
red flags — spoofed sender domains, urgency/pressure language, and suspicious links.

## What it does
- Extracts the sender address from an email file
- Detects lookalike/spoofed domains (e.g. "paypa1.com" instead of "paypal.com")
- Scans for urgency/pressure phrases commonly used in phishing
- Extracts and counts embedded links
- Calculates a risk score (0-100) and gives a verdict: Likely Phishing / Suspicious / Looks Safe
- Saves results to a report file

## Files
- `phishing_detector.py` — the main script
- `sample_phishing.eml` — example phishing email used for testing

## How to run it
1. Make sure your `.eml` file is in the same folder as the script
2. Update the `filename` variable if using a different file
3. Run: `python phishing_detector.py`
4. Check the terminal output and `phishing_report.txt` for results

## Example output
Risk Score: 90/100 — LIKELY PHISHING


## What I learned
- Common social engineering tactics used in phishing (urgency, fear, spoofed domains)
- Using regex to extract structured data (senders, URLs) from unstructured text
- Building a weighted scoring system to prioritize the strongest indicators

## Next steps
- Parse actual email headers (SPF/DKIM/DMARC results) for stronger spoofing detection
- Check links against a real threat intel API (tie into the IP reputation checker project)
- Support batch-analyzing multiple .eml files at once
