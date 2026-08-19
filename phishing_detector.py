def read_email(filename):
    with open(filename, 'r') as f:
        content = f.read()
    return content

email_content = read_email('sample_phishing.eml')
print(email_content)
