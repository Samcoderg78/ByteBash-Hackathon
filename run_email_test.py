from phishing_detector import PhishingDetector

# Change this to your sample file name
FILENAME = "sample_email.txt"

with open(FILENAME, encoding='utf-8') as f:
    email_text = f.read().strip()

# Remove triple quotes if present
if email_text.startswith("'''") and email_text.endswith("'''"):
    email_text = email_text[3:-3].strip()
elif email_text.startswith('"""') and email_text.endswith('"""'):
    email_text = email_text[3:-3].strip()

lines = email_text.split('\n')
subject = ''
body_lines = []
for i, line in enumerate(lines):
    if line.lower().startswith('subject:'):
        subject = line[len('subject:'):].strip()
        body_lines = lines[i+1:]
        break
else:
    subject = lines[0].strip()
    body_lines = lines[1:]
body = '\n'.join([l.strip() for l in body_lines if l.strip()])

detector = PhishingDetector()
detector.predict({'subject': subject, 'body': body})