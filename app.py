import streamlit as st
import pandas as pd
from phishing_detector import PhishingDetector

st.set_page_config(page_title="Phishing Email Detector", layout="centered")

st.title("Phishing Email Detector")
st.write("Enter the subject and body of an email to check if it's phishing or legitimate.")

subject = st.text_input("Email Subject")
body = st.text_area("Email Body", height=200)

if st.button("Check Email"):
    if subject.strip() == "" or body.strip() == "":
        st.warning("Please enter both subject and body.")
    else:
        detector = PhishingDetector()
        result, confidence, probabilities = detector.predict({'subject': subject, 'body': body})
        st.markdown(f"### Result: {'⚠️ Phishing' if result == 'PHISHING' else '✅ Legitimate'}")
        st.markdown(f"**Confidence:** {confidence*100:.1f}%")
        st.markdown(f"**Probabilities:** Legitimate: {probabilities['Legit']}, Phishing: {probabilities['Phishing']}")