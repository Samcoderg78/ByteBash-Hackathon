# 🛡️ Phishing Email Detection System

This project is a machine learning-based system designed to detect phishing emails using advanced text analysis, domain reputation checks, and an ensemble classification model. It’s accurate, explainable, and easy to use.

---

## 📽️ Demo Video

🎥 **[Watch the Demo Here](https://drive.google.com/file/d/1Yl8XefhcONBbOfblre3EWHqRP5-d46ob/view?usp=sharing)**

---

## 🚀 Quick Start

### ✉️ 1. Paste Your Email
- Open the file `sample_email.txt`
- Paste the content of the email you want to test.


### ▶️ 2. Run the Prediction

```bash
python run_email_test.py
```

This script will:
- Read the subject and body
- Process it through the model
- Print the result:
    ✅ LEGITIMATE or ⚠️ PHISHING
- Confidence percentage
- Class probabilities

## 🧰 Project Structure

```text
📁 phishing-email-detector/
├── phishing_detector.py        # Core engine (training + prediction)
├── run_email_test.py           # Run prediction using sample email
├── sample_email.txt            # Paste your email here for testing
├── CEAS_08.csv                 # Training dataset 1
├── kaggle_data.csv             # Training dataset 2
├── phishing_model_voting.pkl   # Trained voting model
├── subject_vectorizer.pkl      # TF-IDF vectorizer for subject
├── body_vectorizer.pkl         # TF-IDF vectorizer for body
├── feature_scaler.pkl          # Scaler for numerical features
├── optimal_threshold.pkl       # Optimal decision threshold
├── reputation_cache.db         # Domain reputation cache (SQLite)



## 🧪Sample Output
```bash
Result: ⚠️ PHISHING (confidence: 92%)
Probabilities: {'Legit': 0.08, 'Phishing': 0.92}
```

