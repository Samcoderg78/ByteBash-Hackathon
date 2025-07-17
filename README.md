# 🛡️ Phishing Email Detection System

**Detect phishing emails with AI** using advanced NLP, domain reputation checks, and an ensemble ML model. Now with **web interface (Streamlit)** and CLI support!

---

## ✨ Features
- **Web Interface**: Easy-to-use GUI via `app.py` (Streamlit)
- **CLI Support**: Run predictions from terminal with `run_email_test.py`
- **Advanced Detection**:
  - Domain reputation (VirusTotal + WHOIS)
  - BERT embeddings + TF-IDF features
  - Ensemble model (Random Forest, Logistic Regression, LightGBM)
- **Explainable Results**: Confidence scores + probabilities

---

## 🚀 Quick Start

### 🌐 **Web App (Recommended)**
1. Install dependencies:
   ```bash
   pip install streamlit pandas numpy scikit-learn lightgbm transformers torch

## 🚀 Quick Start

### 🌐 **Web App (Recommended)**
1. Install dependencies:
   ```bash
   pip install streamlit pandas numpy scikit-learn lightgbm transformers torch
   ```
2. Run the app:
   ```bash
   streamlit run app.py
   ```
3. Enter email subject/body and click **"Check Email"** for instant results

### 💻 **Command Line (CLI)**
1. Paste your email in `sample_email.txt` (format: subject followed by body)
2. Run:
   ```bash
   python run_email_test.py
   ```
3. See output (e.g., `⚠️ PHISHING (92% confidence)`)

### 🛠️ **Training the Model**
```bash
python phishing_detector.py train
```
*(Requires datasets: `CEAS_08.csv` and `kaggle_data.csv`)*

---

## 📂 Project Structure
```text
📁 phishing-email-detector/
phishing-email-detector/
├── app.py                      # Streamlit Frontend
├── example.txt                 # Contains Examples    
├── phishing_detector.py        # Core: train, predict, Streamlit UI
├── run_email_test.py           # CLI script: tests an email
├── sample_email.txt            # Place your email here for CLI
├── CEAS_08.csv                 # Dataset 1
├── kaggle_data.csv             # Dataset 2
├── phishing_model_voting.pkl   # Trained ensemble model
├── subject_vectorizer.pkl      # TF-IDF for subject
├── body_vectorizer.pkl         # TF-IDF for body
├── feature_scaler.pkl          # Scaler for engineered features
├── optimal_threshold.pkl       # Fitted decision threshold
├── reputation_cache.db         # SQLite domain reputation cache
```

---

## 🧪 Sample Outputs
### **Web App**
```
Result: ⚠️ Phishing (confidence: 89%)
Probabilities: Legitimate: 0.11, Phishing: 0.89
```

### **CLI**
```bash
Result: ⚠️ PHISHING (confidence: 92%)
Probabilities: {'Legit': 0.08, 'Phishing': 0.92}
```

---

## 📽️ Demo
🎥 **[Web App Demo Video](https://drive.google.com/file/d/1Yl8XefhcONBbOfblre3EWHqRP5-d46ob/view)**

---

## 🛠️ Dependencies
- Python >= 3.8
- Required packages:
  ```bash
  pip install streamlit pandas numpy scikit-learn lightgbm transformers torch joblib
  ```

## 📜 License
MIT License - Free for educational and commercial use

**Contributions welcome!** 🚀
