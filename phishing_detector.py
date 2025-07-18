import warnings
warnings.filterwarnings('ignore')

import os
os.environ['LIGHTGBM_SILENT'] = 'true'

import pandas as pd
import numpy as np
import re
import joblib
from bs4 import BeautifulSoup
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, precision_recall_curve
from scipy.sparse import hstack
import argparse
from lightgbm import LGBMClassifier
from imblearn.over_sampling import SMOTE
from collections import Counter
from math import log2
import sqlite3
from datetime import datetime, timedelta
import requests
import logging
from transformers import BertTokenizer, BertModel
import torch

# ================== REPUTATION SYSTEM ==================
class DomainReputation:
    def __init__(self):
        self.cache_db = "reputation_cache.db"
        self._init_db()
        self.services = {
            'virus_total': {
                'api_key': '45cfde408fd1cff882ea6231d681bc2cb73a506c4ca82d5b6e37e7e865646117',
                'endpoint': 'https://www.virustotal.com/api/v3/domains/{domain}'
            },
            'whois': {
                'endpoint': 'https://whoisjson.com/api/v1/{domain}'
            }
        }

    def _init_db(self):
        with sqlite3.connect(self.cache_db) as conn:
            conn.execute('''CREATE TABLE IF NOT EXISTS reputation_cache
                         (domain TEXT PRIMARY KEY,
                          score REAL,
                          last_updated TIMESTAMP)''')

    def _check_cache(self, domain):
        with sqlite3.connect(self.cache_db) as conn:
            cursor = conn.cursor()
            cursor.execute('''SELECT score FROM reputation_cache 
                           WHERE domain = ? AND last_updated > ?''',
                         (domain, datetime.now() - timedelta(days=7)))
            return cursor.fetchone()

    def _update_cache(self, domain, score):
        with sqlite3.connect(self.cache_db) as conn:
            conn.execute('''INSERT OR REPLACE INTO reputation_cache 
                          VALUES (?, ?, ?)''',
                        (domain, score, datetime.now()))

    def _query_virustotal(self, domain):
        try:
            headers = {'x-apikey': self.services['virus_total']['api_key']}
            response = requests.get(
                self.services['virus_total']['endpoint'].format(domain=domain),
                headers=headers,
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes']['last_analysis_stats']
                malicious = stats.get('malicious', 0)
                total = sum(stats.values())
                return 1 - (malicious / max(total, 1))
        except Exception as e:
            logging.warning(f"VirusTotal query failed: {str(e)}")
        return 0.5

    def _query_whois(self, domain):
        try:
            response = requests.get(
                self.services['whois']['endpoint'].format(domain=domain),
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                created_date = data.get('created_date', '')[:10]
                if created_date:
                    age_days = (datetime.now() - datetime.strptime(created_date, '%Y-%m-%d')).days
                    age_score = min(age_days / 365, 1)
                    return age_score * 0.5
        except Exception as e:
            logging.warning(f"WHOIS query failed: {str(e)}")
        return 0.3

    def get_reputation(self, domain):
        if not domain:
            return 0.3
        cached = self._check_cache(domain)
        if cached:
            return cached[0]
        vt_score = self._query_virustotal(domain)
        whois_score = self._query_whois(domain)
        final_score = (vt_score * 0.7) + (whois_score * 0.3)
        self._update_cache(domain, final_score)
        return final_score

# ================== TEXT CLEANING ==================
def clean_text(text):
    text = str(text).lower()
    soup = BeautifulSoup(text, "html.parser")
    for a in soup.find_all('a', href=True):
        a.replace_with(f"{a.text} URL_PLACEHOLDER")
    text = soup.get_text()
    text = re.sub(r'&[a-z]+;', ' ', text)
    text = re.sub(r'\$\d+', '$NUM', text)
    text = re.sub(r'\b\d+\b', 'NUM', text)
    text = re.sub(r'http\S+', 'URL_PLACEHOLDER', text)
    text = re.sub(r'\S+@\S+', 'EMAIL_PLACEHOLDER', text)
    text = re.sub(r'[^a-z\s]', ' ', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text

# ================== DOMAIN ANALYSIS ==================
def analyze_domains(text):
    if not isinstance(text, str):
        return (0, 0)
    domains = re.findall(r'(?:https?://)?(?:www\.)?([a-zA-Z0-9-]+\.[a-zA-Z]{2,})', text)
    legitimate_domains = {'gmail.com', 'yahoo.com', 'microsoft.com', 'amazon.com', 'company.com', 'tech.org'}
    suspicious_keywords = {'verify', 'account', 'login', 'secure', 'update'}
    legit_count = sum(1 for domain in domains if domain.lower() in legitimate_domains)
    suspicious_count = sum(1 for domain in domains if any(k in domain.lower() for k in suspicious_keywords))
    return (legit_count, suspicious_count)

# ================== FEATURE ENGINEERING ==================
def url_entropy(url):
    if not url:
        return 0
    try:
        char_counts = Counter(url)
        entropy = -sum((count/len(url)) * log2(count/len(url)) for count in char_counts.values())
        return entropy
    except Exception:
        return 0

def generate_engineered_features(df, reputation_system=None):
    features = pd.DataFrame()
    features['body_char_count'] = df['body'].str.len()
    features['body_word_count'] = df['body'].str.split().str.len()
    features['subject_char_count'] = df['subject'].str.len()
    features['subject_word_count'] = df['subject'].str.split().str.len()
    features['suspicious_term_count'] = df['body'].str.count(r'click|verify|update|confirm|respond|download')
    features['has_signature_block'] = df['body'].str.contains(r'(?i)(regards|thank you|sincerely|department|team)', regex=True).astype(int)
    features['has_bullet_points'] = df['body'].str.contains(r'-\s+').astype(int)
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    urls = df['body'].str.findall(url_pattern)
    features['url_count'] = urls.str.len()
    features['has_urls'] = (features['url_count'] > 0).astype(int)
    features['max_url_entropy'] = urls.apply(lambda x: max([url_entropy(u) for u in x]) if x else 0)
    if reputation_system:
        if 'sender' in df.columns:
            df['sender_domain'] = df['sender'].str.extract(r'@([\w.-]+)')[0]
            features['sender_reputation'] = df['sender_domain'].apply(lambda x: reputation_system.get_reputation(x) if pd.notnull(x) else 0.2)
        else:
            features['sender_reputation'] = 0.5
        features['url_reputation'] = urls.apply(
            lambda x: np.mean([reputation_system.get_reputation(re.sub(r'^www\.', '', u.split('/')[0])) for u in x]) if x else 0.5
        )
    domain_features = df['body'].apply(analyze_domains)
    features['legitimate_domain_count'] = domain_features.apply(lambda x: x[0])
    features['suspicious_domain_count'] = domain_features.apply(lambda x: x[1])
    return features.fillna(0)

# ================== DATA LOADING ==================
def load_and_combine_datasets():
    print("Loading and combining datasets...")
    dfs = []
    datasets = [
        {'name': 'CEAS_08', 'path': 'CEAS_08.csv', 'required_cols': ['subject', 'body', 'label']},
        {'name': 'Kaggle Data', 'path': 'kaggle_data.csv', 'required_cols': ['subject', 'body', 'label']}
    ]
    for dataset in datasets:
        try:
            df = pd.read_csv(dataset['path'], encoding='utf-8', on_bad_lines='skip')
            missing_cols = [col for col in dataset['required_cols'] if col not in df.columns]
            if missing_cols:
                print(f"Warning: {dataset['name']} missing columns {missing_cols} - skipping")
                continue
            df = df[dataset['required_cols']].dropna(subset=['subject', 'body', 'label'])
            df['subject'] = df['subject'].fillna('')
            df['body'] = df['body'].fillna('')
            df['label'] = df['label'].astype(int)
            dfs.append(df)
            print(f"Loaded {dataset['name']}: {len(df)} samples")
        except Exception as e:
            print(f"Warning: Could not load {dataset['name']} dataset: {str(e)}")
    if not dfs:
        raise ValueError("No datasets could be loaded. Please check your data files.")
    combined_df = pd.concat(dfs, ignore_index=True)
    print("\nFinal combined dataset statistics:")
    print(f"Total samples: {len(combined_df)}")
    print(f"Legitimate emails (0): {len(combined_df[combined_df['label'] == 0])}")
    print(f"Phishing emails (1): {len(combined_df[combined_df['label'] == 1])}")
    if len(combined_df) < 20:
        print("\nWarning: Very small dataset - results may not be reliable")
    elif len(combined_df[combined_df['label'] == 0]) < 10 or len(combined_df[combined_df['label'] == 1]) < 10:
        print("\nWarning: Class imbalance detected - consider adding more samples")
    return combined_df

# ================== MODEL TRAINING ==================
def train_models(X_train_final, y_train):
    base_models = [
        ('rf', RandomForestClassifier(
            n_estimators=300, class_weight={0: 1, 1: 3}, max_depth=15,
            min_samples_split=3, random_state=42)),
        ('lr', LogisticRegression(
            class_weight='balanced', max_iter=2000, C=0.5,
            penalty='l2', solver='liblinear', random_state=42)),
        ('lgbm', LGBMClassifier(
            n_estimators=200, learning_rate=0.05, max_depth=10,
            random_state=42, verbose=-1))
    ]
    voting_clf = VotingClassifier(
        estimators=base_models, voting='soft', weights=[0.5, 0.2, 0.3])
    voting_clf.fit(X_train_final, y_train)
    y_scores = voting_clf.predict_proba(X_train_final)[:, 1]
    precision, recall, thresholds = precision_recall_curve(y_train, y_scores)
    f2_scores = (5 * precision * recall) / (4 * precision + recall)
    optimal_threshold = thresholds[np.argmax(f2_scores[:-1])]
    return {'model': voting_clf, 'threshold': optimal_threshold}

# ================== BERT EMBEDDING ==================
class BertEmbedder:
    def __init__(self, model_name='bert-base-uncased'):
        self.tokenizer = BertTokenizer.from_pretrained(model_name)
        self.model = BertModel.from_pretrained(model_name)
        self.model.eval()

    def get_embedding(self, text):
        with torch.no_grad():
            inputs = self.tokenizer(text, return_tensors='pt', truncation=True, max_length=128)
            outputs = self.model(**inputs)
            return outputs.last_hidden_state[:, 0, :].squeeze().numpy()

def generate_bert_features(df, bert_embedder):
    import time
    n = len(df)
    subject_embeddings = []
    body_embeddings = []
    print(f"Generating BERT features for {n} samples...")
    for i, row in df.iterrows():
        subject_embeddings.append(bert_embedder.get_embedding(str(row['subject'])))
        body_embeddings.append(bert_embedder.get_embedding(str(row['body'])))
        if (i+1) % 500 == 0 or (i+1) == n:
            print(f"Processed {i+1}/{n} samples")
    return np.vstack(subject_embeddings), np.vstack(body_embeddings)

# ================== MAIN TRAINING PIPELINE ==================
def train_pipeline():
    print("Training the model...")
    reputation_system = DomainReputation()
    bert_embedder = BertEmbedder()
    df = load_and_combine_datasets()
   # df = df.sample(n=5000, random_state=42)  # Use only 5000 samples for quick testing
    X_train_raw, X_test_raw, y_train, y_test = train_test_split(
        df[['subject', 'body']], df['label'], test_size=0.2, random_state=42)
    print("Vectorizing text data...")
    subject_vectorizer = TfidfVectorizer(max_features=1000)
    body_vectorizer = TfidfVectorizer(max_features=5000)
    X_train_subject = subject_vectorizer.fit_transform(X_train_raw['subject'].apply(clean_text))
    X_train_body = body_vectorizer.fit_transform(X_train_raw['body'].apply(clean_text))
    X_test_subject = subject_vectorizer.transform(X_test_raw['subject'].apply(clean_text))
    X_test_body = body_vectorizer.transform(X_test_raw['body'].apply(clean_text))
    print("Generating engineered features...")
    X_train_eng = generate_engineered_features(X_train_raw, reputation_system)
    X_test_eng = generate_engineered_features(X_test_raw, reputation_system)
    scaler = StandardScaler()
    X_train_eng_scaled = scaler.fit_transform(X_train_eng)
    X_test_eng_scaled = scaler.transform(X_test_eng)
    print("Generating BERT features...")
    X_train_bert_subject, X_train_bert_body = generate_bert_features(X_train_raw, bert_embedder)
    X_test_bert_subject, X_test_bert_body = generate_bert_features(X_test_raw, bert_embedder)
    X_train = hstack([X_train_subject, X_train_body, X_train_eng_scaled, X_train_bert_subject, X_train_bert_body])
    X_test = hstack([X_test_subject, X_test_body, X_test_eng_scaled, X_test_bert_subject, X_test_bert_body])
    print(f"Before balancing: Legit={sum(y_train==0)}, Phish={sum(y_train==1)}")
    if abs(sum(y_train==0) - sum(y_train==1)) > 0.1 * len(y_train):
        sm = SMOTE(random_state=42)
        X_train, y_train = sm.fit_resample(X_train, y_train)
        print(f"After SMOTE: Legit={sum(y_train==0)}, Phish={sum(y_train==1)}")
    print("Training ensemble models...")
    models = train_models(X_train, y_train)
    print("\nEvaluating model performance...")
    print("\nVoting Classifier Performance:")
    y_pred = models['model'].predict(X_test)
    print(classification_report(y_test, y_pred))
    print("\nSaving model artifacts...")
    joblib.dump(models['model'], 'phishing_model_voting.pkl')
    joblib.dump(models['threshold'], 'optimal_threshold.pkl')
    joblib.dump(subject_vectorizer, 'subject_vectorizer.pkl')
    joblib.dump(body_vectorizer, 'body_vectorizer.pkl')
    joblib.dump(scaler, 'feature_scaler.pkl')
    print("Training complete! Model and artifacts have been saved.")

# ================== CLI PREDICTION ==================
class PhishingDetector:
    def __init__(self, model_type='voting'):
        self.model_type = model_type
        self.model = joblib.load("phishing_model_voting.pkl")
        self.threshold = joblib.load("optimal_threshold.pkl")
        self.body_vectorizer = joblib.load("body_vectorizer.pkl")
        self.subject_vectorizer = joblib.load("subject_vectorizer.pkl")
        self.scaler = joblib.load("feature_scaler.pkl")
        self.reputation_system = DomainReputation()
        self.bert_embedder = BertEmbedder()
        self.phishing_patterns = {
            'package_delivery': [
                r'(?:package|parcel|delivery).*?(?:tracking|order|number)[\s#:]*[A-Z0-9-]+',
                r'(?:reschedule|confirm).*?delivery.*?within.*?\d+.*?hours',
                r'(?:click|verify).*?delivery.*?details'
            ],
            'invoice_payment': [
                r'(?:invoice|payment|bill).*?(?:number|id)[\s#:]*[A-Z0-9-]+',
                r'(?:due|overdue).*?payment.*?\$\d+',
                r'(?:click|verify).*?payment.*?details'
            ],
            'maintenance_security': [
                r'(?:maintenance|update|security).*?(?:required|needed)',
                r'(?:system|account).*?(?:update|verify).*?credentials',
                r'(?:click|verify).*?(?:update|maintenance)'
            ]
        }

    def predict(self, email_text):
        df = pd.DataFrame({'subject': [email_text['subject']], 'body': [email_text['body']]})
        manual_features = generate_engineered_features(df, self.reputation_system)
        subject_vec = self.subject_vectorizer.transform(df['subject'].apply(clean_text))
        body_vec = self.body_vectorizer.transform(df['body'].apply(clean_text))
        scaled_features = self.scaler.transform(manual_features)
        bert_subject, bert_body = generate_bert_features(df, self.bert_embedder)
        X = hstack([subject_vec, body_vec, scaled_features, bert_subject, bert_body])
        y_pred_proba = self.model.predict_proba(X)[0]
        y_pred = int(y_pred_proba[1] >= self.threshold)
        legitimate_count = manual_features['legitimate_domain_count'].iloc[0]
        suspicious_count = manual_features['suspicious_domain_count'].iloc[0]
        sender_reputation = manual_features['sender_reputation'].iloc[0]
        url_reputation = manual_features['url_reputation'].iloc[0]
        if sender_reputation > 0.85:
            y_pred = 0
            y_pred_proba = np.array([0.95, 0.05])
        if url_reputation < 0.3:
            y_pred_proba[1] = min(y_pred_proba[1] + 0.3, 1.0)
            y_pred = int(y_pred_proba[1] > 0.5)
        result = "PHISHING" if y_pred == 1 else "LEGITIMATE"
        confidence = max(y_pred_proba)
        probabilities = {"Legit": round(float(y_pred_proba[0]), 2), "Phishing": round(float(y_pred_proba[1]), 2)}
        status = "⚠️ PHISHING" if result == "PHISHING" else "✅ LEGITIMATE"
        print(f"\nResult: {status} (confidence: {confidence*100:.0f}%)")
        return result, confidence, probabilities

def main():
    parser = argparse.ArgumentParser(description="Phishing Email Detector")
    subparsers = parser.add_subparsers(dest='command', required=True)
    subparsers.add_parser('train', help='Train the phishing detection model')
    predict_parser = subparsers.add_parser('predict', help='Predict if an email is phishing')
    predict_parser.add_argument('--subject', type=str, required=True, help='Email subject')
    predict_parser.add_argument('--body', type=str, required=True, help='Email body')
    predict_parser.add_argument('--model', type=str, choices=['voting', 'stacked'], default='voting', help='Model type to use for prediction')
    args = parser.parse_args()
    if args.command == 'train':
        train_pipeline()
    elif args.command == 'predict':
        detector = PhishingDetector(model_type=args.model)
        email = {'subject': args.subject, 'body': args.body}
        detector.predict(email)

if __name__ == "__main__":
    main()
