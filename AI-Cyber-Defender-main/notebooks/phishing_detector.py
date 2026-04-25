"""
XGBoost Phishing URL Detector
Full pipeline: Feature Extraction → Training → Evaluation → Export
"""

import numpy as np
import pandas as pd
import re
import json
import pickle
import warnings
warnings.filterwarnings('ignore')

from urllib.parse import urlparse
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.metrics import (classification_report, confusion_matrix,
                             roc_auc_score, roc_curve, accuracy_score,
                             precision_score, recall_score, f1_score)
from sklearn.preprocessing import StandardScaler

# ─────────────────────────────────────────────
# 1. DATASET  (balanced synthetic + heuristic)
# ─────────────────────────────────────────────

LEGIT_URLS = [
    "https://www.google.com/search?q=python",
    "https://github.com/openai/gpt-4",
    "https://stackoverflow.com/questions/12345",
    "https://www.wikipedia.org/wiki/Machine_learning",
    "https://www.youtube.com/watch?v=abc123",
    "https://docs.python.org/3/library/os.html",
    "https://www.amazon.com/dp/B08N5WRWNW",
    "https://twitter.com/openai/status/123",
    "https://www.reddit.com/r/MachineLearning/",
    "https://en.wikipedia.org/wiki/XGBoost",
    "https://www.linkedin.com/in/username",
    "https://www.microsoft.com/en-us/windows",
    "https://www.apple.com/iphone-15/",
    "https://www.facebook.com/groups/ml",
    "https://www.bbc.com/news/technology",
    "https://www.nytimes.com/section/technology",
    "https://arxiv.org/abs/2303.08774",
    "https://huggingface.co/models",
    "https://www.cloudflare.com/learning/",
    "https://developer.mozilla.org/en-US/docs/Web",
    "https://www.coursera.org/learn/machine-learning",
    "https://www.udemy.com/course/python-bootcamp/",
    "https://medium.com/@user/article-title",
    "https://www.kaggle.com/competitions",
    "https://pytorch.org/docs/stable/index.html",
    "https://www.tensorflow.org/tutorials",
    "https://scikit-learn.org/stable/user_guide.html",
    "https://pandas.pydata.org/docs/",
    "https://numpy.org/doc/stable/",
    "https://matplotlib.org/stable/gallery/",
    "https://www.w3schools.com/python/",
    "https://realpython.com/python-basics/",
    "https://www.geeksforgeeks.org/python-programming-language/",
    "https://flask.palletsprojects.com/en/2.3.x/",
    "https://fastapi.tiangolo.com/tutorial/",
    "https://www.docker.com/get-started/",
    "https://kubernetes.io/docs/home/",
    "https://aws.amazon.com/ec2/",
    "https://cloud.google.com/compute",
    "https://azure.microsoft.com/en-us/services/",
    "https://www.shopify.com/blog/ecommerce",
    "https://stripe.com/docs/api",
    "https://www.twilio.com/docs/sms",
    "https://sendgrid.com/solutions/email-api/",
    "https://www.mongodb.com/docs/",
    "https://www.postgresql.org/docs/",
    "https://redis.io/docs/",
    "https://www.elastic.co/guide/",
    "https://grafana.com/docs/",
    "https://prometheus.io/docs/introduction/",
]

PHISHING_URLS = [
    "http://paypa1-secure-login.xyz/verify?user=admin",
    "https://amazon-security-alert.tk/account/suspend",
    "http://192.168.1.1/bank-login.html",
    "https://secure-paypal.suspicious-domain.ru/signin",
    "http://bit.ly/3xR9fake-login-verify",
    "https://apple-id-verify-now.info/update/credentials",
    "http://login.microsoft-support-team.xyz/verify",
    "https://www.bank0famerica.com/online/login",
    "http://update-your-netflix-billing-info.com/pay",
    "https://chase-bank-alert.gq/secure/login.php",
    "http://tinyurl.com/phish-link-here-click",
    "https://facebook-login-secure.ml/checkpoint",
    "http://google-account-recovery.tk/reset",
    "https://verify-your-steam-account-now.xyz/trade",
    "http://dropbox-share-files.phishing.com/download",
    "https://irs-tax-refund-claim.ga/refund/form",
    "http://fedex-package-held.co/track/12345",
    "https://covid-vaccine-appointment.ru/book",
    "http://free-iphone-winner-claim.xyz/prize",
    "https://customer-support-amazon.xyz/help/verify",
    "http://account-suspended-paypal.info/restore",
    "https://wellsfargo-secure-message.co/login",
    "http://citibank-alert-security.gq/update",
    "https://dhl-package-tracking.suspicious.tk/track",
    "http://login-account-google.xyz/signin",
    "https://apple-icloud-storage-full.info/upgrade",
    "http://netflix-payment-failed-update.com/billing",
    "https://instagram-verify-account.ml/confirm",
    "http://windows-defender-alert.gq/remove-virus",
    "https://bank-secure-login.0wned.ru/access",
    "http://1ogin.paypa1.com.evil.ru/auth",
    "https://secure-ebay-account.tk/verify-now",
    "http://whatsapp-account-banned.xyz/restore",
    "https://twitter-suspension-appeal.ga/verify",
    "http://linkedin-job-offer-apply.ml/apply",
    "https://zoom-meeting-invitation.phish.com/join",
    "http://office365-password-expired.tk/reset",
    "https://coinbase-verify-wallet.gq/login",
    "http://blockchain-secure-verify.xyz/wallet",
    "https://crypto-investment-returns.tk/profit",
    "http://elon-musk-bitcoin-giveaway.xyz/send",
    "https://random-subdomain.malicious.ru/evil.php",
    "http://secure.update.login.verify.domain.tk/page",
    "https://bank-update-required-now.ml/account",
    "http://phishing-example.com/fake-form?redirect=steal",
    "https://login-verify-account-secure.xyz/confirm",
    "http://download-free-software.ru/install.exe",
    "https://prize-winner-claim-now.gq/collect",
    "http://survey-reward-$500.tk/complete",
    "https://account-login-required-asap.ml/now",
]


# ─────────────────────────────────────────────
# 2. FEATURE EXTRACTION  (30 features)
# ─────────────────────────────────────────────

SUSPICIOUS_TLDS = {'.tk', '.ml', '.ga', '.gq', '.cf', '.xyz', '.ru',
                   '.info', '.biz', '.top', '.icu', '.pw', '.cc',
                   '.co', '.click', '.download', '.win', '.racing'}

SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'verify', 'secure', 'update', 'account',
    'password', 'bank', 'paypal', 'amazon', 'apple', 'microsoft',
    'google', 'facebook', 'netflix', 'confirm', 'suspend', 'alert',
    'urgent', 'validate', 'billing', 'payment', 'credential', 'recover',
    'support', 'helpdesk', 'free', 'winner', 'prize', 'claim', 'click',
    'bonus', 'reward', 'offer', 'gift', 'lucky', 'congratulation'
]

SHORTENERS = {'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
              'short.link', 'is.gd', 'buff.ly', 'adf.ly', 'bc.vc'}

def extract_features(url: str) -> dict:
    """Extract 30 hand-crafted features from a URL."""
    try:
        parsed = urlparse(url if url.startswith('http') else 'http://' + url)
    except Exception:
        parsed = urlparse('http://invalid')

    full      = url.lower()
    scheme    = parsed.scheme or ''
    netloc    = parsed.netloc.lower()
    path      = parsed.path.lower()
    query     = parsed.query.lower()
    domain    = netloc.split(':')[0]
    parts     = domain.split('.')
    tld       = '.' + parts[-1] if len(parts) > 1 else ''
    subdomain = '.'.join(parts[:-2]) if len(parts) > 2 else ''

    ip_pattern = re.compile(r'\b\d{1,3}(\.\d{1,3}){3}\b')

    f = {}

    # --- URL structure ---
    f['url_length']          = len(url)
    f['domain_length']       = len(domain)
    f['path_length']         = len(path)
    f['query_length']        = len(query)
    f['num_dots']            = url.count('.')
    f['num_hyphens']         = url.count('-')
    f['num_underscores']     = url.count('_')
    f['num_slashes']         = url.count('/')
    f['num_at_signs']        = url.count('@')
    f['num_question_marks']  = url.count('?')
    f['num_equals']          = url.count('=')
    f['num_digits']          = sum(c.isdigit() for c in url)
    f['digit_ratio']         = f['num_digits'] / max(len(url), 1)

    # --- Domain characteristics ---
    f['has_ip_address']      = int(bool(ip_pattern.search(netloc)))
    f['is_https']            = int(scheme == 'https')
    f['is_suspicious_tld']   = int(tld in SUSPICIOUS_TLDS)
    f['num_subdomains']      = len(subdomain.split('.')) if subdomain else 0
    f['is_url_shortener']    = int(domain in SHORTENERS)
    f['domain_has_digit']    = int(any(c.isdigit() for c in domain))
    f['domain_hyphen_count'] = domain.count('-')

    # --- Keyword presence ---
    keyword_count = sum(kw in full for kw in SUSPICIOUS_KEYWORDS)
    f['suspicious_keyword_count'] = keyword_count
    f['has_login_keyword']   = int('login' in full or 'signin' in full)
    f['has_verify_keyword']  = int('verify' in full or 'confirm' in full)
    f['has_bank_keyword']    = int('bank' in full or 'paypal' in full or 'billing' in full)
    f['has_free_keyword']    = int('free' in full or 'winner' in full or 'prize' in full)
    f['has_secure_keyword']  = int('secure' in full)

    # --- Entropy & obfuscation ---
    def entropy(s):
        if not s: return 0
        from collections import Counter
        counts = Counter(s)
        n = len(s)
        return -sum((c/n)*np.log2(c/n) for c in counts.values())

    f['domain_entropy']      = entropy(domain)
    f['path_entropy']        = entropy(path)
    f['has_double_slash']    = int('//' in path)
    f['has_hex_encoding']    = int('%' in url and any(url[i:i+3].startswith('%') for i in range(len(url)-2)))

    return f


def build_dataset(legit_urls, phishing_urls):
    rows, labels = [], []
    for url in legit_urls:
        rows.append(extract_features(url))
        labels.append(0)
    for url in phishing_urls:
        rows.append(extract_features(url))
        labels.append(1)
    X = pd.DataFrame(rows)
    y = np.array(labels)
    return X, y


# ─────────────────────────────────────────────
# 3. TRAIN & EVALUATE
# ─────────────────────────────────────────────

def train_model(X, y):
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y)

    model = XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        min_child_weight=2,
        gamma=0.1,
        reg_alpha=0.1,
        reg_lambda=1.0,
        use_label_encoder=False,
        eval_metric='logloss',
        random_state=42,
        n_jobs=-1
    )

    model.fit(
        X_train, y_train,
        eval_set=[(X_test, y_test)],
        verbose=False
    )

    y_pred  = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]

    metrics = {
        'accuracy':  accuracy_score(y_test, y_pred),
        'precision': precision_score(y_test, y_pred),
        'recall':    recall_score(y_test, y_pred),
        'f1':        f1_score(y_test, y_pred),
        'roc_auc':   roc_auc_score(y_test, y_proba),
    }

    # Cross-validation
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(model, X, y, cv=cv, scoring='f1')
    metrics['cv_f1_mean'] = cv_scores.mean()
    metrics['cv_f1_std']  = cv_scores.std()

    # Feature importance
    importances = dict(zip(X.columns, model.feature_importances_))
    top_features = sorted(importances.items(), key=lambda x: x[1], reverse=True)

    return model, metrics, top_features, X_test, y_test, y_pred, y_proba


def predict_url(model, url: str) -> dict:
    features = extract_features(url)
    X = pd.DataFrame([features])
    proba = model.predict_proba(X)[0, 1]
    label = 'PHISHING' if proba >= 0.5 else 'LEGITIMATE'
    risk  = 'HIGH' if proba >= 0.75 else ('MEDIUM' if proba >= 0.5 else 'LOW')
    return {
        'url': url,
        'label': label,
        'phishing_probability': round(float(proba), 4),
        'risk_level': risk,
        'features': features
    }


# ─────────────────────────────────────────────
# 4. RUN
# ─────────────────────────────────────────────

if __name__ == '__main__':
    print("=" * 60)
    print("  XGBoost Phishing URL Detector — Full Pipeline")
    print("=" * 60)

    print("\n[1] Building dataset...")
    X, y = build_dataset(LEGIT_URLS, PHISHING_URLS)
    print(f"    Total samples : {len(y)}  (legit={sum(y==0)}, phishing={sum(y==1)})")
    print(f"    Features      : {X.shape[1]}")

    print("\n[2] Training XGBoost model...")
    model, metrics, top_features, X_test, y_test, y_pred, y_proba = train_model(X, y)

    print("\n[3] Evaluation Results:")
    print(f"    Accuracy  : {metrics['accuracy']:.4f}")
    print(f"    Precision : {metrics['precision']:.4f}")
    print(f"    Recall    : {metrics['recall']:.4f}")
    print(f"    F1 Score  : {metrics['f1']:.4f}")
    print(f"    ROC-AUC   : {metrics['roc_auc']:.4f}")
    print(f"    CV F1     : {metrics['cv_f1_mean']:.4f} ± {metrics['cv_f1_std']:.4f}")

    print("\n    Confusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(f"    TN={cm[0,0]}  FP={cm[0,1]}")
    print(f"    FN={cm[1,0]}  TP={cm[1,1]}")

    print("\n[4] Top 10 Most Important Features:")
    for i, (feat, imp) in enumerate(top_features[:10], 1):
        bar = '█' * int(imp * 100)
        print(f"    {i:2}. {feat:<35} {imp:.4f}  {bar}")

    print("\n[5] Live URL Predictions:")
    test_urls = [
        "https://www.google.com/search?q=xgboost",
        "http://paypa1-secure-verify.xyz/login?user=test",
        "https://github.com/scikit-learn/scikit-learn",
        "http://amazon-account-suspended.tk/restore",
        "https://stackoverflow.com/questions",
        "https://apple-id-verify-now.info/update",
    ]
    results = []
    for url in test_urls:
        r = predict_url(model, url)
        icon = "🔴" if r['label'] == 'PHISHING' else "🟢"
        print(f"    {icon} [{r['risk_level']:6}] {r['phishing_probability']:.2%}  {url[:60]}")
        results.append(r)

    # Save artifacts
    print("\n[6] Saving model artifacts...")
    with open('F:/AI_Cyber_Defender_AI_Package_MultiLog/AI_Cyber_Defender_AI_Package_MultiLog/models/url/phishing_model.pkl', 'wb') as f:
        pickle.dump(model, f)

    save_data = {
        'metrics': metrics,
        'top_features': top_features[:15],
        'feature_names': list(X.columns),
        'sample_results': results,
        'confusion_matrix': cm.tolist()
    }
    with open('F:/AI_Cyber_Defender_AI_Package_MultiLog/AI_Cyber_Defender_AI_Package_MultiLog/models/url/model_data.json', 'w') as f:
        json.dump(save_data, f, indent=2, default=str)

    print("    ✓ phishing_model.pkl")
    print("    ✓ model_data.json")
    print("\n✅ Pipeline complete!")
