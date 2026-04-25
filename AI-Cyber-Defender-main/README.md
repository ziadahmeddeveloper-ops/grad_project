# AI Cyber Defender

AI Cyber Defender is an AI-powered cybersecurity platform designed to detect suspicious activity and cyber attacks from multiple data sources in real time.

The system analyzes:

- Windows security logs
- Web logs
- Network logs
- URLs

It combines machine learning models with rule-based enrichment to identify threats, classify attack types, calculate threat severity, extract context such as source IP and affected user, and generate security reports.

---

## Features

- Real-time detection for Windows, Web, Network, and URL inputs
- Anomaly detection using LSTM Autoencoder models
- Malicious URL detection using a classification model
- Attack type classification
- Threat score and severity level
- Source IP, username, host, and event time extraction
- Recommended response actions
- Daily, weekly, and monthly reports
- Web interface for testing logs and URLs

---

## Supported Detection Types

### Windows
- Failed Logon / Brute Force
- Account Enumeration
- Privilege Enumeration
- Suspicious Process Execution

### Web
- SQL Injection
- Cross-Site Scripting (XSS)
- Path Traversal
- Command Injection

### Network
- DDoS / DoS
- Port Scan / Reconnaissance
- Suspicious SYN Activity
- High-rate network flooding

### URL
- Phishing URL
- Malware Delivery URL
- Suspicious / Malicious URL

---

## Project Structure

```bash
AI-Cyber-Defender/
│
├── app.py
├── requirements.txt
├── README.md
│
├── models/
│   ├── windows_logs/
│   ├── web_logs/
│   ├── network_logs/
│   └── url/
│
├── src/
│   ├── enrichment.py
│   ├── reporting.py
│   ├── report_engine.py
│   ├── feature_engineering.py
│   └── preprocessing.py
│
├── reports/
│   └── generated/
│
└── data_samples/
    └── AI_Cyber_Defender_Test_Logs.txt
```

---

## Tech Stack

- Python
- Flask
- TensorFlow / Keras
- Scikit-learn
- Pandas
- NumPy
- Joblib

---

## How It Works

### Single Input Mode
For a single log line or a single URL:
- URLs are analyzed using the trained URL model
- Single logs are analyzed using rule-based single-event detection for fast testing

### Batch Mode
For multiple logs:
- Windows, Web, and Network logs are analyzed using trained LSTM models
- Results are enriched with attack type, severity, context, and recommendations

---

## How to Run

### 1. Clone the repository
```bash
git clone https://github.com/YOUR_USERNAME/AI-Cyber-Defender.git
cd AI-Cyber-Defender
```

### 2. Create a virtual environment
```bash
python -m venv venv
```

### 3. Activate it

#### Windows
```bash
venv\Scripts\activate
```

#### Linux / macOS
```bash
source venv/bin/activate
```

### 4. Install dependencies
```bash
pip install -r requirements.txt
```

### 5. Make sure trained models exist
Put your trained artifacts inside:

- `models/windows_logs/`
- `models/web_logs/`
- `models/network_logs/`
- `models/url/`

Each log model folder should contain:
- trained model file (`.h5` or `.keras`)
- scaler (`.pkl` or `.joblib`)
- config (`.json`)

The URL folder should contain:
- trained URL model
- config file

### 6. Run the app
```bash
python app.py
```

### 7. Open in browser
```text
http://127.0.0.1:5000
```

---

## Testing Samples

You can test the system using:
- safe Windows logs
- attack Windows logs
- safe Web logs
- attack Web logs
- safe Network logs
- attack Network logs
- safe URLs
- malicious URLs

A ready testing file is included in:

```text
data_samples/AI_Cyber_Defender_Test_Logs.txt
```

---

## Example Inputs

### Windows Safe
```text
2024-04-17 09:14:02 Security EventID=4624 An account was successfully logged on User=Ahmed SRC=192.168.1.20
```

### Windows Attack
```text
2024-04-17 03:17:08 Security EventID=4799 A security-enabled local group membership was enumerated User=Administrator SRC=185.234.219.5
```

### Web Attack
```text
GET /login?username=admin' OR 1=1--&password=x HTTP/1.1
```

### URL Attack
```text
http://secure-login-paypal-account-verification.com/login.php?session=834734
```

---

## Reports

The system can generate:
- Daily reports
- Weekly reports
- Monthly reports

Reports include:
- detected threats
- top attack types
- suspicious IPs
- impacted users
- security score

---

## Future Improvements

- Real-time endpoint agent
- SIEM integration
- Database-backed alert storage
- Dashboard with charts and analytics
- Model calibration using validation data
- Improved log parsing and normalization

---

## Author

Developed as a graduation project in cybersecurity and AI.

If you find this project useful, feel free to star the repository.
