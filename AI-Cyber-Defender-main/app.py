import time
import os
import sys
import json
import glob
import re
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from tensorflow.keras.models import load_model
from flask import Flask, render_template_string, request, jsonify, send_from_directory

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.enrichment import (
    enrich_log_alert,
    enrich_url_alert,
    normalize_record,
    extract_context,
)
from src.reporting import threat_level_from_score, build_dashboard_summary, write_dashboard_json
from src.report_engine import append_alerts, generate_report, save_report, load_alert_store
from src.feature_engineering import extract_url_features
from src.preprocessing import (
    clean_column_names,
    basic_log_preprocess,
    add_text_length_features,
    fill_numeric,
    encode_categoricals,
    keep_or_create_columns,
    create_sequences,
)

BASE_DIR = Path(__file__).resolve().parent
MODEL_DIR = BASE_DIR / "models"
REPORTS_DIR = BASE_DIR / "reports"
GENERATED_REPORTS_DIR = REPORTS_DIR / "generated"
ALERT_STORE_PATH = REPORTS_DIR / "alerts_store.json"

REPORTS_DIR.mkdir(exist_ok=True)
GENERATED_REPORTS_DIR.mkdir(exist_ok=True)

app = Flask(__name__)

LOG_SOURCES = {
    "network": MODEL_DIR / "network_logs",
    "web": MODEL_DIR / "web_logs",
    "windows": MODEL_DIR / "windows_logs",
}

artifacts = {k: {"model": None, "scaler": None, "cfg": None} for k in LOG_SOURCES}
url_model = None
url_cfg = None


# =========================
# Load model artifacts
# =========================
def safe_load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _first_existing(patterns):
    for p in patterns:
        matches = glob.glob(str(p))
        if matches:
            return matches[0]
    return None


def load_artifacts():
    global url_model, url_cfg

    for source, model_dir in LOG_SOURCES.items():
        try:
            model_path = _first_existing([
                model_dir / f"{source}_log_lstm_autoencoder.keras",
                model_dir / f"{source}_log_lstm_autoencoder.h5",
                model_dir / "*.keras",
                model_dir / "*.h5",
            ])
            scaler_path = _first_existing([
                model_dir / f"{source}_log_scaler.joblib",
                model_dir / "*.joblib",
                model_dir / "*.pkl",
            ])
            cfg_path = _first_existing([
                model_dir / f"{source}_log_model_config.json",
                model_dir / "*config*.json",
                model_dir / "*.json",
            ])

            if model_path and scaler_path and cfg_path:
                artifacts[source]["model"] = load_model(model_path)
                artifacts[source]["scaler"] = joblib.load(scaler_path)
                artifacts[source]["cfg"] = safe_load_json(cfg_path)
                print(f"[OK] Loaded {source} model")
            else:
                print(f"[WARN] Missing artifacts for {source}")

        except Exception as e:
            print(f"[WARN] Failed loading {source}: {e}")

    try:
        url_dir = None
        for d in [MODEL_DIR / "url", MODEL_DIR / "url_model"]:
            if d.exists():
                url_dir = d
                break

        if url_dir is not None:
            url_model_path = _first_existing([
                url_dir / "url_xgboost_model.joblib",
                url_dir / "*.joblib",
                url_dir / "*.pkl",
            ])
            url_cfg_path = _first_existing([
                url_dir / "url_model_config.json",
                url_dir / "*config*.json",
                url_dir / "*.json",
            ])

            if url_model_path and url_cfg_path:
                url_model = joblib.load(url_model_path)
                url_cfg = safe_load_json(url_cfg_path)
                print("[OK] Loaded URL model")
            else:
                print("[WARN] Missing URL artifacts")
        else:
            print("[WARN] URL folder not found")

    except Exception as e:
        print(f"[WARN] Failed loading URL model: {e}")


load_artifacts()


# =========================
# UI
# =========================
UI_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security AI — Test Interface</title>
<style>
:root {
  --bg:#0f1117; --bg2:#1a1f2e; --bg3:#1e2840; --border:#1e293b;
  --text:#e2e8f0; --muted:#64748b; --blue:#3b82f6;
}
* { box-sizing:border-box; margin:0; padding:0; }
body { background:var(--bg); color:var(--text); font-family:'Segoe UI',system-ui,sans-serif; min-height:100vh; }
.topbar { background:var(--bg2); border-bottom:1px solid var(--border); padding:.9rem 2rem; display:flex; align-items:center; gap:1rem; }
.topbar h1 { font-size:1.1rem; font-weight:600; color:#60a5fa; }
.topbar .badge { background:#172554; color:#60a5fa; font-size:.7rem; padding:2px 8px; border-radius:99px; text-transform:uppercase; }
.mode-tag { margin-left:auto; font-size:.78rem; color:#f59e0b; background:#451a03; padding:3px 10px; border-radius:99px; }
.layout { display:grid; grid-template-columns:1fr 1fr; gap:1.5rem; padding:1.5rem 2rem; max-width:1300px; margin:0 auto; }
@media (max-width:900px){ .layout { grid-template-columns:1fr; } }
.panel { background:var(--bg2); border:1px solid var(--border); border-radius:14px; padding:1.5rem; }
.panel h2 { font-size:.8rem; text-transform:uppercase; letter-spacing:.07em; color:var(--muted); margin-bottom:1rem; }
textarea { width:100%; height:230px; background:var(--bg); border:1px solid var(--border); border-radius:8px; color:var(--text); font-family:'Consolas',monospace; font-size:.82rem; padding:.75rem; resize:vertical; outline:none; }
.samples { display:flex; flex-wrap:wrap; gap:.5rem; margin:.75rem 0; }
.sample-btn { background:var(--bg3); border:1px solid var(--border); color:var(--muted); font-size:.75rem; padding:4px 10px; border-radius:6px; cursor:pointer; }
.run-btn { width:100%; padding:.8rem; background:var(--blue); border:none; border-radius:8px; color:white; font-size:.95rem; font-weight:600; cursor:pointer; margin-top:.75rem; }
.run-btn:disabled { background:var(--bg3); color:var(--muted); cursor:not-allowed; }
.report-btns { display:flex; gap:.75rem; flex-wrap:wrap; margin-top:1rem; }
.report-btn { flex:1; min-width:120px; padding:.65rem; background:var(--bg3); border:1px solid var(--border); border-radius:8px; color:var(--text); font-size:.85rem; cursor:pointer; }
.pred-card { background:var(--bg3); border:1px solid var(--border); border-radius:8px; padding:.75rem 1rem; margin-bottom:.7rem; }
.info-grid { display:grid; grid-template-columns:1fr 1fr; gap:.6rem; margin-top:.75rem; }
.info-item { background:var(--bg3); border-radius:8px; padding:.6rem .75rem; }
.info-item .k { font-size:.72rem; color:var(--muted); text-transform:uppercase; margin-bottom:2px; }
.info-item .v { font-size:.88rem; font-weight:500; word-break:break-word; }
.toast { position:fixed; bottom:1.5rem; right:1.5rem; background:var(--bg2); border:1px solid var(--border); border-radius:10px; padding:.75rem 1.25rem; font-size:.85rem; opacity:0; transition:opacity .3s; z-index:999; pointer-events:none; max-width:420px; }
.toast.show { opacity:1; }
.spinner { display:inline-block; width:16px; height:16px; border:2px solid transparent; border-top-color:white; border-radius:50%; animation:spin .7s linear infinite; vertical-align:middle; margin-right:6px; }
@keyframes spin { to { transform:rotate(360deg);} }
</style>
</head>
<body>
<div class="topbar">
  <h1>🛡️ Security AI</h1>
  <span class="badge">Single + Batch Test</span>
  <span class="mode-tag" id="mode-tag">Loading...</span>
</div>

<div class="layout">
  <div class="panel">
    <h2>Log / URL Input</h2>
    <textarea id="log-input" placeholder="Paste one log / one URL / or multiple logs (one per line)"></textarea>

    <div class="samples">
      <button class="sample-btn" onclick="loadSample('windows_safe')">Windows Safe</button>
      <button class="sample-btn" onclick="loadSample('windows_attack')">Windows Attack</button>
      <button class="sample-btn" onclick="loadSample('web_safe')">Web Safe</button>
      <button class="sample-btn" onclick="loadSample('web_sqli')">Web SQLi</button>
      <button class="sample-btn" onclick="loadSample('network_safe')">Network Safe</button>
      <button class="sample-btn" onclick="loadSample('network_flood')">Network Flood</button>
      <button class="sample-btn" onclick="loadSample('url_safe')">URL Safe</button>
      <button class="sample-btn" onclick="loadSample('url_attack')">URL Attack</button>
      <button class="sample-btn" onclick="loadSample('windows_batch')">Windows Batch</button>
    </div>

    <button class="run-btn" id="run-btn" onclick="analyze()">Analyze</button>

    <div class="report-btns">
      <button class="report-btn" onclick="generateReport('daily')">📋 Daily</button>
      <button class="report-btn" onclick="generateReport('weekly')">📊 Weekly</button>
      <button class="report-btn" onclick="generateReport('monthly')">📅 Monthly</button>
    </div>
  </div>

  <div class="panel">
    <h2>Analysis Result</h2>
    <div id="result-area">
      <div style="color:#64748b">Paste input and click Analyze</div>
    </div>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
const SAMPLES = {
  windows_safe: `2024-04-17 09:14:02 Security EventID=4624 An account was successfully logged on User=Ahmed SRC=192.168.1.20`,
  windows_attack: `2024-04-17 03:17:08 Security EventID=4799 A security-enabled local group membership was enumerated User=Administrator SRC=185.234.219.5`,
  web_safe: `GET /home HTTP/1.1`,
  web_sqli: `GET /login?username=admin' OR 1=1--&password=x HTTP/1.1`,
  network_safe: `Apr 17 09:14:02 fw01 ACCEPT IN=eth0 OUT= SRC=192.168.1.20 DST=10.0.0.5 LEN=60 PROTO=TCP SPT=52344 DPT=443 ACK`,
  network_flood: `May 3 14:05:23 fw01 kernel: [SYN Flood] DROP IN=eth0 OUT= SRC=185.220.101.45 DST=10.0.0.1 LEN=44 PROTO=TCP SPT=52301 DPT=80 WINDOW=65535 SYN`,
  url_safe: `https://www.google.com/search?q=cyber+security`,
  url_attack: `http://secure-login-paypal-account-verification.com/login.php?session=834734`,
  windows_batch: `2024-04-17 09:14:02 Security EventID=4624 An account was successfully logged on User=Ahmed SRC=192.168.1.20
2024-04-17 09:16:11 Security EventID=4634 An account was logged off User=Ahmed SRC=192.168.1.20
2024-04-17 10:02:45 Security EventID=4776 The domain controller attempted to validate credentials for an account User=Sara SRC=192.168.1.25
2024-04-17 10:20:18 Security EventID=4648 A logon was attempted using explicit credentials User=ITSupport SRC=192.168.1.15
2024-04-17 11:05:33 Security EventID=4624 An account was successfully logged on User=Mona SRC=192.168.1.30
2024-04-17 11:10:44 Security EventID=4624 An account was successfully logged on User=Omar SRC=192.168.1.31
2024-04-17 11:15:12 Security EventID=4634 An account was logged off User=Mona SRC=192.168.1.30
2024-04-17 11:19:27 Security EventID=4624 An account was successfully logged on User=Yousef SRC=192.168.1.32
2024-04-17 11:21:52 Security EventID=4624 An account was successfully logged on User=Noha SRC=192.168.1.33
2024-04-17 11:24:08 Security EventID=4624 An account was successfully logged on User=Ahmed SRC=192.168.1.20
2024-04-17 11:28:14 Security EventID=4634 An account was logged off User=Ahmed SRC=192.168.1.20
2024-04-17 11:31:02 Security EventID=4624 An account was successfully logged on User=Kareem SRC=192.168.1.34
2024-04-17 11:35:55 Security EventID=4624 An account was successfully logged on User=Salma SRC=192.168.1.35
2024-04-17 11:40:12 Security EventID=4634 An account was logged off User=Kareem SRC=192.168.1.34
2024-04-17 11:45:18 Security EventID=4624 An account was successfully logged on User=Hana SRC=192.168.1.36
2024-04-17 11:50:03 Security EventID=4625 An account failed to log on User=Administrator SRC=185.234.219.5 FailureReason=Unknown user or bad password
2024-04-17 11:50:10 Security EventID=4625 An account failed to log on User=Administrator SRC=185.234.219.5 FailureReason=Unknown user or bad password
2024-04-17 11:50:18 Security EventID=4797 An attempt was made to query the existence of a blank password for an account User=Guest SRC=185.234.219.5
2024-04-17 11:50:24 Security EventID=4799 A security-enabled local group membership was enumerated User=Administrator SRC=185.234.219.5
2024-04-17 11:50:30 Security EventID=4688 A new process has been created Process=powershell.exe User=Administrator SRC=185.234.219.5`
};

function loadSample(k) {
  document.getElementById('log-input').value = SAMPLES[k] || '';
}

function showToast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 3500);
}

function renderSingle(data) {
  const actions = (data.recommended_actions || []).map(x => `<li>${x}</li>`).join('');
  const rawCtx = data.raw_context ? JSON.stringify(data.raw_context, null, 2) : '{}';

  document.getElementById('result-area').innerHTML = `
    <div class="pred-card">
      <div><b>Prediction:</b> ${data.prediction}</div>
      <div><b>Attack Type:</b> ${data.attack_type || 'Unknown'}</div>
      <div><b>Attack Name:</b> ${data.attack_name || data.attack_type || 'Unknown'}</div>
      <div><b>Threat Score:</b> ${data.threat_score}</div>
      <div><b>Threat Level:</b> ${data.threat_level}</div>
      <div><b>Source Type:</b> ${data.source_type || 'unknown'}</div>
    </div>

    <div class="info-grid">
      <div class="info-item"><div class="k">Attacker IP</div><div class="v">${data.source_ip || 'N/A'}</div></div>
      <div class="info-item"><div class="k">Username</div><div class="v">${data.username || 'N/A'}</div></div>
      <div class="info-item"><div class="k">Host</div><div class="v">${data.host || 'N/A'}</div></div>
      <div class="info-item"><div class="k">Event Time</div><div class="v">${data.event_time || 'N/A'}</div></div>
    </div>

    <div class="pred-card" style="margin-top:10px;">
      <div><b>Recommended Actions</b></div>
      <ul style="margin-top:8px; padding-left:18px;">${actions || '<li>No actions</li>'}</ul>
    </div>

    <div class="pred-card">
      <div><b>Raw Context</b></div>
      <pre style="margin-top:8px; white-space:pre-wrap;">${rawCtx}</pre>
    </div>
  `;
}

function renderBatch(data) {
  const list = Array.isArray(data) ? data : [];
  const items = list.map((x, i) => `
    <div class="pred-card">
      <div><b>#${i+1}</b></div>
      <div><b>Prediction:</b> ${x.prediction}</div>
      <div><b>Attack Type:</b> ${x.attack_type || 'Unknown'}</div>
      <div><b>Threat Score:</b> ${x.threat_score}</div>
      <div><b>Threat Level:</b> ${x.threat_level}</div>
      <div><b>User:</b> ${x.username || 'N/A'}</div>
      <div><b>IP:</b> ${x.source_ip || 'N/A'}</div>
    </div>
  `).join('');

  document.getElementById('result-area').innerHTML = items || '<div style="color:#64748b">No results</div>';
}

async function analyze() {
  const input = document.getElementById('log-input').value.trim();
  if (!input) {
    showToast('Please enter input first');
    return;
  }

  const btn = document.getElementById('run-btn');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span>Analyzing...';

  try {
    const lines = input.split('\\n').map(x => x.trim()).filter(Boolean);
    const endpoint = lines.length > 1 ? '/api/batch' : '/api/predict';
    const body = lines.length > 1 ? { logs: lines } : { input_text: input };

    const res = await fetch(endpoint, {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify(body)
    });

    const text = await res.text();
    let data;
    try {
      data = JSON.parse(text);
    } catch (e) {
      console.error(text);
      showToast('Server returned invalid response');
      return;
    }

    if (data.error) {
      showToast(data.error);
      return;
    }

    if (Array.isArray(data)) {
      renderBatch(data);
    } else {
      renderSingle(data);
    }

  } catch (e) {
    showToast('Error: ' + e.message);
  } finally {
    btn.disabled = false;
    btn.innerHTML = 'Analyze';
  }
}

async function generateReport(type) {
  try {
    const res = await fetch(`/api/report/${type}`, { method: 'POST' });
    const data = await res.json();
    if (data.error) {
      showToast(data.error);
      return;
    }
    showToast(`Saved report: ${data.filename}`);
  } catch (e) {
    showToast('Report error: ' + e.message);
  }
}

fetch('/api/info')
  .then(r => r.json())
  .then(d => {
    document.getElementById('mode-tag').textContent = d.demo_mode ? 'Demo Mode' : 'Hybrid Mode';
  })
  .catch(() => {});
</script>
</body>
</html>
"""


# =========================
# Helper functions
# =========================
def _load_feature_cols(cfg):
    cols = cfg.get("feature_cols", [])
    if isinstance(cols, str):
        cols = [cols]
    return cols


def _score_to_value(err: float, threshold: float) -> float:
    err = float(err)
    threshold = max(float(threshold), 1e-8)

    if err <= threshold:
        return round((err / threshold) * 30, 2)

    ratio = (err - threshold) / threshold
    return round(min(100, 30 + ratio * 70), 2)


def detect_source(input_text: str) -> str:
    t = input_text.lower().strip()

    if t.startswith("http://") or t.startswith("https://"):
        return "url"

    if "eventid" in t or "event id" in t or "security" in t or "logon" in t or "privilege" in t:
        return "windows"

    if "get " in t or "post " in t or "http/1.1" in t or "<script" in t or "sqlmap" in t:
        return "web"

    if "syn" in t or "flood" in t or "proto=tcp" in t or "dst=" in t or "src=" in t:
        return "network"

    return "web"


def extract_event_id(log: str):
    patterns = [
        r'eventid[=:\s]+(\d+)',
        r'event\s*id[=:\s]+(\d+)',
        r'event_id[=:\s]+(\d+)',
    ]
    for p in patterns:
        match = re.search(p, log, flags=re.IGNORECASE)
        if match:
            return match.group(1)
    return None


def extract_ip(log: str):
    match = re.search(r'(?:(?:src|source|ip|client_ip|remote_addr|source_ip)[=:\s]+)?(\b\d{1,3}(?:\.\d{1,3}){3}\b)', log, flags=re.IGNORECASE)
    return match.group(1) if match else None


def extract_username(log: str):
    match = re.search(r'(?:user|username|account_name)[=:\s"]+([A-Za-z0-9._-]+)', log, flags=re.IGNORECASE)
    return match.group(1) if match else None


def try_parse_json_text(input_text: str):
    try:
        obj = json.loads(input_text)
        if isinstance(obj, dict):
            return obj
    except Exception:
        pass
    return None


def extract_web_row(log: str):
    log_l = log.lower()
    path_matches = re.findall(r'/[A-Za-z0-9_./-]*', log)

    return {
        "url_length": len(log),
        "path_length": len(path_matches[0]) if path_matches else 1,
        "query_length": len(log.split("?", 1)[1]) if "?" in log else 0,
        "body_length": len(log.split("body=", 1)[1]) if "body=" in log_l else 0,
        "user_agent_length": 20,
        "host_length": 10,
        "is_post": 1 if log_l.startswith("post") else 0,
        "has_body": 1 if "body=" in log_l else 0,
        "num_params": log.count("&") + (1 if "?" in log else 0),
        "num_slashes": log.count("/"),
        "num_dots": log.count("."),
        "num_special_chars": len(re.findall(r'[\\?\\=\\&\\%\\-\\_\\@\'"]', log)),
        "has_sql_keywords": 1 if any(x in log_l for x in ["union select", "or 1=1", "sqlmap", "drop table", "%27"]) else 0,
        "has_xss_keywords": 1 if any(x in log_l for x in ["<script", "javascript:", "alert("]) else 0,
        "has_traversal": 1 if any(x in log_l for x in ["../", "%2e%2e%2f", "..\\\\"]) else 0,
        "has_cmd_injection": 1 if any(x in log_l for x in ["cmd=", ";wget", ";curl", "|whoami", "powershell"]) else 0,
        "url": log,
        "query": log.split("?", 1)[1] if "?" in log else "",
        "body": log.split("body=", 1)[1] if "body=" in log_l else "",
        "source_ip": extract_ip(log),
        "username": extract_username(log),
    }


def extract_windows_row(log: str):
    return {
        "event_id": int(extract_event_id(log) or 0),
        "source_len": 4,
        "source_digit_count": 4,
        "source_special_count": 0,
        "level_len": 21,
        "level_digit_count": 13,
        "level_special_count": 6,
        "task_category_len": len(log),
        "task_category_digit_count": sum(ch.isdigit() for ch in log),
        "task_category_special_count": len(re.findall(r'[^A-Za-z0-9\\s]', log)),
        "task_category": log,
        "source_ip": extract_ip(log),
        "username": extract_username(log),
        "host": None,
    }


def extract_network_row(log: str):
    log_l = log.lower()
    return {
        "flow_duration": 100 if "flood" not in log_l else 10,
        "total_fwd_packets": 200 if "flood" in log_l else 8,
        "total_backward_packets": 0 if "flood" in log_l else 10,
        "total_length_of_fwd_packets": 8000 if "flood" in log_l else 850,
        "total_length_of_bwd_packets": 0 if "flood" in log_l else 1400,
        "fwd_packet_length_mean": 40.0 if "flood" in log_l else 106.0,
        "bwd_packet_length_mean": 0.0 if "flood" in log_l else 140.0,
        "flow_bytes_s": 1200000.0 if "flood" in log_l else 1800.0,
        "flow_packets_s": 25000.0 if "flood" in log_l else 15.0,
        "syn_flag_count": 30 if "syn" in log_l else 0,
        "ack_flag_count": 0 if "flood" in log_l else 1,
        "average_packet_size": 40.0 if "flood" in log_l else 124.0,
        "source_ip": extract_ip(log),
        "username": extract_username(log),
    }


def prepare_log_features(df: pd.DataFrame, source: str):
    obj = artifacts[source]
    cfg = obj["cfg"]
    scaler = obj["scaler"]

    if cfg is None or scaler is None:
        raise ValueError(f"{source} config/scaler not found")

    timestamp_col = cfg.get("timestamp_col", "timestamp")
    feature_cols = _load_feature_cols(cfg)
    text_cols = cfg.get("text_cols", [])
    sequence_length = int(cfg.get("sequence_length", 10))

    df = clean_column_names(df)
    df = basic_log_preprocess(df, timestamp_col=timestamp_col)
    df = add_text_length_features(df, text_cols)
    df = fill_numeric(df)
    df, _ = encode_categoricals(df)
    df = keep_or_create_columns(df, feature_cols)

    missing = [c for c in feature_cols if c not in df.columns]
    if missing:
        raise ValueError(f"Missing feature columns: {missing}")

    X = scaler.transform(df[feature_cols])
    X_seq = create_sequences(X, sequence_length=sequence_length)

    return df, X_seq, sequence_length


def predict_log_source(source: str, records: list):
    obj = artifacts[source]
    model = obj["model"]
    cfg = obj["cfg"]

    if model is None or obj["scaler"] is None or cfg is None:
        raise ValueError(f"{source} model not loaded")

    raw_df = pd.DataFrame(records)
    threshold = float(cfg.get("threshold", 0.5))

    df_proc, X_seq, sequence_length = prepare_log_features(raw_df, source)

    if len(X_seq) == 0:
        raise ValueError(f"Need at least {sequence_length} rows")

    recon = model.predict(X_seq, verbose=0)
    mse = np.mean(np.power(X_seq - recon, 2), axis=(1, 2))

    results = []
    for idx, err in enumerate(mse):
        row_idx = idx + sequence_length - 1
        score = _score_to_value(float(err), threshold)

        base = {
            "generated_at": pd.Timestamp.utcnow().isoformat(),
            "source_type": source,
            "row_index": int(row_idx),
            "anomaly_score": round(float(err), 6),
            "prediction": "anomaly" if float(err) > threshold else "normal",
            "threshold": threshold,
            "threat_score": score,
            "threat_level": threat_level_from_score(score),
        }

        enriched = enrich_log_alert(base, raw_df.iloc[row_idx].to_dict(), source)

        # attack_name
        if enriched.get("prediction") == "normal":
            enriched["attack_name"] = "Normal Activity"
        else:
            at = enriched.get("attack_type", "Unknown")
            if source == "windows":
                enriched["attack_name"] = f"Windows {at}"
            elif source == "web":
                enriched["attack_name"] = f"Web {at}"
            else:
                enriched["attack_name"] = f"Network {at}"

        results.append(enriched)

    return results


def predict_url(url: str):
    if url_model is None or url_cfg is None:
        raise ValueError("URL model not loaded")

    X = pd.DataFrame([extract_url_features(url)])
    probs = url_model.predict_proba(X)[:, 1]
    preds = (probs >= 0.5).astype(int)

    score = round(float(probs[0]) * 100, 2)
    base = {
        "generated_at": pd.Timestamp.utcnow().isoformat(),
        "url": url,
        "prediction": "malicious" if int(preds[0]) == 1 else "safe",
        "threat_score": score,
        "threat_level": threat_level_from_score(score),
        "source_type": "url",
    }

    enriched = enrich_url_alert(base)
    enriched["attack_name"] = enriched.get("attack_type", "URL Analysis")
    return enriched


def single_log_rule_detection(input_text: str):
    source = detect_source(input_text)

    if source == "url":
        return predict_url(input_text)

    if source == "windows":
        row = extract_windows_row(input_text)
    elif source == "network":
        row = extract_network_row(input_text)
    else:
        row = extract_web_row(input_text)

    norm = normalize_record(row)
    ctx = extract_context(norm)

    attack_type = "Normal Activity"
    prediction = "normal"

    if source == "windows":
        event_id = str(norm.get("event_id", ""))
        msg = str(norm.get("task_category", "")).lower()

        if event_id == "4625" or "failed to log on" in msg:
            attack_type = "Brute Force / Failed Logon"
            prediction = "anomaly"
        elif event_id == "4797":
            attack_type = "Account Enumeration"
            prediction = "anomaly"
        elif event_id == "4799":
            attack_type = "Privilege Enumeration"
            prediction = "anomaly"
        elif event_id == "4688" and any(x in msg for x in ["powershell", "cmd.exe", "wscript", "cscript"]):
            attack_type = "Suspicious Process Execution"
            prediction = "anomaly"

    elif source == "web":
        raw = input_text.lower()
        if any(x in raw for x in ["union select", "or 1=1", "sqlmap", "drop table", "%27", "--"]):
            attack_type = "SQL Injection"
            prediction = "anomaly"
        elif any(x in raw for x in ["<script", "javascript:", "alert("]):
            attack_type = "Cross-Site Scripting (XSS)"
            prediction = "anomaly"
        elif any(x in raw for x in ["../", "%2e%2e%2f", "..\\"]):
            attack_type = "Path Traversal"
            prediction = "anomaly"
        elif any(x in raw for x in ["cmd=", ";wget", ";curl", "|whoami", "powershell"]):
            attack_type = "Command Injection"
            prediction = "anomaly"

    elif source == "network":
        raw = input_text.lower()
        if "syn flood" in raw or "ddos" in raw or "dos" in raw:
            attack_type = "DDoS / DoS"
            prediction = "anomaly"
        elif "portscan" in raw or "scan" in raw:
            attack_type = "Port Scan / Reconnaissance"
            prediction = "anomaly"
        elif "syn" in raw and "drop" in raw:
            attack_type = "Suspicious SYN Activity"
            prediction = "anomaly"

    if prediction == "normal":
        threat_score = 15.0
        threat_level = "low"
        attack_name = "Normal Activity"
    else:
        if attack_type in ["DDoS / DoS", "Privilege Enumeration", "Command Injection"]:
            threat_score = 90.0
        elif attack_type in ["SQL Injection", "Cross-Site Scripting (XSS)", "Account Enumeration", "Brute Force / Failed Logon"]:
            threat_score = 78.0
        else:
            threat_score = 65.0

        threat_level = threat_level_from_score(threat_score)
        if source == "windows":
            attack_name = f"Windows {attack_type}"
        elif source == "web":
            attack_name = f"Web {attack_type}"
        else:
            attack_name = f"Network {attack_type}"

    base = {
        "generated_at": pd.Timestamp.utcnow().isoformat(),
        "source_type": source,
        "prediction": prediction,
        "anomaly_score": None,
        "threshold": None,
        "threat_score": threat_score,
        "threat_level": threat_level,
        "attack_type": attack_type,
        "attack_name": attack_name,
    }
    base.update(ctx)
    base["recommended_actions"] = [{
        "windows": [
            "Review the affected host and recent Windows security events around the same time.",
            "Verify whether the action was authorized.",
            "Escalate to the security team if repeated."
        ],
        "web": [
            "Inspect the endpoint and validate/sanitize input.",
            "Review web server logs and block the source IP if needed.",
            "Investigate recent suspicious requests."
        ],
        "network": [
            "Rate-limit or block the source IP.",
            "Inspect firewall and IDS/IPS telemetry.",
            "Escalate if attack volume increases."
        ],
        "url": [
            "Block the domain/URL and warn users immediately.",
            "Search for related clicks or referrals.",
            "Escalate if users were exposed."
        ]
    }.get(source, ["Review the event manually."])]

    base["raw_context"] = {
        k: norm.get(k)
        for k in ["event_id", "task_category", "source_ip", "username", "url", "query", "body"]
        if k in norm
    }
    return base


# =========================
# Routes
# =========================
@app.route("/")
def index():
    return render_template_string(UI_HTML)


@app.route("/api/info")
def api_info():
    return jsonify({"demo_mode": False, "version": "3.0-hybrid"})

@app.route("/api/predict", methods=["POST"])
def api_predict():
    data = request.get_json(silent=True) or {}
    input_text = data.get("input_text", "").strip()

    if not input_text:
        return jsonify({"error": "Missing input_text"}), 400

    try:
        start = time.time()

        # 🔥 LOG قبل التنفيذ
        print("🚀 Incoming request:", input_text)

        result = single_log_rule_detection(input_text)

        print("✅ Done in:", time.time() - start, "sec")

        append_alerts([result], str(ALERT_STORE_PATH))

        return jsonify(result)

    except Exception as e:
        print("❌ ERROR:", str(e))
        return jsonify({"error": str(e)}), 500

@app.route("/api/batch", methods=["POST"])
def api_batch():
    data = request.get_json(silent=True) or {}
    logs = data.get("logs", [])

    if not logs:
        return jsonify({"error": "Missing 'logs' field"}), 400

    try:
        source = detect_source(str(logs[0]))

        if source == "url":
            results = [predict_url(str(u)) for u in logs]
            append_alerts(results, str(ALERT_STORE_PATH))
            return jsonify(results)

        records = []
        for log in logs:
            log = str(log)
            if source == "windows":
                records.append(extract_windows_row(log))
            elif source == "network":
                records.append(extract_network_row(log))
            else:
                records.append(extract_web_row(log))

        results = predict_log_source(source, records)
        append_alerts(results, str(ALERT_STORE_PATH))
        return jsonify(results)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/report/<report_type>", methods=["POST"])
def api_report(report_type):
    if report_type not in ("daily", "weekly", "monthly"):
        return jsonify({"error": "Invalid report type"}), 400

    try:
        alerts = load_alert_store(str(ALERT_STORE_PATH))
        report = generate_report(alerts, report_type)
        path = GENERATED_REPORTS_DIR / f"{report_type}_report.json"
        save_report(report, str(path))
        return jsonify({"path": str(path), "filename": path.name})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/reports/<filename>")
def serve_report(filename):
    return send_from_directory(str(REPORTS_DIR.resolve()), filename)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", default=5000, type=int)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    print("\\n🛡️  Security AI Test UI")
    print(f"   http://localhost:{args.port}")
    print("   Mode: HYBRID (single=rules, batch=LSTM, url=model)\\n")
    app.run(host=args.host, port=args.port, debug=args.debug)