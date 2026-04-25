import json
import os
from collections import Counter
from datetime import datetime, timedelta
from typing import Dict, List


def _now_iso():
    return datetime.utcnow().isoformat() + 'Z'


def load_alert_store(path: str) -> List[Dict]:
    if not os.path.exists(path):
        return []
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return []


def save_alert_store(alerts: List[Dict], path: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(alerts, f, ensure_ascii=False, indent=2)


def append_alerts(new_alerts: List[Dict], path: str):
    alerts = load_alert_store(path)
    alerts.extend(new_alerts)
    save_alert_store(alerts, path)
    return alerts


def _parse_time(v: str):
    if not v:
        return None
    for fmt in (None, '%m/%d/%Y %I:%M:%S %p', '%Y-%m-%d %H:%M:%S'):
        try:
            if fmt is None:
                return datetime.fromisoformat(str(v).replace('Z', '+00:00')).replace(tzinfo=None)
            return datetime.strptime(str(v), fmt)
        except Exception:
            pass
    return None


def _filter_period(alerts: List[Dict], period: str) -> List[Dict]:
    now = datetime.utcnow()
    if period == 'daily':
        start = now - timedelta(days=1)
    elif period == 'weekly':
        start = now - timedelta(days=7)
    elif period == 'monthly':
        start = now - timedelta(days=30)
    else:
        start = datetime.min
    out = []
    for a in alerts:
        dt = _parse_time(a.get('event_time') or a.get('generated_at')) or now
        if dt >= start:
            out.append(a)
    return out


def _security_score(alerts: List[Dict]) -> float:
    score = 100.0
    for a in alerts:
        level = str(a.get('threat_level', 'low')).lower()
        if level == 'critical':
            score -= 18
        elif level == 'high':
            score -= 10
        elif level == 'medium':
            score -= 5
        else:
            score -= 1
    return max(0.0, round(score, 2))


def generate_report(alerts: List[Dict], period: str) -> Dict:
    scoped = _filter_period(alerts, period)
    threats = [a for a in scoped if a.get('prediction') in ('anomaly', 'malicious')]
    type_counter = Counter(a.get('attack_type', 'Unknown') for a in threats)
    ip_counter = Counter(str(a.get('source_ip')) for a in threats if a.get('source_ip'))
    user_counter = Counter(str(a.get('username')) for a in threats if a.get('username'))
    return {
        'report_type': period,
        'generated_at': _now_iso(),
        'summary': {
            'items_analyzed': len(scoped),
            'threats_detected': len(threats),
            'security_score': _security_score(threats),
            'top_attack_types': type_counter.most_common(5),
            'top_suspicious_ips': ip_counter.most_common(5),
            'top_impacted_users': user_counter.most_common(5),
        },
        'top_alerts': sorted(threats, key=lambda x: float(x.get('threat_score', 0)), reverse=True)[:15],
        'recommendations': [
            'Review the top suspicious IPs and block or rate-limit confirmed malicious sources.',
            'Investigate repeated attack types and patch the affected services/endpoints.',
            'Review affected user accounts and enforce MFA for exposed services.',
        ],
    }


def save_report(report: Dict, path: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
