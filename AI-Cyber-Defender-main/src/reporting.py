import json
import os
from datetime import datetime


def threat_level_from_score(score: float) -> str:
    score = float(score)
    if score >= 85:
        return 'critical'
    if score >= 65:
        return 'high'
    if score >= 40:
        return 'medium'
    return 'low'


def _count_by_level(items):
    out = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    for item in items:
        level = str(item.get('threat_level', 'low')).lower()
        out[level] = out.get(level, 0) + 1
    return out


def build_dashboard_summary(url_results=None, log_results=None):
    url_results = url_results or []
    log_results = log_results or []
    malicious_urls = [x for x in url_results if x.get('prediction') == 'malicious']
    anomalous_logs = [x for x in log_results if x.get('prediction') == 'anomaly']
    total_items = len(url_results) + len(log_results)
    total_threats = len(malicious_urls) + len(anomalous_logs)
    avg_score = 0 if total_items == 0 else round(sum(float(x.get('threat_score', 0)) for x in url_results + log_results) / total_items, 2)
    security_score = round(max(0, 100 - avg_score), 2)
    return {
        'generated_at': datetime.utcnow().isoformat() + 'Z',
        'overview': {
            'total_items_analyzed': total_items,
            'total_threats_detected': total_threats,
            'security_score': security_score,
            'average_threat_score': avg_score,
        },
        'urls': {
            'total_urls': len(url_results),
            'malicious_urls': len(malicious_urls),
            'safe_urls': len(url_results) - len(malicious_urls),
            'severity_distribution': _count_by_level(url_results),
        },
        'logs': {
            'total_log_windows': len(log_results),
            'anomalous_windows': len(anomalous_logs),
            'normal_windows': len(log_results) - len(anomalous_logs),
            'severity_distribution': _count_by_level(log_results),
        },
        'top_alerts': sorted([x for x in (url_results + log_results) if float(x.get('threat_score', 0)) >= 60], key=lambda x: float(x.get('threat_score', 0)), reverse=True)[:10],
    }


def write_dashboard_json(summary: dict, output_path: str):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
