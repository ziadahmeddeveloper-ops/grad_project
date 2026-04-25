from datetime import datetime
from typing import Any, Dict, List

IP_KEYS = ['src_ip', 'source_ip', 'client_ip', 'ip', 'remote_addr', 'remote_ip', 'destination_ip', 'dst_ip']
USER_KEYS = ['username', 'user_name', 'user', 'account_name', 'targetusername', 'subjectusername', 'login_user']
TIME_KEYS = ['timestamp', 'date_and_time', 'event_time', 'time', '@timestamp']
HOST_KEYS = ['host', 'hostname', 'computer', 'machine_name', 'server_name']


def _first_present(row: Dict[str, Any], keys: List[str], default: Any = None):
    lower_map = {str(k).lower(): v for k, v in row.items()}
    for key in keys:
        if key.lower() in lower_map and str(lower_map[key.lower()]).strip() not in ('', 'nan', 'None'):
            return lower_map[key.lower()]
    return default


def normalize_record(row: Dict[str, Any]) -> Dict[str, Any]:
    return {str(k).strip().lower().replace(' ', '_'): v for k, v in row.items()}


def extract_context(row: Dict[str, Any]) -> Dict[str, Any]:
    row = normalize_record(row)
    return {
        'source_ip': _first_present(row, IP_KEYS),
        'username': _first_present(row, USER_KEYS),
        'event_time': _first_present(row, TIME_KEYS, datetime.utcnow().isoformat() + 'Z'),
        'host': _first_present(row, HOST_KEYS),
    }


def _contains(text: str, patterns: List[str]) -> bool:
    text = (text or '').lower()
    return any(p.lower() in text for p in patterns)


def classify_windows_attack(row: Dict[str, Any]) -> str:
    row = normalize_record(row)
    event_id = str(row.get('event_id') or '')
    msg = str(row.get('task_category') or row.get('message') or '')
    if event_id == '4625' or _contains(msg, ['failed logon', 'failed login']):
        return 'Brute Force / Failed Logon'
    if event_id == '4688' or _contains(msg, ['process creation', 'powershell', 'cmd.exe', 'wscript', 'cscript']):
        return 'Suspicious Process Execution'
    if event_id == '4797' or _contains(msg, ['blank password', 'query the existence']):
        return 'Account Enumeration'
    if event_id == '4799' or _contains(msg, ['group membership was enumerated']):
        return 'Privilege Enumeration'
    if _contains(msg, ['special privileges assigned', 'privilege']):
        return 'Privilege Escalation Activity'
    return 'Windows Anomaly'


def classify_web_attack(row: Dict[str, Any]) -> str:
    row = normalize_record(row)
    has_sql = int(row.get('has_sql_keywords', 0) or 0)
    has_xss = int(row.get('has_xss_keywords', 0) or 0)
    has_traversal = int(row.get('has_traversal', 0) or 0)
    has_cmd = int(row.get('has_cmd_injection', 0) or 0)
    raw = ' '.join([
        str(row.get('url', '')), str(row.get('query', '')), str(row.get('content', '')),
        str(row.get('body', '')), str(row.get('user_agent', '')), str(row.get('classification', '')),
    ]).lower()
    if has_sql == 1 or _contains(raw, ['union select', "' or 1=1", '--', 'sqlmap', 'drop table', '%27']):
        return 'SQL Injection'
    if has_xss == 1 or _contains(raw, ['<script', 'javascript:', 'alert(', '%3cscript']):
        return 'Cross-Site Scripting (XSS)'
    if has_traversal == 1 or _contains(raw, ['../', '%2e%2e%2f', '..\\']):
        return 'Path Traversal'
    if has_cmd == 1 or _contains(raw, ['cmd=', ';wget', ';curl', '|whoami', 'powershell']):
        return 'Command Injection'
    if _contains(raw, ['/login', '401', '403']) and _contains(raw, ['bot', 'python-requests', 'sqlmap']):
        return 'Web Brute Force / Automated Abuse'
    return 'Web Anomaly'


def classify_network_attack(row: Dict[str, Any]) -> str:
    row = normalize_record(row)
    text = ' '.join(str(v) for v in row.values()).lower()
    try:
        flow_pkts = float(row.get('flow_packets/s', row.get('flow_packets_s', row.get('flow_packets_per_s', row.get('flow_packets_per_second', 0)))) or 0)
    except Exception:
        flow_pkts = 0.0
    try:
        syn_count = float(row.get('syn_flag_count', 0) or 0)
    except Exception:
        syn_count = 0.0
    try:
        flow_bytes = float(row.get('flow_bytes/s', row.get('flow_bytes_s', row.get('flow_bytes_per_s', 0))) or 0)
    except Exception:
        flow_bytes = 0.0
    if _contains(text, ['ddos', 'dos', 'hulk', 'goldeneye', 'slowloris']):
        return 'DDoS / DoS'
    if syn_count > 20 or _contains(text, ['portscan', 'scan']):
        return 'Port Scan / Reconnaissance'
    if _contains(text, ['bot', 'infiltration', 'c2']):
        return 'Botnet / C2 Activity'
    if flow_pkts > 10000 or flow_bytes > 1000000:
        return 'High-Rate Network Flood'
    return 'Network Anomaly'


def classify_url_attack(url: str, prediction: str, score: float) -> str:
    u = (url or '').lower()
    if prediction != 'malicious':
        return 'Safe URL'
    if any(x in u for x in ['login', 'signin', 'verify', 'bank', 'account', 'update']):
        return 'Phishing URL'
    if any(x in u for x in ['.exe', '.zip', 'payload', 'download']):
        return 'Malware Delivery URL'
    return 'Malicious URL'


def recommend_actions(source: str, attack_type: str, level: str) -> List[str]:
    level = str(level).lower()
    recs = []
    if source in ('network', 'web'):
        recs.append('Block or rate-limit the source IP on the firewall/WAF.')
    if source == 'windows':
        recs.append('Review the affected host and recent Windows security events around the same time.')
    if 'Phishing' in attack_type or 'Malicious URL' in attack_type:
        recs.append('Block the URL/domain and warn affected users immediately.')
    if 'SQL Injection' in attack_type:
        recs.append('Inspect the vulnerable endpoint, sanitize inputs, and review recent database queries.')
    if 'Cross-Site Scripting' in attack_type:
        recs.append('Encode output, validate input, and inspect recent reflected/stored payloads.')
    if 'Brute Force' in attack_type:
        recs.append('Reset impacted credentials, enable MFA, and review failed login spikes.')
    if 'Privilege' in attack_type:
        recs.append('Audit group memberships/privileges and verify whether the change was authorized.')
    if 'Process Execution' in attack_type:
        recs.append('Inspect spawned processes, command lines, and isolate the host if needed.')
    if not recs:
        recs.append('Review the raw log context and correlate with nearby events before taking action.')
    if level in ('high', 'critical'):
        recs.append('Escalate to the security team and open an incident ticket.')
    return recs[:4]


def enrich_log_alert(base_result: Dict[str, Any], original_row: Dict[str, Any], source: str) -> Dict[str, Any]:
    row = normalize_record(original_row)
    ctx = extract_context(row)
    if base_result.get('prediction') == 'normal':
        attack_type = 'Normal Activity'
    else:
        if source == 'windows':
            attack_type = classify_windows_attack(row)
        elif source == 'web':
            attack_type = classify_web_attack(row)
        else:
            attack_type = classify_network_attack(row)
    enriched = dict(base_result)
    enriched.update(ctx)
    enriched['attack_type'] = attack_type
    enriched['recommended_actions'] = recommend_actions(source, attack_type, base_result.get('threat_level', 'low'))
    enriched['raw_context'] = {k: row.get(k) for k in ['url', 'query', 'event_id', 'source', 'task_category', 'message', 'host', 'method', 'src_ip', 'source_ip', 'username'] if k in row}
    return enriched


def enrich_url_alert(base_result: Dict[str, Any]) -> Dict[str, Any]:
    attack_type = classify_url_attack(base_result.get('url', ''), base_result.get('prediction', 'safe'), float(base_result.get('threat_score', 0)))
    enriched = dict(base_result)
    enriched['attack_type'] = attack_type
    enriched['recommended_actions'] = recommend_actions('url', attack_type, base_result.get('threat_level', 'low'))
    return enriched
