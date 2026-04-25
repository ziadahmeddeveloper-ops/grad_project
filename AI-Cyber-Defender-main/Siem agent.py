"""
siem_agent.py
=============
The bridge between your company's SIEM tool and the AI platform.

Reads logs from:
  - Syslog / log files (default)
  - Splunk REST API
  - Elastic SIEM
  - QRadar
  - Any folder of .log / .txt files

Then normalizes them and sends to SecurityClassifier for analysis.

Usage:
    python agents/siem_agent.py --mode file --path /var/log/syslog
    python agents/siem_agent.py --mode splunk
    python agents/siem_agent.py --mode watch --path /var/log/
"""

import os
import sys
import json
import time
import argparse
import threading
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Iterator

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from models.classifier import SecurityClassifier

# ── Optional imports ──────────────────────────────────────────────────────────
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False


# ─────────────────────────────────────────────────────────────────────────────
# Log Normalizer
# ─────────────────────────────────────────────────────────────────────────────

class LogNormalizer:
    """Parses raw log lines into structured dicts."""

    # Common syslog pattern
    SYSLOG_RE   = r'(\w+ \d+ \d+:\d+:\d+)\s+(\S+)\s+(\S+):\s+(.*)'
    APACHE_RE   = r'(\S+) \S+ \S+ \[([^\]]+)\] "([^"]+)" (\d+) (\d+|-)'
    WINDOWS_RE  = r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(\w+)\s+(\d+)\s+(.*)'

    import re as _re

    @classmethod
    def normalize(cls, raw_line: str, source: str = "unknown") -> dict:
        """
        Convert a raw log string into a normalized dict.
        Returns the original line plus extracted fields.
        """
        normalized = {
            "raw":       raw_line.strip(),
            "source":    source,
            "timestamp": datetime.now().isoformat(),
            "log_id":    hashlib.md5(raw_line.encode()).hexdigest()[:12],
        }

        # Try Apache/Nginx
        import re
        m = re.match(cls.APACHE_RE, raw_line)
        if m:
            normalized.update({
                "log_type": "web",
                "src_ip":   m.group(1),
                "request":  m.group(3),
                "status":   m.group(4),
            })
            return normalized

        # Try Windows Event
        m = re.match(cls.WINDOWS_RE, raw_line)
        if m:
            normalized.update({
                "log_type":  "windows",
                "event_id":  m.group(3),
                "message":   m.group(4),
            })
            return normalized

        # Try Syslog
        m = re.match(cls.SYSLOG_RE, raw_line)
        if m:
            normalized.update({
                "log_type": "network",
                "host":     m.group(2),
                "process":  m.group(3),
                "message":  m.group(4),
            })
            return normalized

        # Generic fallback
        normalized["log_type"] = "unknown"
        return normalized


# ─────────────────────────────────────────────────────────────────────────────
# SIEM Connectors
# ─────────────────────────────────────────────────────────────────────────────

class FileSIEMConnector:
    """Reads logs from a file or directory."""

    def __init__(self, path: str, tail: bool = False):
        self.path = Path(path)
        self.tail = tail

    def stream_logs(self) -> Iterator[str]:
        if self.path.is_file():
            yield from self._read_file(self.path)
        elif self.path.is_dir():
            for log_file in sorted(self.path.glob("*.log")) + sorted(self.path.glob("*.txt")):
                yield from self._read_file(log_file)

    def _read_file(self, filepath: Path) -> Iterator[str]:
        print(f"[SIEM] Reading: {filepath}")
        with open(filepath, "r", errors="replace") as f:
            for line in f:
                line = line.strip()
                if line:
                    yield line


class SplunkSIEMConnector:
    """
    Fetches events from Splunk REST API.
    Configure SPLUNK_HOST, SPLUNK_TOKEN in environment or .env file.
    """

    def __init__(self, host: str = None, token: str = None,
                 search: str = "search index=* earliest=-1h"):
        self.host   = host   or os.getenv("SPLUNK_HOST", "https://localhost:8089")
        self.token  = token  or os.getenv("SPLUNK_TOKEN", "")
        self.search = search

    def stream_logs(self) -> Iterator[str]:
        if not REQUESTS_AVAILABLE:
            print("[ERROR] 'requests' library not installed. Run: pip install requests")
            return

        headers = {"Authorization": f"Bearer {self.token}"}
        url     = f"{self.host}/services/search/jobs/export"
        params  = {"search": self.search, "output_mode": "json"}

        try:
            resp = requests.post(url, headers=headers, params=params,
                                 verify=False, stream=True, timeout=30)
            for line in resp.iter_lines():
                if line:
                    try:
                        event = json.loads(line)
                        raw   = event.get("result", {}).get("_raw", "")
                        if raw:
                            yield raw
                    except json.JSONDecodeError:
                        pass
        except Exception as e:
            print(f"[SPLUNK ERROR] {e}")


class ElasticSIEMConnector:
    """
    Fetches events from Elastic SIEM / Elasticsearch.
    Configure ELASTIC_HOST, ELASTIC_API_KEY in environment.
    """

    def __init__(self, host: str = None, api_key: str = None,
                 index: str = "logs-*"):
        self.host    = host    or os.getenv("ELASTIC_HOST", "http://localhost:9200")
        self.api_key = api_key or os.getenv("ELASTIC_API_KEY", "")
        self.index   = index

    def stream_logs(self) -> Iterator[str]:
        if not REQUESTS_AVAILABLE:
            print("[ERROR] Install requests: pip install requests")
            return

        url     = f"{self.host}/{self.index}/_search"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"ApiKey {self.api_key}",
        }
        body = {
            "size": 500,
            "sort": [{"@timestamp": "desc"}],
            "query": {"range": {"@timestamp": {"gte": "now-1h"}}},
        }

        try:
            resp = requests.post(url, json=body, headers=headers, timeout=30)
            data = resp.json()
            for hit in data.get("hits", {}).get("hits", []):
                msg = (hit.get("_source", {}).get("message") or
                       json.dumps(hit.get("_source", {})))
                if msg:
                    yield msg
        except Exception as e:
            print(f"[ELASTIC ERROR] {e}")


# ─────────────────────────────────────────────────────────────────────────────
# Results Exporter
# ─────────────────────────────────────────────────────────────────────────────

class ResultsExporter:
    """Saves prediction results to JSON / CSV / JSONL."""

    def __init__(self, output_dir: str = "outputs"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._buffer = []

    def append(self, result: dict):
        self._buffer.append(result)

    def save_jsonl(self, filename: str = None):
        filename = filename or f"results_{datetime.now():%Y%m%d_%H%M%S}.jsonl"
        path = self.output_dir / filename
        with open(path, "a") as f:
            for r in self._buffer:
                f.write(json.dumps(r) + "\n")
        print(f"[EXPORT] Saved {len(self._buffer)} records → {path}")
        self._buffer.clear()

    def save_json(self, filename: str = None):
        filename = filename or f"results_{datetime.now():%Y%m%d_%H%M%S}.json"
        path = self.output_dir / filename
        with open(path, "w") as f:
            json.dump(self._buffer, f, indent=2, default=str)
        print(f"[EXPORT] Saved {len(self._buffer)} records → {path}")
        self._buffer.clear()


# ─────────────────────────────────────────────────────────────────────────────
# Main Agent
# ─────────────────────────────────────────────────────────────────────────────

class SIEMAgent:
    """
    Orchestrates: Connector → Normalizer → Classifier → Exporter
    """

    def __init__(self, connector, classifier: SecurityClassifier = None,
                 output_dir: str = "outputs", batch_size: int = 50,
                 alert_callback=None):
        self.connector       = connector
        self.classifier      = classifier or SecurityClassifier()
        self.exporter        = ResultsExporter(output_dir)
        self.normalizer      = LogNormalizer()
        self.batch_size      = batch_size
        self.alert_callback  = alert_callback
        self.processed_count = 0
        self.alert_count     = 0

    def run(self):
        print(f"\n{'='*60}")
        print(f"  Security AI SIEM Agent - Started {datetime.now():%Y-%m-%d %H:%M:%S}")
        print(f"{'='*60}\n")

        batch = []
        for raw_log in self.connector.stream_logs():
            normalized = self.normalizer.normalize(raw_log)
            result     = self.classifier.predict(raw_log)

            # Merge metadata
            result["log_id"]   = normalized.get("log_id")
            result["log_type"] = normalized.get("log_type", "unknown")
            result["source"]   = normalized.get("source", "unknown")

            self._print_result(result)
            self.exporter.append(result)
            self.processed_count += 1

            if result.get("is_attack"):
                self.alert_count += 1
                if self.alert_callback:
                    self.alert_callback(result)

            batch.append(result)
            if len(batch) >= self.batch_size:
                self.exporter.save_jsonl()
                batch.clear()

        # Save remaining
        if self.exporter._buffer:
            self.exporter.save_jsonl()

        print(f"\n[DONE] Processed: {self.processed_count} | Alerts: {self.alert_count}")

    def _print_result(self, r: dict):
        icon = "🚨" if r.get("is_attack") else "✅"
        attacks = [f"{p['attack_type']} ({p['confidence']:.0%})"
                   for p in r.get("predictions", [])]
        attack_str = " | ".join(attacks) if attacks else "—"
        ip = r.get("ip_info", {}).get("attacker_ip", "N/A")

        print(f"{icon} [{r.get('risk_level','?'):8s}] "
              f"Safety:{r.get('safety_score',0):5.1f}% | "
              f"IP:{ip:16s} | "
              f"Device:{r.get('device_type','?'):18s} | "
              f"{attack_str}")


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Security AI SIEM Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python siem_agent.py --mode file --path data/sample_logs/
  python siem_agent.py --mode splunk
  python siem_agent.py --mode elastic --index security-logs-*
        """
    )
    parser.add_argument("--mode",   choices=["file", "splunk", "elastic"],
                        default="file", help="SIEM source")
    parser.add_argument("--path",   default="data/sample_logs/",
                        help="Path to log file or directory (file mode)")
    parser.add_argument("--index",  default="logs-*",
                        help="Elastic index pattern")
    parser.add_argument("--output", default="outputs/",
                        help="Output directory for results")
    parser.add_argument("--demo",   action="store_true",
                        help="Force demo mode (no model files needed)")
    args = parser.parse_args()

    # Choose connector
    if args.mode == "file":
        connector = FileSIEMConnector(args.path)
    elif args.mode == "splunk":
        connector = SplunkSIEMConnector()
    elif args.mode == "elastic":
        connector = ElasticSIEMConnector(index=args.index)

    clf   = SecurityClassifier(demo_mode=args.demo or None)
    agent = SIEMAgent(connector, clf, output_dir=args.output)
    agent.run()


if __name__ == "__main__":
    main()