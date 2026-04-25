"""
report_engine.py
================
Generates Daily / Weekly / Monthly security reports from prediction results.

Output formats: HTML (beautiful, standalone) + JSON summary

Usage:
    from reports.report_engine import ReportEngine
    engine = ReportEngine(results_dir="outputs/")
    engine.generate_daily()
    engine.generate_weekly()
    engine.generate_monthly()

    # Or via CLI:
    python reports/report_engine.py --type daily
    python reports/report_engine.py --type weekly --output reports/
"""

import os
import sys
import json
import argparse
from datetime import datetime, timedelta
from pathlib import Path
from collections import Counter, defaultdict
from typing import List, Dict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ─────────────────────────────────────────────────────────────────────────────
# Data Loader
# ─────────────────────────────────────────────────────────────────────────────

class ResultsLoader:
    """Loads prediction results from JSONL / JSON files."""

    def __init__(self, results_dir: str = "outputs"):
        self.results_dir = Path(results_dir)

    def load_range(self, start: datetime, end: datetime) -> List[Dict]:
        """Load all results within a date range."""
        all_results = []

        for path in sorted(self.results_dir.glob("*.jsonl")):
            try:
                with open(path) as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        record = json.loads(line)
                        ts = datetime.fromisoformat(
                            record.get("timestamp", "2000-01-01")
                        )
                        if start <= ts <= end:
                            all_results.append(record)
            except Exception:
                pass

        for path in sorted(self.results_dir.glob("*.json")):
            try:
                with open(path) as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        for record in data:
                            ts = datetime.fromisoformat(
                                record.get("timestamp", "2000-01-01")
                            )
                            if start <= ts <= end:
                                all_results.append(record)
            except Exception:
                pass

        return all_results

    def load_demo(self, n: int = 200) -> List[Dict]:
        """Generate realistic fake data when no real results exist."""
        import random
        rng = random.Random(42)
        attack_types = [
            "Normal", "DDoS", "SQL Injection", "XSS", "Brute Force",
            "Port Scan", "Ransomware", "Privilege Escalation", "MITM",
        ]
        device_types = [
            "Web Server", "Router / Firewall", "Windows Endpoint",
            "Database Server", "Linux Server",
        ]
        ips = [f"185.{rng.randint(1,254)}.{rng.randint(1,254)}.{rng.randint(1,254)}"
               for _ in range(20)]

        results = []
        now = datetime.now()
        for i in range(n):
            ts = now - timedelta(hours=rng.randint(0, 720))
            attack = rng.choices(attack_types, weights=[45,8,10,8,9,7,3,6,4], k=1)[0]
            is_atk = attack != "Normal"
            score  = rng.uniform(10, 45) if is_atk else rng.uniform(75, 99)
            results.append({
                "timestamp":   ts.isoformat(),
                "attack_type": attack,
                "is_attack":   is_atk,
                "safety_score": round(score, 1),
                "risk_level":  "Critical" if score < 25 else
                               "High"     if score < 50 else
                               "Medium"   if score < 70 else
                               "Low"      if score < 90 else "Safe",
                "device_type": rng.choice(device_types),
                "ip_info":     {"attacker_ip": rng.choice(ips) if is_atk else "N/A"},
            })
        return results


# ─────────────────────────────────────────────────────────────────────────────
# Statistics Calculator
# ─────────────────────────────────────────────────────────────────────────────

class StatsCalculator:
    def __init__(self, records: List[Dict]):
        self.records = records

    def compute(self) -> Dict:
        if not self.records:
            return self._empty_stats()

        total     = len(self.records)
        attacks   = [r for r in self.records if r.get("is_attack")]
        normals   = [r for r in self.records if not r.get("is_attack")]

        attack_types = Counter()
        for r in attacks:
            # Support both old and new format
            atype = r.get("attack_type") or (
                r.get("predictions", [{}])[0].get("attack_type", "Unknown")
                if r.get("predictions") else "Unknown"
            )
            attack_types[atype] += 1

        device_types  = Counter(r.get("device_type", "Unknown") for r in self.records)
        risk_levels   = Counter(r.get("risk_level", "Unknown") for r in self.records)
        attacker_ips  = Counter(
            r.get("ip_info", {}).get("attacker_ip", "N/A")
            for r in attacks
            if r.get("ip_info", {}).get("attacker_ip") not in ("N/A", None)
        )

        safety_scores = [r.get("safety_score", 100) for r in self.records]
        avg_safety    = round(sum(safety_scores) / len(safety_scores), 1)

        # Hourly distribution
        hourly = defaultdict(int)
        for r in attacks:
            try:
                h = datetime.fromisoformat(r["timestamp"]).hour
                hourly[h] += 1
            except Exception:
                pass

        return {
            "total_logs":    total,
            "total_attacks": len(attacks),
            "total_normal":  len(normals),
            "attack_rate":   round(len(attacks) / total * 100, 1) if total else 0,
            "avg_safety":    avg_safety,
            "top_attacks":   attack_types.most_common(10),
            "top_devices":   device_types.most_common(5),
            "risk_levels":   dict(risk_levels),
            "top_ips":       attacker_ips.most_common(10),
            "hourly_attacks": dict(hourly),
        }

    def _empty_stats(self) -> Dict:
        return {
            "total_logs": 0, "total_attacks": 0, "total_normal": 0,
            "attack_rate": 0, "avg_safety": 100,
            "top_attacks": [], "top_devices": [], "risk_levels": {},
            "top_ips": [], "hourly_attacks": {},
        }


# ─────────────────────────────────────────────────────────────────────────────
# HTML Report Builder
# ─────────────────────────────────────────────────────────────────────────────

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security AI Report - {report_type} - {date_label}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
    background: #0f1117; color: #e2e8f0; min-height: 100vh;
  }}
  .header {{
    background: linear-gradient(135deg, #1a1f2e 0%, #0d1117 100%);
    border-bottom: 1px solid #1e40af;
    padding: 2rem 3rem;
    display: flex; justify-content: space-between; align-items: center;
  }}
  .header h1 {{ font-size: 1.6rem; color: #60a5fa; font-weight: 600; }}
  .header .meta {{ text-align: right; color: #64748b; font-size: 0.85rem; }}
  .header .meta strong {{ color: #94a3b8; }}
  .container {{ max-width: 1200px; margin: 0 auto; padding: 2rem 3rem; }}

  .stats-grid {{
    display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 1rem; margin-bottom: 2rem;
  }}
  .stat-card {{
    background: #1a1f2e; border: 1px solid #1e293b;
    border-radius: 12px; padding: 1.25rem;
    text-align: center;
  }}
  .stat-card .value {{
    font-size: 2.2rem; font-weight: 700; line-height: 1;
    margin-bottom: 0.25rem;
  }}
  .stat-card .label {{ color: #64748b; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; }}
  .val-blue {{ color: #60a5fa; }}
  .val-red {{ color: #f87171; }}
  .val-green {{ color: #4ade80; }}
  .val-yellow {{ color: #fbbf24; }}

  .section {{
    background: #1a1f2e; border: 1px solid #1e293b;
    border-radius: 12px; padding: 1.5rem; margin-bottom: 1.5rem;
  }}
  .section h2 {{
    font-size: 1rem; font-weight: 600; color: #94a3b8;
    text-transform: uppercase; letter-spacing: 0.08em;
    margin-bottom: 1.25rem; padding-bottom: 0.75rem;
    border-bottom: 1px solid #1e293b;
  }}

  .bar-row {{
    display: flex; align-items: center; gap: 0.75rem;
    margin-bottom: 0.6rem;
  }}
  .bar-label {{ width: 180px; font-size: 0.85rem; color: #94a3b8; flex-shrink: 0; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
  .bar-track {{ flex: 1; background: #0f1117; border-radius: 4px; height: 8px; overflow: hidden; }}
  .bar-fill {{ height: 100%; border-radius: 4px; background: #3b82f6; transition: width 0.3s; }}
  .bar-fill.red {{ background: #ef4444; }}
  .bar-fill.yellow {{ background: #f59e0b; }}
  .bar-fill.green {{ background: #22c55e; }}
  .bar-count {{ width: 40px; text-align: right; font-size: 0.82rem; color: #64748b; }}

  .hourly-grid {{
    display: grid; grid-template-columns: repeat(24, 1fr);
    gap: 3px; align-items: end; height: 80px;
  }}
  .hour-bar {{ background: #1e3a5f; border-radius: 2px 2px 0 0; min-height: 4px; }}
  .hour-labels {{
    display: grid; grid-template-columns: repeat(24, 1fr);
    margin-top: 4px;
  }}
  .hour-labels span {{ font-size: 9px; color: #334155; text-align: center; }}

  .ip-table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
  .ip-table th {{ text-align: left; padding: 0.5rem 0.75rem; color: #475569; font-weight: 500; border-bottom: 1px solid #1e293b; }}
  .ip-table td {{ padding: 0.5rem 0.75rem; border-bottom: 1px solid #1a2236; }}
  .ip-table tr:last-child td {{ border-bottom: none; }}
  .badge {{
    display: inline-block; padding: 2px 8px; border-radius: 4px;
    font-size: 0.75rem; font-weight: 500;
  }}
  .badge-red {{ background: #450a0a; color: #f87171; }}
  .badge-yellow {{ background: #451a03; color: #fbbf24; }}
  .badge-blue {{ background: #172554; color: #60a5fa; }}
  .badge-green {{ background: #052e16; color: #4ade80; }}

  .footer {{
    text-align: center; padding: 2rem;
    color: #334155; font-size: 0.8rem;
    border-top: 1px solid #1e293b; margin-top: 2rem;
  }}

  @media print {{
    body {{ background: white; color: #1a1a2e; }}
    .header, .section, .stat-card {{ border-color: #e2e8f0; }}
  }}
</style>
</head>
<body>
<div class="header">
  <div>
    <h1>🛡️ Security AI — {report_type} Report</h1>
    <div style="color:#475569;font-size:0.85rem;margin-top:4px">{period_label}</div>
  </div>
  <div class="meta">
    <div>Generated: <strong>{generated_at}</strong></div>
    <div>Total Logs Analyzed: <strong>{total_logs}</strong></div>
  </div>
</div>

<div class="container">

  <!-- Stats Grid -->
  <div class="stats-grid">
    <div class="stat-card">
      <div class="value val-blue">{total_logs}</div>
      <div class="label">Logs Analyzed</div>
    </div>
    <div class="stat-card">
      <div class="value val-red">{total_attacks}</div>
      <div class="label">Attacks Detected</div>
    </div>
    <div class="stat-card">
      <div class="value val-yellow">{attack_rate}%</div>
      <div class="label">Attack Rate</div>
    </div>
    <div class="stat-card">
      <div class="value val-green">{avg_safety}%</div>
      <div class="label">Avg Safety Score</div>
    </div>
    <div class="stat-card">
      <div class="value" style="color:{critical_color}">{critical_count}</div>
      <div class="label">Critical Alerts</div>
    </div>
  </div>

  <!-- Attack Types -->
  <div class="section">
    <h2>Top Attack Types</h2>
    {attack_bars}
  </div>

  <!-- Hourly Distribution -->
  <div class="section">
    <h2>Attack Hourly Distribution (24h)</h2>
    <div class="hourly-grid">
      {hour_bars}
    </div>
    <div class="hour-labels">
      {hour_labels}
    </div>
  </div>

  <!-- Device Types -->
  <div class="section">
    <h2>Affected Device Types</h2>
    {device_bars}
  </div>

  <!-- Top Attacker IPs -->
  <div class="section">
    <h2>Top Attacker IPs</h2>
    <table class="ip-table">
      <thead>
        <tr>
          <th>#</th><th>IP Address</th><th>Hit Count</th><th>Risk</th>
        </tr>
      </thead>
      <tbody>
        {ip_rows}
      </tbody>
    </table>
  </div>

  <!-- Risk Level Breakdown -->
  <div class="section">
    <h2>Risk Level Breakdown</h2>
    {risk_bars}
  </div>

</div>
<div class="footer">
  Security AI Platform — Graduation Project &nbsp;|&nbsp; Report auto-generated {generated_at}
</div>
</body>
</html>"""


class HTMLReportBuilder:
    def build(self, stats: Dict, report_type: str, period_label: str,
              date_label: str) -> str:
        def make_bars(items, max_val=None, color=""):
            if not items:
                return '<div style="color:#334155;font-size:0.85rem">No data</div>'
            mx = max_val or max(c for _, c in items) or 1
            rows = []
            for label, count in items:
                pct = round(count / mx * 100)
                fill_class = f"bar-fill {color}" if color else "bar-fill"
                rows.append(
                    f'<div class="bar-row">'
                    f'<div class="bar-label">{label}</div>'
                    f'<div class="bar-track"><div class="{fill_class}" style="width:{pct}%"></div></div>'
                    f'<div class="bar-count">{count}</div>'
                    f'</div>'
                )
            return "\n".join(rows)

        # Hourly bars
        hourly = stats["hourly_attacks"]
        max_h  = max(hourly.values(), default=1)
        hour_bars = ""
        for h in range(24):
            cnt = hourly.get(h, 0)
            hpct = round(cnt / max_h * 100) if max_h else 0
            color = "#ef4444" if cnt == max_h and max_h > 0 else "#3b82f6"
            hour_bars += (
                f'<div class="hour-bar" style="height:{max(hpct,5)}%;background:{color}" '
                f'title="{h:02d}:00 — {cnt} attacks"></div>'
            )
        hour_labels = "".join(
            f'<span>{h:02d}</span>' for h in range(24)
        )

        # IP rows
        ip_rows = ""
        for i, (ip, cnt) in enumerate(stats["top_ips"], 1):
            badge = ("badge-red" if cnt > 20 else "badge-yellow" if cnt > 5 else "badge-blue")
            risk  = ("Critical"  if cnt > 20 else "High"         if cnt > 5 else "Medium")
            ip_rows += (
                f'<tr><td>{i}</td><td><code style="color:#7dd3fc">{ip}</code></td>'
                f'<td>{cnt}</td>'
                f'<td><span class="badge {badge}">{risk}</span></td></tr>'
            )
        if not ip_rows:
            ip_rows = '<tr><td colspan="4" style="color:#334155;text-align:center">No attack IPs recorded</td></tr>'

        risk_colors = {
            "Critical": "red", "High": "red", "Medium": "yellow",
            "Low": "green", "Safe": "green",
        }
        risk_items = [(k, v) for k, v in stats["risk_levels"].items()]

        critical_count = stats["risk_levels"].get("Critical", 0)
        critical_color = "#f87171" if critical_count > 0 else "#4ade80"

        return HTML_TEMPLATE.format(
            report_type     = report_type,
            date_label      = date_label,
            period_label    = period_label,
            generated_at    = datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total_logs      = stats["total_logs"],
            total_attacks   = stats["total_attacks"],
            attack_rate     = stats["attack_rate"],
            avg_safety      = stats["avg_safety"],
            critical_count  = critical_count,
            critical_color  = critical_color,
            attack_bars     = make_bars(stats["top_attacks"], color="red"),
            device_bars     = make_bars(stats["top_devices"]),
            risk_bars       = make_bars(
                [(k, v) for k, v in stats["risk_levels"].items()],
                color=""
            ),
            hour_bars       = hour_bars,
            hour_labels     = hour_labels,
            ip_rows         = ip_rows,
        )


# ─────────────────────────────────────────────────────────────────────────────
# Main Report Engine
# ─────────────────────────────────────────────────────────────────────────────

class ReportEngine:
    def __init__(self, results_dir: str = "outputs",
                 output_dir: str = "reports"):
        self.loader   = ResultsLoader(results_dir)
        self.builder  = HTMLReportBuilder()
        self.out_dir  = Path(output_dir)
        self.out_dir.mkdir(parents=True, exist_ok=True)

    def _generate(self, start: datetime, end: datetime,
                  report_type: str, filename: str) -> str:
        records = self.loader.load_range(start, end)

        if not records:
            print(f"[REPORT] No real data found for {report_type}. Using demo data.")
            records = self.loader.load_demo()

        stats       = StatsCalculator(records).compute()
        period_label = f"{start.strftime('%Y-%m-%d')} → {end.strftime('%Y-%m-%d')}"
        date_label  = end.strftime("%B %d, %Y")
        html        = self.builder.build(stats, report_type, period_label, date_label)

        path = self.out_dir / filename
        with open(path, "w") as f:
            f.write(html)

        # Save JSON summary alongside
        json_path = self.out_dir / filename.replace(".html", "_summary.json")
        with open(json_path, "w") as f:
            json.dump({"period": period_label, "stats": stats,
                       "generated": datetime.now().isoformat()}, f, indent=2)

        print(f"[REPORT] ✅ {report_type} report saved → {path}")
        return str(path)

    def generate_daily(self, date: datetime = None) -> str:
        date  = date or datetime.now()
        start = date.replace(hour=0, minute=0, second=0, microsecond=0)
        end   = date.replace(hour=23, minute=59, second=59)
        name  = f"daily_{date.strftime('%Y%m%d')}.html"
        return self._generate(start, end, "Daily", name)

    def generate_weekly(self, end_date: datetime = None) -> str:
        end   = end_date or datetime.now()
        start = end - timedelta(days=7)
        name  = f"weekly_{end.strftime('%Y%m%d')}.html"
        return self._generate(start, end, "Weekly", name)

    def generate_monthly(self, year: int = None, month: int = None) -> str:
        now   = datetime.now()
        year  = year  or now.year
        month = month or now.month
        start = datetime(year, month, 1)
        end   = datetime(year, month + 1, 1) - timedelta(seconds=1) \
                if month < 12 else datetime(year + 1, 1, 1) - timedelta(seconds=1)
        name  = f"monthly_{year}_{month:02d}.html"
        return self._generate(start, end, "Monthly", name)


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Security AI Report Generator")
    parser.add_argument("--type",   choices=["daily", "weekly", "monthly", "all"],
                        default="all")
    parser.add_argument("--input",  default="outputs/",   help="Results directory")
    parser.add_argument("--output", default="reports/",   help="Reports output directory")
    args = parser.parse_args()

    engine = ReportEngine(results_dir=args.input, output_dir=args.output)

    if args.type in ("daily",   "all"): engine.generate_daily()
    if args.type in ("weekly",  "all"): engine.generate_weekly()
    if args.type in ("monthly", "all"): engine.generate_monthly()


if __name__ == "__main__":
    main()