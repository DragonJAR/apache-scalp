"""JSON reporter for Scalp, designed for SIEM, DevSecOps pipelines, and automation."""
from datetime import datetime
import json
import time
from scalp.core.engine import ScanResult
from scalp.core.rules import ATTACK_NAMES
from scalp.reporters.base import BaseReporter


class JsonReporter(BaseReporter):
    @classmethod
    def generate(cls, result: ScanResult, output_path: str, source_name: str = "") -> None:
        data = {
            "metadata": {
                "generator": "Scalp! Modernized Edition",
                "version": "1.0.0",
                "source_file": source_name,
                "generated_at": datetime.now().isoformat(),
            },
            "summary": {
                "total_lines": result.total_lines,
                "processed_lines": result.processed_lines,
                "unmatched_lines": len(result.unmatched_lines),
                "total_matches": len(result.matches),
                "duration_seconds": round(result.elapsed_seconds, 4),
            },
            "matches": [
                {
                    "ip": m.entry.ip,
                    "method": m.entry.method,
                    "url": m.entry.url,
                    "protocol": m.entry.protocol,
                    "status_code": m.entry.status_code,
                    "bytes_sent": m.entry.bytes_sent,
                    "user_agent": m.entry.user_agent,
                    "referrer": m.entry.referrer,
                    "timestamp": m.entry.timestamp.isoformat() if m.entry.timestamp else None,
                    "tag": m.tag,
                    "attack_type": ATTACK_NAMES.get(m.tag.lower(), m.tag.upper()),
                    "impact": m.rule.impact,
                    "rule_id": m.rule.rule_id,
                    "description": m.rule.description,
                    "matched_token": m.matched_string,
                    "raw_line": m.entry.raw_line,
                }
                for m in result.matches
            ],
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
