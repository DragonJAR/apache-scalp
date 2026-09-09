#!/usr/bin/env python3
"""
    Anathema heuristic module
    by Nanopony
    Modernized by DragonJAR SAS

    Licensed under the Apache License, Version 2.0.
"""
from datetime import datetime
import json
from pathlib import Path
import sys
import regex as re

SIGNATURES_FILE = Path(__file__).parent / "signature.json"


class AbstractSignatureBase:
    def analyse(self, ip, method, url, agent):
        return 0


class JsonSignatureBase:
    def __init__(self, sig_file=None):
        path = Path(sig_file) if sig_file else SIGNATURES_FILE
        if not path.is_file():
            raise FileNotFoundError(f"Signature file not found: {path}")

        with open(path, "r", encoding="utf-8") as rf:
            raw = rf.read()
        self._json = json.loads(raw)
        self._compile_signatures()

    def _compile_signatures(self):
        self._signatures = []
        for s in self._json.get("signatures", []):
            self._signatures.append((
                re.compile(s["q"], re.IGNORECASE),
                int(s.get("s", 5)),
            ))

    def analyse(self, ip, method, url, agent):
        for s in self._signatures:
            if s[0].search(url) or (agent and s[0].search(agent)):
                return s[1]
        return 0


class Violator:
    def __init__(self, ip):
        self.ip = ip
        self.violations = []
        self.should_be_banned = False

    def pretty_print(self):
        status = "[BUSTED]" if self.should_be_banned else ""
        print(f"Violator: {self.ip} {status}")
        print("Crimes:")
        for v in self.violations:
            print(f"  {v[0]} {v[1]} {v[2]} : {v[3]}")
        print("")

    def push_violation(self, date, method, url, agent, severity):
        self.latest_violation = date
        self.violations.append((method, url, agent, severity))
        if severity >= 10:
            self.should_be_banned = True
        return self.should_be_banned

    def push_evidence(self, date, method, url, agent):
        self.violations.append((method, url, agent, 10))


class Anathema:
    def __init__(self, filename, sig_file=None):
        self.filename = filename
        self.heuristic = JsonSignatureBase(sig_file)
        self.purgatory = dict()
        self.jail = set()

    def parse_log(self):
        from scalp.core.parser import LogParser

        for _, entry, _ in LogParser.stream_file(self.filename):
            if not entry:
                continue

            ip = entry.ip
            if ip in self.jail:
                self.purgatory[ip].push_evidence(entry.timestamp, entry.method, entry.url, entry.user_agent)
                continue

            sev = self.heuristic.analyse(ip, entry.method, entry.url, entry.user_agent)
            if sev > 0:
                if ip not in self.purgatory:
                    self.purgatory[ip] = Violator(ip)
                if self.purgatory[ip].push_violation(entry.timestamp, entry.method, entry.url, entry.user_agent, sev):
                    self.jail.add(ip)

        for _, violator in self.purgatory.items():
            violator.pretty_print()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 -m anathema.anathema <access_log>")
        sys.exit(0)

    a = Anathema(sys.argv[1])
    a.parse_log()