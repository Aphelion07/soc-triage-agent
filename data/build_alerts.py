"""Builds a synthetic-but-realistic labelled SOC alert dataset.

Five detection rules, each firing on both a genuine incident and a
benign look-alike that trips the same rule for an innocent reason - the
actual shape of SOC alert fatigue: the same signature that catches an SSH
brute-force also catches a developer who mistyped their password, the same
WAF rule that blocks real SQL injection also blocks a book search for a
title with "SELECT" in it. Telling the two apart is the whole triage
problem; a dataset where the rule alone determines the label would let a
lookup table pass for a triage agent.

Two categories are deliberately harder than the rest. ``port_scan_detected``
sees similarly bursty history for a real scan and a health-check-style
prober, so history alone doesn't discriminate. ``outbound_beacon`` sees a
lower threat-intel hit rate for the malicious case (new C2 infrastructure is
often unlisted) and a similarly periodic history for a legitimate telemetry
service - which is the same reason malware beaconing was the hardest class
in this portfolio's ``finetune-lora`` project, just approached from the
agent side instead of the classifier side this time.

Deterministic on a seed: the same seed always produces the same dataset.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import random
from dataclasses import dataclass
from pathlib import Path

from soc_triage.world import ASSET_CRITICALITY

RULES = [
    "ssh_auth_failures",
    "sql_injection_pattern",
    "xss_pattern_waf",
    "port_scan_detected",
    "outbound_beacon",
]

_HOSTS = list(ASSET_CRITICALITY)
_DGA_TLDS = ["top", "xyz", "biz", "info", "cn", "ru"]
_VENDOR_DOMAINS = [
    "telemetry.vendor-analytics.com",
    "status.cloudmonitor.io",
    "beacon.saas-metrics.net",
    "ping.uptime-service.com",
]
_SQLI_PAYLOADS = [
    "1' OR '1'='1",
    "1; DROP TABLE users--",
    "' UNION SELECT username,password FROM users--",
    "admin'--",
    "1' AND SLEEP(5)--",
]
_XSS_PAYLOADS = [
    "<script>alert(document.cookie)</script>",
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
    "<svg onload=alert(1)>",
]
_LEGIT_SQL_LIKE_SEARCHES = [
    "SELECT poems by Robert Frost",
    "how to write a SELECT statement in SQL",
    "union select tutorial for beginners",
    "DROP shipping vs standard shipping comparison",
    "delete from cart button not working",
]
_LEGIT_MARKUP_TEXT = [
    "<3 this new feature, well done team",
    'code sample: <div class="container">hello</div>',
    "review: 'the onerror handling in v2 finally works great'",
    "forum post about <canvas> element performance",
]
_SCANNER_USERNAMES = ["root", "admin", "administrator", "oracle", "postgres", "test"]
_REAL_USERNAMES = ["alice", "bmueller", "j.schmidt", "k.wagner"]


def _rand_ip(rng: random.Random, private: bool = False) -> str:
    if private:
        return f"10.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
    while True:
        addr = ipaddress.IPv4Address(rng.randint(1, 2**32 - 1))
        if not (addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_multicast):
            return str(addr)


def _rand_dga_domain(rng: random.Random) -> str:
    consonants, vowels = "bcdfghjklmnpqrstvwxz", "aeiouy"
    length = rng.randint(8, 14)
    chars = [rng.choice(consonants if i % 2 == 0 else vowels) for i in range(length)]
    return f"{''.join(chars)}.{rng.choice(_DGA_TLDS)}"


@dataclass(frozen=True)
class Alert:
    id: str
    rule: str
    summary: str
    hostname: str
    indicator: str
    threat_intel_reputation: str
    recent_alert_count: int
    malicious: bool
    severity: str


def _reputation(rng: random.Random, malicious: bool, hit_rate: float) -> str:
    if not malicious:
        return "clean"
    return "known_malicious" if rng.random() < hit_rate else rng.choice(["suspicious", "unknown"])


def _ssh_auth_failures(rng: random.Random, malicious: bool) -> Alert:
    host = rng.choice(_HOSTS)
    if malicious:
        user = rng.choice(_SCANNER_USERNAMES)
        ip = _rand_ip(rng)
        count = rng.randint(8, 40)
        summary = (
            f"{count} failed SSH logins for user '{user}' from {ip} against {host} "
            "in the last 10 minutes"
        )
        severity = rng.choice(["medium", "high", "high", "critical"])
        reputation = _reputation(rng, True, hit_rate=0.6)
    else:
        user = rng.choice(_REAL_USERNAMES)
        ip = _rand_ip(rng, private=True)
        count = rng.randint(1, 3)
        summary = (
            f"{count} failed SSH login(s) for user '{user}' from {ip} against {host}, "
            "no lockout triggered"
        )
        severity = "none"
        reputation = "clean"
    return Alert("", "ssh_auth_failures", summary, host, ip, reputation, count, malicious, severity)


def _sql_injection_pattern(rng: random.Random, malicious: bool) -> Alert:
    host = rng.choice(_HOSTS)
    ip = _rand_ip(rng)
    if malicious:
        payload = rng.choice(_SQLI_PAYLOADS)
        count = rng.randint(5, 30)
        summary = f"WAF flagged SQLi pattern '{payload}' in {count} requests to {host} from {ip}"
        severity = rng.choice(["high", "high", "critical"])
        reputation = _reputation(rng, True, hit_rate=0.5)
    else:
        query = rng.choice(_LEGIT_SQL_LIKE_SEARCHES)
        count = rng.randint(1, 2)
        summary = f"WAF flagged SQLi-like pattern in search query '{query}' to {host} from {ip}"
        severity = "none"
        reputation = "clean"
    return Alert(
        "", "sql_injection_pattern", summary, host, ip, reputation, count, malicious, severity
    )


def _xss_pattern_waf(rng: random.Random, malicious: bool) -> Alert:
    host = rng.choice(_HOSTS)
    ip = _rand_ip(rng)
    if malicious:
        payload = rng.choice(_XSS_PAYLOADS)
        count = rng.randint(3, 15)
        summary = f"WAF flagged XSS payload '{payload}' in {count} requests to {host} from {ip}"
        severity = rng.choice(["medium", "high", "high"])
        reputation = _reputation(rng, True, hit_rate=0.5)
    else:
        text = rng.choice(_LEGIT_MARKUP_TEXT)
        count = rng.randint(1, 2)
        summary = f"WAF flagged XSS-like markup in submitted text '{text}' to {host} from {ip}"
        severity = "none"
        reputation = "clean"
    return Alert("", "xss_pattern_waf", summary, host, ip, reputation, count, malicious, severity)


def _port_scan_detected(rng: random.Random, malicious: bool) -> Alert:
    host = rng.choice(_HOSTS)
    ports = rng.randint(10, 60)
    if malicious:
        ip = _rand_ip(rng)
        summary = (
            f"{ports} distinct ports probed on {host} from external host {ip} within 5 minutes"
        )
        severity = rng.choice(["low", "medium", "medium", "high"])
        reputation = _reputation(rng, True, hit_rate=0.55)
        count = ports
    else:
        # A misconfigured internal health-check probe generates a similarly
        # bursty pattern to a real scan - this is the category where
        # recent_alert_count alone does not discriminate.
        ip = _rand_ip(rng, private=True)
        summary = (
            f"{ports} distinct ports probed on {host} from internal host {ip} within 5 minutes"
        )
        severity = "none"
        reputation = "clean"
        count = ports
    return Alert(
        "", "port_scan_detected", summary, host, ip, reputation, count, malicious, severity
    )


def _outbound_beacon(rng: random.Random, malicious: bool) -> Alert:
    host = rng.choice(_HOSTS)
    hits = rng.randint(20, 48)
    if malicious:
        domain = _rand_dga_domain(rng)
        summary = f"{host} made {hits} periodic outbound POST requests to {domain} over 24h"
        severity = rng.choice(["high", "high", "critical"])
        # New C2 infrastructure is often unlisted - the lowest threat-intel
        # hit rate of any malicious category on purpose.
        reputation = _reputation(rng, True, hit_rate=0.3)
    else:
        domain = rng.choice(_VENDOR_DOMAINS)
        summary = f"{host} made {hits} periodic outbound POST requests to {domain} over 24h"
        severity = "none"
        reputation = "clean"
    return Alert(
        "", "outbound_beacon", summary, host, domain, reputation, hits, malicious, severity
    )


_GENERATORS = {
    "ssh_auth_failures": _ssh_auth_failures,
    "sql_injection_pattern": _sql_injection_pattern,
    "xss_pattern_waf": _xss_pattern_waf,
    "port_scan_detected": _port_scan_detected,
    "outbound_beacon": _outbound_beacon,
}


def build_alerts(seed: int, per_category: int) -> list[Alert]:
    """``per_category`` alerts for each (rule, malicious) pair - so the
    dataset is balanced both across rules and across the malicious/benign
    split within each rule, which is what makes accuracy a meaningful
    single number instead of one dominated by whichever split is bigger.
    """
    rng = random.Random(seed)
    alerts: list[Alert] = []
    counter = 0
    for rule in RULES:
        generator = _GENERATORS[rule]
        for malicious in (True, False):
            for _ in range(per_category):
                alert = generator(rng, malicious)
                counter += 1
                alerts.append(
                    Alert(
                        id=f"a{counter:04d}",
                        rule=alert.rule,
                        summary=alert.summary,
                        hostname=alert.hostname,
                        indicator=alert.indicator,
                        threat_intel_reputation=alert.threat_intel_reputation,
                        recent_alert_count=alert.recent_alert_count,
                        malicious=alert.malicious,
                        severity=alert.severity,
                    )
                )
    rng.shuffle(alerts)
    return alerts


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="data/alerts.jsonl")
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--per-category", type=int, default=30)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = _parse_args(argv)
    alerts = build_alerts(args.seed, args.per_category)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w") as f:
        for alert in alerts:
            f.write(json.dumps(alert.__dict__) + "\n")

    n_malicious = sum(1 for a in alerts if a.malicious)
    print(
        f"wrote {len(alerts)} alerts ({n_malicious} malicious / "
        f"{len(alerts) - n_malicious} benign) to {out_path}"
    )


if __name__ == "__main__":
    main()
