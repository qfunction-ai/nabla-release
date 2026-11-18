"""Synthetic population generator for the end-to-end harness (round 3, phase 0).

~50 users with Poisson activity at varied rates, realistic hour-of-day
shaping, hosts and IPs; emitted as 5-minute event-time batches over
simulated days. The reviewer's spec: normal users must NOT trigger the
entity-baseline detectors (>2% = R4) or GCN-LOF (>1% = R3), risk must
update every run without degradation (R1), and one injected multi-stage
attack user must be detected while (almost) no normal user crosses the
cutoff.
"""

from __future__ import annotations

import json
import math
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

FIRST_NAMES = [
    "avery", "blake", "casey", "dana", "ellis", "flynn", "gray", "harper",
    "indigo", "jules", "kai", "logan", "morgan", "noel", "oakley", "parker",
    "quinn", "rowan", "sage", "tatum", "vera", "wren", "yuri", "zane",
    "ada", "bo", "cleo", "devi", "emi", "fen", "gus", "hana",
]

HOSTS = [f"WS-{i:03d}" for i in range(1, 8)] + ["SRV-DC01", "SRV-APP01", "SRV-FILE01"]
OFFICE_IPS = [f"10.20.{i}.{j}" for i in range(1, 6) for j in range(2, 20)]

# Hour-of-day activity shape (0-23): office hours weighted, light night tail.
# R4 calibration note: contrast capped ~3x (peak/night) — real per-user
# diurnal swings are 2-4x; the original 20x contrast made every high-rate
# user a baseline outlier on each day/night crossing (the harness's own
# noise-floor teaching moment: shaped-but-stable is what "normal" means
# to a baseline-relative detector)
_HOUR_WEIGHTS = [
    0.12, 0.10, 0.10, 0.10, 0.10, 0.12, 0.4, 1.0, 1.4, 1.6, 1.7, 1.7,
    1.5, 1.5, 1.6, 1.6, 1.5, 1.4, 1.2, 1.1, 1.0, 0.8, 0.4, 0.2,
]
_HOUR_CUM = []
_acc = 0.0
for _w in _HOUR_WEIGHTS:
    _acc += _w
    _HOUR_CUM.append(_acc)
_HOUR_TOTAL = _acc


def _shaped_hour(rng: random.Random) -> int:
    x = rng.random() * _HOUR_TOTAL
    for h, c in enumerate(_HOUR_CUM):
        if x <= c:
            return h
    return 23


class Population:
    """A stable synthetic user population with per-user Poisson rates."""

    def __init__(self, seed: int = 42, n_users: int = 40):
        self.rng = random.Random(seed)
        self.users: dict[str, dict] = {}
        names = self.rng.sample(FIRST_NAMES * 2, n_users)
        for i, name in enumerate(names):
            uname = name if name not in self.users else f"{name}{i}"
            # Log-uniform rates 0.3 .. 40 events/hour
            rate = math.exp(self.rng.uniform(math.log(0.3), math.log(40.0)))
            self.users[uname] = {
                "rate": rate,
                "host": self.rng.choice(HOSTS),
                "ip": self.rng.choice(OFFICE_IPS),
                "hour_bias": self.rng.gauss(0, 1.0),  # individual schedule skew
            }

    def _emit_user_events(self, user: str, start: datetime, minutes: float) -> list[dict]:
        u = self.users[user]
        expected = u["rate"] * (minutes / 60.0)
        n = max(0, round(self.rng.gauss(expected, math.sqrt(max(expected, 0.01)))))
        events = []
        for _ in range(n):
            # 5-min batch: pick a shaped hour consistent with the batch window,
            # then a uniform minute inside it
            span_start = start
            span_end = start + timedelta(minutes=minutes)
            # choose time weighted by hour shape across the span
            t = span_start
            # simple approach: weighted pick among the minutes in the span
            total_min = int(minutes)
            weights = []
            for m in range(total_min):
                hh = (span_start + timedelta(minutes=m)).hour
                weights.append(_HOUR_WEIGHTS[hh] * math.exp(-abs(u["hour_bias"]) if hh in (8, 9, 17, 18) else 0))
            tot = sum(weights) or 1.0
            r = self.rng.random() * tot
            acc = 0.0
            for m, w in enumerate(weights):
                acc += w
                if r <= acc:
                    t = span_start + timedelta(minutes=m)
                    break
            events.append({
                "timestamp": t.isoformat().replace("+00:00", "Z"),
                "log_type": "endpoint",
                "user": user,
                "host": u["host"],
                "event_code": "1",
                "source_ip": u["ip"],
                "dest_ip": "",
                "process": self.rng.choice(["bash", "python3", "curl", "grep", "systemd", "ssh"]),
                "command_line": "",
                "action": self.rng.choice(["process_start", "process_exit", "network_connect", "file_write"]),
            })
        return events

    def batches(self, start: datetime, days: float, batch_minutes: int = 5):
        """Yield (batch_start, events) covering `days` of event time."""
        t = start
        end = start + timedelta(days=days)
        while t < end:
            events = []
            for user in self.users:
                events.extend(self._emit_user_events(user, t, batch_minutes))
            events.sort(key=lambda e: e["timestamp"])
            yield t, events
            t += timedelta(minutes=batch_minutes)

    def write_batches(self, out_dir: Path, start: datetime, days: float, batch_minutes: int = 5):
        """Write day-shaped files (harness ingests per simulated hour)."""
        out_dir.mkdir(parents=True, exist_ok=True)
        # Aggregate into hourly files: the harness's natural chunk
        hours: dict[datetime, list] = {}
        for t, events in self.batches(start, days, batch_minutes):
            hour = t.replace(minute=0, second=0, microsecond=0)
            hours.setdefault(hour, []).extend(events)
        for hour in sorted(hours):
            f = out_dir / f"{hour.strftime('%Y-%m-%dT%H')}.jsonl"
            with f.open("w") as fh:
                for e in hours[hour]:
                    fh.write(json.dumps(e) + "\n")
        return len(hours)


def attack_batch(pop: Population, target: str, at: datetime, n: int = 600,
                 span_minutes: float = 90) -> list[dict]:
    """The multi-stage attack: high-rate burst + failures + off-hours mix."""
    rng = random.Random(1337)
    events = []
    for i in range(n):
        t = at + timedelta(minutes=float(i) * span_minutes / max(n - 1, 1))
        failure = rng.random() < 0.6
        events.append({
            "timestamp": t.isoformat().replace("+00:00", "Z"),
            "log_type": "auth",
            "user": target,
            "host": pop.users[target]["host"],
            "event_code": "4625" if failure else "4624",
            "source_ip": "203.0.113.99" if failure else pop.users[target]["ip"],
            "dest_ip": "",
            "process": "",
            "command_line": "",
            "action": "login_failure" if failure else "login_success",
        })
    return events
