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

# F5: the real dataset-v1 is 13 machine principals to one human, and the
# harness was 100% human — so it could not reproduce the defect it was
# supposed to catch. These are the principals that actually fired in the
# rehearsal, plus the placeholder value that shows up as an entity.
MACHINE_PRINCIPALS = [
    "root", "SYSTEM", "WIN-SRV01$", "WIN-SRV02$",
    "svc-jenkins", "adm", "-",
]

# Hour-of-day activity shape (0-23): day-active office population.
# R4 calibration note: contrast capped ~3x (peak/shoulder) — real per-user
# diurnal swings are 2-4x; the original 20x contrast made every high-rate
# user a baseline outlier on each day/night crossing (the harness's own
# noise-floor teaching moment: shaped-but-stable is what "normal" means
# to a baseline-relative detector)
# N1 follow-through (round 4, found live — three layers deep):
# 1. The old minute-weighted shaping was a no-op inside 5-minute batches
#    (every minute shares one hour weight), so the population was uniform
#    around the clock: 33% night share, every human tripping off-hours
#    nightly, hidden only by wall-clock risk decay. The honest clock (N2)
#    exposed it; the count is now shaped by the hour weight.
# 2. A thin night tail (~1.5% share) is the WORST of both worlds for this
#    product's semantics: below hour_is_unusual's per-hour min_share (2%)
#    forever — never "typical" — while its Poisson tail still produces 3+
#    night-hour batches, which is exactly the off_hours_count threshold.
#    fen fired 7 times on 0.2-0.75%/hr shares. A normal population for a
#    detector that defines human night activity as off-hours is DAY-ACTIVE;
#    night is the attack's signature, not the background. Trace weights
#    (not zero) keep timestamps realistic without ever reaching threshold.
_HOUR_WEIGHTS = [
    0.01, 0.01, 0.01, 0.01, 0.01, 0.01, 0.4, 1.0, 1.4, 1.6, 1.7, 1.7,
    1.5, 1.5, 1.6, 1.6, 1.5, 1.4, 1.2, 1.1, 1.0, 0.8, 0.01, 0.01,
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

    def __init__(self, seed: int = 42, n_users: int = 40, machine_users: bool = True):
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
        # F5: machine principals run continuously and at high volume. That is
        # the whole point — they are the population that made off-hours
        # detection fire on its own baseline.
        #
        # Their own RNG stream, deliberately. Drawing from `self.rng` would
        # shift every human user's rate and hour bias, silently recalibrating
        # the population the R3/R4 ceilings were measured against — the human
        # population must not move because a machine population was added.
        self.machine_users: dict[str, dict] = {}
        if machine_users:
            mrng = random.Random(seed ^ 0x5EED)
            for name in MACHINE_PRINCIPALS:
                self.machine_users[name] = {
                    "rate": math.exp(mrng.uniform(math.log(60.0), math.log(400.0))),
                    "host": mrng.choice(HOSTS),
                    "ip": mrng.choice(OFFICE_IPS),
                }
            self._machine_rng = mrng

    def _emit_machine_events(self, user: str, start: datetime, minutes: float) -> list[dict]:
        """Machine activity: uniform across all 24 hours, no diurnal shape.

        A service account has no schedule to deviate from. Emitting it flat is
        not a simplification — it is the exact condition under which
        off-hours detection misfires on it.
        """
        u = self.machine_users[user]
        expected = u["rate"] * (minutes / 60.0)
        n = max(0, round(self._machine_rng.gauss(expected, math.sqrt(max(expected, 0.01)))))
        events = []
        for _ in range(n):
            t = start + timedelta(minutes=self._machine_rng.random() * minutes)
            events.append({
                "timestamp": t.isoformat().replace("+00:00", "Z"),
                "log_type": "endpoint",
                "user": user,
                "host": u["host"],
                "event_code": "1",
                "source_ip": u["ip"],
                "dest_ip": "",
                "process": self._machine_rng.choice(["systemd", "cron", "sshd", "python3"]),
                "command_line": "",
                "action": self._machine_rng.choice(
                    ["process_start", "file_write", "network_connect"]
                ),
            })
        return events

    def _emit_user_events(self, user: str, start: datetime, minutes: float) -> list[dict]:
        u = self.users[user]
        # N1 follow-through (round 4): shape the COUNT by the hour weight —
        # the old code drew an hour-independent count then "weighted" the
        # minute-pick inside a 5-minute span, where every minute shares one
        # hour weight. The shaping cancelled to zero and the population was
        # uniform around the clock (33% night share) — every human tripped
        # off-hours nightly, and only wall-clock risk decay hid it. The
        # honest clock (N2) made the noise visible; this makes it absent.
        hh = start.hour
        shape = _HOUR_WEIGHTS[hh] / 1.7  # peak weight -> 1.0
        expected = u["rate"] * (minutes / 60.0) * shape
        n = max(0, round(self.rng.gauss(expected, math.sqrt(max(expected, 0.01)))))
        events = []
        for _ in range(n):
            t = start + timedelta(minutes=self.rng.random() * minutes)
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
            for user in self.machine_users:
                events.extend(self._emit_machine_events(user, t, batch_minutes))
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
