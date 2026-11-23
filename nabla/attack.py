"""MITRE ATT&CK integration for Nabla.

Downloads the Enterprise ATT&CK STIX bundle at bootstrap, builds a compact
mapping of Nabla anomaly types → ATT&CK technique IDs, and formats it as
a shared memory block for the threat hunter agent.

The mapping is pre-computed on the host side (where mitreattack-python is
available) and stored as block text. Tools running in Letta's sandbox
read the block at runtime — they cannot import mitreattack-python.
"""

import hashlib
import os
from pathlib import Path

from nabla.log import get_logger

logger = get_logger("attack")

# STIX bundle — PINNED (F-1, final review). The old source was
# mitre/cti master (a moving branch) with an empty hash: snapshots built
# on different days checked against different ATT&CK releases, breaking
# D-21's same-state promise, and an unverified download from a moving
# branch is the supply-chain pattern the course teaches against.
# mitre-attack/attack-stix-data carries versioned tags; the hash makes
# the pin verifiable. Bump BOTH constants together, and the shipped copy
# (course-assets/attack/), when a new ATT&CK release is wanted.
ATTACK_STIX_VERSION = "20.1"
ATTACK_STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "v20.1/enterprise-attack/enterprise-attack.json"
)
ATTACK_STIX_SHA256 = "539a843a7b53ed9749740b2123dddae3726b1a4831841c32aca740b011b910b5"

# Nabla anomaly type → ATT&CK technique IDs
ANOMALY_TO_TECHNIQUES = {
    "brute_force_attempt": ["T1110"],
    "privilege_escalation": ["T1078", "T1548"],
    "off_hours_activity": ["T1078"],
    "multiple_source_ips": ["T1078", "T1021"],
    "suspicious_domain": ["T1071", "T1568"],
    "activity_spike": ["T1059", "T1036"],
    "z_score_spike": ["T1059"],
    "lolbin_abuse": ["T1218", "T1202"],
    "known_attack_script": ["T1082", "T1003", "T1055", "T1057", "T1087", "T1071", "T1548", "T1110", "T1021"],
    "enumeration_behavior": ["T1082", "T1057", "T1005", "T1059"],
    "renamed_attack_tool": ["T1558", "T1003", "T1087", "T1036", "T1071", "T1548", "T1021"],
    "ewma_drift": ["T1059", "T1078"],
    "cusum_shift": ["T1059", "T1078"],
    "suspicious_process": ["T1059"],
    "unusual_icmp_flood": ["T1095"],
}

# All unique technique IDs referenced in the mapping
ALL_TECHNIQUE_IDS = sorted(
    set(tid for tids in ANOMALY_TO_TECHNIQUES.values() for tid in tids)
)


def _file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _verify_bundle_hash(content: bytes) -> None:
    """The pin is mandatory (F-1): an unverified bundle is a supply-chain
    hole, and an empty pin is a configuration error, not a skip."""
    if not ATTACK_STIX_SHA256:
        raise ValueError(
            "ATTACK_STIX_SHA256 must be set — the ATT&CK bundle pin is mandatory"
        )
    actual = hashlib.sha256(content).hexdigest()
    if actual != ATTACK_STIX_SHA256:
        logger.error(
            "ATT&CK STIX bundle integrity check FAILED: expected %s, got %s. "
            "The bundle may be corrupted, tampered with, or from a different "
            "ATT&CK release than the pin.",
            ATTACK_STIX_SHA256, actual,
        )
        raise ValueError("ATT&CK STIX bundle integrity check failed — hash mismatch")


def download_attack_bundle(data_dir: str) -> str:
    """Return the path to the pinned Enterprise ATT&CK STIX bundle.

    Resolution order (F-1):
      1. The data_dir copy, if its SHA-256 matches the pin — a pinned
         bundle never goes stale, so there is no age-based refresh.
      2. A shipped copy (settings.attack_bundle_local_path) — course
         snapshot builds use this and never touch GitHub.
      3. Network download from the pinned, tagged URL.

    Every source is hash-verified; the check cannot be skipped.

    Args:
        data_dir: Directory to store the bundle file.

    Returns:
        Path to the STIX bundle file.
    """
    bundle_path = os.path.join(data_dir, "enterprise-attack.json")

    if os.path.exists(bundle_path):
        if _file_sha256(bundle_path) == ATTACK_STIX_SHA256:
            logger.info(
                "ATT&CK bundle present and matches the pin (v%s), skipping fetch",
                ATTACK_STIX_VERSION,
            )
            return bundle_path
        logger.warning(
            "ATT&CK bundle in data_dir does not match the pin (v%s) — refetching",
            ATTACK_STIX_VERSION,
        )

    # 2. Shipped copy (course fixtures): hermetic snapshot builds.
    from nabla.config import get_settings

    local_path = get_settings().attack_bundle_local_path
    if local_path and os.path.exists(local_path):
        content = Path(local_path).read_bytes()
        _verify_bundle_hash(content)
        Path(data_dir).mkdir(parents=True, exist_ok=True)
        with open(bundle_path, "wb") as f:
            f.write(content)
        logger.info(
            "ATT&CK bundle copied from shipped copy %s (v%s, no network)",
            local_path, ATTACK_STIX_VERSION,
        )
        return bundle_path

    # 3. Network download from the pinned tag.
    logger.info("Downloading ATT&CK STIX bundle from %s", ATTACK_STIX_URL)
    from nabla.ssrf import follow_get_redirects_safe

    _GITHUB_HOSTS = ("github.com", "raw.githubusercontent.com",
                     "objects.githubusercontent.com", "codeload.github.com")
    resp = follow_get_redirects_safe(
        ATTACK_STIX_URL,
        allowed_hosts=_GITHUB_HOSTS,
        caller_name="ATT&CK",
    )

    resp.raise_for_status()

    # Verify integrity — mandatory
    content = resp.content
    _verify_bundle_hash(content)
    logger.info("ATT&CK STIX bundle integrity verified (SHA-256 match, v%s)",
                ATTACK_STIX_VERSION)

    Path(data_dir).mkdir(parents=True, exist_ok=True)
    with open(bundle_path, "wb") as f:
        f.write(content)

    # Also verify the written file matches (detect disk corruption)
    with open(bundle_path, "rb") as f:
        disk_hash = hashlib.sha256(f.read()).hexdigest()
    if disk_hash != ATTACK_STIX_SHA256:
        logger.error("ATT&CK STIX bundle on-disk hash mismatch: %s vs %s",
                     ATTACK_STIX_SHA256, disk_hash)
        os.unlink(bundle_path)
        raise ValueError("ATT&CK STIX bundle on-disk integrity check failed")

    logger.info("ATT&CK bundle saved to %s (%d bytes)", bundle_path, len(content))
    return bundle_path


def build_attack_index(stix_path: str) -> dict[str, list[dict]]:
    """Build an index of technique details for all mapped anomaly types.

    Args:
        stix_path: Path to the Enterprise ATT&CK STIX bundle.

    Returns:
        {anomaly_type: [{"id": str, "name": str, "tactic": str, "description": str,
                          "groups": [str], "mitigations": [str]}, ...]}
    """
    from mitreattack.stix20 import MitreAttackData

    attack_data = MitreAttackData(stix_filepath=stix_path)

    # Build technique lookup: attack_id → technique object
    techniques = attack_data.get_techniques(remove_revoked_deprecated=True)
    technique_lookup = {}
    for t in techniques:
        refs = t.get("external_references", [])
        for ref in refs:
            if ref.get("source_name") == "mitre-attack":
                technique_lookup[ref["external_id"]] = t
                break

    # Build group → technique relationships
    groups_by_technique = attack_data.get_all_groups_using_all_techniques()

    # Build mitigation → technique relationships
    mitigations_by_technique = attack_data.get_all_mitigations_mitigating_all_techniques()

    index = {}
    for anomaly_type, technique_ids in ANOMALY_TO_TECHNIQUES.items():
        entries = []
        for tid in technique_ids:
            t = technique_lookup.get(tid)
            if t is None:
                logger.warning("Technique %s not found in STIX bundle", tid)
                continue

            # Get tactic names
            tactics = attack_data.get_tactics_by_technique(t["id"])
            tactic_names = [tac.get("name", tac.get("x_mitre_shortname", "")) for tac in tactics]
            primary_tactic = tactic_names[0] if tactic_names else "Unknown"

            # Truncate description to first sentence
            desc = t.get("description", "")
            if desc:
                # Take first sentence (up to first period followed by space or end)
                first_sentence = desc.split(". ")[0] + "."
                desc = first_sentence[:200]
            else:
                desc = ""

            # Get groups using this technique
            group_names = []
            if t["id"] in groups_by_technique:
                for entry in groups_by_technique[t["id"]]:
                    name = entry["object"].get("name", "")
                    if name:
                        group_names.append(name)

            # Get mitigations for this technique
            mitigation_names = []
            if t["id"] in mitigations_by_technique:
                for entry in mitigations_by_technique[t["id"]]:
                    name = entry["object"].get("name", "")
                    if name:
                        mitigation_names.append(name)

            entries.append({
                "id": tid,
                "name": t.get("name", tid),
                "tactic": primary_tactic,
                "description": desc,
                "groups": group_names[:5],  # Limit to top 5
                "mitigations": mitigation_names[:5],  # Limit to top 5
            })

        index[anomaly_type] = entries

    logger.info("Built ATT&CK index: %d anomaly types, %d techniques",
                len(index), sum(len(v) for v in index.values()))
    return index


_TECHNIQUE_IDS_CACHE: set[str] | None = None


def get_attack_technique_ids() -> set[str]:
    """ALL technique IDs (e.g. T1059) in the pinned bundle.

    One source, not a second copy (the L11 lesson): derived from the
    same STIX bundle behind the attack_mapping block, cached per
    process. The D-10 resolver uses this to flag unknown IDs the
    supervisor cites — flagged, never silently dropped.

    Deliberately the FULL bundle set, not the 18 IDs the
    ANOMALY_TO_TECHNIQUES mapping references: detectors cite techniques
    from their own signature lists (e.g. certutil carries T1105/T1140
    while lolbin_abuse maps to T1218/T1202), so the narrow set flagged
    real techniques as unknown (found live in the Phase 3 smoke).
    """
    global _TECHNIQUE_IDS_CACHE
    if _TECHNIQUE_IDS_CACHE is not None:
        return _TECHNIQUE_IDS_CACHE
    from nabla.config import get_settings

    data_dir = get_settings().data_dir
    stix_path = os.path.join(data_dir, "enterprise-attack.json")
    if not os.path.exists(stix_path):
        stix_path = download_attack_bundle(data_dir)
    from mitreattack.stix20 import MitreAttackData

    attack_data = MitreAttackData(stix_filepath=stix_path)
    ids: set[str] = set()
    for t in attack_data.get_techniques(remove_revoked_deprecated=True):
        for ref in t.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                ext = ref.get("external_id")
                if ext:
                    ids.add(str(ext).upper())
                break
    _TECHNIQUE_IDS_CACHE = ids
    return ids


def format_attack_block(index: dict[str, list[dict]]) -> str:
    """Format the attack index as compact text for the shared memory block.

    The block text is parsed by the threat hunter's produce_finding tool
    at runtime to enrich findings with ATT&CK technique IDs.

    Format:
        anomaly_type:
          T1110 | Brute Force | Credential Access | Adversaries guess passwords...
          Groups: APT1, APT28
          Mitigations: Account Use Policies
    """
    lines = []
    for anomaly_type, entries in sorted(index.items()):
        lines.append(f"{anomaly_type}:")
        for e in entries:
            lines.append(
                f"  {e['id']} | {e['name']} | {e['tactic']} | {e['description']}"
            )
            if e.get("groups"):
                lines.append(f"  Groups: {', '.join(e['groups'])}")
            if e.get("mitigations"):
                lines.append(f"  Mitigations: {', '.join(e['mitigations'])}")

    text = "\n".join(lines)
    logger.info("Formatted ATT&CK block: %d lines, %d bytes", len(lines), len(text))
    return text


def enrich_lolbin_attack_mapping(attack_index: dict, lolbin_index: dict) -> dict:
    """Enrich the attack index with per-process LOLBIN technique IDs.

    When the LOLBIN database provides specific technique IDs for a process,
    those are added to the lolbin_abuse entry in the attack index.
    This replaces the generic T1218/T1202 mapping with process-specific IDs.

    Args:
        attack_index: The attack index from build_attack_index().
        lolbin_index: The LOLBIN index from build_lolbin_index().

    Returns:
        The attack_index with enriched lolbin_abuse entries.
    """
    # Collect all unique MITRE IDs from the LOLBIN database
    lolbin_mitre_ids = set()
    for entry in lolbin_index.get("windows", {}).values():
        for mid in entry.get("mitre_ids", []):
            lolbin_mitre_ids.add(mid)
    for entry in lolbin_index.get("unix", {}).values():
        for mid in entry.get("mitre_ids", []):
            lolbin_mitre_ids.add(mid)

    if not lolbin_mitre_ids:
        return attack_index

    # Add database-sourced technique IDs to the lolbin_abuse entry
    if "lolbin_abuse" in attack_index:
        existing_ids = {e["id"] for e in attack_index["lolbin_abuse"]}
        for mid in sorted(lolbin_mitre_ids):
            if mid not in existing_ids:
                attack_index["lolbin_abuse"].append({
                    "id": mid,
                    "name": f"LOLBIN technique {mid}",
                    "tactic": "Execution",
                    "description": "Identified from LOLBAS/GTFOBins database",
                    "groups": [],
                    "mitigations": [],
                })
                existing_ids.add(mid)

    return attack_index


def build_tool_name_index(stix_path: str) -> dict[str, tuple[str, str]]:
    """Extract attack tool/malware names from the STIX bundle for detection.

    Parses all tool and malware objects in the ATT&CK STIX bundle and
    returns a lookup dict of lowercase name → (description, primary_technique_id).

    This replaces the hardcoded KNOWN_ATTACK_SCRIPTS list in detection.py.
    The STIX bundle is the authoritative source for known attack tool names;
    maintaining a separate hardcoded list means every new tool requires a
    manual code change.

    Args:
        stix_path: Path to the Enterprise ATT&CK STIX bundle.

    Returns:
        {lowercase_name: (description, technique_id)} — e.g.
        {"cobalt strike": ("C2 framework", "T1071"), "mimikatz": ("Credential dumping", "T1003")}
    """
    import json

    with open(stix_path, encoding="utf-8") as f:
        bundle = json.load(f)

    # Build technique ID lookup for resolving relationships
    technique_lookup: dict[str, str] = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        refs = obj.get("external_references", [])
        for ref in refs:
            if ref.get("source_name") == "mitre-attack":
                technique_lookup[obj["id"]] = ref["external_id"]
                break

    # Build tool/malware → technique relationships
    tool_techniques: dict[str, list[str]] = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "relationship":
            continue
        if obj.get("relationship_type") != "uses":
            continue
        src = obj.get("source_ref", "")
        tgt = obj.get("target_ref", "")
        if tgt in technique_lookup:
            tool_techniques.setdefault(src, []).append(technique_lookup[tgt])

    # Extract tool and malware names
    # Skip names that are too short for reliable substring matching (< 3 chars)
    # or too generic (common English words that cause false positives).
    _SKIP_NAMES = {
        "at", "ps", "sc", "ds", "ds-1", "ds-2", "go", "id", "nc",
        "ncat", "ss", "sh", "vi", "rm", "cp", "mv", "ls", "cat",
        "sed", "awk", "top", "ps", "dd", "df", "du",
        "ps1", "ps2", "bat", "cmd", "vbs", "hta", "dll", "exe",
        "msi", "zip", "tar", "gz", "7z", "rar",
    }
    result: dict[str, tuple[str, str]] = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") not in ("tool", "malware"):
            continue
        name = obj.get("name", "")
        if not name:
            continue
        lower_name = name.lower()
        # Skip names too short for reliable substring matching
        if len(lower_name) < 3 or lower_name in _SKIP_NAMES:
            continue
        stix_id = obj.get("id", "")

        # Get primary technique (first one from relationships)
        techs = tool_techniques.get(stix_id, [])
        primary_tech = techs[0] if techs else "T1059"

        # Description: use STIX description if available, else type-based fallback
        desc = obj.get("description", "")
        if desc:
            # First sentence only, truncated
            desc = desc.split(". ")[0][:80]
        else:
            obj_type = obj.get("type", "tool")
            desc = f"Known {obj_type}"

        # Store lowercase name
        result[lower_name] = (desc, primary_tech)

        # Also store common aliases (skip short ones too)
        for alias in obj.get("x_mitre_aliases", []):
            alias_lower = alias.lower()
            if alias_lower not in result and len(alias_lower) >= 3 and alias_lower not in _SKIP_NAMES:
                result[alias_lower] = (desc, primary_tech)

    logger.info(
        "Built tool name index: %d entries from %d STIX objects",
        len(result),
        sum(1 for o in bundle.get("objects", []) if o.get("type") in ("tool", "malware")),
    )
    return result
