"""LOLBIN database — fetches LOLBAS and GTFOBins APIs for real-world detection.

Downloads the LOLBAS (Windows) and GTFOBins (Unix) JSON APIs at bootstrap,
builds a compact index suitable for a shared memory block, and caches
the raw data locally.

The compact index maps process names to their abuse categories and
MITRE ATT&CK technique IDs, keeping the block text under ~10KB.
"""

import hashlib
import json
import os
import time
from pathlib import Path

from nabla.log import get_logger

logger = get_logger("lolbin_db")

# API URLs
LOLBAS_API_URL = "https://lolbas-project.github.io/api/lolbas.json"
GTFOBINS_API_URL = "https://gtfobins.org/api.json"

# Allowed redirect hosts for each download source (SSRF protection)
_LOLBAS_HOSTS = ("lolbas-project.github.io", "pages.github.com")
_GTFOBINS_HOSTS = ("gtfobins.org", "pages.github.com")

# Expected SHA-256 checksums (empty string skips check — set to verify
# integrity). N14 (round 4): via Settings (lolbas_sha256 / gtfobins_sha256)
# — the raw env reads were unreachable in Docker and invisible to the
# plumbing guard. Read at DOWNLOAD time, not import time: a bad Settings
# value must not crash every importer of this module.
def _pinned_hash(setting_name: str) -> str:
    from nabla.config import get_settings
    return getattr(get_settings(), setting_name) or ""

# Cache filenames
LOLBAS_CACHE = "lolbas.json"
GTFOBINS_CACHE = "gtfobins.json"
LOLBIN_INDEX_CACHE = "lolbin_index.json"


def _download(url: str, cache_path: str, refresh_days: int = 30, expected_sha256: str = "", allowed_hosts: tuple[str, ...] = ()) -> str:
    """Download a URL if the cache is missing or stale.

    Args:
        url: URL to download.
        cache_path: Local file path for the cache.
        refresh_days: Re-download if cache is older than this.
        expected_sha256: If non-empty, verify downloaded content matches this hash.
        allowed_hosts: If non-empty, only allow redirects to these hostnames.

    Returns the path to the cached file.

    Raises:
        ValueError: If integrity check fails (hash mismatch) or redirect
            target is not in allowed_hosts.
    """
    if os.path.exists(cache_path):
        age_days = (time.time() - os.path.getmtime(cache_path)) / 86400
        if age_days < refresh_days:
            logger.info("Cache fresh (%.0f days old): %s", age_days, cache_path)
            return cache_path

    logger.info("Downloading %s", url)
    from nabla.ssrf import follow_get_redirects_safe

    resp = follow_get_redirects_safe(
        url,
        allowed_hosts=allowed_hosts,
        caller_name="LOLBIN download",
    )

    resp.raise_for_status()

    content = resp.content

    # Verify integrity if a checksum is configured
    if expected_sha256:
        actual = hashlib.sha256(content).hexdigest()
        if actual != expected_sha256:
            logger.error(
                "Download integrity check FAILED for %s: expected %s, got %s",
                url, expected_sha256, actual,
            )
            raise ValueError(f"Download integrity check failed for {url} — hash mismatch")
        logger.info("Download integrity verified for %s (SHA-256 match)", url)
    else:
        actual = hashlib.sha256(content).hexdigest()
        logger.warning(
            "No SHA-256 checksum configured for %s — integrity verification disabled. "
            "Actual SHA-256: %s. Set NABLA_LOLBAS_SHA256 or NABLA_GTFOBINS_SHA256 to enable.",
            url, actual,
        )

    Path(os.path.dirname(cache_path)).mkdir(parents=True, exist_ok=True)
    with open(cache_path, "wb") as f:
        f.write(content)

    logger.info("Cached %s (%d bytes)", cache_path, len(content))
    return cache_path


def fetch_lolbin_data(data_dir: str, refresh_days: int = 30) -> dict:
    """Fetch LOLBAS and GTFOBins APIs, returning raw data.

    Caches both JSON files locally. Returns {"lolbas": list, "gtfobins": dict}.

    Args:
        data_dir: Directory for cached files.
        refresh_days: Re-download if cache is older than this.

    Returns:
        Dict with "lolbas" (list) and "gtfobins" (dict) keys.
        Empty values on failure (never raises).
    """
    result = {"lolbas": [], "gtfobins": {}}

    # LOLBAS
    try:
        lolbas_path = _download(
            LOLBAS_API_URL,
            os.path.join(data_dir, LOLBAS_CACHE),
            refresh_days,
            expected_sha256=_pinned_hash("lolbas_sha256"),
            allowed_hosts=_LOLBAS_HOSTS,
        )
        with open(lolbas_path) as f:
            result["lolbas"] = json.load(f)
        logger.info("LOLBAS: %d entries", len(result["lolbas"]))
    except Exception as e:
        logger.warning("Failed to fetch LOLBAS: %s", e)

    # GTFOBins
    try:
        gtfobins_path = _download(
            GTFOBINS_API_URL,
            os.path.join(data_dir, GTFOBINS_CACHE),
            refresh_days,
            expected_sha256=_pinned_hash("gtfobins_sha256"),
            allowed_hosts=_GTFOBINS_HOSTS,
        )
        with open(gtfobins_path) as f:
            result["gtfobins"] = json.load(f)
        executables = result["gtfobins"].get("executables", {})
        logger.info("GTFOBins: %d entries", len(executables))
    except Exception as e:
        logger.warning("Failed to fetch GTFOBins: %s", e)

    return result


def build_lolbin_index(data: dict) -> dict:
    """Build a compact index from raw LOLBAS and GTFOBins data.

    Returns:
        {
            "windows": {name_lower: {"name": str, "categories": [str], "mitre_ids": [str], "detection": [str]}},
            "unix": {name_lower: {"name": str, "functions": [str], "mitre_ids": [str]}},
        }
    """
    index = {"windows": {}, "unix": {}}

    # --- Process LOLBAS (Windows) ---
    for entry in data.get("lolbas", []):
        name = entry.get("Name", "")
        if not name:
            continue

        categories = set()
        mitre_ids = set()
        detection_refs = []

        for cmd in entry.get("Commands", []):
            cat = cmd.get("Category", "")
            if cat:
                categories.add(cat)
            mid = cmd.get("MitreID", "")
            if mid:
                mitre_ids.add(mid)

        # Round 8: upstream LOLBAS entries can carry "Detection": null
        # (e.g. Ngen.exe) — one malformed entry must not kill the whole
        # index (it left the supervisor block "not loaded", which silently
        # disabled lolbin detection on the stack).
        for det in entry.get("Detection") or []:
            for key, val in det.items():
                if key in ("Sigma", "Splunk", "Elastic") and val:
                    # Extract rule name from URL
                    rule_name = val.rsplit("/", 1)[-1].replace(".yml", "")
                    detection_refs.append(f"{key}:{rule_name}")

        key = name.lower().replace(".exe", "").strip()
        index["windows"][key] = {
            "name": name,
            "categories": sorted(categories),
            "mitre_ids": sorted(mitre_ids),
            "detection": detection_refs[:5],  # Limit to 5
        }

    # --- Process GTFOBins (Unix) ---
    # The GTFOBins api.json structure:
    #   {"functions": {func_name: {"mitre": [...], ...}, ...},
    #    "contexts": {...},
    #    "executables": {name: {"functions": {func_name: [...]}, ...}, ...}}
    # We look up each binary's function names in the top-level "functions"
    # dict to collect MITRE technique IDs.
    gtfobins_raw = data.get("gtfobins", {})
    function_definitions = gtfobins_raw.get("functions", {})
    executables = gtfobins_raw.get("executables", {})

    for name, entry in executables.items():
        if not name:
            continue

        functions = set()
        mitre_ids = set()

        # Entry has a "functions" dict mapping function type names to code lists
        funcs = entry.get("functions", {})
        if isinstance(funcs, dict):
            for func_name in funcs:
                functions.add(func_name)
                # Look up MITRE IDs from the top-level function definitions
                func_def = function_definitions.get(func_name, {})
                if isinstance(func_def, dict):
                    for mid in func_def.get("mitre", []):
                        if mid:
                            mitre_ids.add(mid)

        key = name.lower().strip()
        index["unix"][key] = {
            "name": name,
            "functions": sorted(functions),
            "mitre_ids": sorted(mitre_ids),
        }

    logger.info(
        "LOLBIN index: %d Windows, %d Unix entries",
        len(index["windows"]),
        len(index["unix"]),
    )
    return index


def format_lolbin_block(index: dict) -> str:
    """Format the LOLBIN index as compact text for the shared memory block.

    Format (name | categories | mitre | detection, " | "-separated):
        === WINDOWS LOLBINS ===
        certutil.exe | Download,Encode,Decode | T1105,T1140 | Sigma:proc_creation_win_certutil_download
        mshta.exe | Execute | T1218
        ...

        === UNIX GTFOBINS ===
        bash | shell,file-read,file-write,download | T1059
        curl | download,file-read,upload | T1105
        ...

    The block text is parsed by tools at runtime to enrich LOLBIN detections
    with real technique IDs and detection references.
    """
    lines = []

    # Windows
    lines.append("=== WINDOWS LOLBINS ===")
    for key in sorted(index["windows"]):
        entry = index["windows"][key]
        cats = ", ".join(entry["categories"]) if entry["categories"] else "unknown"
        mitre = ", ".join(entry["mitre_ids"]) if entry["mitre_ids"] else ""
        det = ", ".join(entry["detection"]) if entry["detection"] else ""
        parts = [entry["name"], cats]
        if mitre:
            parts.append(mitre)
        if det:
            parts.append(det)
        lines.append(" | ".join(parts))

    # Unix
    lines.append("")
    lines.append("=== UNIX GTFOBINS ===")
    for key in sorted(index["unix"]):
        entry = index["unix"][key]
        funcs = ", ".join(entry["functions"]) if entry["functions"] else "unknown"
        mitre = ", ".join(entry["mitre_ids"]) if entry["mitre_ids"] else ""
        parts = [entry["name"], funcs]
        if mitre:
            parts.append(mitre)
        lines.append(" | ".join(parts))

    text = "\n".join(lines)
    logger.info("LOLBIN block: %d lines, %d bytes", len(lines), len(text))
    return text


def parse_lolbin_block(block_text: str) -> dict:
    """Parse the lolbin_db block text back into a lookup dict.

    Returns:
        {
            "windows": {name_lower: {"name": str, "categories": [str], "mitre_ids": [str], "detection": [str]}},
            "unix": {name_lower: {"name": str, "functions": [str], "mitre_ids": [str]}},
        }
    """
    result = {"windows": {}, "unix": {}}
    section = None

    for line in block_text.strip().split("\n"):
        line = line.strip()
        if not line:
            continue

        if line == "=== WINDOWS LOLBINS ===":
            section = "windows"
            continue
        elif line == "=== UNIX GTFOBINS ===":
            section = "unix"
            continue

        if section and " | " in line:
            parts = [p.strip() for p in line.split("|")]
            name = parts[0]
            key = name.lower().replace(".exe", "").strip()

            if section == "windows":
                categories = [c.strip() for c in parts[1].split(",")] if len(parts) > 1 else []
                mitre_ids = [m.strip() for m in parts[2].split(",")] if len(parts) > 2 else []
                detection = [d.strip() for d in parts[3].split(",")] if len(parts) > 3 else []
                result["windows"][key] = {
                    "name": name,
                    "categories": categories,
                    "mitre_ids": mitre_ids,
                    "detection": detection,
                }
            elif section == "unix":
                functions = [f.strip() for f in parts[1].split(",")] if len(parts) > 1 else []
                mitre_ids = [m.strip() for m in parts[2].split(",")] if len(parts) > 2 else []
                result["unix"][key] = {
                    "name": name,
                    "functions": functions,
                    "mitre_ids": mitre_ids,
                }

    return result

