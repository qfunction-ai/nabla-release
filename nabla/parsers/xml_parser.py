r"""XML log file parser — Sysmon EventData format.

Parses Windows Event Log XML exports, specifically the Sysmon schema
where EventData/Data elements have Name attributes that map to field names.

Handles:
- Sysmon EventData: <Data Name="Image">C:\Windows\cmd.exe</Data>
- Generic Windows Event Log: <Event><System>...<EventData>...</EventData></Event>
- Flat XML: <row><field1>value1</field1><field2>value2</field2></row>
"""

from __future__ import annotations

from pathlib import Path

import defusedxml.ElementTree as ElementTree

from nabla.log import get_logger

logger = get_logger("parsers.xml")

# Sysmon EventID to log type mapping
SYSMON_EVENT_TYPES: dict[str, str] = {
    "1": "endpoint",    # Process Create
    "2": "endpoint",    # File creation time changed
    "3": "network",     # Network connection detected
    "5": "endpoint",    # Process terminated
    "6": "endpoint",    # Driver loaded
    "7": "endpoint",    # Image loaded (DLL)
    "8": "endpoint",    # CreateRemoteThread detected
    "9": "endpoint",    # RawAccessRead detected
    "10": "endpoint",   # Process accessed
    "11": "endpoint",   # File create
    "12": "endpoint",   # Registry object added/deleted
    "13": "endpoint",   # Registry value set
    "14": "endpoint",   # Registry object renamed
    "15": "endpoint",   # File stream created
    "17": "endpoint",   # Pipe created
    "18": "endpoint",   # Pipe connected
    "19": "endpoint",   # WMI filter
    "20": "endpoint",   # WMI consumer
    "21": "endpoint",   # WMI consumer filter
    "22": "dns",        # DNS query
    "23": "endpoint",   # File delete
    "25": "endpoint",   # Process tampering
    "26": "endpoint",   # File delete logged
}

# Windows Security EventID to log type mapping
SECURITY_EVENT_TYPES: dict[str, str] = {
    "4624": "auth",     # Successful logon
    "4625": "auth",     # Failed logon
    "4634": "auth",     # Logoff
    "4648": "auth",     # Explicit credential logon
    "4672": "auth",     # Special privileges assigned
    "4720": "auth",     # User account created
    "4728": "auth",     # Member added to global group
    "4732": "auth",     # Member added to local group
    "4756": "auth",     # Member added to universal group
    "4768": "auth",     # Kerberos TGT requested
    "4769": "auth",     # Kerberos service ticket requested
    "4770": "auth",     # Kerberos service ticket renewed
    "4771": "auth",     # Kerberos pre-auth failed
    "4688": "endpoint",  # Process created
    "4689": "endpoint",  # Process terminated
    "5152": "network",  # Windows Filtering Platform blocked
    "5156": "network",  # Windows Filtering Platform allowed
    "5157": "network",  # Windows Filtering Platform blocked connection
}


# Sysmon EventID to action mapping — gives detection methods meaningful action values
SYSMON_ACTIONS: dict[str, str] = {
    "1": "process_create",       # Process Create
    "2": "file_time_change",     # File creation time changed
    "3": "network_connect",      # Network connection detected
    "5": "process_terminate",   # Process terminated
    "6": "driver_load",          # Driver loaded
    "7": "image_load",          # Image loaded (DLL)
    "8": "create_remote_thread",  # CreateRemoteThread detected
    "9": "raw_access_read",     # RawAccessRead detected
    "10": "process_access",      # Process accessed
    "11": "file_create",         # File create
    "12": "registry_add_delete",  # Registry object added/deleted
    "13": "registry_set",        # Registry value set
    "14": "registry_rename",     # Registry object renamed
    "15": "file_stream_create",  # File stream created
    "17": "pipe_create",         # Pipe created
    "18": "pipe_connect",        # Pipe connected
    "19": "wmi_filter",          # WMI filter
    "20": "wmi_consumer",        # WMI consumer
    "21": "wmi_binding",         # WMI consumer filter binding
    "22": "dns_query",           # DNS query
    "23": "file_delete",         # File delete archived
    "25": "process_tamper",      # Process tampering
    "26": "file_delete_logged",  # File delete logged
}


def _get_ns(elem: ElementTree.Element) -> str:
    """Extract XML namespace from an element's tag.

    Args:
        elem: An XML element.

    Returns:
        Namespace string including braces, or empty string if none.
    """
    tag = elem.tag
    if "}" in tag:
        return tag[:tag.index("}") + 1]
    return ""


def _extract_sysmon_event(event_elem: ElementTree.Element) -> dict:
    """Extract fields from a Sysmon-style Event element.

    Handles both namespaced and non-namespaced XML.

    Args:
        event_elem: An XML <Event> element.

    Returns:
        Dict of extracted fields.
    """
    entry: dict = {}
    ns = _get_ns(event_elem)

    # Extract System fields
    system = event_elem.find(f"{ns}System")
    if system is not None:
        event_id_elem = system.find(f"{ns}EventID")
        if event_id_elem is not None and event_id_elem.text:
            entry["event_code"] = event_id_elem.text.strip()

        computer_elem = system.find(f"{ns}Computer")
        if computer_elem is not None and computer_elem.text:
            entry["host"] = computer_elem.text.strip()

        time_elem = system.find(f"{ns}TimeCreated")
        if time_elem is not None:
            entry["timestamp"] = time_elem.get("SystemTime", "")

        provider = system.find(f"{ns}Provider")
        if provider is not None:
            guid = provider.get("Guid", "")
            if "sysmon" in guid.lower() or "sysmon" in (provider.get("Name", "")).lower():
                entry["source"] = "sysmon"

    # Extract EventData fields
    event_data = event_elem.find(f"{ns}EventData")
    if event_data is not None:
        for data_elem in event_data.findall(f"{ns}Data"):
            name = data_elem.get("Name", "")
            value = data_elem.text or ""
            if name:
                entry[name] = value

    # Derive action from EventID for Sysmon events
    event_code = entry.get("event_code", "")
    if event_code in SYSMON_ACTIONS:
        entry["action"] = SYSMON_ACTIONS[event_code]

    return entry


def _extract_flat_event(event_elem: ElementTree.Element) -> dict:
    """Extract fields from a flat XML element (tag → text).

    Used for non-Sysmon XML where each child element is a field.

    Args:
        event_elem: An XML element with child elements as fields.

    Returns:
        Dict of extracted fields.
    """
    entry: dict = {}
    for child in event_elem:
        tag = child.tag
        # Strip namespace if present
        if "}" in tag:
            tag = tag.split("}", 1)[1]
        value = child.text or ""
        if tag:
            entry[tag] = value
    return entry


def _infer_log_type_from_event(entry: dict) -> str:
    """Infer log type from event_code and source fields.

    Args:
        entry: Parsed event dict.

    Returns:
        One of "auth", "network", "dns", "endpoint".
    """
    event_code = str(entry.get("event_code", ""))

    # Check Sysmon events
    if event_code in SYSMON_EVENT_TYPES:
        return SYSMON_EVENT_TYPES[event_code]

    # Check Windows Security events
    if event_code in SECURITY_EVENT_TYPES:
        return SECURITY_EVENT_TYPES[event_code]

    # Heuristic from field names
    if "Image" in entry or "ParentImage" in entry or "CommandLine" in entry:
        return "endpoint"
    if "QueryName" in entry or "QueryResults" in entry:
        return "dns"
    if "DestinationPort" in entry or "SourcePort" in entry or "Initiated" in entry:
        return "network"
    if "TargetUserName" in entry or "SubjectUserName" in entry or "LogonType" in entry:
        return "auth"

    return "auth"


def _parse_xml_fragments(content: str, max_entries: int = 100_000) -> list[dict]:
    """Parse XML content where each <Event> is a standalone fragment.

    Common in Sysmon exports — no root element, each line is a complete
    <Event> element. We parse each line individually.

    Args:
        content: Full file content.
        max_entries: Maximum number of entries to parse.

    Returns:
        List of dicts (one per Event element).

    Raises:
        ValueError: If no events could be parsed.
    """
    entries: list[dict] = []
    for i, line in enumerate(content.splitlines(), 1):
        if len(entries) >= max_entries:
            logger.warning(
                "XML fragments exceeded %d entries, truncating at line %d.",
                max_entries, i,
            )
            break

        line = line.strip()
        if not line or not line.startswith("<"):
            continue

        try:
            elem = ElementTree.fromstring(line)
        except ElementTree.ParseError:
            logger.debug("Skipping unparseable XML line %d", i)
            continue

        # Detect element type
        tag = elem.tag
        if "}" in tag:
            tag = tag.split("}", 1)[1]

        if tag == "Event":
            entry = _extract_sysmon_event(elem)
        else:
            entry = _extract_flat_event(elem)

        if entry:
            entries.append(entry)

    if not entries:
        raise ValueError("Could not parse any XML event fragments")

    logger.info("Parsed %d entries from XML fragments", len(entries))
    return entries


def parse_xml(
    path: Path,
    max_entries: int = 100_000,
    encoding: str = "utf-8",
) -> list[dict]:
    """Parse an XML log file into a list of dicts.

    Handles:
    - Sysmon/Windows Event Log: <Event><System>...<EventData>...</EventData></Event>
    - Flat row-based: <root><row><field1>val</field1>...</row></root>

    Args:
        path: Path to the XML file.
        max_entries: Maximum number of entries to parse.
        encoding: File encoding.

    Returns:
        List of dicts (one per Event/row element).

    Raises:
        FileNotFoundError: If the file doesn't exist.
        ValueError: If the XML cannot be parsed.
    """
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    content = path.read_text(encoding=encoding, errors="replace")

    # Try parsing as a single XML document first
    try:
        root = ElementTree.fromstring(content)
    except ElementTree.ParseError:
        # Common Sysmon export format: no root element, each <Event> is a
        # standalone fragment on its own line. Wrap in a synthetic root.
        logger.debug("XML parse failed, trying fragment mode (one Event per line)")
        return _parse_xml_fragments(content, max_entries)

    entries: list[dict] = []

    # Strategy 1: Find <Event> elements (Sysmon / Windows Event Log)
    event_elems = root.findall("Event")
    if not event_elems:
        # Try with namespace
        event_elems = root.findall(".//{http://schemas.microsoft.com/win/2004/08/events/event}Event")

    if event_elems:
        for elem in event_elems:
            if len(entries) >= max_entries:
                logger.warning(
                    "XML file exceeded %d entries, truncating.",
                    max_entries,
                )
                break
            entry = _extract_sysmon_event(elem)
            if entry:
                entries.append(entry)
    else:
        # Strategy 2: Treat direct children as rows
        for child in root:
            if len(entries) >= max_entries:
                logger.warning(
                    "XML file exceeded %d entries, truncating.",
                    max_entries,
                )
                break
            entry = _extract_flat_event(child)
            if entry:
                entries.append(entry)

    if not entries:
        raise ValueError(f"No parseable events found in XML file: {path}")

    logger.info("Parsed %d entries from XML file: %s", len(entries), path)
    return entries
