"""Tests for the LOLBIN database module."""

from nabla.lolbin_db import (
    build_lolbin_index,
    format_lolbin_block,
    parse_lolbin_block,
)


# --- Sample data for testing ---

SAMPLE_LOLBAS = [
    {
        "Name": "Certutil.exe",
        "Commands": [
            {"Category": "Download", "MitreID": "T1105", "Usecase": "Download file"},
            {"Category": "Encode", "MitreID": "T1140", "Usecase": "Encode data"},
        ],
        "Full_Path": [{"Path": "C:\\Windows\\System32\\certutil.exe"}],
        "Detection": [
            {"Sigma": "https://github.com/SigmaHQ/sigma/blob/main/rules/proc_creation_win_certutil_download.yml"},
        ],
        "Resources": [],
    },
    {
        "Name": "Mshta.exe",
        "Commands": [
            {"Category": "Execute", "MitreID": "T1218", "Usecase": "Execute HTA"},
        ],
        "Full_Path": [{"Path": "C:\\Windows\\System32\\mshta.exe"}],
        "Detection": [],
        "Resources": [],
    },
    {
        "Name": "Rundll32.exe",
        "Commands": [
            {"Category": "Execute", "MitreID": "T1218", "Usecase": "Execute DLL"},
            {"Category": "Download", "MitreID": "T1105", "Usecase": "Download file"},
        ],
        "Full_Path": [{"Path": "C:\\Windows\\System32\\rundll32.exe"}],
        "Detection": [
            {"Elastic": "https://elastic.co/rules/rundll32_suspicious.yml"},
        ],
        "Resources": [],
    },
]

SAMPLE_GTFOBINS = {
    "functions": {
        "shell": {"label": "Shell", "mitre": ["T1059"]},
        "file-read": {"label": "File Read", "mitre": ["T1005"]},
        "download": {"label": "Download", "mitre": ["T1105"]},
        "upload": {"label": "Upload", "mitre": ["T1105"]},
    },
    "contexts": {},
    "executables": {
        "bash": {
            "functions": {
                "shell": [{"code": "bash", "contexts": {"sudo": None}}],
                "file-read": [{"code": "cat", "contexts": {"unprivileged": None}}],
            },
        },
        "curl": {
            "functions": {
                "download": [{"code": "curl http://", "contexts": {"unprivileged": None}}],
                "upload": [{"code": "curl -T", "contexts": {"unprivileged": None}}],
            },
        },
        "python3": {
            "functions": {
                "shell": [{"code": "python3 -c 'import os'", "contexts": {"sudo": None}}],
                "file-read": [{"code": "python3 -c 'open'", "contexts": {"unprivileged": None}}],
            },
        },
    },
}


def test_build_lolbin_index_windows():
    """Building index from LOLBAS data should produce Windows entries."""
    data = {"lolbas": SAMPLE_LOLBAS, "gtfobins": {}}
    index = build_lolbin_index(data)

    assert "windows" in index
    assert "unix" in index
    assert "certutil" in index["windows"]
    assert "mshta" in index["windows"]
    assert "rundll32" in index["windows"]

    # Check categories
    assert "Download" in index["windows"]["certutil"]["categories"]
    assert "Encode" in index["windows"]["certutil"]["categories"]
    assert "Execute" in index["windows"]["mshta"]["categories"]

    # Check MITRE IDs
    assert "T1105" in index["windows"]["certutil"]["mitre_ids"]
    assert "T1140" in index["windows"]["certutil"]["mitre_ids"]
    assert "T1218" in index["windows"]["mshta"]["mitre_ids"]


def test_build_lolbin_index_unix():
    """Building index from GTFOBins data should produce Unix entries."""
    data = {"lolbas": [], "gtfobins": SAMPLE_GTFOBINS}
    index = build_lolbin_index(data)

    assert "bash" in index["unix"]
    assert "curl" in index["unix"]
    assert "python3" in index["unix"]

    # Check functions
    assert "shell" in index["unix"]["bash"]["functions"]
    assert "file-read" in index["unix"]["bash"]["functions"]
    assert "download" in index["unix"]["curl"]["functions"]

    # Check MITRE IDs from function definitions
    assert "T1059" in index["unix"]["bash"]["mitre_ids"]
    assert "T1005" in index["unix"]["bash"]["mitre_ids"]
    assert "T1105" in index["unix"]["curl"]["mitre_ids"]


def test_build_lolbin_index_empty():
    """Building index from empty data should produce empty results."""
    data = {"lolbas": [], "gtfobins": {}}
    index = build_lolbin_index(data)

    assert index["windows"] == {}
    assert index["unix"] == {}


def test_format_and_parse_roundtrip():
    """Formatting and parsing the LOLBIN block should preserve key data."""
    data = {"lolbas": SAMPLE_LOLBAS, "gtfobins": SAMPLE_GTFOBINS}
    index = build_lolbin_index(data)
    text = format_lolbin_block(index)
    parsed = parse_lolbin_block(text)

    assert "certutil" in parsed["windows"]
    assert parsed["windows"]["certutil"]["name"] == "Certutil.exe"
    assert "Download" in parsed["windows"]["certutil"]["categories"]
    assert "T1105" in parsed["windows"]["certutil"]["mitre_ids"]

    assert "bash" in parsed["unix"]
    assert "shell" in parsed["unix"]["bash"]["functions"]
    assert "T1059" in parsed["unix"]["bash"]["mitre_ids"]


def test_format_lolbin_block_structure():
    """The formatted block should have section headers."""
    data = {"lolbas": SAMPLE_LOLBAS, "gtfobins": SAMPLE_GTFOBINS}
    index = build_lolbin_index(data)
    text = format_lolbin_block(index)

    assert "=== WINDOWS LOLBINS ===" in text
    assert "=== UNIX GTFOBINS ===" in text


def test_parse_empty_block():
    """Parsing an empty block should return empty results."""
    result = parse_lolbin_block("")
    assert result == {"windows": {}, "unix": {}}


def test_detection_refs_limited():
    """Detection references should be limited to 5 per entry."""
    # Create entry with many detection refs
    many_dets = [
        {
            "Name": "Test.exe",
            "Commands": [{"Category": "Execute", "MitreID": "T1059", "Usecase": "test"}],
            "Full_Path": [],
            "Detection": [
                {"Sigma": f"https://sigma/rule{i}.yml"} for i in range(10)
            ],
            "Resources": [],
        }
    ]
    data = {"lolbas": many_dets, "gtfobins": {}}
    index = build_lolbin_index(data)

    assert len(index["windows"]["test"]["detection"]) <= 5


def test_format_lolbin_block_empty():
    """Formatting an empty index should produce section headers only."""
    index = {"windows": {}, "unix": {}}
    text = format_lolbin_block(index)

    assert "=== WINDOWS LOLBINS ===" in text
    assert "=== UNIX GTFOBINS ===" in text
