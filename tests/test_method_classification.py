"""S1/D1 (round 5): machine-account method classification coverage.

Both-direction enforcement per the round-5 plan (Epsilon REQUIRED 2):

  emission scan = {detection_method string literals} ∪ {type string
                   literals} across the five detector modules;

  assert BEHAVIORAL_METHODS ∪ SIGNATURE_KEEP == emitted corpus
  assert BEHAVIORAL_METHODS ∩ SIGNATURE_KEEP == ∅

A new detector that emits a method in neither set fails here before it
ships name-drifted risk classification. A set entry that nothing emits
(a phantom) fails here too — that exact disease slipped through review
twice (peer_group_deviation in plan v1, spike in v2).

Host-side methods (entity_host_composite, entity_new_process,
entity_unusual_process) are deliberately in NEITHER set — the machine
filter is user-typed only; hosts always score. They must still appear
in the emitted corpus; the sets-cover-emission assertion is scoped to
the union, so their absence from both sets is fine ONLY because they
are not user-entity methods. The test pins that reasoning by asserting
they are emitted and in neither set.
"""

import re
from pathlib import Path

import nabla.risk as risk_mod

DETECTOR_MODULES = [
    "nabla/detection.py",
    "nabla/exfiltration.py",
    "nabla/temporal.py",
    "nabla/provenance.py",
    "nabla/gcn_lof.py",
]

REPO_ROOT = Path(__file__).resolve().parent.parent


def _emitted_corpus() -> set[str]:
    corpus: set[str] = set()
    pat = re.compile(
        r'"(?:detection_method|type)":\s*"([a-z_0-9]+)"'
    )
    for rel in DETECTOR_MODULES:
        p = REPO_ROOT / rel
        if not p.exists():
            continue
        for m in pat.finditer(p.read_text()):
            corpus.add(m.group(1))
    return corpus


def test_sets_are_disjoint():
    inter = risk_mod.BEHAVIORAL_METHODS & risk_mod.SIGNATURE_KEEP
    assert not inter, f"methods in both sets: {sorted(inter)}"


def test_sets_cover_emission():
    corpus = _emitted_corpus()
    union = risk_mod.BEHAVIORAL_METHODS | risk_mod.SIGNATURE_KEEP
    missing = corpus - union
    # Non-method literals excluded by explicit, justified ignore lists so
    # the scan stays mechanical:
    IGNORE = {
        # Event types (not detection names):
        "endpoint", "authentication", "network", "file", "registry",
        "process", "unknown", "process_proxy", "dns", "http", "tls",
        "anomaly", "graph_node", "graph_edge",
        # type-string twins: every one pairs with a classified
        # detection_method in the same literal (verified round-5 Phase 1);
        # risk reads detection_method first, so the twin is unreachable
        # unless the pair is split — at which point this test fails and
        # forces a classification decision:
        "brute_force_attempt", "data_exfiltration", "known_attack_script",
        "lolbin_abuse", "rapid_action_sequence", "renamed_attack_tool",
        "suspicious_file_path", "suspicious_parent_child", "z_score_spike",
        "off_hours_activity", "unusual_process_per_host",
        "entity_event_count_spike", "entity_auth_failure_spike",
        "entity_off_hours_activity", "ewma_drift", "cusum_shift",
        "cusum_drop", "gcn_lof_anomaly",
        # Deliberately unclassified (pinned by their own tests below —
        # removing an entry here requires changing those too):
        "entity_host_composite", "entity_new_process",
        "entity_unusual_process",  # host-side: filter is user-typed only
        "gcn_lof",                 # detector disabled by default (R3/N11)
    }
    missing -= IGNORE
    assert not missing, (
        f"emitted detection names in NEITHER set (name drift or an "
        f"unclassified new detector): {sorted(missing)}")


def test_no_phantom_entries():
    corpus = _emitted_corpus()
    for name in sorted(risk_mod.BEHAVIORAL_METHODS | risk_mod.SIGNATURE_KEEP):
        assert name in corpus, (
            f"{name!r} is in a classification set but emitted NOWHERE — "
            f"a phantom entry (the peer_group_deviation/spike disease)")


def test_gcn_lof_classified_where_it_sits():
    """gcn_lof is emitted (gcn_lof.py:725) and lives in NEITHER set —
    the detector is disabled by default (R3/N11). If it is ever
    re-enabled, it must be classified into one of the sets and this
    test updated deliberately: it is behavioral in spirit (unsupervised
    deviation) but was never risk-reviewed while broken."""
    assert "gcn_lof" in _emitted_corpus()
    assert "gcn_lof" not in risk_mod.BEHAVIORAL_METHODS
    assert "gcn_lof" not in risk_mod.SIGNATURE_KEEP


def test_host_methods_deliberately_unclassified():
    """Epsilon fold 1: host-side methods are emitted and in neither set,
    because the machine filter is user-typed only. Pinned so a future
    'fix' has to change this test on purpose."""
    corpus = _emitted_corpus()
    for name in ("entity_host_composite", "entity_new_process",
                 "entity_unusual_process"):
        assert name in corpus, f"{name} no longer emitted — update the test"
        assert name not in risk_mod.BEHAVIORAL_METHODS
        assert name not in risk_mod.SIGNATURE_KEEP
