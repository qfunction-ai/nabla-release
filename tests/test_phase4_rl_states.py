"""Phase 4 (L6): the /rl response carries the honest calibration states.

Verified pre-change: the response served current/default/changed plus a
GLOBAL label count — the held (min_labels) state and the
not_calibratable tier knobs were absent, so the Config page could not
show what the calibration loop was actually doing. Mockup 03 (clip 10)
needs per-threshold state + label evidence.

These witnesses hit the REAL endpoint through the FastAPI TestClient
with REAL label files on disk — never a fixture of our own making.
"""
import json

import pytest


@pytest.fixture
def rl_env(tmp_path, monkeypatch):
    import importlib
    import nabla.config
    import nabla.rl.calibration as cal

    monkeypatch.setenv("NABLA_DATA_DIR", str(tmp_path))
    nabla.config._settings = None
    importlib.reload(nabla.config)
    importlib.reload(cal)

    # Seed labels: 35 for entity_event_count_sigma (>= min_labels 30),
    # 12 for brute_force_ratio (held), mix of TP/FP.
    recs = []
    for i in range(35):
        recs.append({
            "anomaly_id": f"z{i:04d}",
            "detection_method": "entity_z_score",
            "raw_score": 2.0 + (i % 5) * 0.1,
            "disposition": "false_positive" if i % 4 == 0 else "true_positive",
        })
    for i in range(12):
        recs.append({
            "anomaly_id": f"b{i:04d}",
            "detection_method": "failed_login_ratio",
            "raw_score": 0.5 + (i % 3) * 0.1,
            "disposition": "false_positive" if i % 3 == 0 else "benign_true_positive",
        })
    cal.write_labels(recs)
    return cal


class TestRLStates:
    def test_states_and_counts_served(self, rl_env):
        from fastapi.testclient import TestClient
        from nabla.server import app
        from nabla.auth import require_user

        app.dependency_overrides[require_user] = lambda: None
        try:
            client = TestClient(app)
            resp = client.get("/api/system/rl")
        finally:
            app.dependency_overrides.pop(require_user, None)
        assert resp.status_code == 200
        data = resp.json()

        # min_labels served (mockup 03 header stat)
        assert data["min_labels"] == 30

        th = data["thresholds"]

        # entity_event_count_sigma: 35 labels >= 30 -> calibratable
        z = th["entity_event_count_sigma"]
        assert z["state"] == "calibratable", z
        assert z["label_count"] == 35
        assert z["tp_count"] + z["fp_count"] == 35
        assert z["tp_count"] == 35 - len([i for i in range(35) if i % 4 == 0])
        assert "entity_z_score" in z["methods"]

        # brute_force_ratio: 12 labels < 30 -> held with reason
        b = th["brute_force_ratio"]
        assert b["state"] == "held"
        assert b["label_count"] == 12
        assert "12/30" in (b["reason"] or "")

        # a tier knob: not_calibratable, no methods feed it
        lol = th["lolbin_sensitivity"]
        assert lol["state"] == "not_calibratable"
        assert lol["methods"] == []
        assert lol["reason"]

        # global count served alongside per-threshold counts
        assert data["feedback_labels"] == 47

    def test_response_model_drops_nothing(self, rl_env):
        """R-4: the response model IS the contract — every served field
        is declared in ThresholdState (the L14 disease check)."""
        from fastapi.testclient import TestClient
        from nabla.server import app
        from nabla.auth import require_user

        app.dependency_overrides[require_user] = lambda: None
        try:
            client = TestClient(app)
            data = client.get("/api/system/rl").json()
        finally:
            app.dependency_overrides.pop(require_user, None)
        for entry in data["thresholds"].values():
            for key in entry:
                assert key in {
                    "name", "current", "default", "changed", "pinned",
                    "state", "evidence", "label_count", "tp_count",
                    "fp_count", "min_labels", "methods", "reason",
                }, f"undeclared field served: {key}"
