"""Phase 6 (L11): /api/system/methods — the ground-truth method list.

The frontend's detectionMethods.ts was a stale third copy extracted
2026-09-02: 15 emitted bandit methods had no entry under any name, one
row was a slash-triple, no R7 map. This endpoint serves the backend's
own tables; the Methods page joins it with authored prose by key.
"""
import pytest


@pytest.fixture
def methods_response(monkeypatch):
    from fastapi.testclient import TestClient
    from nabla.server import app
    from nabla.auth import require_user

    monkeypatch.setitem(app.dependency_overrides, require_user, lambda: None)
    client = TestClient(app)
    resp = client.get("/api/system/methods")
    assert resp.status_code == 200
    return resp.json()


class TestMethodsEndpoint:
    def test_every_emitted_method_served(self, methods_response):
        """The ground truth is EMITTED methods, not just bandit arms —
        attack_script/cusum/ewma/renamed_tool emit without an arm."""
        from nabla.rl.bandit import DETECTION_METHODS
        from nabla.api.system import _emitted_method_types
        served = {m["method"] for m in methods_response["methods"]}
        expected = set(_emitted_method_types()) | set(DETECTION_METHODS)
        assert served == expected
        by = {m["method"]: m for m in methods_response["methods"]}
        assert by["attack_script"]["bandit_arm"] is False
        assert by["z_score"]["bandit_arm"] is True

    def test_emitted_type_strings_correct(self, methods_response):
        by_method = {m["method"]: m for m in methods_response["methods"]}
        # the R5 emitted-name case: multi_ip emits multiple_source_ips
        assert by_method["multi_ip"]["types"] == ["multiple_source_ips"]
        assert by_method["off_hours"]["types"] == ["off_hours_activity"]
        # the wide-window case: 21 lines between type and method
        assert by_method["enumeration_behavior"]["types"] == ["enumeration_behavior"]
        # every served method carries at least one emitted type string.
        # Exception: pre_flagged — its `type` is a PASSTHROUGH from the
        # source event (detection.py: "type": e["anomaly"]), so no
        # literal exists and [] is the honest answer.
        missing = [
            m for m in methods_response["methods"]
            if not m["types"] and m["method"] != "pre_flagged"
        ]
        assert not missing, f"methods with no emitted type: {missing}"

    def test_states_match_r7_classification(self, methods_response):
        from nabla.rl.calibration import (
            METHOD_TO_THRESHOLD, NOT_CALIBRATABLE_METHODS, STATIC_DETECTORS,
        )
        for m in methods_response["methods"]:
            if m["method"] in METHOD_TO_THRESHOLD:
                assert m["state"] == "calibratable", m
                assert m["threshold"] == METHOD_TO_THRESHOLD[m["method"]]
            elif m["method"] in NOT_CALIBRATABLE_METHODS:
                assert m["state"] == "not_calibratable", m
            elif m["method"] in STATIC_DETECTORS:
                assert m["state"] == "static", m
            else:
                pytest.fail(f"unclassified method served: {m}")

    def test_calibratable_defaults_from_thresholds(self, methods_response):
        from nabla.rl.calibration import THRESHOLDS, METHOD_TO_THRESHOLD
        for m in methods_response["methods"]:
            if m["state"] == "calibratable":
                assert m["default"] == THRESHOLDS[METHOD_TO_THRESHOLD[m["method"]]][3]
