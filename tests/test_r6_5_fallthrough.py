"""R6-5 (round 6): a baselined user is judged ONCE — by their own baseline.

The bug: the `continue` sat inside the alert branch, so a DEDUPED hour
(or one the user's baseline called normal) fell through to the batch
z-score, re-alerting the exact hour S7's dedup had silenced — and
judging warm users against batch statistics their own EWMA had already
cleared.
"""

import os
import tempfile


D = "2026-08-12T"


def _warm(store, user="u"):
    for day in (8, 9, 10, 11):
        store.update_user(user, [
            {"user": user, "action": "activity", "type": "authentication",
             "timestamp": f"2026-08-{day}T{h:02d}:{i:02d}:00Z"}
            for h in range(24) for i in range(4)])


class TestFallThrough:
    def test_deduped_hour_not_realerted_by_batch_z(self):
        os.environ["NABLA_DATA_DIR"] = tempfile.mkdtemp()
        import logging
        logging.disable(logging.CRITICAL)
        from nabla.baselines import EntityProfileStore
        from nabla.detection import detect_anomalies
        from pathlib import Path
        store = EntityProfileStore(str(Path(tempfile.mkdtemp()) / "p.json"))
        _warm(store)
        # First batch: burst fires entity_z and marks the hour alerted
        b1 = [{"user": "u", "action": "activity", "type": "authentication",
               "timestamp": f"{D}03:{i:02d}:00Z"} for i in range(25)]
        a1, _ = detect_anomalies(b1, phase="detection", entity_profiles=store)
        fired1 = [a for a in a1 if a.get("detection_method") == "entity_z_score"]
        # Second batch: SAME hour, bigger — deduped by S7, but the old code
        # fell through to z_score_spike (batch stat). With enough synthetic
        # peers to make the batch z computable:
        peers = [{"user": f"p{j}", "action": "activity", "type": "authentication",
                  "timestamp": f"{D}03:{i:02d}:00Z"}
                 for j in range(12) for i in range(2)]
        b2 = b1 + [{"user": "u", "action": "activity", "type": "authentication",
                    "timestamp": f"{D}03:{i:02d}:00Z"} for i in range(30, 55)] + peers
        a2, _ = detect_anomalies(b2, phase="detection", entity_profiles=store)
        u_batch_z = [a for a in a2
                     if a.get("detection_method") == "z_score"
                     and a.get("user") == "u"]
        deduped = not [a for a in a2
                       if a.get("detection_method") == "entity_z_score"
                       and a.get("user") == "u"]
        assert fired1, "setup failed: first burst did not fire"
        assert deduped, "setup failed: second same-hour burst was not deduped"
        assert not u_batch_z, (
            "R6-5: a baselined user's DEDUPED hour fell through to the "
            "batch z-score — S7's dedup is undone by the fall-through")

    def test_normal_activity_not_realerted_by_batch_z(self):
        """A warm user's NORMAL hour, cleared by their own EWMA, must not
        be re-flagged by batch statistics (the comment always promised
        this; the code never delivered)."""
        os.environ["NABLA_DATA_DIR"] = tempfile.mkdtemp()
        import logging
        logging.disable(logging.CRITICAL)
        from nabla.baselines import EntityProfileStore
        from nabla.detection import detect_anomalies
        from pathlib import Path
        store = EntityProfileStore(str(Path(tempfile.mkdtemp()) / "p.json"))
        _warm(store)
        # u does their normal 4/hour while quiet peers make u look
        # "spiky" to the batch statistic
        peers = [{"user": f"p{j}", "action": "activity", "type": "authentication",
                  "timestamp": f"{D}03:{i:02d}:00Z"}
                 for j in range(12) for i in range(1)]
        batch = [{"user": "u", "action": "activity", "type": "authentication",
                  "timestamp": f"{D}03:{i * 15:02d}:00Z"} for i in range(4)] + peers
        anoms, _ = detect_anomalies(batch, phase="detection", entity_profiles=store)
        # R6-5 scope: the BATCH-STATISTIC family (z_score, activity_spike)
        # must not judge a baselined user. Off-hours is a different
        # detector with its own site-tz semantics (C9) — out of scope here.
        stat_family = ("z_score", "activity_spike")
        u_stat = [a for a in anoms
                  if a.get("user") == "u"
                  and a.get("detection_method") in stat_family]
        assert not u_stat, (
            f"R6-5: u's normal hour (4/hr vs their own 4/hr baseline) "
            f"flagged by {[a.get('detection_method') for a in u_stat]} — "
            f"a baselined user is judged by their baseline, not the batch")
