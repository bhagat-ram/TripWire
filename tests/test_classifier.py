"""
tests/test_classifier.py

Pytest wrapper around classifier.py's Stage 4 reliability checkpoint:
  - Window state persists across a server restart mid-burst
  - Clock skew / out-of-order wall-clock timestamps don't break the window

Run: pytest tests/test_classifier.py -v
"""

import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config
from events import EventStore
from classifier import Classifier


@pytest.fixture
def store(tmp_path):
    db_path = os.path.join(tmp_path, "test_tripwire.db")
    return EventStore(db_path=db_path)


@pytest.fixture
def store2(tmp_path):
    db_path = os.path.join(tmp_path, "test_tripwire_2.db")
    return EventStore(db_path=db_path)


# ─── functional checkpoint ──────────────────────────────────────────────────

def test_severity_escalates_on_synthetic_burst(store):
    clf = Classifier(store, window_s=10.0)
    results = [clf.record_touch(f"decoys/file_{i}.xlsx")
               for i in range(config.CRITICAL_TOUCH_THRESHOLD + 1)]
    assert results[0].severity == "info"
    assert results[-1].severity == "critical"


def test_warning_threshold_fires_before_critical(store):
    clf = Classifier(store, window_s=10.0)
    results = [clf.record_touch(f"decoys/f{i}.xlsx")
               for i in range(config.WARNING_TOUCH_THRESHOLD)]
    assert results[-1].severity in ("warning", "critical")


# ─── reliability checkpoint ─────────────────────────────────────────────────

def test_window_persists_across_restart_mid_burst(store):
    """A server crash mid-incident must not lose the evidence trail: a fresh
    Classifier built on the same DB should immediately see the prior touches."""
    clf = Classifier(store, window_s=10.0)
    for i in range(config.CRITICAL_TOUCH_THRESHOLD + 1):
        clf.record_touch(f"decoys/file_{i}.xlsx")

    # simulate the process dying and server.py constructing a fresh
    # Classifier(store) on boot, against the same on-disk DB
    del clf
    clf2 = Classifier(store, window_s=10.0)

    assert clf2.current_window_count() == config.CRITICAL_TOUCH_THRESHOLD + 1

    r_after_restart = clf2.record_touch("decoys/after_restart.xlsx")
    assert r_after_restart.severity == "critical"


def test_window_ages_out_old_touches(store2):
    clf = Classifier(store2, window_s=0.3)
    clf.record_touch("decoys/x.xlsx")
    clf.record_touch("decoys/y.xlsx")
    time.sleep(0.4)
    r = clf.record_touch("decoys/z.xlsx")
    assert r.touch_count == 1
    assert r.severity == "info"


def test_backward_wall_clock_jump_does_not_corrupt_window(store):
    """Simulates an NTP backward clock correction mid-run. Window math uses
    time.monotonic() internally so touches already recorded must not vanish
    or double-count when wall time jumps backwards."""
    clf = Classifier(store, window_s=10.0)
    clf.record_touch("decoys/a.xlsx")
    clf._last_wall -= 5.0  # simulate NTP backward jump
    r = clf.record_touch("decoys/b.xlsx")
    assert r.touch_count == 2


def test_out_of_order_timestamps_do_not_break_window(store):
    """Touches recorded with a monotonic reference should still all count
    within the window even if wall-clock deltas are non-uniform."""
    clf = Classifier(store, window_s=10.0)
    for _ in range(3):
        clf.record_touch("decoys/a.xlsx")
        time.sleep(0.05)
    assert clf.current_window_count() == 3


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
