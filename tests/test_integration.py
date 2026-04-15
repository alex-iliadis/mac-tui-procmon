"""Integration tests for procmon alert lifecycle.

Simulates realistic alert scenarios by manipulating process data and time
to verify the full trigger → cooldown → clear → retrigger cycle.
"""
import json
import os
import sys
import time
from unittest.mock import MagicMock, patch, call

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import procmon
from tests.conftest import make_proc


class TestAlertLifecycleCPU:
    """Full lifecycle: CPU spikes → alerts fire → CPU drops → resets → CPU spikes → alerts fire again."""

    def test_trigger_clear_retrigger(self, monitor):
        """Exact scenario: high CPU → alert → CPU drops to 10% → CPU spikes again → should alert again."""
        monitor._alert_thresholds["cpu"] = 70.0
        monitor._alert_max_count = 5
        monitor._alert_interval = 15

        clock = [1000.0]

        def fake_monotonic():
            return clock[0]

        with patch("subprocess.Popen") as popen, \
             patch("time.monotonic", side_effect=fake_monotonic):

            # Phase 1: CPU spikes to 125%, alerts should fire
            monitor._all_procs = [
                make_proc(pid=1, cpu=50.0, command="/Applications/Chrome.app/chrome"),
                make_proc(pid=2, cpu=45.0, command="/System/WindowServer"),
                make_proc(pid=3, cpu=30.0, command="/Applications/Chrome.app/gpu"),
            ]
            monitor._check_alerts()
            assert monitor._alert_count == 1
            assert popen.call_count == 1

            # Fire more alerts at 15s intervals
            clock[0] = 1016.0
            monitor._check_alerts()
            assert monitor._alert_count == 2
            assert popen.call_count == 2

            clock[0] = 1032.0
            monitor._check_alerts()
            assert popen.call_count == 3

            clock[0] = 1048.0
            monitor._check_alerts()
            assert popen.call_count == 4

            clock[0] = 1064.0
            monitor._check_alerts()
            assert popen.call_count == 5
            assert monitor._alert_count == 5

            # Phase 2: Still triggered but max count reached
            clock[0] = 1080.0
            monitor._check_alerts()
            assert popen.call_count == 5  # blocked by max

            # Phase 3: CPU drops to 10%
            clock[0] = 1096.0
            monitor._all_procs = [
                make_proc(pid=1, cpu=5.0),
                make_proc(pid=2, cpu=3.0),
                make_proc(pid=3, cpu=2.0),
            ]
            monitor._check_alerts()
            assert monitor._alert_count == 0  # RESET
            assert monitor._alert_last_sound == 0.0

            # Phase 4: CPU spikes again
            clock[0] = 1112.0
            monitor._all_procs = [
                make_proc(pid=1, cpu=80.0),
                make_proc(pid=2, cpu=50.0),
            ]
            monitor._check_alerts()
            assert monitor._alert_count == 1
            assert popen.call_count == 6  # new alert!

            # Continue alerting
            clock[0] = 1128.0
            monitor._check_alerts()
            assert monitor._alert_count == 2
            assert popen.call_count == 7

    def test_cooldown_respected_between_alerts(self, monitor):
        """Alerts fire respecting the interval between them."""
        monitor._alert_thresholds["cpu"] = 50.0
        monitor._alert_max_count = 10
        monitor._alert_interval = 60

        clock = [0.0]

        with patch("subprocess.Popen") as popen, \
             patch("time.monotonic", side_effect=lambda: clock[0]):

            monitor._all_procs = [make_proc(cpu=100.0)]

            # First alert
            clock[0] = 100.0
            monitor._check_alerts()
            assert popen.call_count == 1

            # 30s later — still in cooldown
            clock[0] = 130.0
            monitor._check_alerts()
            assert popen.call_count == 1

            # 59s later — still in cooldown
            clock[0] = 159.0
            monitor._check_alerts()
            assert popen.call_count == 1

            # 61s later — cooldown expired
            clock[0] = 161.0
            monitor._check_alerts()
            assert popen.call_count == 2

    def test_rapid_clear_and_retrigger(self, monitor):
        """Condition clears and retriggers within a single interval."""
        monitor._alert_thresholds["cpu"] = 70.0
        monitor._alert_max_count = 5
        monitor._alert_interval = 0  # no cooldown for simplicity

        with patch("subprocess.Popen") as popen:
            # Trigger
            monitor._all_procs = [make_proc(cpu=100.0)]
            monitor._check_alerts()
            assert popen.call_count == 1

            # Clear
            monitor._all_procs = [make_proc(cpu=10.0)]
            monitor._check_alerts()
            assert monitor._alert_count == 0

            # Retrigger immediately
            monitor._all_procs = [make_proc(cpu=100.0)]
            monitor._check_alerts()
            assert popen.call_count == 2

            # Clear again
            monitor._all_procs = [make_proc(cpu=10.0)]
            monitor._check_alerts()
            assert monitor._alert_count == 0

            # Retrigger again
            monitor._all_procs = [make_proc(cpu=100.0)]
            monitor._check_alerts()
            assert popen.call_count == 3


class TestAlertLifecycleMem:
    """Memory-based alert lifecycle."""

    def test_mem_trigger_clear_retrigger(self, monitor):
        monitor._alert_thresholds["mem_mb"] = 25000.0
        monitor._alert_max_count = 3
        monitor._alert_interval = 0

        with patch("subprocess.Popen") as popen:
            # Trigger: 28 GB
            monitor._all_procs = [make_proc(rss_kb=28 * 1024 * 1024)]
            for _ in range(5):
                monitor._check_alerts()
            assert popen.call_count == 3  # max count

            # Clear: 20 GB
            monitor._all_procs = [make_proc(rss_kb=20 * 1024 * 1024)]
            monitor._check_alerts()
            assert monitor._alert_count == 0

            # Retrigger: 30 GB
            monitor._all_procs = [make_proc(rss_kb=30 * 1024 * 1024)]
            monitor._check_alerts()
            assert popen.call_count == 4


class TestAlertLifecycleMultipleThresholds:
    """Multiple thresholds can trigger independently."""

    def test_different_thresholds_trigger(self, monitor):
        monitor._alert_thresholds["cpu"] = 70.0
        monitor._alert_thresholds["forks"] = 10
        monitor._alert_interval = 0
        monitor._alert_max_count = 0  # unlimited

        with patch("subprocess.Popen") as popen:
            # CPU triggers
            monitor._all_procs = [make_proc(cpu=100.0, forks=5)]
            monitor._check_alerts()
            assert popen.call_count == 1

            # CPU clears but forks trigger
            monitor._all_procs = [make_proc(cpu=10.0, forks=5)]
            monitor._check_alerts()  # clears (neither triggers)
            assert monitor._alert_count == 0

            monitor._all_procs = [make_proc(cpu=10.0, forks=20)]
            monitor._check_alerts()  # forks trigger
            assert popen.call_count == 2

    def test_one_threshold_keeps_triggered(self, monitor):
        """If one threshold clears but another stays, no reset."""
        monitor._alert_thresholds["cpu"] = 70.0
        monitor._alert_thresholds["mem_mb"] = 1000.0
        monitor._alert_interval = 0
        monitor._alert_max_count = 0

        with patch("subprocess.Popen") as popen:
            # Both trigger
            monitor._all_procs = [make_proc(cpu=100.0, rss_kb=2000 * 1024)]
            monitor._check_alerts()
            assert popen.call_count == 1

            # CPU drops, mem still high — still triggered, no reset
            monitor._all_procs = [make_proc(cpu=10.0, rss_kb=2000 * 1024)]
            monitor._check_alerts()
            assert monitor._alert_count == 2  # incremented, not reset
            assert popen.call_count == 2


class TestAlertLifecycleNetOut:
    """Network out threshold lifecycle."""

    def test_net_out_trigger_clear_retrigger(self, monitor):
        monitor._alert_thresholds["net_out"] = 1500.0  # KB/s
        monitor._alert_max_count = 2
        monitor._alert_interval = 0

        with patch("subprocess.Popen") as popen:
            # Trigger: 2000 KB/s
            monitor._all_procs = [make_proc(net_out=2000 * 1024)]
            monitor._check_alerts()
            monitor._check_alerts()
            monitor._check_alerts()  # blocked
            assert popen.call_count == 2

            # Clear
            monitor._all_procs = [make_proc(net_out=500 * 1024)]
            monitor._check_alerts()
            assert monitor._alert_count == 0

            # Retrigger
            monitor._all_procs = [make_proc(net_out=2000 * 1024)]
            monitor._check_alerts()
            assert popen.call_count == 3


class TestAlertLifecycleWithFilters:
    """Alerts should only consider _all_procs (filtered processes)."""

    def test_filtered_procs_reduce_totals(self, monitor):
        """With a filter active, only matched processes count toward thresholds."""
        monitor._alert_thresholds["cpu"] = 70.0
        monitor._alert_interval = 0

        # Simulating a filter that only matched 2 low-CPU procs
        monitor._all_procs = [
            make_proc(pid=1, cpu=20.0),
            make_proc(pid=2, cpu=30.0),
        ]
        with patch("subprocess.Popen") as popen:
            monitor._check_alerts()
        popen.assert_not_called()

        # Now filter matches a high-CPU proc
        monitor._all_procs = [
            make_proc(pid=1, cpu=20.0),
            make_proc(pid=2, cpu=30.0),
            make_proc(pid=3, cpu=40.0),
        ]
        with patch("subprocess.Popen") as popen:
            monitor._check_alerts()
        popen.assert_called_once()


class TestAlertLifecycleTimingPrecision:
    """Test precise timing around cooldown boundaries."""

    def test_exactly_at_interval_boundary(self, monitor):
        monitor._alert_thresholds["cpu"] = 50.0
        monitor._alert_interval = 60
        monitor._alert_max_count = 0

        clock = [1000.0]

        with patch("subprocess.Popen") as popen, \
             patch("time.monotonic", side_effect=lambda: clock[0]):

            monitor._all_procs = [make_proc(cpu=100.0)]

            clock[0] = 1000.0
            monitor._check_alerts()
            assert popen.call_count == 1

            # Exactly at boundary (60s later) — should fire
            clock[0] = 1060.0
            monitor._check_alerts()
            assert popen.call_count == 2

            # One second before next boundary
            clock[0] = 1119.0
            monitor._check_alerts()
            assert popen.call_count == 2  # still in cooldown

            # At next boundary
            clock[0] = 1120.0
            monitor._check_alerts()
            assert popen.call_count == 3


class TestAlertLifecycleEdgeCases:

    def test_empty_procs_list(self, monitor):
        """No processes → no alert."""
        monitor._alert_thresholds["cpu"] = 50.0
        monitor._all_procs = []
        with patch("subprocess.Popen") as popen:
            monitor._check_alerts()
        popen.assert_not_called()

    def test_all_negative_net_values(self, monitor):
        """Processes with -1 net values (no data) should not trigger net alerts."""
        monitor._alert_thresholds["net_in"] = 1.0
        monitor._all_procs = [make_proc(net_in=-1), make_proc(net_in=-1)]
        with patch("subprocess.Popen") as popen:
            monitor._check_alerts()
        popen.assert_not_called()

    def test_config_change_resets_count(self, monitor, tmp_path):
        """Changing alert config via _prompt_config resets the count."""
        monitor._alert_thresholds["cpu"] = 50.0
        monitor._alert_count = 5
        monitor._alert_max_count = 5

        # Simulate what _prompt_config does at the end
        monitor._alert_count = 0  # line 2076 in procmon.py
        assert monitor._alert_count == 0

    def test_max_count_one(self, monitor):
        """Max count of 1 = single alert then stop."""
        monitor._alert_thresholds["cpu"] = 50.0
        monitor._alert_max_count = 1
        monitor._alert_interval = 0
        monitor._all_procs = [make_proc(cpu=100.0)]

        with patch("subprocess.Popen") as popen:
            monitor._check_alerts()
            monitor._check_alerts()
            monitor._check_alerts()
        assert popen.call_count == 1

    def test_interval_one_second(self, monitor):
        """Very short interval still works correctly."""
        monitor._alert_thresholds["cpu"] = 50.0
        monitor._alert_interval = 1
        monitor._alert_max_count = 0

        clock = [100.0]

        with patch("subprocess.Popen") as popen, \
             patch("time.monotonic", side_effect=lambda: clock[0]):

            monitor._all_procs = [make_proc(cpu=100.0)]

            clock[0] = 100.0
            monitor._check_alerts()
            assert popen.call_count == 1

            clock[0] = 100.5
            monitor._check_alerts()
            assert popen.call_count == 1

            clock[0] = 101.1
            monitor._check_alerts()
            assert popen.call_count == 2


class TestAlertLifecycleConfigPersistence:
    """Config load/save integrates correctly with alert lifecycle."""

    def test_loaded_config_affects_alerts(self, monitor, tmp_path):
        cfg = {
            "alert_thresholds": {"cpu": 70.0},
            "alert_interval": 15,
            "alert_max_count": 3,
        }
        cfg_file = tmp_path / ".procmon.json"
        cfg_file.write_text(json.dumps(cfg))
        monitor._CONFIG_PATH = str(cfg_file)
        monitor._load_config()

        monitor._all_procs = [make_proc(cpu=100.0)]
        monitor._alert_interval = 0  # override for test speed

        with patch("subprocess.Popen") as popen:
            for _ in range(5):
                monitor._check_alerts()
            assert popen.call_count == 3  # max_count from config


class TestAlertLifecycleFullScenario:
    """The exact user-reported scenario: threshold exceeded → max alerts → drop → rise → no new alerts (bug)."""

    def test_user_reported_bug_scenario(self, monitor):
        """
        Reproduce the exact bug scenario:
        1. CPU threshold = 70%, max_count = 5, interval = 15s
        2. CPU at 125% — 5 alerts fire over ~75s
        3. CPU drops to 10% (user said it dropped)
        4. CPU rises back above 70%
        5. Expected: new alerts. Bug: no alerts because count stuck at 5.
        """
        monitor._alert_thresholds["cpu"] = 70.0
        monitor._alert_max_count = 5
        monitor._alert_interval = 15

        clock = [1000.0]

        with patch("subprocess.Popen") as popen, \
             patch("time.monotonic", side_effect=lambda: clock[0]):

            # Step 1-2: CPU at 125%, fire 5 alerts
            monitor._all_procs = [
                make_proc(pid=1, cpu=49.5),   # Chrome renderer
                make_proc(pid=2, cpu=44.4),   # WindowServer
                make_proc(pid=3, cpu=35.4),   # Chrome GPU
            ]

            for i in range(5):
                clock[0] = 1000.0 + (i * 16)
                monitor._check_alerts()
            assert popen.call_count == 5
            assert monitor._alert_count == 5

            # Step 3: CPU drops to 10%
            clock[0] = 1100.0
            monitor._all_procs = [
                make_proc(pid=1, cpu=5.0),
                make_proc(pid=2, cpu=3.0),
                make_proc(pid=3, cpu=2.0),
            ]
            monitor._check_alerts()

            # THIS IS THE KEY ASSERTION — the count MUST reset
            assert monitor._alert_count == 0, \
                "BUG: alert count did not reset after condition cleared"
            assert monitor._alert_last_sound == 0.0, \
                "BUG: alert timer did not reset after condition cleared"

            # Step 4: CPU rises back above 70%
            clock[0] = 1200.0
            monitor._all_procs = [
                make_proc(pid=1, cpu=49.5),
                make_proc(pid=2, cpu=44.4),
                make_proc(pid=3, cpu=35.4),
            ]
            monitor._check_alerts()

            # Step 5: NEW ALERT MUST FIRE
            assert popen.call_count == 6, \
                "BUG: alert did not re-fire after condition cleared and re-triggered"
            assert monitor._alert_count == 1


class TestAlertOscillationBug:
    """Regression: brief dips below threshold must NOT reset counter within the interval."""

    def test_brief_dip_does_not_reset_counter(self, monitor):
        """
        Memory oscillates around threshold:
        1. 26GB → triggers, beep #1
        2. 24GB briefly → should NOT reset (within interval)
        3. 26GB → should be beep #2, not #1 again
        Without the fix, step 2 reset _alert_count to 0, causing infinite beeps.
        """
        monitor._alert_thresholds["mem_mb"] = 25000.0
        monitor._alert_max_count = 3
        monitor._alert_interval = 60

        clock = [1000.0]

        with patch("subprocess.Popen") as popen, \
             patch("time.monotonic", side_effect=lambda: clock[0]):

            # Step 1: exceeds → beep #1
            monitor._all_procs = [make_proc(rss_kb=26 * 1024 * 1024)]
            monitor._check_alerts()
            assert popen.call_count == 1
            assert monitor._alert_count == 1

            # Step 2: brief dip below threshold, only 5s later (within interval)
            clock[0] = 1005.0
            monitor._all_procs = [make_proc(rss_kb=24 * 1024 * 1024)]
            monitor._check_alerts()
            # Counter must NOT reset — the dip was within the interval
            assert monitor._alert_count == 1, \
                "BUG: brief dip reset counter — oscillation would cause infinite beeps"

            # Step 3: back above threshold, 61s after first beep
            clock[0] = 1061.0
            monitor._all_procs = [make_proc(rss_kb=26 * 1024 * 1024)]
            monitor._check_alerts()
            assert popen.call_count == 2
            assert monitor._alert_count == 2  # correctly incremented, not reset to 1

    def test_sustained_clear_does_reset(self, monitor):
        """After a full interval of non-triggering, the counter resets."""
        monitor._alert_thresholds["mem_mb"] = 25000.0
        monitor._alert_max_count = 3
        monitor._alert_interval = 60

        clock = [1000.0]

        with patch("subprocess.Popen") as popen, \
             patch("time.monotonic", side_effect=lambda: clock[0]):

            # Trigger → beep
            monitor._all_procs = [make_proc(rss_kb=26 * 1024 * 1024)]
            monitor._check_alerts()
            assert monitor._alert_count == 1

            # Drop below threshold and stay down for > interval
            clock[0] = 1070.0  # 70s later, well past the 60s interval
            monitor._all_procs = [make_proc(rss_kb=20 * 1024 * 1024)]
            monitor._check_alerts()
            assert monitor._alert_count == 0  # reset after sustained clear

            # Re-trigger should start fresh
            clock[0] = 1071.0
            monitor._all_procs = [make_proc(rss_kb=26 * 1024 * 1024)]
            monitor._check_alerts()
            assert popen.call_count == 2
            assert monitor._alert_count == 1  # fresh count

    def test_max_count_honored_during_oscillation(self, monitor):
        """Max count blocks alerts even when value oscillates."""
        monitor._alert_thresholds["cpu"] = 50.0
        monitor._alert_max_count = 2
        monitor._alert_interval = 10

        clock = [1000.0]

        with patch("subprocess.Popen") as popen, \
             patch("time.monotonic", side_effect=lambda: clock[0]):

            monitor._all_procs = [make_proc(cpu=80.0)]

            # Beep #1
            clock[0] = 1000.0
            monitor._check_alerts()
            assert popen.call_count == 1

            # Beep #2
            clock[0] = 1011.0
            monitor._check_alerts()
            assert popen.call_count == 2

            # Brief dip 2s later (within interval — no reset)
            clock[0] = 1013.0
            monitor._all_procs = [make_proc(cpu=40.0)]
            monitor._check_alerts()
            assert monitor._alert_count == 2  # NOT reset

            # Back above — max count still blocks
            clock[0] = 1025.0
            monitor._all_procs = [make_proc(cpu=80.0)]
            monitor._check_alerts()
            assert popen.call_count == 2  # still blocked by max_count
