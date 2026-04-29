"""Tests for the eight new visually-spectacular features.

Each section corresponds to one feature so test failures are easy to
attribute. The shared `monitor` fixture lives in conftest.py.

Features:
  1. Process Event Ripples  — colored row pulse on CPU/net/disk spikes
  2. AI Narrator           — auto-generated voiceover for anomalous PIDs
  3. Resource Oscilloscope — Braille waveforms for one PID, all metrics
  4. Three-Model Consensus Race — streamed parallel LLM lanes
  5. Attack Chain Replay   — scrubbable event playback
  6. Network Orbit         — animated remote-endpoint constellation
  7. Process Galaxy        — force-directed process-tree graph
  8. Process Lifecycle DVR — Gantt-style PID timeline
"""
from __future__ import annotations

import os
import sys
import time
import threading
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import procmon


# ── 1. Process Event Ripples ──────────────────────────────────────────


def _proc(pid, cpu=0.0, net_in=0, net_out=0, disk_in=0, disk_out=0):
    return {
        "pid": pid, "cpu": cpu,
        "net_in": net_in, "net_out": net_out,
        "disk_in": disk_in, "disk_out": disk_out,
    }


class TestRowPulses:
    def test_no_pulse_on_first_tick(self, monitor):
        # First tick has no prior snapshot, so no pulse can be armed.
        monitor._update_row_pulses([_proc(1, cpu=80.0)])
        assert 1 not in monitor._row_pulses

    def test_cpu_spike_triggers_salmon_pulse(self, monitor):
        monitor._update_row_pulses([_proc(1, cpu=2.0)])
        monitor._update_row_pulses([_proc(1, cpu=80.0)])
        assert 1 in monitor._row_pulses
        color_pair_id, frames = monitor._row_pulses[1]
        assert color_pair_id == 12  # salmon = CPU spike
        assert frames == monitor._pulse_frames

    def test_net_burst_triggers_light_green_pulse(self, monitor):
        monitor._update_row_pulses([_proc(1, net_in=0, net_out=0)])
        # 2 MB/s spike — well above 1 MB/s threshold
        monitor._update_row_pulses(
            [_proc(1, net_in=2 * 1024 * 1024, net_out=0)])
        assert 1 in monitor._row_pulses
        color_pair_id, _ = monitor._row_pulses[1]
        assert color_pair_id == 11  # light green

    def test_disk_burst_triggers_pulse(self, monitor):
        monitor._update_row_pulses([_proc(1, disk_in=0)])
        monitor._update_row_pulses([_proc(1, disk_in=10 * 1024 * 1024)])
        assert 1 in monitor._row_pulses
        color_pair_id, _ = monitor._row_pulses[1]
        assert color_pair_id == 11

    def test_pulse_decays_each_tick(self, monitor):
        monitor._update_row_pulses([_proc(1, cpu=2.0)])
        monitor._update_row_pulses([_proc(1, cpu=80.0)])
        start_frames = monitor._row_pulses[1][1]
        # Successive non-spiking ticks should decay until the entry is gone.
        for _ in range(start_frames + 1):
            monitor._update_row_pulses([_proc(1, cpu=80.0)])
        assert 1 not in monitor._row_pulses

    def test_pulse_attr_returns_zero_when_no_pulse(self, monitor):
        assert monitor._row_pulse_attr(999) == 0

    def test_pulse_attr_returns_nonzero_when_armed(self, monitor):
        monitor._row_pulses[42] = (12, 3)
        with patch.object(procmon.curses, "color_pair", return_value=0x100):
            with patch.object(procmon.curses, "A_BOLD", 0x200):
                attr = monitor._row_pulse_attr(42)
        assert attr != 0

    def test_dead_pids_dropped_from_pulses(self, monitor):
        monitor._update_row_pulses([_proc(1, cpu=2.0)])
        monitor._update_row_pulses([_proc(1, cpu=80.0)])
        assert 1 in monitor._row_pulses
        # Process 1 disappears — pulse should be dropped immediately.
        monitor._update_row_pulses([_proc(2, cpu=2.0)])
        assert 1 not in monitor._row_pulses


# ── 2. AI Narrator / Guided Spotlight ─────────────────────────────────


def _row(pid, cmd="proc", cpu=0.0, rss_kb=0, threads=1,
          ppid=1, net_in=0, net_out=0):
    return {
        "pid": pid, "ppid": ppid, "cpu": cpu, "agg_cpu": cpu,
        "rss_kb": rss_kb, "agg_rss_kb": rss_kb, "threads": threads,
        "agg_threads": threads, "fds": 0, "forks": 0,
        "net_in": net_in, "net_out": net_out,
        "agg_net_in": net_in, "agg_net_out": net_out,
        "bytes_in": 0, "bytes_out": 0,
        "agg_bytes_in": 0, "agg_bytes_out": 0,
        "command": cmd, "depth": 0, "prefix": "",
        "has_children": False, "is_collapsed": False,
    }


class TestNarrator:
    def test_toggle_on_off(self, monitor):
        assert monitor._narrator_enabled is False
        monitor._toggle_narrator_mode()
        assert monitor._narrator_enabled is True
        monitor._toggle_narrator_mode()
        assert monitor._narrator_enabled is False

    def test_anomaly_score_prefers_high_cpu(self, monitor):
        idle = _row(1, cpu=0.5, rss_kb=10 * 1024)
        busy = _row(2, cpu=85.0, rss_kb=10 * 1024)
        assert (monitor._narrator_anomaly_score(busy)
                > monitor._narrator_anomaly_score(idle))

    def test_select_target_returns_none_for_idle_rows(self, monitor):
        # No pulse, no novelty bonus past 60s — recently-seen quiet rows
        # should NOT trigger narration.
        monitor.rows = [_row(1, cpu=0.0)]
        # Mark pid 1 as seen recently so the novelty bonus is gone.
        monitor._narrator_seen_pids[1] = time.monotonic()
        assert monitor._select_narrator_target() is None

    def test_select_target_returns_busy_row(self, monitor):
        monitor.rows = [
            _row(1, cmd="idle", cpu=0.0),
            _row(2, cmd="busy", cpu=90.0, rss_kb=4 * 1024 * 1024),
        ]
        target = monitor._select_narrator_target()
        assert target is not None
        assert target["pid"] == 2

    def test_maybe_run_narrator_only_when_enabled(self, monitor):
        monitor.rows = [_row(2, cpu=90.0)]
        monitor._narrator_enabled = False
        monitor._maybe_run_narrator()
        assert monitor._narrator_loading is False
        assert monitor._narrator_target_pid is None

    def test_maybe_run_narrator_fires_caption_when_enabled(self, monitor):
        monitor.rows = [_row(7, cmd="suspicious", cpu=90.0,
                              rss_kb=4 * 1024 * 1024)]
        monitor._narrator_enabled = True
        monitor._narrator_last_tick = 0.0
        with patch.object(monitor, "_narrator_generate_caption",
                           return_value="PID 7 is spiking."):
            monitor._maybe_run_narrator()
            # Wait for worker
            for _ in range(50):
                if monitor._narrator_pending is not None:
                    break
                time.sleep(0.02)
        assert monitor._narrator_target_pid == 7
        assert monitor._narrator_pending == "PID 7 is spiking."

    def test_speak_only_when_speak_flag_true(self, monitor):
        monitor._narrator_enabled = True
        monitor._narrator_speak = False
        monitor._narrator_pending = "Hello world"
        with patch.object(monitor, "_narrator_speak_async") as spk:
            monitor._poll_narrator_result()
        spk.assert_not_called()

    def test_speak_called_when_flag_true(self, monitor):
        monitor._narrator_enabled = True
        monitor._narrator_speak = True
        monitor._narrator_pending = "Hello world"
        monitor._narrator_target_pid = 1
        with patch.object(monitor, "_narrator_speak_async") as spk:
            monitor._poll_narrator_result()
        spk.assert_called_once()

    def test_speak_async_invokes_say_subprocess(self, monitor):
        with patch("subprocess.Popen") as popen:
            with patch("shutil.which", return_value="/usr/bin/say"):
                monitor._narrator_speak_async("hi there")
                # Spawned in a daemon thread; give it a moment.
                for _ in range(50):
                    if popen.called:
                        break
                    time.sleep(0.02)
        assert popen.called
        argv = popen.call_args[0][0]
        assert argv[0] == "/usr/bin/say"
        assert "hi there" in argv

    def test_speak_async_skips_when_say_missing(self, monitor):
        with patch("shutil.which", return_value=None):
            with patch("subprocess.Popen") as popen:
                monitor._narrator_speak_async("hi there")
                time.sleep(0.05)
                popen.assert_not_called()

    def test_history_capped(self, monitor):
        monitor._narrator_enabled = True
        monitor._narrator_history_max = 3
        for i in range(10):
            monitor._narrator_target_pid = i
            monitor._narrator_pending = f"caption{i}"
            with patch.object(monitor, "_narrator_speak_async"):
                monitor._poll_narrator_result()
        assert len(monitor._narrator_history) == 3
