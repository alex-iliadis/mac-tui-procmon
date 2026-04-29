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
