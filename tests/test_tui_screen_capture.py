import json
from unittest.mock import patch

from tests.conftest import make_proc


def test_capture_screen_snapshot_exports_visible_lines(tmp_path, monitor):
    monitor._tui_capture_dir = str(tmp_path)
    monitor._tui_capture_action = "surface_case"
    monitor.stdscr.getmaxyx.return_value = (3, 18)
    monitor.stdscr.instr.side_effect = [
        b" procmon \x00    ",
        b" Sort dialog      ",
        b" Dynamic sort     ",
    ]

    monitor._capture_screen_snapshot(
        "sort_dialog",
        "Sort",
        focus_box=(1, 3, 2, 12),
    )

    data = json.loads(
        (tmp_path / "surface_case.screen.json").read_text(encoding="utf-8"))
    assert data["scope"] == "screen"
    assert data["action"] == "sort_dialog"
    assert data["requested_action"] == "surface_case"
    assert data["title"] == "Sort"
    assert data["visible_lines"] == [
        " procmon",
        " Sort dialog",
        " Dynamic sort",
    ]
    assert data["focus_box"] == {
        "y": 1,
        "x": 3,
        "height": 2,
        "width": 12,
    }


def test_render_labels_events_surface(monitor):
    monitor.rows = [make_proc(pid=1, command="/bin/test")]
    monitor._events_mode = True
    monitor._events_source = "eslogger"
    monitor._events = []

    with patch("curses.color_pair", side_effect=lambda n: n), \
         patch("curses.curs_set", return_value=None), \
         patch.object(monitor, "_capture_screen_snapshot") as capture:
        monitor.render()

    assert capture.call_args[0][0] == "events_view"


def test_render_labels_traffic_surface(monitor):
    monitor.rows = [make_proc(pid=1, command="/bin/test")]
    monitor._traffic_mode = True
    monitor._traffic_error = "mitmdump not found"

    with patch("curses.color_pair", side_effect=lambda n: n), \
         patch("curses.curs_set", return_value=None), \
         patch.object(monitor, "_capture_screen_snapshot") as capture:
        monitor.render()

    assert capture.call_args[0][0] == "traffic_view"
