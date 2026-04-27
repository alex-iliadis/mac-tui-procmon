import tui_screen_assertions as tsa


def test_screen_capture_matches_surface_and_visible_text():
    capture = {
        "scope": "screen",
        "action": "sort_dialog",
        "visible_lines": [
            " Sort - up/down navigate, Enter select/toggle, Esc close ",
            "  Dynamic sort  [off]",
            "  Group by vendor  [on]",
        ],
    }

    assert tsa.review_capture(
        capture,
        "sort_dialog",
        ["Dynamic sort", "Group by vendor"],
    ) == []


def test_screen_capture_detects_wrong_surface():
    capture = {
        "scope": "screen",
        "action": "main",
        "visible_lines": [" procmon "],
    }

    errors = tsa.review_capture(capture, "audit_menu", ["procmon"])
    assert any("surface mismatch" in error for error in errors)


def test_screen_capture_detects_missing_visible_text():
    capture = {
        "scope": "screen",
        "action": "forensic_menu",
        "visible_lines": [" Process Investigation ", "  Inspect process "],
    }

    errors = tsa.review_capture(
        capture,
        "forensic_menu",
        ["Deep process triage"],
    )
    assert any("missing expected text" in error for error in errors)
