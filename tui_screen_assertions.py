#!/usr/bin/env python3
"""Assertions for secprocmon visible-screen capture files."""

from __future__ import annotations

import json
from pathlib import Path


def load_capture(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def review_capture(capture: dict, surface: str, needles: list[str]) -> list[str]:
    errors: list[str] = []
    visible_lines = capture.get("visible_lines") or []
    joined = "\n".join(visible_lines)

    if capture.get("scope") != "screen":
        errors.append(
            f"scope mismatch: expected 'screen', got {capture.get('scope')!r}")
    if capture.get("action") != surface:
        errors.append(
            f"surface mismatch: expected {surface!r}, got {capture.get('action')!r}")
    if not visible_lines:
        errors.append("visible_lines is empty")

    for needle in needles:
        if needle not in joined:
            errors.append(f"missing expected text: {needle!r}")

    return errors
