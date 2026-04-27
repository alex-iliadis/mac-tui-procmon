"""Compatibility module for the renamed mac-tui-procmon app."""
import sys as _sys

import mac_tui_procmon as _impl

_sys.modules[__name__] = _impl
