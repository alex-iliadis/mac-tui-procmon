"""Compatibility entrypoint for the renamed mac-tui-procmon app."""
import sys as _sys

import mac_tui_procmon as _impl

if __name__ == "__main__":
    _impl.main()
else:
    _sys.modules[__name__] = _impl
