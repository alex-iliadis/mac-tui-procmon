"""Public module and CLI entrypoint for mac-tui-procmon."""

import sys as _sys

import mac_tui_procmon_impl as _impl
from mac_tui_procmon_impl import *  # noqa: F401,F403


if __name__ == "__main__":  # pragma: no cover
    _impl.main()
else:
    _sys.modules[__name__] = _impl
