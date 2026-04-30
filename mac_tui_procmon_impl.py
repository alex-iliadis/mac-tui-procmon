#!/usr/bin/env python3
"""mac-tui-procmon — process monitor for macOS.

Uses macOS libproc/sysctl directly via ctypes for process inspection,
avoiding fork()/exec() so the monitor survives fork bombs and memory
exhaustion. A single persistent process with locked memory and elevated
priority that continues monitoring even when the system cannot fork.

"""

import argparse
import collections
import ctypes
import ctypes.util
import curses
import gc
import html as _html
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import threading
import textwrap
import time
import urllib.parse as _urlparse

HOME = os.path.expanduser("~")
MAX_TREE_DEPTH = 20
MAX_PIDS = 65536
SORT_MEM = "m"
SORT_CPU = "c"
SORT_NET = "n"
SORT_BYTES_IN = "R"
SORT_BYTES_OUT = "O"
SORT_VENDOR = "V"
SORT_ALPHA = "A"
SORT_DYNAMIC = "d"
_HEADLESS_PROGRESS_LOCK = threading.Lock()


# ── macOS Native Interface (ctypes) ──────────────────────────────────────

# libproc flavors
PROC_ALL_PIDS = 1
PROC_PIDTASKALLINFO = 2
PROC_PIDTBSDINFO = 3
PROC_PIDTASKINFO = 4
PROC_PIDLISTFDS = 1
PROC_PIDVNODEPATHINFO = 9
# proc_pidinfo flavor for Mach file ports (count of named-port handles
# the process holds). Returns sizeof(proc_fileportinfo) * count, which
# we parse for length only — we don't dereference the names.
PROC_PIDLISTFILEPORTS = 14
PROC_PIDPATHINFO_MAXSIZE = 4096

# sysctl
CTL_KERN = 1
KERN_PROCARGS2 = 49

# mlock
MCL_CURRENT = 1
MCL_FUTURE = 2

MAXCOMLEN = 16
MAXPATHLEN = 1024

# Load native libraries
try:
    _libproc = ctypes.CDLL(ctypes.util.find_library("proc") or "/usr/lib/libproc.dylib")
    _libc = ctypes.CDLL(ctypes.util.find_library("c") or "/usr/lib/libc.dylib")
except OSError:
    print("Fatal: cannot load libproc/libc. This tool requires macOS.", file=sys.stderr)
    sys.exit(1)


# ── Ctypes Structures ────────────────────────────────────────────────────

class mach_timebase_info_data_t(ctypes.Structure):
    _fields_ = [
        ("numer", ctypes.c_uint32),
        ("denom", ctypes.c_uint32),
    ]


class proc_bsdinfo(ctypes.Structure):
    _fields_ = [
        ("pbi_flags", ctypes.c_uint32),
        ("pbi_status", ctypes.c_uint32),
        ("pbi_xstatus", ctypes.c_uint32),
        ("pbi_pid", ctypes.c_uint32),
        ("pbi_ppid", ctypes.c_uint32),
        ("pbi_uid", ctypes.c_uint32),
        ("pbi_gid", ctypes.c_uint32),
        ("pbi_ruid", ctypes.c_uint32),
        ("pbi_rgid", ctypes.c_uint32),
        ("pbi_svuid", ctypes.c_uint32),
        ("pbi_svgid", ctypes.c_uint32),
        ("rfu_1", ctypes.c_uint32),
        ("pbi_comm", ctypes.c_char * MAXCOMLEN),
        ("pbi_name", ctypes.c_char * (2 * MAXCOMLEN)),
        ("pbi_nfiles", ctypes.c_uint32),
        ("pbi_pgid", ctypes.c_uint32),
        ("pbi_pjobc", ctypes.c_uint32),
        ("e_tdev", ctypes.c_uint32),
        ("e_tpgid", ctypes.c_uint32),
        ("pbi_nice", ctypes.c_int16),
        ("pbi_start_tvsec", ctypes.c_char * 8),
        ("pbi_start_tvusec", ctypes.c_char * 8),
    ]


class proc_taskinfo(ctypes.Structure):
    _fields_ = [
        ("pti_virtual_size", ctypes.c_uint64),
        ("pti_resident_size", ctypes.c_uint64),
        ("pti_total_user", ctypes.c_uint64),
        ("pti_total_system", ctypes.c_uint64),
        ("pti_threads_user", ctypes.c_uint64),
        ("pti_threads_system", ctypes.c_uint64),
        ("pti_policy", ctypes.c_int32),
        ("pti_faults", ctypes.c_int32),
        ("pti_pageins", ctypes.c_int32),
        ("pti_cow_faults", ctypes.c_int32),
        ("pti_messages_sent", ctypes.c_int32),
        ("pti_messages_received", ctypes.c_int32),
        ("pti_syscalls_mach", ctypes.c_int32),
        ("pti_syscalls_unix", ctypes.c_int32),
        ("pti_csw", ctypes.c_int32),
        ("pti_threadnum", ctypes.c_int32),
        ("pti_numrunning", ctypes.c_int32),
        ("pti_priority", ctypes.c_int32),
    ]


class proc_taskallinfo(ctypes.Structure):
    _fields_ = [
        ("pbsd", proc_bsdinfo),
        ("ptinfo", proc_taskinfo),
    ]


class vinfo_stat(ctypes.Structure):
    _fields_ = [
        ("vst_dev", ctypes.c_uint32),
        ("vst_mode", ctypes.c_uint16),
        ("vst_nlink", ctypes.c_uint16),
        ("vst_ino", ctypes.c_uint64),
        ("vst_uid", ctypes.c_uint32),
        ("vst_gid", ctypes.c_uint32),
        ("vst_atime", ctypes.c_int64),
        ("vst_atimensec", ctypes.c_int64),
        ("vst_mtime", ctypes.c_int64),
        ("vst_mtimensec", ctypes.c_int64),
        ("vst_ctime", ctypes.c_int64),
        ("vst_ctimensec", ctypes.c_int64),
        ("vst_birthtime", ctypes.c_int64),
        ("vst_birthtimensec", ctypes.c_int64),
        ("vst_size", ctypes.c_int64),
        ("vst_blocks", ctypes.c_int64),
        ("vst_blksize", ctypes.c_int32),
        ("vst_flags", ctypes.c_uint32),
        ("vst_gen", ctypes.c_uint32),
        ("vst_rdev", ctypes.c_uint32),
        ("vst_qspare", ctypes.c_int64 * 2),
    ]


class vnode_info(ctypes.Structure):
    _fields_ = [
        ("vi_stat", vinfo_stat),
        ("vi_type", ctypes.c_int32),
        ("vi_pad", ctypes.c_int32),
        ("vi_fsid", ctypes.c_int32 * 2),
    ]


class vnode_info_path(ctypes.Structure):
    _fields_ = [
        ("vip_vi", vnode_info),
        ("vip_path", ctypes.c_char * MAXPATHLEN),
    ]


class proc_vnodepathinfo(ctypes.Structure):
    _fields_ = [
        ("pvi_cdir", vnode_info_path),
        ("pvi_rdir", vnode_info_path),
    ]


# proc_pid_rusage flavors (sys/resource.h). Used here for cumulative disk
# I/O bytes (ri_diskio_bytesread / ri_diskio_byteswritten). The struct is
# defined to its full v4 layout so ctypes computes the right field offsets;
# we only ever read the diskio fields, but partial structs are dangerous —
# proc_pid_rusage writes the full sizeof(rusage_info_v4) regardless.
RUSAGE_INFO_V4 = 4


class rusage_info_v4(ctypes.Structure):
    _fields_ = [
        ("ri_uuid", ctypes.c_uint8 * 16),
        ("ri_user_time", ctypes.c_uint64),
        ("ri_system_time", ctypes.c_uint64),
        ("ri_pkg_idle_wkups", ctypes.c_uint64),
        ("ri_interrupt_wkups", ctypes.c_uint64),
        ("ri_pageins", ctypes.c_uint64),
        ("ri_wired_size", ctypes.c_uint64),
        ("ri_resident_size", ctypes.c_uint64),
        ("ri_phys_footprint", ctypes.c_uint64),
        ("ri_proc_start_abstime", ctypes.c_uint64),
        ("ri_proc_exit_abstime", ctypes.c_uint64),
        ("ri_child_user_time", ctypes.c_uint64),
        ("ri_child_system_time", ctypes.c_uint64),
        ("ri_child_pkg_idle_wkups", ctypes.c_uint64),
        ("ri_child_interrupt_wkups", ctypes.c_uint64),
        ("ri_child_pageins", ctypes.c_uint64),
        ("ri_child_elapsed_abstime", ctypes.c_uint64),
        ("ri_diskio_bytesread", ctypes.c_uint64),
        ("ri_diskio_byteswritten", ctypes.c_uint64),
        ("ri_cpu_time_qos_default", ctypes.c_uint64),
        ("ri_cpu_time_qos_maintenance", ctypes.c_uint64),
        ("ri_cpu_time_qos_background", ctypes.c_uint64),
        ("ri_cpu_time_qos_utility", ctypes.c_uint64),
        ("ri_cpu_time_qos_legacy", ctypes.c_uint64),
        ("ri_cpu_time_qos_user_initiated", ctypes.c_uint64),
        ("ri_cpu_time_qos_user_interactive", ctypes.c_uint64),
        ("ri_billed_system_time", ctypes.c_uint64),
        ("ri_serviced_system_time", ctypes.c_uint64),
        ("ri_logical_writes", ctypes.c_uint64),
        ("ri_lifetime_max_phys_footprint", ctypes.c_uint64),
        ("ri_instructions", ctypes.c_uint64),
        ("ri_cycles", ctypes.c_uint64),
        ("ri_billed_energy", ctypes.c_uint64),
        ("ri_serviced_energy", ctypes.c_uint64),
        ("ri_interval_max_phys_footprint", ctypes.c_uint64),
        ("ri_runnable_time", ctypes.c_uint64),
    ]


# ── Function Prototypes ──────────────────────────────────────────────────

_libproc.proc_listallpids.argtypes = [ctypes.c_void_p, ctypes.c_int]
_libproc.proc_listallpids.restype = ctypes.c_int

_libproc.proc_pidinfo.argtypes = [
    ctypes.c_int, ctypes.c_int, ctypes.c_uint64,
    ctypes.c_void_p, ctypes.c_int,
]
_libproc.proc_pidinfo.restype = ctypes.c_int

_libproc.proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
_libproc.proc_pidpath.restype = ctypes.c_int

# proc_pid_rusage(pid, flavor, &rusage_info_t) → 0 on success, -1 on failure.
# We use it to read cumulative ri_diskio_bytesread / ri_diskio_byteswritten
# (per-process disk I/O bytes since process start) from the rusage_info_v4
# flavor.
try:
    _libproc.proc_pid_rusage.argtypes = [
        ctypes.c_int, ctypes.c_int, ctypes.c_void_p,
    ]
    _libproc.proc_pid_rusage.restype = ctypes.c_int
except AttributeError:
    # Older macOS without proc_pid_rusage — degrade gracefully.
    pass

_libc.sysctl.argtypes = [
    ctypes.POINTER(ctypes.c_int), ctypes.c_uint,
    ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t),
    ctypes.c_void_p, ctypes.c_size_t,
]
_libc.sysctl.restype = ctypes.c_int

_libc.mach_timebase_info.argtypes = [ctypes.POINTER(mach_timebase_info_data_t)]
_libc.mach_timebase_info.restype = ctypes.c_int

_libc.mlockall.argtypes = [ctypes.c_int]
_libc.mlockall.restype = ctypes.c_int

_libc.sysctlbyname.argtypes = [
    ctypes.c_char_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t),
    ctypes.c_void_p, ctypes.c_size_t,
]
_libc.sysctlbyname.restype = ctypes.c_int


# ── Mach Timebase ─────────────────────────────────────────────────────────

_tb_info = mach_timebase_info_data_t()
_libc.mach_timebase_info(ctypes.byref(_tb_info))


def _mach_to_ns(ticks):
    """Convert Mach absolute time ticks to nanoseconds."""
    return ticks * _tb_info.numer // _tb_info.denom


# ── Pre-allocated Buffers (no heap allocation during monitoring) ──────────

_pid_buf = (ctypes.c_int * MAX_PIDS)()
_taskallinfo_buf = proc_taskallinfo()
_bsdinfo_buf = proc_bsdinfo()
_vnodepathinfo_buf = proc_vnodepathinfo()
_path_buf = ctypes.create_string_buffer(PROC_PIDPATHINFO_MAXSIZE)
_args_buf = ctypes.create_string_buffer(65536)
_PROC_PIDLISTFD_SIZE = 8  # sizeof(struct proc_fdinfo)


# ── Process Hardening ─────────────────────────────────────────────────────

def _harden_process():
    """Lock memory and boost priority to survive resource exhaustion."""
    # Boost scheduling priority (negative nice = higher priority)
    for nice_val in (-20, -10, -5, 0):
        try:
            os.setpriority(os.PRIO_PROCESS, 0, nice_val)
            break
        except PermissionError:
            continue

    # Lock all current and future memory pages to prevent swapout
    try:
        _libc.mlockall(MCL_CURRENT | MCL_FUTURE)
    except Exception:
        pass

    # Force a full GC now so we start clean
    gc.collect()


_EXTERNAL_TOOLS = [
    {
        "name": "lsof",
        "category": "important",
        "feature_desc": "network connections, open file inspection",
        "install_hint": "usually preinstalled on macOS",
        "candidates": ["lsof"],
    },
    {
        "name": "ps",
        "category": "important",
        "feature_desc": "hidden process detection (background + deep scan)",
        "install_hint": "preinstalled on macOS",
        "candidates": ["ps"],
    },
    {
        "name": "nettop",
        "category": "important",
        "feature_desc": "per-process network rates and cumulative bytes",
        "install_hint": "preinstalled on macOS",
        "candidates": ["nettop"],
    },
    {
        "name": "codesign",
        "category": "important",
        "feature_desc": "inspect mode: signature verification and entitlements",
        "install_hint": "preinstalled on macOS",
        "candidates": ["codesign"],
    },
    {
        "name": "otool",
        "category": "important",
        "feature_desc": "inspect mode: linked dylibs",
        "install_hint": "xcode-select --install",
        "candidates": ["otool"],
    },
    {
        "name": "shasum",
        "category": "important",
        "feature_desc": "inspect mode: binary hash",
        "install_hint": "preinstalled on macOS",
        "candidates": ["shasum"],
    },
    {
        "name": "vmmap",
        "category": "optional",
        "feature_desc": "inspect mode: memory regions (root-only)",
        "install_hint": "preinstalled on macOS",
        "candidates": ["vmmap"],
    },
    {
        "name": "afplay",
        "category": "optional",
        "feature_desc": "alert sound playback",
        "install_hint": "preinstalled on macOS",
        "candidates": ["afplay"],
    },
    {
        "name": "claude",
        "category": "optional",
        "feature_desc": "inspect mode: Claude security analysis",
        "install_hint": "npm install -g @anthropic-ai/claude-code",
        "candidates": ["claude"],
    },
    {
        "name": "codex",
        "category": "optional",
        "feature_desc": "inspect mode: Codex security analysis",
        "install_hint": "npm install -g @openai/codex",
        "candidates": ["codex"],
    },
    {
        "name": "gemini",
        "category": "optional",
        "feature_desc": "inspect mode: Gemini security analysis",
        "install_hint": "npm install -g @google/gemini-cli",
        "candidates": ["gemini"],
    },
    {
        "name": "eslogger",
        "category": "optional",
        "feature_desc": "live security timeline (Endpoint Security, macOS 12+)",
        "install_hint": "preinstalled on macOS 12+; grant Full Disk Access to Terminal if needed",
        "candidates": ["eslogger"],
    },
    {
        "name": "dtrace",
        "category": "optional",
        "feature_desc": "live event stream fallback (exec tracing)",
        "install_hint": "preinstalled on macOS",
        "candidates": ["dtrace"],
    },
    {
        "name": "yara",
        "category": "optional",
        "feature_desc": "on-disk and memory malware signature scanning",
        "install_hint": "brew install yara",
        "candidates": ["yara"],
    },
    {
        "name": "lldb",
        "category": "optional",
        "feature_desc": "memory snapshot for YARA memory scan",
        "install_hint": "xcode-select --install",
        "candidates": ["lldb"],
    },
    {
        "name": "osquery",
        "category": "integration",
        "feature_desc": "optional backend for process/runtime cross-checks",
        "install_hint": "brew install --cask osquery",
        "candidates": ["osqueryi", "/usr/local/bin/osqueryi", "/opt/homebrew/bin/osqueryi"],
    },
    {
        "name": "knockknock",
        "category": "integration",
        "feature_desc": "optional persistence-enrichment backend from Objective-See KnockKnock",
        "install_hint": "brew install --cask knockknock",
        "candidates": [
            "/Applications/KnockKnock.app/Contents/MacOS/KnockKnock",
            "/Applications/KnockKnock.app/Contents/MacOS/knockknock",
            "~/Applications/KnockKnock.app/Contents/MacOS/KnockKnock",
        ],
    },
    {
        "name": "taskexplorer",
        "category": "integration",
        "feature_desc": "optional per-process corroboration backend from Objective-See TaskExplorer",
        "install_hint": "brew install --cask taskexplorer",
        "candidates": [
            "/Applications/TaskExplorer.app/Contents/MacOS/TaskExplorer",
            "/Applications/TaskExplorer.app/Contents/MacOS/taskexplorer",
            "~/Applications/TaskExplorer.app/Contents/MacOS/TaskExplorer",
        ],
    },
    {
        "name": "blockblock",
        "category": "integration",
        "feature_desc": "optional persistence telemetry backend from Objective-See BlockBlock",
        "install_hint": "brew install --cask blockblock",
        "candidates": [
            "/Library/Objective-See/BlockBlock/BlockBlock.app/Contents/MacOS/BlockBlock",
            "/Applications/BlockBlock.app/Contents/MacOS/BlockBlock",
            "~/Applications/BlockBlock.app/Contents/MacOS/BlockBlock",
        ],
    },
    {
        "name": "santa",
        "category": "integration",
        "feature_desc": "optional binary authorization telemetry backend from Santa",
        "install_hint": "brew install --cask santa",
        "candidates": ["santactl", "/usr/local/bin/santactl", "/opt/homebrew/bin/santactl"],
    },
    {
        "name": "mitmdump",
        "category": "experimental",
        "feature_desc": "experimental traffic interception backend for Traffic Inspector",
        "install_hint": "brew install mitmproxy",
        "candidates": ["mitmdump"],
    },
]

_EXTERNAL_TOOL_MAP = {tool["name"]: tool for tool in _EXTERNAL_TOOLS}

_PROCMON_PREFLIGHT_TOOLS = {
    "lsof",
    "ps",
    "nettop",
    "codesign",
    "otool",
    "shasum",
    "vmmap",
    "afplay",
    "claude",
    "codex",
    "gemini",
    "yara",
    "lldb",
}


def _resolve_external_tool(name_or_spec):
    """Return the first usable executable path for a configured tool."""
    spec = (name_or_spec if isinstance(name_or_spec, dict)
            else _EXTERNAL_TOOL_MAP.get(name_or_spec))
    if not spec:
        return None
    for candidate in spec.get("candidates") or (spec.get("name"),):
        if not candidate:
            continue
        if candidate.startswith("~/"):
            candidate = os.path.expanduser(candidate)
        if os.path.isabs(candidate):
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
            continue
        resolved = shutil.which(candidate, path=_USER_TOOL_PATH)
        if resolved:
            return resolved
    return None


def _blocking_missing_tools(missing):
    """Return missing-tool tuples that should block startup.

    mac-tui-procmon now always starts the core monitor. Missing integrations and
    experimental backends degrade independently at runtime instead of blocking
    startup.
    """
    return []


def _check_external_tools(scope="all"):
    """Scan for missing external CLI dependencies via shutil.which (no fork).

    Uses the augmented user-tool PATH plus explicit app-bundle paths so
    sudo-run mac-tui-procmon doesn't falsely report user-installed CLIs as missing
    just because sudo sanitized PATH.

    Returns a list of (tool, category, feature_desc, install_hint) tuples for
    tools that are NOT on PATH. Empty list means everything is present.
    """
    missing = []
    for spec in _EXTERNAL_TOOLS:
        if scope == "process" and spec["name"] not in _PROCMON_PREFLIGHT_TOOLS:
            continue
        if _resolve_external_tool(spec) is None:
            missing.append((
                spec["name"],
                spec["category"],
                spec["feature_desc"],
                spec["install_hint"],
            ))
    return missing


def _render_preflight_report(missing, stream=None):
    """Print the preflight report for missing tools to `stream`."""
    if stream is None:
        stream = sys.stderr
    order = {
        "important": 0,
        "integration": 1,
        "experimental": 2,
        "optional": 3,
    }
    missing_sorted = sorted(missing, key=lambda t: order.get(t[1], 99))
    print("", file=stream)
    print("mac-tui-procmon preflight \u2014 some external tools are missing", file=stream)
    print("", file=stream)
    for tool, category, feature_desc, install_hint in missing_sorted:
        print(f"  [{category}] {tool:<10} \u2014 {feature_desc}", file=stream)
        print(f"              install: {install_hint}", file=stream)
    print("", file=stream)
    print("mac-tui-procmon will continue in DEGRADED mode.", file=stream)
    print("Core monitoring stays available; integrations and experimental", file=stream)
    print("features surface when installed and otherwise report a clear", file=stream)
    print("backend-unavailable state at runtime.", file=stream)
    print("", file=stream)


def _installable_command(install_hint):
    """Parse an install hint and return a runnable argv, or None.

    Only recognizes install commands we can safely invoke non-interactively
    and without sudo: `brew install ...`, `brew install --cask ...`,
    `npm install -g ...`, and `xcode-select --install`
    (which pops up an interactive installer).
    Anything else (e.g. "preinstalled on macOS") returns None.
    """
    if not install_hint:
        return None
    hint = install_hint.strip()
    # Strip trailing comments (`# preinstalled` etc.)
    if "#" in hint:
        hint = hint.split("#", 1)[0].strip()
    if hint.startswith("brew install --cask ") and shutil.which("brew"):
        pkg = hint[len("brew install --cask "):].strip()
        if pkg:
            return ["brew", "install", "--cask", pkg]
    if hint.startswith("brew install ") and shutil.which("brew"):
        pkg = hint[len("brew install "):].strip()
        if pkg:
            return ["brew", "install", pkg]
    if hint.startswith("npm install -g ") and shutil.which("npm"):
        pkg = hint[len("npm install -g "):].strip()
        if pkg:
            return ["npm", "install", "-g", pkg]
    if hint.startswith("xcode-select --install") and shutil.which("xcode-select"):
        return ["xcode-select", "--install"]
    return None


def _auto_installable(missing):
    """Return the subset of missing tools that have a runnable install command."""
    out = []
    for entry in missing:
        argv = _installable_command(entry[3])
        if argv is not None:
            out.append((entry, argv))
    return out


def _install_can_use_sudo(argv):
    """Return True when an install command is safe to retry with sudo."""
    if not argv:
        return False
    tool = os.path.basename(argv[0])
    return tool == "npm" and len(argv) >= 3 and argv[1] == "install" and "-g" in argv[2:]


def _sudo_install_argv(argv):
    """Return a sudo-prefixed argv, resolving the executable path first."""
    if not argv:
        return ["sudo"]
    exe = argv[0]
    if not os.path.isabs(exe):
        exe = shutil.which(exe, path=_USER_TOOL_PATH) or exe
    return ["sudo", exe, *argv[1:]]


def _install_requires_sudo(argv):
    """Detect when the install target is not writable by the current user."""
    if os.geteuid() == 0 or not _install_can_use_sudo(argv):
        return False

    npm = argv[0]
    if not os.path.isabs(npm):
        npm = shutil.which("npm", path=_USER_TOOL_PATH) or npm

    try:
        proc = subprocess.run(
            [npm, "prefix", "-g"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5,
            env=_tool_env(),
        )
    except (FileNotFoundError, OSError, subprocess.SubprocessError):
        return False

    if proc.returncode != 0:
        return False

    prefix = (proc.stdout or "").strip()
    if not prefix:
        return False

    probe = os.path.abspath(os.path.expanduser(prefix))
    while not os.path.exists(probe):
        parent = os.path.dirname(probe)
        if not parent or parent == probe:
            break
        probe = parent
    return not os.access(probe, os.W_OK)


def _prompt_install_sudo(argv, reason="", stream=None):
    """Ask whether to rerun an install command with sudo."""
    if stream is None:
        stream = sys.stderr
    if not sys.stdin.isatty():
        print("  [!] install needs sudo but stdin is not a TTY", file=stream)
        return False

    cmd = " ".join(argv)
    suffix = f" ({reason})" if reason else ""
    try:
        answer = input(
            f"Install command needs sudo{suffix}.\n"
            f"  {cmd}\n"
            "Run with sudo? (y / n / Ctrl-C to abort): "
        ).strip().lower()
    except (KeyboardInterrupt, EOFError):
        print("\nAborted.", file=stream)
        return False
    return answer in ("y", "yes")


def _run_install(argv, stream=None):
    """Run an install command with the user watching. Inherits stdout/stderr
    so users see progress. Returns True on success.
    """
    if stream is None:
        stream = sys.stderr

    install_argv = list(argv)
    if _install_requires_sudo(install_argv):
        if not _prompt_install_sudo(
                install_argv,
                reason="global npm prefix is not writable by the current user",
                stream=stream):
            print("  [!] skipped install requiring sudo", file=stream)
            return False
        install_argv = _sudo_install_argv(install_argv)

    print(f"\n$ {' '.join(install_argv)}", file=stream)
    try:
        rc = subprocess.call(install_argv, env=_tool_env())
    except (FileNotFoundError, OSError) as e:
        print(f"  [!] failed to launch: {e}", file=stream)
        return False

    if (rc != 0
            and install_argv == list(argv)
            and os.geteuid() != 0
            and _install_can_use_sudo(argv)
            and _prompt_install_sudo(
                argv,
                reason="the first install attempt failed",
                stream=stream)):
        install_argv = _sudo_install_argv(argv)
        print(f"\n$ {' '.join(install_argv)}", file=stream)
        try:
            rc = subprocess.call(install_argv, env=_tool_env())
        except (FileNotFoundError, OSError) as e:
            print(f"  [!] failed to launch: {e}", file=stream)
            return False

    if rc != 0:
        print(f"  [!] command exited with code {rc}", file=stream)
        return False
    return True


def _preflight(skip=False, scope="all"):
    """Run the startup preflight. Blocks on Enter if stdin is a TTY.

    If any missing tools have a runnable install command, offer to run them.
    After a successful install pass, re-check so the user sees what (if
    anything) is still missing before continuing.

    Returns True on success (continue), False if the user aborted.
    """
    if skip:
        return True
    missing = _check_external_tools(scope=scope)
    if not missing:
        return True
    _render_preflight_report(missing)

    if not sys.stdin.isatty():
        print("(stdin is not a TTY \u2014 continuing in degraded mode without prompt)",
              file=sys.stderr)
        return True

    installable = _auto_installable(missing)
    if installable:
        tool_list = ", ".join(entry[0] for entry, _ in installable)
        try:
            answer = input(
                f"Install now? [{tool_list}] (y / n / Ctrl-C to abort): "
            ).strip().lower()
        except (KeyboardInterrupt, EOFError):
            print("\nAborted.", file=sys.stderr)
            return False
        if answer in ("y", "yes"):
            failures = []
            for entry, argv in installable:
                ok = _run_install(argv)
                if not ok:
                    failures.append(entry[0])
            if failures:
                print(f"\n[!] install failed for: {', '.join(failures)}",
                      file=sys.stderr)
            # Re-check what's still missing so the user has current info
            still_missing = _check_external_tools()
            if not still_missing:
                print("\nAll tools installed. Continuing...", file=sys.stderr)
                return True
            if len(still_missing) < len(missing):
                print(
                    f"\n{len(missing) - len(still_missing)} of {len(missing)} "
                    f"tool(s) installed. Still missing:", file=sys.stderr)
                _render_preflight_report(still_missing)

    try:
        input("Press Enter to continue (or Ctrl-C to abort)... ")
    except (KeyboardInterrupt, EOFError):
        print("\nAborted.", file=sys.stderr)
        return False
    return True


def _self_test():
    """Verify struct definitions by querying our own process."""
    pid = os.getpid()
    ret = _libproc.proc_pidinfo(
        pid, PROC_PIDTASKALLINFO, 0,
        ctypes.byref(_taskallinfo_buf), ctypes.sizeof(_taskallinfo_buf),
    )
    if ret <= 0:
        print("Warning: libproc self-test failed (proc_pidinfo returned 0).",
              file=sys.stderr)
        print("Struct sizes: taskallinfo=%d bsdinfo=%d taskinfo=%d" % (
            ctypes.sizeof(proc_taskallinfo),
            ctypes.sizeof(proc_bsdinfo),
            ctypes.sizeof(proc_taskinfo)), file=sys.stderr)
        return False
    expected_ppid = os.getppid()
    actual_ppid = _taskallinfo_buf.pbsd.pbi_ppid
    if actual_ppid != expected_ppid:
        print(f"Warning: struct layout mismatch — ppid {actual_ppid} != {expected_ppid}",
              file=sys.stderr)
        return False
    return True


# ── Fork-Free Data Collection ─────────────────────────────────────────────

def _list_all_pids():
    """List all PIDs via libproc (no fork)."""
    n = _libproc.proc_listallpids(_pid_buf, ctypes.sizeof(_pid_buf))
    if n <= 0:
        return []
    return [_pid_buf[i] for i in range(n)]


def _get_proc_args(pid):
    """Get full command line via sysctl KERN_PROCARGS2 (no fork)."""
    mib = (ctypes.c_int * 3)(CTL_KERN, KERN_PROCARGS2, pid)
    buf_size = ctypes.c_size_t(ctypes.sizeof(_args_buf))
    ret = _libc.sysctl(mib, 3, _args_buf, ctypes.byref(buf_size), None, 0)
    if ret != 0 or buf_size.value < 8:
        return None
    raw = _args_buf.raw[:buf_size.value]
    argc = int.from_bytes(raw[:4], sys.byteorder)
    pos = 4
    # Skip exec path
    try:
        end = raw.index(b"\x00", pos)
    except ValueError:
        return None
    exec_path = raw[pos:end].decode("utf-8", errors="replace")
    pos = end + 1
    # Skip null padding
    while pos < len(raw) and raw[pos:pos + 1] == b"\x00":
        pos += 1
    # Read argv entries
    args = []
    for _ in range(min(argc, 256)):
        if pos >= len(raw):
            break
        try:
            end = raw.index(b"\x00", pos)
        except ValueError:
            args.append(raw[pos:].decode("utf-8", errors="replace"))
            break
        args.append(raw[pos:end].decode("utf-8", errors="replace"))
        pos = end + 1
    return " ".join(args) if args else exec_path


def _get_proc_env(pid):
    """Get environment variables via sysctl KERN_PROCARGS2 (no fork).

    Uses a thread-local buffer to avoid races with the global _args_buf.
    """
    buf = ctypes.create_string_buffer(65536)
    mib = (ctypes.c_int * 3)(CTL_KERN, KERN_PROCARGS2, pid)
    buf_size = ctypes.c_size_t(ctypes.sizeof(buf))
    ret = _libc.sysctl(mib, 3, buf, ctypes.byref(buf_size), None, 0)
    if ret != 0 or buf_size.value < 8:
        return {}
    raw = buf.raw[:buf_size.value]
    argc = int.from_bytes(raw[:4], sys.byteorder)
    pos = 4
    # Skip exec path
    try:
        end = raw.index(b"\x00", pos)
    except ValueError:
        return {}
    pos = end + 1
    # Skip null padding
    while pos < len(raw) and raw[pos:pos + 1] == b"\x00":
        pos += 1
    # Skip argv entries
    for _ in range(min(argc, 256)):
        if pos >= len(raw):
            return {}
        try:
            end = raw.index(b"\x00", pos)
        except ValueError:
            break
        pos = end + 1
    # Remaining null-terminated strings are environment variables
    env = {}
    while pos < len(raw):
        try:
            end = raw.index(b"\x00", pos)
        except ValueError:
            break
        entry = raw[pos:end].decode("utf-8", errors="replace")
        if "=" in entry:
            k, v = entry.split("=", 1)
            env[k] = v
        pos = end + 1
    return env


def _get_proc_path(pid):
    """Get executable path via proc_pidpath (no fork)."""
    ret = _libproc.proc_pidpath(pid, _path_buf, ctypes.sizeof(_path_buf))
    if ret <= 0:
        return None
    return _path_buf.value.decode("utf-8", errors="replace")


def _get_fd_count(pid):
    """Get open file descriptor count via libproc (no fork)."""
    buf_needed = _libproc.proc_pidinfo(pid, PROC_PIDLISTFDS, 0, None, 0)
    if buf_needed <= 0:
        return -1
    return buf_needed // _PROC_PIDLISTFD_SIZE


# sizeof(struct proc_fileportinfo) — 8 bytes (two uint32_t fields).
_PROC_FILEPORTINFO_SIZE = 8


def _get_mach_port_count(pid):
    """Return the number of Mach file ports the pid holds, or -1.

    Uses proc_pidinfo(PROC_PIDLISTFILEPORTS) — unlike task_for_pid this
    does NOT require root or any task entitlement, so we can read it for
    any pid we can already see in proc_listallpids. The kernel returns
    the total bytes that *would* be written; we divide by sizeof to
    recover the count and never actually dereference the buffer.
    """
    if pid <= 0:
        return -1
    try:
        ret = _libproc.proc_pidinfo(
            pid, PROC_PIDLISTFILEPORTS, 0, None, 0)
    except OSError:
        return -1
    if ret < 0:
        return -1
    return ret // _PROC_FILEPORTINFO_SIZE


def _get_cwd(pid):
    """Get current working directory via libproc (no fork)."""
    ret = _libproc.proc_pidinfo(
        pid, PROC_PIDVNODEPATHINFO, 0,
        ctypes.byref(_vnodepathinfo_buf), ctypes.sizeof(_vnodepathinfo_buf),
    )
    if ret <= 0:
        return "-"
    try:
        path = _vnodepathinfo_buf.pvi_cdir.vip_path
        if path:
            return path.decode("utf-8", errors="replace")
    except Exception:
        pass
    return "-"


def _get_total_memory_kb():
    """Get total physical memory in KB via sysctl hw.memsize (no fork)."""
    val = ctypes.c_uint64(0)
    sz = ctypes.c_size_t(ctypes.sizeof(val))
    _libc.sysctlbyname(b"hw.memsize", ctypes.byref(val), ctypes.byref(sz), None, 0)
    return val.value // 1024


def _get_disk_io(pid):
    """Return (bytes_read, bytes_written) since process start, or (None, None).

    Reads cumulative disk I/O via proc_pid_rusage(RUSAGE_INFO_V4). Returns
    (None, None) if the kernel rejects the call (process exited, permissions,
    or the symbol is missing on an older macOS). NOT a rate — caller must
    diff against a previous snapshot to derive bytes/sec.
    """
    if pid <= 0:
        return (None, None)
    if not hasattr(_libproc, "proc_pid_rusage"):
        return (None, None)
    info = rusage_info_v4()
    try:
        ret = _libproc.proc_pid_rusage(
            pid, RUSAGE_INFO_V4, ctypes.byref(info))
    except OSError:
        return (None, None)
    if ret != 0:
        return (None, None)
    return (int(info.ri_diskio_bytesread),
            int(info.ri_diskio_byteswritten))


def get_all_processes():
    """Collect all process info using libproc (no fork)."""
    pids = _list_all_pids()
    own_pid = os.getpid()
    procs = []
    for pid in pids:
        if pid == own_pid or pid <= 0:
            continue

        # Try combined bsdinfo+taskinfo call
        ret = _libproc.proc_pidinfo(
            pid, PROC_PIDTASKALLINFO, 0,
            ctypes.byref(_taskallinfo_buf), ctypes.sizeof(_taskallinfo_buf),
        )

        if ret > 0:
            ppid = _taskallinfo_buf.pbsd.pbi_ppid
            pbi_name = _taskallinfo_buf.pbsd.pbi_name
            pbi_comm = _taskallinfo_buf.pbsd.pbi_comm
            rss_kb = _taskallinfo_buf.ptinfo.pti_resident_size // 1024
            cpu_ticks = (_taskallinfo_buf.ptinfo.pti_total_user
                         + _taskallinfo_buf.ptinfo.pti_total_system)
            threads = max(1, _taskallinfo_buf.ptinfo.pti_threadnum)
        else:
            # Fallback: bsdinfo only (zombies, restricted processes)
            ret2 = _libproc.proc_pidinfo(
                pid, PROC_PIDTBSDINFO, 0,
                ctypes.byref(_bsdinfo_buf), ctypes.sizeof(_bsdinfo_buf),
            )
            if ret2 <= 0:
                continue
            ppid = _bsdinfo_buf.pbi_ppid
            pbi_name = _bsdinfo_buf.pbi_name
            pbi_comm = _bsdinfo_buf.pbi_comm
            rss_kb = 0
            cpu_ticks = 0
            threads = 0

        # Get command string (full argv > exec path > name > pid)
        command = _get_proc_args(pid)
        if not command:
            command = _get_proc_path(pid)
        if not command:
            name = pbi_name.rstrip(b"\x00").decode("utf-8", errors="replace")
            if not name:
                name = pbi_comm.rstrip(b"\x00").decode("utf-8", errors="replace")
            command = name if name else f"[{pid}]"

        procs.append({
            "pid": pid,
            "ppid": ppid,
            "rss_kb": rss_kb,
            "cpu": 0.0,
            "cpu_ticks": cpu_ticks,
            "threads": threads,
            "command": command,
        })
    return procs


def get_fd_counts(pids):
    """Get FD counts for a list of PIDs (no fork)."""
    if not pids:
        return {}
    return {pid: _get_fd_count(pid) for pid in pids}


def get_cwds(pids):
    """Get working directories for a list of PIDs (no fork)."""
    if not pids:
        return {}
    return {pid: _get_cwd(pid) for pid in pids}


# ── Network (best-effort, only part that uses subprocess) ─────────────────

def get_net_snapshot():
    """Get network stats via nettop. Best-effort — fails silently if fork blocked."""
    try:
        proc = subprocess.Popen(
            ["nettop", "-P", "-L", "1", "-x", "-J", "bytes_in,bytes_out", "-n"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        try:
            stdout, _ = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            return {}
    except (FileNotFoundError, OSError):
        # OSError catches fork failure during resource exhaustion
        return {}
    stats = {}
    for line in stdout.decode("utf-8", errors="replace").splitlines():
        if line.startswith(",") or not line.strip():
            continue
        parts = line.rstrip(",").split(",")
        if len(parts) < 3:
            continue
        try:
            pid = int(parts[0].rsplit(".", 1)[-1])
            stats[pid] = (int(parts[1]), int(parts[2]))
        except (ValueError, IndexError):
            continue
    return stats


# ── Hidden Process Detection ─────────────────────────────────────────────

def _check_hidden_pids_quick(libproc_pids):
    """Quick cross-reference: compare libproc PIDs with ps output.

    Returns set of PIDs visible to ps but NOT to libproc.

    Re-samples libproc after ps completes to suppress races with short-lived
    processes (including the ps subprocess itself): a PID is only flagged if
    it's missing from BOTH snapshots.
    """
    libproc_set = set(libproc_pids)
    try:
        proc = subprocess.Popen(
            ["ps", "-axo", "pid="],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        ps_pid = proc.pid
        try:
            stdout, _ = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            return set()
    except (FileNotFoundError, OSError):
        return set()
    # Second libproc snapshot to catch transient processes that spawned
    # between the caller's snapshot and the ps call
    libproc_set |= set(_list_all_pids())
    ps_pids = set()
    for line in stdout.decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if line:
            try:
                ps_pids.add(int(line))
            except ValueError:
                pass
    hidden = ps_pids - libproc_set
    hidden.discard(0)
    hidden.discard(os.getpid())
    hidden.discard(ps_pid)  # ps includes itself in output, but it exits before resample
    return hidden


# ── Kernel Module (kext) Enumeration ──────────────────────────────────────

def _kextmanager_loaded_kexts():
    """Enumerate loaded kernel extensions via IOKit KextManagerCopyLoadedKextInfo.

    Returns a list of dicts: {bundle_id, version, path, load_tag, refs, size,
    team_id, started}. Empty list if the IOKit framework / symbol is
    unavailable (pre-10.7) or any ctypes call fails.

    No root required for the listing itself, but rootkits that unlink their
    kmod_info from the kernel linked list will be invisible here too — that
    is an acknowledged limitation of every userland enumeration on modern
    macOS (per the synthesi research).
    """
    try:
        iokit = ctypes.CDLL(
            "/System/Library/Frameworks/IOKit.framework/IOKit",
            use_errno=True,
        )
        cf = ctypes.CDLL(
            "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation",
            use_errno=True,
        )
    except OSError:
        return []

    # Function prototypes for KextManagerCopyLoadedKextInfo(CFArrayRef kextIdentifiers,
    #                                                        CFArrayRef infoKeys)
    try:
        iokit.KextManagerCopyLoadedKextInfo.restype = ctypes.c_void_p
        iokit.KextManagerCopyLoadedKextInfo.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    except AttributeError:
        return []

    cf.CFDictionaryGetCount.restype = ctypes.c_long
    cf.CFDictionaryGetCount.argtypes = [ctypes.c_void_p]
    cf.CFDictionaryGetKeysAndValues.restype = None
    cf.CFDictionaryGetKeysAndValues.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    cf.CFDictionaryGetValue.restype = ctypes.c_void_p
    cf.CFDictionaryGetValue.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    cf.CFStringCreateWithCString.restype = ctypes.c_void_p
    cf.CFStringCreateWithCString.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint32]
    cf.CFStringGetCString.restype = ctypes.c_bool
    cf.CFStringGetCString.argtypes = [ctypes.c_void_p, ctypes.c_char_p,
                                      ctypes.c_long, ctypes.c_uint32]
    cf.CFStringGetLength.restype = ctypes.c_long
    cf.CFStringGetLength.argtypes = [ctypes.c_void_p]
    cf.CFGetTypeID.restype = ctypes.c_ulong
    cf.CFGetTypeID.argtypes = [ctypes.c_void_p]
    cf.CFStringGetTypeID.restype = ctypes.c_ulong
    cf.CFNumberGetTypeID.restype = ctypes.c_ulong
    cf.CFBooleanGetTypeID.restype = ctypes.c_ulong
    cf.CFNumberGetValue.restype = ctypes.c_bool
    cf.CFNumberGetValue.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]
    cf.CFBooleanGetValue.restype = ctypes.c_bool
    cf.CFBooleanGetValue.argtypes = [ctypes.c_void_p]
    cf.CFRelease.argtypes = [ctypes.c_void_p]

    kUTF8 = 0x08000100

    def _cf_to_py(ref):
        if not ref:
            return None
        type_id = cf.CFGetTypeID(ref)
        if type_id == cf.CFStringGetTypeID():
            length = cf.CFStringGetLength(ref)
            buflen = length * 4 + 1
            buf = ctypes.create_string_buffer(buflen)
            if cf.CFStringGetCString(ref, buf, buflen, kUTF8):
                return buf.value.decode("utf-8", errors="replace")
            return None
        if type_id == cf.CFNumberGetTypeID():
            # kCFNumberLongLongType == 11
            out = ctypes.c_longlong(0)
            if cf.CFNumberGetValue(ref, 11, ctypes.byref(out)):
                return int(out.value)
            return None
        if type_id == cf.CFBooleanGetTypeID():
            return bool(cf.CFBooleanGetValue(ref))
        return None

    info = iokit.KextManagerCopyLoadedKextInfo(None, None)
    if not info:
        return []
    try:
        count = cf.CFDictionaryGetCount(info)
        keys = (ctypes.c_void_p * count)()
        values = (ctypes.c_void_p * count)()
        cf.CFDictionaryGetKeysAndValues(info,
                                         ctypes.cast(keys, ctypes.c_void_p),
                                         ctypes.cast(values, ctypes.c_void_p))

        key_names = {
            "bundle_id": "CFBundleIdentifier",
            "version": "CFBundleVersion",
            "path": "OSBundlePath",
            "load_tag": "OSBundleLoadTag",
            "refs": "OSBundleRetainCount",
            "size": "OSBundleLoadSize",
            "team_id": "TeamIdentifier",
            "started": "OSBundleStarted",
        }
        # Pre-build CFString keys
        cf_keys = {
            name: cf.CFStringCreateWithCString(None, raw.encode("utf-8"), kUTF8)
            for name, raw in key_names.items()
        }

        result = []
        try:
            for i in range(count):
                kext_dict = values[i]
                if not kext_dict:
                    continue
                entry = {}
                for name, cf_key in cf_keys.items():
                    val = cf.CFDictionaryGetValue(kext_dict, cf_key)
                    entry[name] = _cf_to_py(val)
                result.append(entry)
        finally:
            for cf_key in cf_keys.values():
                if cf_key:
                    cf.CFRelease(cf_key)
        return result
    finally:
        cf.CFRelease(info)


def _kmutil_showloaded():
    """Run `kmutil showloaded` and return a set of bundle IDs.

    Used as a cross-reference against KextManagerCopyLoadedKextInfo. Any
    bundle ID visible to one but not the other is suspicious.
    """
    rc, out, _ = _run_cmd_short(["kmutil", "showloaded"], timeout=10)
    if rc is None or rc != 0:
        return set()
    bundle_ids = set()
    # kmutil output columns include a Name (bundle id) in the trailing cols.
    # The format can vary by macOS version, so we scan every token for
    # reverse-DNS patterns with ≥ 2 dots and reasonable length.
    import re
    pat = re.compile(r"\b([a-zA-Z0-9]+(?:\.[a-zA-Z0-9_-]+){2,})\b")
    for line in out.splitlines():
        # skip header line(s) with "Address" / "Index" / "UUID"
        if "Address" in line and "Size" in line:
            continue
        for tok in line.split():
            m = pat.fullmatch(tok)
            if m:
                bundle_ids.add(m.group(1))
    return bundle_ids


def _list_system_extensions():
    """Parse `systemextensionsctl list` output.

    Returns a list of dicts: {team_id, bundle_id, state, name, version}.
    Empty list on failure. No root required.
    """
    rc, out, _ = _run_cmd_short(["systemextensionsctl", "list"], timeout=10)
    if rc is None or rc != 0:
        return []
    entries = []
    # systemextensionsctl uses tab-delimited columns:
    #   enabled<TAB>active<TAB>teamID<TAB>bundleID (version)<TAB>name<TAB>[state]
    # where enabled/active are either "*" (set) or empty.
    for line in out.splitlines():
        if not line.strip() or line.startswith("---") \
                or line.startswith("enabled") or "No system extensions" in line:
            continue
        fields = line.split("\t")
        if len(fields) < 5:
            continue
        # Trim enabled/active flag fields
        fields = [f.strip() for f in fields]
        # Expected layout: ['', '*', 'TEAMID', 'bundle (ver)', 'name', '[state]']
        # Find the first field that looks like a TeamID or reverse-DNS
        team_id = ""
        bundle_and_version = ""
        name = ""
        state = ""
        if fields and fields[-1].startswith("["):
            state = fields[-1].strip("[]")
            fields = fields[:-1]
        # Now the tail fields are: teamID, bundle(ver), name
        if len(fields) >= 4:
            # Skip the two boolean flags at the start
            tail = fields[-3:]
            team_id, bundle_and_version = tail[0], tail[1]
            name = tail[2] if len(tail) > 2 else ""
        bundle_id = ""
        version = ""
        if "(" in bundle_and_version and ")" in bundle_and_version:
            bundle_id = bundle_and_version.split("(", 1)[0].strip()
            version = bundle_and_version[bundle_and_version.find("(") + 1:
                                         bundle_and_version.find(")")]
        else:
            bundle_id = bundle_and_version
        entries.append({
            "team_id": team_id,
            "bundle_id": bundle_id,
            "version": version,
            "name": name,
            "state": state,
            "raw": line,
        })
    return entries


def _find_hidden_kexts():
    """Cross-reference kext enumeration sources to spot hiding.

    Returns a list of (severity, description) tuples. A kext visible to one
    API but missing from another is suspicious (but not definitive — many
    false positives are possible because the two sources use slightly
    different views of the same data).

    Signals produced:
      - IOKit-listed kexts with no on-disk path
      - Kexts loaded by third parties with no TeamIdentifier
      - IOKit-listed kexts not seen by `kmutil showloaded` (or vice versa)
    """
    kexts = _kextmanager_loaded_kexts()
    kmutil_set = _kmutil_showloaded()
    findings = []
    # Exclude synthetic entries that appear in IOKit but aren't kexts in the
    # rootkit sense (kernel itself, pseudo-kexts).
    IGNORED = {"__kernel__", ""}
    iokit_ids = {k["bundle_id"] for k in kexts
                 if k.get("bundle_id") and k["bundle_id"] not in IGNORED}

    for k in kexts:
        bid = k.get("bundle_id") or "(unknown)"
        if bid in IGNORED:
            continue
        path = k.get("path") or ""
        team = k.get("team_id")
        if not path:
            findings.append(("HIGH",
                f"kext with no on-disk path: {bid}"))
        elif path and not path.startswith("/System/") \
                and not path.startswith("/Library/") \
                and team is None:
            findings.append(("MEDIUM",
                f"3rd-party kext with no TeamIdentifier: {bid} ({path})"))

    if kmutil_set:
        in_iokit_not_kmutil = iokit_ids - kmutil_set
        in_kmutil_not_iokit = (kmutil_set - iokit_ids) - IGNORED
        for bid in sorted(in_iokit_not_kmutil):
            findings.append(("MEDIUM",
                f"kext in IOKit but NOT in kmutil: {bid}"))
        for bid in sorted(in_kmutil_not_iokit):
            findings.append(("MEDIUM",
                f"kext in kmutil but NOT in IOKit: {bid}"))
    return findings


# ── Keyboard-Hook / Keylogger Detection ───────────────────────────────────

# kCGEventKeyDown = 10, kCGEventKeyUp = 11, kCGEventFlagsChanged = 12
_CG_KEY_EVENT_TYPES = (10, 11, 12)


class _CGEventTapInformation(ctypes.Structure):
    """Mirror of CoreGraphics' CGEventTapInformation struct (public API)."""
    _fields_ = [
        ("eventTapID", ctypes.c_uint32),
        ("tapPoint", ctypes.c_uint32),
        ("options", ctypes.c_uint32),
        ("eventsOfInterest", ctypes.c_uint64),
        ("tappingProcess", ctypes.c_int32),
        ("processBeingTapped", ctypes.c_int32),
        ("enabled", ctypes.c_bool),
        ("minUsecLatency", ctypes.c_float),
        ("avgUsecLatency", ctypes.c_float),
        ("maxUsecLatency", ctypes.c_float),
    ]


def _enumerate_event_taps():
    """Enumerate active CGEventTaps via CoreGraphics.

    Returns a list of dicts: {pid, target_pid, tap_point, enabled,
    events_of_interest_mask, hooks_keys}. Empty list if CG is unavailable.

    No root required. Equivalent to Objective-See's ReiKey — flag any tap
    whose eventsOfInterest mask contains key events and whose owner is
    unsigned or in a user-writable directory.
    """
    try:
        cg = ctypes.CDLL(
            "/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics",
        )
    except OSError:
        return []
    try:
        cg.CGGetEventTapList.restype = ctypes.c_uint32
        cg.CGGetEventTapList.argtypes = [
            ctypes.c_uint32,
            ctypes.POINTER(_CGEventTapInformation),
            ctypes.POINTER(ctypes.c_uint32),
        ]
    except AttributeError:
        return []

    # Call twice: first to get the count, second to fill the buffer
    count = ctypes.c_uint32(0)
    cg.CGGetEventTapList(0, None, ctypes.byref(count))
    n = count.value
    if n == 0:
        return []
    buf = (_CGEventTapInformation * n)()
    filled = ctypes.c_uint32(0)
    rc = cg.CGGetEventTapList(n, buf, ctypes.byref(filled))
    if rc != 0:
        return []
    result = []
    for i in range(filled.value):
        t = buf[i]
        mask = int(t.eventsOfInterest)
        hooks_keys = any(mask & (1 << et) for et in _CG_KEY_EVENT_TYPES)
        result.append({
            "tap_id": int(t.eventTapID),
            "pid": int(t.tappingProcess),
            "target_pid": int(t.processBeingTapped),
            "tap_point": int(t.tapPoint),
            "enabled": bool(t.enabled),
            "events_of_interest_mask": mask,
            "hooks_keys": hooks_keys,
        })
    return result


_TCC_SYSTEM_DB = "/Library/Application Support/com.apple.TCC/TCC.db"


def _query_tcc_input_monitoring():
    """Read the TCC database and return entries that grant Input Monitoring
    (kTCCServiceListenEvent) or Accessibility (kTCCServiceAccessibility).

    Returns a list of dicts: {service, client, client_type, auth_value,
    auth_reason, db}. Root / Full Disk Access required for the system DB;
    we also try the per-user DB which the current euid can read.

    auth_value meanings: 0=denied, 1=unknown, 2=allowed, 3=limited.
    """
    import sqlite3
    entries = []
    dbs = [_TCC_SYSTEM_DB, os.path.join(_EFFECTIVE_HOME,
                                         "Library/Application Support/com.apple.TCC/TCC.db")]
    query = (
        "SELECT service, client, client_type, auth_value, auth_reason "
        "FROM access "
        "WHERE service IN ('kTCCServiceListenEvent', 'kTCCServiceAccessibility', "
        "                  'kTCCServicePostEvent')")
    for db in dbs:
        if not os.path.exists(db):
            continue
        try:
            conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=2)
            cursor = conn.cursor()
            cursor.execute(query)
            for row in cursor.fetchall():
                service, client, client_type, auth_value, auth_reason = row
                entries.append({
                    "service": service,
                    "client": client,
                    "client_type": client_type,
                    "auth_value": auth_value,
                    "auth_reason": auth_reason,
                    "db": db,
                })
            conn.close()
        except sqlite3.Error:
            # Usually "authorization denied" — skip
            continue
    return entries


def _list_input_methods():
    """List installed Input Method bundles.

    Returns a list of dicts: {path, bundle_id, team_id, codesign_ok}.
    Bundles under /System/Library/Input Methods/ are Apple-shipped and
    treated as trusted by _is_apple_signed().
    """
    results = []
    roots = [
        "/Library/Input Methods",
        "/System/Library/Input Methods",
        os.path.join(_EFFECTIVE_HOME, "Library/Input Methods"),
    ]
    for root in roots:
        if not os.path.isdir(root):
            continue
        try:
            for name in os.listdir(root):
                bundle = os.path.join(root, name)
                if not bundle.endswith(".app"):
                    continue
                info = _codesign_structured(bundle) or {}
                results.append({
                    "path": bundle,
                    "bundle_id": info.get("identifier", ""),
                    "team_id": info.get("team_id", ""),
                    "authority": info.get("authority", []),
                    "codesign_ok": info.get("rc") == 0,
                })
        except (PermissionError, OSError):
            continue
    return results


def _effective_home():
    """Return the invoking user's HOME, respecting sudo.

    When mac-tui-procmon is launched with `sudo mac-tui-procmon`, $HOME resolves to /var/root
    — so anything living in the real user's home (YARA rules at
    ~/.mac-tui-procmon.yar, Claude's auth at ~/.claude, npm global bin, etc.) is
    invisible. This helper falls back to SUDO_USER's home in that case so
    per-user config and credentials stay reachable.

    Order of preference:
      1. SUDO_USER's home from pwd (canonical)
      2. /Users/<SUDO_USER> as a last-resort guess
      3. $HOME of the current euid
    """
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        try:
            import pwd
            return pwd.getpwnam(sudo_user).pw_dir
        except (ImportError, KeyError):
            return f"/Users/{sudo_user}"
    return os.path.expanduser("~")


# Cached at module load; process restart picks up new sudo state.
_EFFECTIVE_HOME = _effective_home()
_CHAT_TIMEOUT_SECS = max(
    15, int(os.environ.get("MAC_TUI_PROCMON_CHAT_TIMEOUT", "60"))
)


def _build_user_tool_path():
    """Return an augmented PATH so user-installed CLIs (claude, codex, gemini,
    yara, etc.) remain reachable when mac-tui-procmon is started with sudo.

    sudo resets PATH to a sanitized system-only value, which hides Homebrew
    and npm-global locations. We rebuild those from SUDO_USER's home plus
    well-known Homebrew locations so `Popen([tool, ...])` keeps working.
    """
    parts = []
    existing = os.environ.get("PATH", "")
    if existing:
        parts.append(existing)

    extra_dirs = ["/opt/homebrew/bin", "/usr/local/bin", "/opt/homebrew/sbin"]

    # Resolve inline so tests that mock SUDO_USER / pwd.getpwnam stay effective
    home = _effective_home()
    if home:
        extra_dirs.extend([
            f"{home}/.local/bin",
            f"{home}/.npm-global/bin",
            f"{home}/bin",
        ])
        nvm_root = os.path.join(home, ".nvm", "versions", "node")
        try:
            for ver in os.listdir(nvm_root):
                extra_dirs.append(os.path.join(nvm_root, ver, "bin"))
        except (FileNotFoundError, NotADirectoryError, PermissionError):
            pass

    for d in extra_dirs:
        if d and d not in existing.split(os.pathsep):
            parts.append(d)
    return os.pathsep.join(parts)


# Cached PATH string so we don't rebuild it on every subprocess call
_USER_TOOL_PATH = _build_user_tool_path()


def _run_cmd_short(argv, timeout=5, stdin_bytes=None, env=None):
    """Run a subprocess and return (rc, stdout_text, stderr_text).
    On timeout/OSError/FileNotFoundError returns (None, "", error_str).

    `env=None` inherits the current process env (default behavior);
    pass an explicit dict to override it (used by _delete_tcc_grant to
    retarget tccutil at the system vs. user TCC.db).
    """
    try:
        p = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE if stdin_bytes is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=env,
        )
        try:
            out, err = p.communicate(input=stdin_bytes, timeout=timeout)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()
            return (None, "", "timeout")
        return (
            p.returncode,
            out.decode("utf-8", errors="replace"),
            err.decode("utf-8", errors="replace"),
        )
    except (FileNotFoundError, OSError) as e:
        return (None, "", str(e))


def _tool_env():
    """Environment used when launching external user-installed tools."""
    env = {
        **os.environ,
        "PATH": _USER_TOOL_PATH,
        "HOME": _EFFECTIVE_HOME,
    }
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        env["USER"] = sudo_user
        env["LOGNAME"] = sudo_user
    return env


def _run_external_tool(tool_name, argv_tail, timeout=20, stdin_bytes=None):
    """Run a configured external tool by logical name."""
    tool_path = _resolve_external_tool(tool_name)
    if not tool_path:
        return (None, "", f"{tool_name} not installed")
    return _run_cmd_short(
        [tool_path] + list(argv_tail),
        timeout=timeout,
        stdin_bytes=stdin_bytes,
        env=_tool_env(),
    )


def _extract_user_writable_paths(text):
    """Extract paths rooted in user-writable locations from free-form text."""
    hits = []
    seen = set()
    for raw in re.findall(r"(/[^\s\"'):,]+)", text or ""):
        path = raw.rstrip(".,;:")
        for prefix in _USER_WRITABLE_DYLIB_PREFIXES:
            if path.startswith(prefix) and path not in seen:
                hits.append(path)
                seen.add(path)
                break
    return hits


def _summarize_issue_lines(text, limit=8):
    """Return short, non-empty lines that look like security signals."""
    hits = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        lower = line.lower()
        if any(tok in lower for tok in (
            "warning", "warn", "error", "fail", "issue", "blocked",
            "denied", "tamper", "unsigned", "adhoc", "ad-hoc",
            "unknown", "not loaded", "waiting for the user",
        )):
            hits.append(line[:240])
        if len(hits) >= limit:
            break
    return hits


_ANTI_DEBUG_BYTE_MARKERS = {
    b"PT_DENY_ATTACH": "PT_DENY_ATTACH anti-debug marker",
    b"ptrace": "ptrace anti-debug marker",
    b"task_set_exception_ports": "Mach exception-port anti-debug marker",
    b"mach_exception_port": "Mach exception-port anti-debug marker",
    b"sysctl": "sysctl anti-debug marker",
    b"P_TRACED": "P_TRACED anti-debug marker",
}

_INJECTION_FRAMEWORK_MARKERS = {
    b"FridaGadget": "Frida gadget marker",
    b"frida": "Frida marker",
    b"Substrate": "Substrate marker",
    b"libsubstrate": "Substrate library marker",
    b"libhooker": "libhooker marker",
    b"DYLD_INSERT_LIBRARIES": "DYLD injection marker",
}

_ANTI_DEBUG_IMPORT_MARKERS = {
    "_ptrace": "ptrace import",
    "_task_set_exception_ports": "task_set_exception_ports import",
    "_sysctl": "sysctl import",
}

_BLOCKBLOCK_LOG_PATHS = (
    "/Library/Objective-See/BlockBlock/BlockBlock.log",
    os.path.join(_EFFECTIVE_HOME, "Library/Logs/BlockBlock.log"),
)


def _scan_binary_markers(exe_path, limit=8):
    """Return static anti-debug / injection markers found in a binary."""
    if not exe_path or not os.path.isfile(exe_path):
        return []
    hits = []
    seen = set()
    try:
        size = os.path.getsize(exe_path)
        with open(exe_path, "rb") as fh:
            data = fh.read(min(size, 16 * 1024 * 1024))
    except OSError:
        return []
    for marker, label in {**_ANTI_DEBUG_BYTE_MARKERS,
                          **_INJECTION_FRAMEWORK_MARKERS}.items():
        if marker in data and label not in seen:
            hits.append(label)
            seen.add(label)
        if len(hits) >= limit:
            break
    return hits


def _scan_import_markers(exe_path, limit=6):
    """Return anti-debug import markers from `otool -Iv`."""
    if not exe_path or not os.path.isfile(exe_path):
        return []
    rc, out, _ = _run_cmd_short(["otool", "-Iv", exe_path], timeout=8)
    if rc is None or rc != 0 or not out:
        return []
    hits = []
    for symbol, label in _ANTI_DEBUG_IMPORT_MARKERS.items():
        if symbol in out:
            hits.append(label)
        if len(hits) >= limit:
            break
    return hits


def _scan_vmmap_signals(pid, timeout=10):
    """Return suspicious vmmap lines for a process."""
    rc, out, err = _run_cmd_short(["vmmap", str(pid)], timeout=timeout)
    if rc is None or rc != 0:
        return {"raw": "", "signals": [], "error": (err or out or "").strip()}
    signals = []
    seen = set()
    for raw in out.splitlines():
        line = raw.strip()
        if not line:
            continue
        lower = line.lower()
        if ("rwx/rwx" in line or "rwx/r-x" in line) and line not in seen:
            signals.append(f"RWX memory region: {line[:180]}")
            seen.add(line)
        elif "malloc_jit" in lower and line not in seen:
            signals.append(f"JIT memory region: {line[:180]}")
            seen.add(line)
        for path in _extract_user_writable_paths(line):
            msg = f"User-writable mapped image: {path}"
            if msg not in seen:
                signals.append(msg)
                seen.add(msg)
    return {"raw": out, "signals": signals[:10], "error": ""}


def _osquery_process_snapshot(timeout=20):
    """Return {pid: row} from osquery's processes table."""
    rc, out, err = _run_external_tool(
        "osquery",
        ["--json",
         ("SELECT pid, parent, name, path, cmdline, on_disk "
          "FROM processes;")],
        timeout=timeout)
    if rc is None:
        return {}, err or "osquery unavailable"
    if rc != 0 or not out.strip():
        return {}, (err or out or f"exit code {rc}").strip()
    try:
        rows = _json.loads(out)
    except ValueError as e:
        return {}, f"invalid osquery JSON: {e}"
    by_pid = {}
    for row in rows or []:
        try:
            pid = int(row.get("pid"))
        except (TypeError, ValueError):
            continue
        by_pid[pid] = row
    return by_pid, ""


def _taskexplorer_pid_snapshot(pid, timeout=20):
    """Return a lightweight TaskExplorer detail snapshot for one PID."""
    rc, out, err = _run_external_tool(
        "taskexplorer",
        ["-explore", "-pid", str(pid), "-detailed", "-pretty"],
        timeout=timeout)
    if rc is None:
        return {"error": err or "taskexplorer unavailable", "signals": [], "paths": [], "raw": ""}
    text = (out or err or "").strip()
    if rc != 0:
        return {"error": text[:240] or f"exit code {rc}", "signals": [], "paths": [], "raw": text}
    paths = _extract_user_writable_paths(text)
    signals = []
    lower = text.lower()
    if "frida" in lower:
        signals.append("TaskExplorer output references Frida")
    if "substrate" in lower:
        signals.append("TaskExplorer output references Substrate")
    for path in paths[:6]:
        signals.append(f"TaskExplorer saw user-writable path: {path}")
    return {"error": "", "signals": signals[:8], "paths": paths[:8], "raw": text}


def _run_knockknock_scan(timeout=120):
    """Run Objective-See KnockKnock and summarize the scan."""
    rc, out, err = _run_external_tool(
        "knockknock",
        ["-whosthere", "-verbose", "-skipVT"],
        timeout=timeout)
    if rc is None:
        return {"error": err or "knockknock unavailable"}
    text = (out or err or "").strip()
    if rc != 0:
        return {"error": text[:240] or f"exit code {rc}"}
    match = re.search(
        r"RESULTS:\s*(\d+)\s+persistent items\s*(\d+)\s+flagged items",
        text,
        flags=re.IGNORECASE | re.DOTALL,
    )
    categories = [line.strip() for line in text.splitlines()
                  if "found " in line.lower() and len(line.strip()) < 120][:10]
    result = {
        "raw": text,
        "persistent_items": 0,
        "flagged_items": 0,
        "categories": categories,
    }
    if match:
        result["persistent_items"] = int(match.group(1))
        result["flagged_items"] = int(match.group(2))
    return result


def _read_blockblock_summary(limit=12):
    """Read and summarize recent BlockBlock activity from its log."""
    log_path = next((p for p in _BLOCKBLOCK_LOG_PATHS if os.path.exists(p)), "")
    if not log_path:
        return {"error": "log not found", "path": "", "blocked": 0, "alerts": 0, "samples": []}
    try:
        with open(log_path, encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except OSError as e:
        return {"error": str(e), "path": log_path, "blocked": 0, "alerts": 0, "samples": []}
    recent = [line.strip() for line in lines[-200:] if line.strip()]
    blocked = sum(1 for line in recent if "block" in line.lower())
    alerts = sum(1 for line in recent if "persist" in line.lower() or "launch" in line.lower())
    samples = _summarize_issue_lines("\n".join(recent), limit=limit)
    return {
        "error": "",
        "path": log_path,
        "blocked": blocked,
        "alerts": alerts,
        "samples": samples,
    }


def _codesign_structured(exe_path):
    """Structured parse of codesign metadata.

    Runs `codesign -dvvv -r- --entitlements :- <path>`.  codesign puts the
    informational metadata (Executable=, Identifier=, Authority=, ...) on
    *stderr* and the requirements + entitlements XML on stdout, so we have to
    parse the two streams independently.  Extracts: team_id, authority
    (cert chain, outer first), identifier, hardened_runtime, flags,
    requirements, entitlements_xml. Missing fields become empty strings or
    empty lists. Returns {} if codesign is unavailable or the path is invalid.
    """
    if not exe_path:
        return {}
    # 30s covers cold-cache reads of large signed bundles (Chrome, Xcode,
    # some Electron apps). codesign -dvvv doesn't do trust evaluation,
    # so the long-tail is purely the on-disk binary read; SSDs hit it
    # in <1s warm but can take 10–20s cold on a quiet machine.
    rc, out, err = _run_cmd_short(
        ["codesign", "-dvvv", "-r-", "--entitlements", ":-", exe_path],
        timeout=30,
    )
    if rc is None:
        return {}
    info = {
        "team_id": "",
        "authority": [],
        "identifier": "",
        "hardened_runtime": False,
        "flags": "",
        "requirements": "",
        "entitlements_xml": "",
        "raw": (err + "\n---\n" + out).strip(),
        "rc": rc,
    }
    # Metadata lives on stderr
    for line in err.splitlines():
        if line.startswith("TeamIdentifier="):
            info["team_id"] = line.split("=", 1)[1].strip()
        elif line.startswith("Authority="):
            info["authority"].append(line.split("=", 1)[1].strip())
        elif line.startswith("Identifier="):
            info["identifier"] = line.split("=", 1)[1].strip()
        elif line.startswith("CodeDirectory"):
            # e.g. "CodeDirectory v=20500 size=... flags=0x10000(runtime)"
            if "runtime" in line:
                info["hardened_runtime"] = True
            if "flags=" in line:
                frag = line.split("flags=", 1)[1].split()[0]
                info["flags"] = frag

    # Requirements + entitlements XML live on stdout
    req_lines = []
    ent_start = None
    out_lines = out.splitlines()
    for i, line in enumerate(out_lines):
        if line.startswith("# designated =>") or line.startswith("designated =>"):
            req_lines.append(line.split("=>", 1)[1].strip())
        elif "<?xml" in line:
            ent_start = i
            break
    if ent_start is not None:
        info["entitlements_xml"] = "\n".join(out_lines[ent_start:])
    info["requirements"] = "\n".join(req_lines)
    return info


def _check_gatekeeper(exe_path):
    """Run `spctl --assess` for Gatekeeper/notarization verdict.

    Returns a dict: {accepted: bool, notarized: bool, origin: str, raw: str,
    reason: str (when rejected)}. Empty dict on tool failure.

    For rejected paths, extracts just the parenthetical reason (e.g.
    "the code is valid but does not seem to be an app") rather than the
    entire path-prefixed line so the reason stays readable.
    """
    if not exe_path:
        return {}
    rc, out, err = _run_cmd_short(
        ["spctl", "--assess", "--verbose=4", "--type", "execute", exe_path],
        timeout=10,
    )
    if rc is None:
        return {}
    text = (out + "\n" + err).strip()
    info = {
        "accepted": rc == 0,
        "notarized": False,
        "origin": "",
        "reason": "",
        "raw": text,
        "rc": rc,
    }
    for line in text.splitlines():
        ls = line.strip()
        if "Notarized" in ls:
            info["notarized"] = True
        if ls.startswith("source="):
            info["origin"] = ls.split("=", 1)[1].strip()
        elif ls.startswith("origin="):
            info["origin"] = ls.split("=", 1)[1].strip()
        if "rejected" in ls.lower() and not info["reason"]:
            # Typical shape: "/path: rejected (<reason>)"
            lower = ls.lower()
            marker = "rejected"
            idx = lower.find(marker)
            tail = ls[idx + len(marker):].strip()  # " (<reason>)" or just ""
            if tail.startswith("(") and tail.endswith(")"):
                info["reason"] = tail[1:-1].strip()
            elif tail:
                info["reason"] = tail.lstrip(":").strip()
            else:
                info["reason"] = "rejected"
    return info


def _binary_trust_profile(exe_path, codesign_info=None, gatekeeper_info=None):
    """Classify a binary into an analyst-facing trust tier."""
    cs = codesign_info or {}
    gate = gatekeeper_info or {}
    apple = _is_apple_signed(exe_path, cs)
    team = cs.get("team_id") or ""
    accepted = bool(gate.get("accepted"))
    notarized = bool(gate.get("notarized"))
    profile = {
        "tier": "unsigned",
        "label": "Unsigned / unverifiable",
        "apple_signed": apple,
        "team_id": team,
        "accepted": accepted,
        "notarized": notarized,
    }
    if apple:
        profile.update({"tier": "apple", "label": "Apple platform-signed"})
        return profile
    if cs.get("rc") not in (None, 0):
        profile.update({"tier": "invalid", "label": "Invalid or unverifiable signature"})
        return profile
    if not team:
        profile.update({"tier": "ad_hoc", "label": "Ad-hoc or local signature"})
        return profile
    if accepted and notarized:
        profile.update({
            "tier": "developer_id_notarized",
            "label": f"Developer ID + notarized ({team})",
        })
        return profile
    if accepted:
        profile.update({
            "tier": "developer_id_accepted",
            "label": f"Gatekeeper-accepted third-party signature ({team})",
        })
        return profile
    profile.update({
        "tier": "third_party_untrusted",
        "label": f"Third-party signature not accepted by Gatekeeper ({team})",
    })
    return profile


def _parse_entitlements_xml(xml_text):
    """Very-minimal plist parse: extract <key>name</key><true/> entries.

    Uses a dependency-free regex scan. Returns a set of boolean-true keys.
    (Non-boolean entitlement values are surfaced via the full xml dump; we
    only care about dangerous boolean flags for heuristics.)
    """
    if not xml_text:
        return set()
    import re
    # Match <key>X</key> followed by <true/> with only whitespace between
    pattern = re.compile(r"<key>([^<]+)</key>\s*<true\s*/>", re.MULTILINE)
    return set(pattern.findall(xml_text))


_APPLE_SYSTEM_PATH_PREFIXES = (
    "/System/",
    "/usr/libexec/",
    "/usr/sbin/",
    "/usr/bin/",
    "/sbin/",
    "/bin/",
    "/Library/Apple/",
)


def _is_apple_signed(exe_path, codesign_info):
    """Return True for binaries shipped and signed by Apple.

    Used to suppress heuristic noise: Apple's own tooling legitimately uses
    entitlements like allow-jit or allow-dyld-environment-variables, and
    flagging those would produce dozens of false positives on any scan.

    Signals considered Apple-signed (any one is enough):
      - Binary lives under a known system path prefix
      - Authority chain is the Apple Software Signing chain
        ("Software Signing" / "Apple Code Signing Certification Authority")
    """
    if exe_path:
        for pfx in _APPLE_SYSTEM_PATH_PREFIXES:
            if exe_path.startswith(pfx):
                return True
    authority = (codesign_info or {}).get("authority") or []
    for a in authority:
        if a in ("Software Signing", "Apple Code Signing Certification Authority"):
            return True
    return False


_DANGEROUS_ENTITLEMENTS = {
    # Actively weakens runtime security — injection surface
    "com.apple.security.cs.disable-library-validation":
        "disables dylib signature validation (injection surface)",
    "com.apple.security.cs.allow-dyld-environment-variables":
        "allows DYLD_* env vars (injection)",
    "com.apple.security.cs.disable-executable-page-protection":
        "disables W^X page protection",
    "com.apple.security.cs.allow-unsigned-executable-memory":
        "allows unsigned executable memory (RWX)",
    "com.apple.security.cs.allow-jit":
        "allows JIT / runtime code generation",
    # Powerful privileges
    "com.apple.security.get-task-allow":
        "allows other processes to read this one's memory (debug)",
    "com.apple.security.cs.debugger":
        "grants debugger permissions to other processes",
}


_PERSISTENCE_PATH_PREFIXES = (
    "/Library/LaunchAgents/",
    "/Library/LaunchDaemons/",
    "/Library/StartupItems/",
    "/System/Library/LaunchAgents/",
    "/System/Library/LaunchDaemons/",
    "/Library/LoginHook/",
    "/Library/LogoutHook/",
    os.path.expanduser("~/Library/LaunchAgents/"),
    os.path.expanduser("~/Library/LaunchDaemons/"),
    os.path.expanduser("~/Library/StartupItems/"),
)


_USER_WRITABLE_DYLIB_PREFIXES = (
    "/tmp/",
    "/private/tmp/",
    "/var/tmp/",
    "/Users/Shared/",
    os.path.expanduser("~/Downloads/"),
    os.path.expanduser("~/Desktop/"),
    os.path.expanduser("~/Library/Caches/"),
)


def _lsof_hits_persistence(lsof_output):
    """Return list of (path, category) for file descriptors that point at
    known persistence locations. Works on raw `lsof -p` output.
    """
    if not lsof_output:
        return []
    hits = []
    for line in lsof_output.splitlines():
        # `lsof` columns: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
        # NAME starts around column 9; just look for our prefixes in the whole line
        for pfx in _PERSISTENCE_PATH_PREFIXES:
            idx = line.find(pfx)
            if idx != -1:
                # Try to isolate just the path from idx to end of line
                path = line[idx:].split()[0] if idx < len(line) else line[idx:]
                hits.append((path, "persistence"))
                break
    return hits


def _otool_user_writable_dylibs(otool_output):
    """From `otool -L` output, return list of dylib paths loaded from
    user-writable locations (likely injection).
    """
    if not otool_output:
        return []
    hits = []
    for line in otool_output.splitlines():
        stripped = line.strip()
        if not stripped or stripped.endswith(":"):
            continue  # header line (the binary path)
        path = stripped.split()[0]
        for pfx in _USER_WRITABLE_DYLIB_PREFIXES:
            if path.startswith(pfx):
                hits.append(path)
                break
    return hits


_DEFAULT_YARA_RULES_PATH = os.path.join(_EFFECTIVE_HOME, ".mac-tui-procmon.yar")


def _yara_scan_file(path, rules_path=None, timeout=15):
    """Scan a file on disk with `yara`. Returns list of matched rule names.

    Shells out to `yara` CLI (no Python dep required). Uses
    `~/.mac-tui-procmon.yar` as the default rule file; gracefully returns [] if
    yara or the rules file is missing.
    """
    if not path or not os.path.exists(path):
        return []
    rules = rules_path or _DEFAULT_YARA_RULES_PATH
    if not os.path.exists(rules):
        return []
    rc, out, err = _run_cmd_short(
        ["yara", "-r", "-w", rules, path], timeout=timeout)
    if rc is None:
        return []
    matches = []
    for line in out.splitlines():
        if not line.strip():
            continue
        # format: "RULE_NAME path" → grab first token
        parts = line.split()
        if parts:
            matches.append(parts[0])
    return matches


def _yara_scan_memory(pid, rules_path=None, timeout=60,
                     core_dir="/tmp"):
    """Dump process memory with lldb and scan the core with yara.

    Returns a dict: {success, matches, core_size, error}.

    Requires either root or a task_for_pid entitlement; silently returns
    {'success': False, 'error': '...'} on failure.
    """
    rules = rules_path or _DEFAULT_YARA_RULES_PATH
    if not os.path.exists(rules):
        return {"success": False,
                "error": f"no yara rules file at {rules} — create one or set rules_path"}
    core_path = os.path.join(core_dir, f"mac-tui-procmon.core.{pid}")
    lldb_script = (
        f"process save-core {core_path}\n"
        "detach\n"
        "quit\n"
    )
    rc, out, err = _run_cmd_short(
        ["lldb", "-p", str(pid), "--batch",
         "-o", f"process save-core {core_path}",
         "-o", "detach",
         "-o", "quit"],
        timeout=timeout,
    )
    if rc is None or not os.path.exists(core_path):
        msg = (err.strip() or out.strip() or "lldb failed")[:200]
        try:
            if os.path.exists(core_path):
                os.unlink(core_path)
        except OSError:
            pass
        return {"success": False, "error": msg}
    core_size = os.path.getsize(core_path)
    try:
        matches = _yara_scan_file(core_path, rules_path=rules, timeout=timeout)
    finally:
        try:
            os.unlink(core_path)
        except OSError:
            pass
    return {
        "success": True,
        "matches": matches,
        "core_size": core_size,
        "core_path": core_path,
        "error": "",
    }


# ── Formatting ───────────────────────────────────────────────────────────

def short_cwd(path):
    if path.startswith(HOME):
        path = "~" + path[len(HOME):]
    return path


def fmt_mem(kb):
    if kb < 1024:
        return f"{kb} KB"
    elif kb < 1024 * 1024:
        return f"{kb / 1024:.1f} MB"
    else:
        return f"{kb / 1048576:.2f} GB"


def fmt_bytes(b):
    if b < 1024:
        return f"{b} B"
    elif b < 1024 * 1024:
        return f"{b / 1024:.1f} KB"
    elif b < 1024 * 1024 * 1024:
        return f"{b / 1048576:.1f} MB"
    else:
        return f"{b / 1073741824:.2f} GB"


def fmt_rate(bps):
    if bps < 0:
        return "-"
    if bps < 1024:
        return f"{bps:.0f} B/s"
    elif bps < 1024 * 1024:
        return f"{bps / 1024:.1f} KB/s"
    else:
        return f"{bps / 1048576:.1f} MB/s"


_SPARK_BLOCKS = "▁▂▃▄▅▆▇█"


def _sparkline(values, width=24):
    """Render an iterable of numeric samples as Unicode-block bars.

    Returns a string of length ≤ `width`. Empty input returns an empty
    string. Values are normalized over [0, max(values)]; an all-zero or
    all-equal series renders as the lowest block to make 'something
    here' visible without misleading magnitude.
    """
    try:
        nums = [float(v) for v in values if v is not None]
    except (TypeError, ValueError):
        return ""
    if not nums:
        return ""
    if width <= 0:
        return ""
    # Truncate to the right-most `width` samples (most recent).
    if len(nums) > width:
        nums = nums[-width:]
    peak = max(nums)
    if peak <= 0:
        return _SPARK_BLOCKS[0] * len(nums)
    out = []
    for v in nums:
        if v < 0:
            v = 0.0
        idx = int((v / peak) * (len(_SPARK_BLOCKS) - 1))
        idx = max(0, min(len(_SPARK_BLOCKS) - 1, idx))
        out.append(_SPARK_BLOCKS[idx])
    return "".join(out)


import socket as _socket
import concurrent.futures as _futures

_rdns_cache = {}  # ip -> hostname or None
_rdns_executor = _futures.ThreadPoolExecutor(max_workers=2, thread_name_prefix="rdns")


def _resolve_ip(ip):
    """Reverse-DNS lookup with cache. Returns hostname or original IP."""
    if ip in _rdns_cache:
        cached = _rdns_cache[ip]
        return cached if cached else ip
    # Skip local/private/wildcard
    if ip.startswith(("127.", "10.", "192.168.", "172.16.", "172.17.",
                      "172.18.", "172.19.", "172.2", "172.30.", "172.31.",
                      "169.254.", "0.", "*", ":")) or ip == "localhost":
        _rdns_cache[ip] = None
        return ip
    try:
        hostname = _rdns_executor.submit(_socket.gethostbyaddr, ip).result(timeout=3)[0]
        _rdns_cache[ip] = hostname
        return hostname
    except Exception:
        _rdns_cache[ip] = None
        return ip


def _resolve_addr(addr):
    """Resolve the IP part of 'ip:port', return 'hostname:port'."""
    if ":" not in addr:
        return addr
    # Handle IPv6 [::1]:port
    if addr.startswith("["):
        return addr
    ip, port = addr.rsplit(":", 1)
    resolved = _resolve_ip(ip)
    return f"{resolved}:{port}"


import json as _json
import urllib.request as _urllib

_geoip_cache = {}  # ip -> "City/CC" or ""
_org_cache = {}    # ip -> "OrgName" or ""

_LOCAL_PREFIXES = ("127.", "10.", "192.168.", "172.16.", "172.17.",
                   "172.18.", "172.19.", "172.2", "172.30.", "172.31.",
                   "169.254.", "0.", "*", ":")


def _is_local_ip(ip):
    return ip.startswith(_LOCAL_PREFIXES) or ip in ("localhost", "")


def _lookup_geoip(ips):
    """Batch GeoIP lookup via ip-api.com. Populates _geoip_cache."""
    uncached = [ip for ip in set(ips) if ip not in _geoip_cache and not _is_local_ip(ip)]
    if not uncached:
        return
    # Batch API: POST JSON array, max 100 per request
    for i in range(0, len(uncached), 100):
        batch = uncached[i:i + 100]
        payload = _json.dumps([{"query": ip, "fields": "status,city,countryCode,org"}
                               for ip in batch]).encode()
        try:
            req = _urllib.Request("http://ip-api.com/batch",
                                 data=payload,
                                 headers={"Content-Type": "application/json"})
            with _urllib.urlopen(req, timeout=5) as resp:
                results = _json.loads(resp.read())
            for ip, result in zip(batch, results):
                if result.get("status") == "success":
                    city = result.get("city", "")
                    cc = result.get("countryCode", "")
                    _geoip_cache[ip] = f"{city}/{cc}" if city else cc
                    _org_cache[ip] = result.get("org", "")
                else:
                    _geoip_cache[ip] = ""
                    _org_cache[ip] = ""
        except Exception:
            for ip in batch:
                _geoip_cache.setdefault(ip, "")
                _org_cache.setdefault(ip, "")


def _get_geo(ip):
    """Get cached geo string for an IP, or empty string."""
    if _is_local_ip(ip):
        return ""
    return _geoip_cache.get(ip, "")


def _get_org(ip):
    """Get cached org name for an IP, or empty string."""
    if _is_local_ip(ip):
        return ""
    return _org_cache.get(ip, "")


_ORG_ABBREVS = {
    "amazon": "AWS", "aws": "AWS",
    "google": "Google", "alphabet": "Google",
    "microsoft": "Microsoft", "azure": "Azure",
    "cloudflare": "Cloudflare",
    "akamai": "Akamai",
    "fastly": "Fastly",
    "apple": "Apple",
    "meta": "Meta", "facebook": "Meta",
    "netflix": "Netflix",
    "digitalocean": "DigitalOcean",
    "linode": "Linode",
    "oracle": "Oracle",
    "ibm": "IBM", "softlayer": "IBM",
    "anthropic": "Anthropic",
    "openai": "OpenAI",
    "hetzner": "Hetzner",
    "ovh": "OVH",
    "vultr": "Vultr",
    "github": "GitHub",
    "slack": "Slack",
    "salesforce": "Salesforce",
    "dropbox": "Dropbox",
    "twitter": "X", "x corp": "X",
    "telegram": "Telegram",
    "discord": "Discord",
    "spotify": "Spotify",
    "zoom": "Zoom",
    "datadog": "Datadog",
    "twitch": "Twitch",
    "stripe": "Stripe",
    "shopify": "Shopify",
    "uber": "Uber",
    "linkedin": "LinkedIn",
    "adobe": "Adobe",
    "samsung": "Samsung",
    "sony": "Sony",
    "valve": "Valve",
    "riot": "Riot",
    "tencent": "Tencent",
    "alibaba": "Alibaba", "aliyun": "Alibaba",
    "baidu": "Baidu",
    "huawei": "Huawei",
}


def _short_org(org):
    """Abbreviate an org name like 'AWS Global Accelerator (GLOBAL)' to 'AWS'."""
    if not org:
        return ""
    lower = org.lower()
    for keyword, short in _ORG_ABBREVS.items():
        if keyword in lower:
            return short
    # Fallback: first word, strip Inc/LLC/Ltd etc.
    first = org.split(",")[0].split("(")[0].strip()
    for suffix in (" Inc", " LLC", " Ltd", " Corp", " Co.", " GmbH", " S.A."):
        if first.endswith(suffix):
            first = first[:-len(suffix)].strip()
    return first


_VENDOR_PATHS = {
    "/System/": "Apple",
    "/usr/libexec/": "Apple",
    "/usr/sbin/": "Apple",
    "/usr/bin/": "Apple",
    "/Library/Apple/": "Apple",
    "/Applications/Google Chrome": "Google",
    "/Applications/Firefox": "Mozilla",
    "/Applications/Safari": "Apple",
    "/Applications/Signal": "Signal",
    "/Applications/Slack": "Slack",
    "/Applications/Docker": "Docker",
    "/Applications/Microsoft": "Microsoft",
    "/Applications/Visual Studio Code": "Microsoft",
    "/Applications/Xcode": "Apple",
    "/Applications/iTerm": "iTerm",
    "/Applications/Spotify": "Spotify",
    "/Applications/Discord": "Discord",
    "/Applications/Zoom": "Zoom",
    "/Applications/1Password": "1Password",
}


_VENDOR_RDNS = {
    "com.apple.": "Apple",
    "com.microsoft.": "Microsoft",
    "com.google.": "Google",
    "com.docker.": "Docker",
    "org.mozilla.": "Mozilla",
}


def _get_vendor(command):
    """Extract vendor name from command path, or 'No Vendor'."""
    for prefix, v in _VENDOR_PATHS.items():
        if command.startswith(prefix):
            return v
    # Match reverse-DNS names anywhere in the command
    # (e.g. "com.apple.weather.menu" or "Contents/Library/.../com.microsoft.teams2.agent")
    for prefix, v in _VENDOR_RDNS.items():
        if prefix in command:
            return v
    return "No Vendor"


def _short_command(command):
    """Shorten a command path to just the binary name with vendor tag."""
    vendor = ""
    for prefix, v in _VENDOR_PATHS.items():
        if command.startswith(prefix):
            vendor = v
            break

    # Extract the short name: just the binary name
    if command.startswith("/"):
        app_idx = command.rfind(".app/")
        if app_idx != -1:
            # "/Applications/Firefox.app/.../plugin-container.app/..." → "plugin-container"
            app_path = command[:app_idx]
            name = app_path.rsplit("/", 1)[-1]
        else:
            parts = command.split()
            name = parts[0].rsplit("/", 1)[-1]
    else:
        parts = command.split()
        name = parts[0].rsplit("/", 1)[-1]

    # Check reverse-DNS patterns anywhere in command for vendor tag
    if not vendor:
        for prefix, v in _VENDOR_RDNS.items():
            if prefix in command:
                vendor = v
                break

    if vendor:
        return f"{name} [{vendor}]"
    return name


_PORT_SERVICES = {
    20: "FTP-D", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
    123: "NTP", 135: "RPC", 139: "NetBIOS", 143: "IMAP", 161: "SNMP",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "Syslog",
    587: "SMTP", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 2049: "NFS", 3306: "MySQL",
    3389: "RDP", 5432: "PgSQL", 5672: "AMQP", 5900: "VNC",
    6379: "Redis", 6443: "K8s", 8080: "HTTP", 8443: "HTTPS",
    9090: "Prometheus", 9200: "Elastic", 11211: "Memcache", 27017: "MongoDB",
}


def _extract_port(addr):
    """Extract port number from 'ip:port' or '[::1]:port' or '*:port'."""
    try:
        return int(addr.rsplit(":", 1)[-1])
    except (ValueError, IndexError):
        return 0


def _port_service(port):
    return _PORT_SERVICES.get(port, "")


# ── Tree Building ────────────────────────────────────────────────────────

#: PIDs that never appear in the tree — their children surface as top-level
#: roots instead. launchd (PID 1) is the parent of most of the system when
#: mac-tui-procmon runs as root, so leaving it visible collapses everything under a
#: single branch. PID 0 is the kernel task and is already excluded elsewhere.
_PHANTOM_TREE_PARENTS = {1}


def build_tree(matched, all_procs, sort_key, reverse=True):
    matched_pids = {p["pid"] for p in matched}
    parent_of = {p["pid"]: p["ppid"] for p in all_procs}
    children_of = {}
    for p in all_procs:
        children_of.setdefault(p["ppid"], []).append(p)

    def has_matched_ancestor(pid):
        seen = set()
        cur = parent_of.get(pid)
        while cur and cur not in seen:
            if cur in matched_pids:
                return True
            seen.add(cur)
            cur = parent_of.get(cur)
        return False

    roots = [p for p in matched if not has_matched_ancestor(p["pid"])]

    def build_node(proc, depth=0):
        node = {**proc, "depth": depth, "children": []}
        if depth < MAX_TREE_DEPTH:
            for child in children_of.get(proc["pid"], []):
                node["children"].append(build_node(child, depth + 1))
        # Compute subtree aggregates (children already aggregated via recursion)
        node["agg_rss_kb"] = node["rss_kb"] + sum(c["agg_rss_kb"] for c in node["children"])
        node["agg_cpu"] = node["cpu"] + sum(c["agg_cpu"] for c in node["children"])
        node["agg_cpu_ticks"] = node["cpu_ticks"] + sum(c["agg_cpu_ticks"] for c in node["children"])
        node["agg_threads"] = node["threads"] + sum(c["agg_threads"] for c in node["children"])
        node["agg_forks"] = len(node["children"]) + sum(c["agg_forks"] for c in node["children"])
        node["agg_net_in"] = max(node.get("net_in", 0), 0) + sum(c["agg_net_in"] for c in node["children"])
        node["agg_net_out"] = max(node.get("net_out", 0), 0) + sum(c["agg_net_out"] for c in node["children"])
        node["agg_bytes_in"] = node.get("bytes_in", 0) + sum(c.get("agg_bytes_in", 0) for c in node["children"])
        node["agg_bytes_out"] = node.get("bytes_out", 0) + sum(c.get("agg_bytes_out", 0) for c in node["children"])
        # Group children with the same short name
        node["children"] = _group_siblings(node["children"])
        # Sort children by aggregate values
        node["children"].sort(key=sort_key, reverse=reverse)
        return node

    return sorted([build_node(r) for r in roots], key=sort_key, reverse=reverse)


def build_vendor_tree(matched, all_procs, sort_key, reverse=True):
    """Build a tree grouped by vendor at the top level.

    Each vendor becomes a synthetic root node whose children are the normal
    process trees for that vendor's processes.  Sorting applies both at the
    vendor level (by aggregate) and within each vendor group.
    """
    from collections import OrderedDict

    # First build the normal tree so we get proper parent-child relationships
    normal_tree = build_tree(matched, all_procs, sort_key, reverse)

    # Group root nodes by vendor
    vendor_groups = OrderedDict()
    for node in normal_tree:
        vendor = _get_vendor(node["command"])
        vendor_groups.setdefault(vendor, []).append(node)

    result = []
    for vendor, nodes in vendor_groups.items():
        if len(nodes) == 1 and vendor == "No Vendor":
            # Don't wrap single unvendored processes
            result.append(nodes[0])
            continue
        # Create synthetic vendor root
        leader = nodes[0]
        vnode = {**leader}
        vnode["command"] = vendor
        vnode["pid"] = -abs(hash(vendor)) % 1000000 - 1  # stable synthetic PID per vendor
        vnode["ppid"] = 0
        vnode["depth"] = 0
        vnode["children"] = nodes
        vnode["vendor_group"] = True
        # Aggregate across all member trees
        vnode["rss_kb"] = sum(n.get("rss_kb", 0) for n in nodes)
        vnode["cpu"] = sum(n.get("cpu", 0) for n in nodes)
        vnode["cpu_ticks"] = sum(n.get("cpu_ticks", 0) for n in nodes)
        vnode["threads"] = sum(n.get("threads", 0) for n in nodes)
        vnode["agg_rss_kb"] = sum(n.get("agg_rss_kb", n.get("rss_kb", 0)) for n in nodes)
        vnode["agg_cpu"] = sum(n.get("agg_cpu", n.get("cpu", 0)) for n in nodes)
        vnode["agg_cpu_ticks"] = sum(n.get("agg_cpu_ticks", 0) for n in nodes)
        vnode["agg_threads"] = sum(n.get("agg_threads", n.get("threads", 0)) for n in nodes)
        vnode["agg_forks"] = len(nodes) + sum(n.get("agg_forks", 0) for n in nodes)
        vnode["agg_net_in"] = sum(n.get("agg_net_in", 0) for n in nodes)
        vnode["agg_net_out"] = sum(n.get("agg_net_out", 0) for n in nodes)
        vnode["agg_bytes_in"] = sum(n.get("agg_bytes_in", 0) for n in nodes)
        vnode["agg_bytes_out"] = sum(n.get("agg_bytes_out", 0) for n in nodes)
        for key in ("net_in", "net_out", "bytes_in", "bytes_out"):
            vnode[key] = sum(n.get(key, 0) for n in nodes)
        vnode["sibling_count"] = len(nodes)
        result.append(vnode)

    return sorted(result, key=sort_key, reverse=reverse)


def _group_siblings(children):
    """Group sibling nodes that share the same short command name into a
    synthetic parent with the original members as its children."""
    if len(children) <= 1:
        return children
    from collections import OrderedDict
    groups = OrderedDict()
    for child in children:
        name = _short_command(child["command"])
        groups.setdefault(name, []).append(child)

    result = []
    for name, members in groups.items():
        if len(members) == 1:
            result.append(members[0])
            continue
        # Create a synthetic parent; the real processes become its children
        leader = members[0]
        group = {**leader}
        group["command"] = leader["command"]
        group["pid"] = leader["pid"]  # use first PID for expand/collapse
        group["sibling_count"] = len(members)
        group["children"] = members    # original members are now children
        # Recompute aggregates across all members
        group["rss_kb"] = sum(m["rss_kb"] for m in members)
        group["cpu"] = sum(m["cpu"] for m in members)
        group["cpu_ticks"] = sum(m["cpu_ticks"] for m in members)
        group["threads"] = sum(m["threads"] for m in members)
        group["agg_rss_kb"] = sum(m.get("agg_rss_kb", m["rss_kb"]) for m in members)
        group["agg_cpu"] = sum(m.get("agg_cpu", m["cpu"]) for m in members)
        group["agg_cpu_ticks"] = sum(m.get("agg_cpu_ticks", m["cpu_ticks"]) for m in members)
        group["agg_threads"] = sum(m.get("agg_threads", m["threads"]) for m in members)
        group["agg_forks"] = len(members) + sum(m.get("agg_forks", 0) for m in members)
        group["agg_net_in"] = sum(m.get("agg_net_in", 0) for m in members)
        group["agg_net_out"] = sum(m.get("agg_net_out", 0) for m in members)
        group["agg_bytes_in"] = sum(m.get("agg_bytes_in", 0) for m in members)
        group["agg_bytes_out"] = sum(m.get("agg_bytes_out", 0) for m in members)
        for key in ("net_in", "net_out", "bytes_in", "bytes_out"):
            group[key] = sum(m.get(key, 0) for m in members)
        result.append(group)
    return result


def flatten_tree(tree, expanded=None):
    if expanded is None:
        expanded = set()
    rows = []

    def walk(node, prefix="", is_last=True, is_root=True):
        if is_root:
            display_prefix = ""
        else:
            display_prefix = prefix + ("\u2514\u2500 " if is_last else "\u251c\u2500 ")

        has_children = len(node["children"]) > 0
        is_expanded = node["pid"] in expanded

        row = {k: v for k, v in node.items() if k != "children"}
        row["prefix"] = display_prefix
        row["forks"] = len(node["children"])
        row["has_children"] = has_children
        row["is_collapsed"] = has_children and not is_expanded
        rows.append(row)

        # Only show children if explicitly expanded
        if not is_expanded:
            return

        children = node["children"]
        child_prefix = prefix + ("   " if is_last else "\u2502  ") if not is_root else ""
        for i, child in enumerate(children):
            walk(child, child_prefix, i == len(children) - 1, False)

    for node in tree:
        walk(node)
    return rows


#
# Each audit returns a list of finding dicts:
#   {"severity": "CRITICAL"|"HIGH"|"MEDIUM"|"INFO"|"OK",
#    "message":  str,
#    "evidence": str,   # optional, multi-line context shown under the finding
#    "action":   None | {"type": <remediation>, ...}}
#
_SUSPICIOUS_RUNTIME_PATH_PREFIXES = (
    "/tmp/",
    "/private/tmp/",
    "/var/tmp/",
    "/private/var/tmp/",
    "/var/folders/",
    "/private/var/folders/",
    "/Users/Shared/",
)


def _severity_max(current, new):
    """Return the more severe of two severity labels."""
    rank = {"OK": 0, "INFO": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    if current is None:
        return new
    return current if rank.get(current, -1) >= rank.get(new, -1) else new


def _audit_injection_antidebug_pid(pid, osquery_rows=None,
                                   taskexplorer_enabled=True,
                                   taskexplorer_timeout=12,
                                   runtime_mapping_enabled=True,
                                   vmmap_timeout=8):
    """Inspect one live process for injection / anti-debug signals."""
    osq = (osquery_rows or {}).get(pid) or {}
    exe = _get_proc_path(pid)
    if not exe or not exe.startswith("/"):
        rc, out, _ = _run_cmd_short(
            ["ps", "-p", str(pid), "-o", "command="],
            timeout=5,
        )
        if rc == 0 and out.strip():
            exe = out.strip().split()[0]
    if not exe or not exe.startswith("/"):
        for raw in (osq.get("path"), osq.get("cmdline")):
            candidate = str(raw or "").strip()
            if not candidate:
                continue
            candidate = candidate.split()[0]
            if candidate.startswith("/"):
                exe = candidate
                break
    if not exe or not exe.startswith("/"):
        return None

    exists = os.path.exists(exe)
    cs = _codesign_structured(exe) if exists else {}
    apple = _is_apple_signed(exe, cs)
    team = cs.get("team_id", "") if cs else ""
    ent_set = _parse_entitlements_xml(cs.get("entitlements_xml", "")) if cs else set()

    try:
        env = _get_proc_env(pid)
    except Exception:
        env = {}
    dyld_env = {k: v for k, v in env.items() if k.startswith("DYLD_")}

    # Skip stock Apple binaries unless something abnormal is already visible.
    if apple and not dyld_env and str(osq.get("on_disk", "1")) not in ("0", "false"):
        return None

    issues = []
    evidence = [
        f"exe: {exe}",
        f"team: {team or '(none)'}",
        f"apple_signed: {apple}",
    ]
    severity = None

    if not exists:
        issues.append("executable missing on disk")
        severity = _severity_max(severity, "CRITICAL")
    if str(osq.get("on_disk", "1")) in ("0", "false"):
        issues.append("osquery reports on_disk=0")
        severity = _severity_max(severity, "HIGH")
        evidence.append(f"osquery: path={osq.get('path') or exe} on_disk={osq.get('on_disk')}")

    for prefix in _SUSPICIOUS_RUNTIME_PATH_PREFIXES:
        if exe.startswith(prefix):
            issues.append(f"running from suspicious path ({prefix.rstrip('/')})")
            severity = _severity_max(severity, "HIGH")
            break
    if "/AppTranslocation/" in exe:
        issues.append("running under AppTranslocation")
        severity = _severity_max(severity, "HIGH")

    if dyld_env:
        issues.append("live DYLD injection environment")
        evidence.extend(f"{k}={v}" for k, v in sorted(dyld_env.items()))
        severity = _severity_max(
            severity,
            "CRITICAL" if (
                "com.apple.security.cs.disable-library-validation" in ent_set
                or "com.apple.security.cs.allow-dyld-environment-variables" in ent_set
            ) else "HIGH",
        )

    dangerous_ents = [ent for ent in _DANGEROUS_ENTITLEMENTS if ent in ent_set]
    if dangerous_ents and not apple:
        short = [ent.rsplit(".", 1)[-1] for ent in dangerous_ents[:4]]
        issues.append("dangerous entitlements: " + ", ".join(short))
        for ent in dangerous_ents[:6]:
            evidence.append(f"entitlement: {ent} — {_DANGEROUS_ENTITLEMENTS[ent]}")
        severity = _severity_max(
            severity,
            "HIGH" if any(
                ent in dangerous_ents for ent in (
                    "com.apple.security.cs.disable-library-validation",
                    "com.apple.security.cs.allow-dyld-environment-variables",
                    "com.apple.security.cs.allow-unsigned-executable-memory",
                )
            ) else "MEDIUM",
        )

    binary_hits = []
    import_hits = []
    if not apple and exists:
        binary_hits = _scan_binary_markers(exe)
        import_hits = _scan_import_markers(exe)
    anti_hits = [hit for hit in binary_hits + import_hits
                 if "anti-debug" in hit.lower() or "ptrace" in hit.lower()
                 or "exception" in hit.lower() or "sysctl" in hit.lower()]
    inject_hits = [hit for hit in binary_hits if hit not in anti_hits]
    if anti_hits:
        issues.append("anti-debug markers in binary")
        evidence.append("anti_debug: " + ", ".join(anti_hits[:6]))
        severity = _severity_max(
            severity,
            "HIGH" if any(exe.startswith(pfx) for pfx in _SUSPICIOUS_RUNTIME_PATH_PREFIXES)
            else "MEDIUM",
        )
    if inject_hits:
        issues.append("injection framework markers in binary")
        evidence.append("injection_markers: " + ", ".join(inject_hits[:6]))
        severity = _severity_max(severity, "HIGH")

    vmmap = {"signals": [], "error": "", "raw": ""}
    if runtime_mapping_enabled and (dyld_env or anti_hits or inject_hits
                                    or not apple or not exists):
        vmmap = _scan_vmmap_signals(pid, timeout=vmmap_timeout)
    if vmmap.get("signals"):
        issues.append("suspicious memory mappings")
        evidence.extend(f"vmmap: {line}" for line in vmmap["signals"][:6])
        if any("User-writable mapped image" in line or "RWX" in line
               for line in vmmap["signals"]):
            severity = _severity_max(severity, "HIGH")
        else:
            severity = _severity_max(severity, "MEDIUM")

    taskexplorer = {"signals": [], "error": "", "paths": []}
    if taskexplorer_enabled and (dyld_env or anti_hits or inject_hits or not exists):
        taskexplorer = _taskexplorer_pid_snapshot(
            pid, timeout=taskexplorer_timeout)
    if taskexplorer.get("signals"):
        issues.append("TaskExplorer corroborates suspicious mappings")
        evidence.extend(f"taskexplorer: {line}"
                        for line in taskexplorer["signals"][:6])
        severity = _severity_max(severity, "HIGH")

    if not issues:
        return None

    # Deduplicate while preserving order.
    compact_issues = []
    seen = set()
    for issue in issues:
        if issue not in seen:
            compact_issues.append(issue)
            seen.add(issue)

    return {
        "severity": severity or "MEDIUM",
        "message": (f"PID {pid}: {os.path.basename(exe)} — "
                    f"{'; '.join(compact_issues[:3])}"),
        "evidence": "\n".join(evidence[:18]),
        "action": (None if apple else {
            "type": "kill_process",
            "pid": pid,
            "exe": exe,
        }),
    }




# ── Curses UI ────────────────────────────────────────────────────────────

class ProcMonUI:
    def __init__(self, stdscr, name, interval, skip_fd):
        self.stdscr = stdscr
        self.name = name
        self.patterns = [p.strip().lower() for p in name.split(",") if p.strip()] if name else []
        self.exclude_name = ""
        self.exclude_patterns = []
        self.interval = interval
        self.skip_fd = skip_fd
        self.selected = 0
        self.scroll_offset = 0
        self.rows = []
        self.matched_count = 0
        self.prev_net = {}
        self.prev_time = None
        self.net_rates = {}
        # Per-PID cumulative disk I/O bytes from proc_pid_rusage. Sampled in
        # collect_data each refresh; rates derived by diffing against the
        # prior snapshot, just like net rates.
        self._prev_disk_io = {}    # pid -> (bytes_read, bytes_written)
        self._disk_io_rates = {}   # pid -> (B/s read, B/s written)
        # Per-PID metric history for sparklines. Each pid maps to a dict
        # of {metric_name: deque(maxlen=60)}. Populated each refresh in
        # collect_data; pids that haven't been seen for
        # _metric_history_max_age seconds are evicted so dead-process
        # rings don't accumulate forever.
        self._metric_history = {}
        self._metric_history_lock = threading.Lock()
        self._metric_history_max_age = 300  # seconds
        self._metric_history_seen = {}   # pid -> last-seen monotonic time
        self._metric_history_max = 60    # samples per metric per pid
        self.sort_mode = SORT_MEM
        self._sort_inverted = False
        self._dynamic_sort = False  # threshold-exceeding processes bubble to top
        self._vendor_grouped = False  # group processes by vendor at top level
        self._prev_cpu = {}  # pid -> (cpu_ns, monotonic_time)
        self._collapsed = set()  # PIDs whose children are hidden
        self._expanded = set()  # PIDs explicitly expanded by user
        self._detail_focus = False  # True when detail box has keyboard focus
        self._net_mode = False     # True when showing network connections
        self._net_entries = []     # Structured connection entries
        self._net_selected = 0     # Selected line in network detail
        self._net_scroll = 0       # Scroll offset in network detail
        self._net_pid = None       # PID the net connections are for
        self._net_bytes = {}       # (pid, fd) -> cumulative bytes
        self._total_mem_kb = _get_total_memory_kb()
        # Alert thresholds (0 = disabled)
        self._alert_thresholds = {
            "cpu": 0.0,      # CPU %
            "mem_mb": 0.0,   # MEM in MB
            "threads": 0,    # Thread count
            "fds": 0,        # File descriptors
            "forks": 0,      # Fork count
            "net_in": 0.0,   # ↓ In (KB/s)
            "net_out": 0.0,  # ↑ Out (KB/s)
            "recv_mb": 0.0,  # ↓ Recv (MB)
            "sent_mb": 0.0,  # ↑ Sent (MB)
        }
        self._alert_last_sound = 0.0  # monotonic time of last alert sound
        self._alert_interval = 60     # seconds between repeated alerts
        self._alert_max_count = 5     # max number of alert sounds (0 = unlimited)
        self._alert_count = 0         # alerts fired so far
        # Background network fetch state
        self._net_worker = None      # threading.Thread for async net fetch
        self._net_pending = None     # result list from background fetch (or "loading" sentinel)
        self._net_loading = False    # True while a background fetch is in flight
        # Inspect mode state
        self._inspect_mode = False
        self._inspect_pid = None
        self._inspect_cmd = ""
        self._inspect_lines = []        # rendered output lines
        self._inspect_scroll = 0
        self._inspect_worker = None     # threading.Thread
        self._inspect_pending = None    # (status, lines) tuple from background
        self._inspect_loading = False
        self._inspect_phase = ""        # "collecting" | "analyzing" | ""
        # Hidden process detection state (passive header badge only)
        self._hidden_pids = set()
        self._hidden_alert_count = 0
        self._last_hidden_check = 0.0
        # Debug log — append-only ring buffer that every interesting
        # subprocess / verification / action writes into. Accessible via
        # the `L` key from any view so the user can see *exactly* what
        # happened when something didn't work.
        self._log_messages = []      # list of (timestamp, category, text)
        self._log_lock = threading.Lock()
        self._log_max = 500
        self._log_mode = False
        self._log_scroll = 0
        # Universal "Ask Claude" chat overlay — layered on top of any other
        # mode so Esc returns to whatever the user was looking at.
        self._chat_mode = False
        self._chat_messages = []       # list of {"role": "user"|"assistant", "content": str}
        self._chat_input = ""
        self._chat_cursor = 0
        self._chat_scroll = 0
        self._chat_loading = False
        self._chat_worker = None
        self._chat_pending = None      # response text from the background thread
        self._chat_status = None       # in-flight status line ("[claude thinking…]", "[trying with codex…]")
        self._chat_context_label = ""  # shown in the chat title
        self._chat_context_text = ""   # full context string fed into the prompt
        # LLM-generated executive summaries rendered above each finding list.
        # Stored per-view so switching modes doesn't lose context. The *_pending
        # slot is written by the background worker and consumed by the poll
        # helper; *_loading drives a "thinking…" indicator in the UI.
        self._llm_summary = {
            "audit": None,
            "inspect": None, "events": None,
        }
        self._llm_summary_pending = {
            "audit": None,
            "inspect": None, "events": None,
        }
        self._llm_summary_loading = {
            "audit": False,
            "inspect": False, "events": False,
        }
        self._llm_summary_worker = {
            "audit": None,
            "inspect": None, "events": None,
        }
        # Structured-findings panel (used by Deep Process Triage)
        self._audit_mode = False
        self._audit_type = None           # currently only "process_triage"
        self._audit_lines = []
        self._audit_scroll = 0
        self._audit_worker = None
        self._audit_pending = None
        self._audit_loading = False
        self._audit_progress_lines = []
        self._audit_progress_lock = threading.Lock()
        self._audit_findings_structured = []
        self._audit_line_for_finding = []
        self._audit_cursor = 0
        self._audit_action_result = None
        self._audit_context_pid = None
        self._audit_context_cmd = ""
        self._audit_title_override = ""
        # Security timeline state
        self._events_mode = False
        self._events = []  # list of event dicts: {ts, kind, pid, ppid, cmd, extra}
        self._events_scroll = 0
        self._events_worker = None
        self._events_proc = None  # subprocess.Popen handle for the event source
        self._events_cancel = False
        self._events_source = ""  # "eslogger" | "dtrace" | "praudit" | ""
        self._events_filter = ""
        self._events_lock = threading.Lock()
        self._events_max = 500  # ring buffer cap
        # Two-stage exit: first Esc stops the stream and triggers an LLM
        # summary of the captured events; a second Esc actually closes.
        self._events_awaiting_summary = False
        # ── GPU / Metal per-process utilization ───────────────────────
        # `powermetrics --samplers tasks --show-process-gpu` exposes
        # per-PID gputime_ms_per_s in its JSON output, but it requires
        # root. We probe lazily — _gpu_supported becomes True only if we
        # see root + a working `powermetrics` binary. Otherwise we leave
        # it disabled and skip rendering the GPU% column entirely.
        self._gpu_supported = False
        self._gpu_supported_probed = False
        self._gpu_samples = {}        # pid -> gpu_pct (0..100, None=unknown)
        self._gpu_samples_lock = threading.Lock()
        self._gpu_worker = None       # threading.Thread
        self._gpu_pending = None      # latest sample dict from worker
        self._gpu_loading = False
        self._gpu_status = ""         # "" | "needs root" | "unsupported"
        self._gpu_last_sample_ts = 0.0
        self._gpu_sample_interval = 5.0  # seconds between powermetrics runs

        # ── Unified Logging per-process stream ────────────────────────
        # Wraps `log stream --process <pid>` so the user can watch the
        # native macOS unified-log feed for a single process. No sudo
        # required for most info-level entries; system-private payloads
        # may render as <private> without root.
        self._unified_log_mode = False
        self._unified_log_pid = None
        self._unified_log_cmd = ""
        self._unified_log_lines = collections.deque(maxlen=2000)
        self._unified_log_lock = threading.Lock()
        self._unified_log_proc = None
        self._unified_log_worker = None
        self._unified_log_loading = False
        self._unified_log_cancel = False
        self._unified_log_scroll = 0
        self._unified_log_max = 2000

        # ── Traffic Inspector (experimental mitmproxy wrapper) ────────
        # MITM proxy mode: launches `mitmdump` in a subprocess with a shim
        # script that prints one JSON line per completed flow. A reader
        # thread parses those lines into self._traffic_flows. Pre-TLS
        # inspection works for any app that respects the system proxy and
        # trusts the mitmproxy CA; hardened-runtime + TLS-pinned apps
        # bypass us. Limitations are surfaced in the UI.
        self._traffic_mode = False
        self._traffic_proc = None
        self._traffic_flows = []
        self._traffic_flows_lock = threading.Lock()
        self._traffic_flows_max = 500
        self._traffic_scroll = 0
        self._traffic_reader_thread = None
        self._traffic_port = 8080
        self._traffic_loading = False
        self._traffic_error = ""
        self._traffic_shim_path = ""
        # ── Feature 1: Process Event Ripples ─────────────────────────
        # When a PID's CPU% or net rate spikes between two refresh ticks
        # (delta exceeds a configured threshold), its row briefly pulses
        # with a highlight color. Each entry is (color_pair_id, frames_remaining).
        self._row_pulses = {}
        self._pulse_thresholds = {
            "cpu_delta": 20.0,      # CPU% absolute delta
            "net_delta_mbps": 1.0,  # net B/s -> MB/s threshold
            "io_delta_mbps": 5.0,   # disk B/s -> MB/s threshold
        }
        self._pulse_frames = 4
        # Snapshot of last-tick metrics for pulse delta computation. Keyed
        # by pid so transient pids fall out of the dict naturally.
        self._pulse_prev = {}  # pid -> {"cpu", "net", "io"}
        # ── Feature 4: Three-Model Consensus Race ────────────────────
        # While Inspect runs, claude/codex/gemini stream their analyses
        # into three side-by-side lanes. The risk bar fills 33% per
        # finished lane.
        self._consensus_lanes = {"claude": [], "codex": [], "gemini": []}
        self._consensus_lane_lock = threading.Lock()
        self._consensus_lane_done = {"claude": False, "codex": False,
                                      "gemini": False}
        self._consensus_risk_bar = 0  # percentage 0..100
        self._consensus_running = False
        self._consensus_lane_max_lines = 60
        # ── Feature 5: Attack Chain Replay ───────────────────────────
        # Persist the captured event buffer when the events stream
        # closes so the user can scrub through it later. Heuristic
        # linker tags exec-of-shell-after-curl as a "drive-by".
        self._events_persist_on_close = True
        self._replay_mode = False
        self._replay_events = []
        self._replay_cursor = 0
        self._replay_playing = False
        self._replay_speed = 1.0
        # Cached drive-by hits keyed by (parent_curl_pid, child_shell_pid)
        self._replay_driveby_pairs = set()
        # Window for considering a curl→shell sequence "drive-by"
        self._replay_driveby_window_secs = 5.0
        # ── Feature 6: Network Orbit / Constellation ────────────────
        # Renders the selected PID as a center node with each remote
        # endpoint orbiting it. Edges are colored by service. Animated
        # particles travel along edges to imply throughput.
        self._orbit_mode = False
        self._orbit_tick = 0  # increments each render so particles move
        # ── Feature 7: Process Galaxy ───────────────────────────────
        # Force-directed graph of the entire process tree. We cap node
        # count to keep the terminal readable.
        self._galaxy_mode = False
        self._galaxy_positions = {}   # pid -> (x: float, y: float)
        self._galaxy_velocity = {}    # pid -> (vx: float, vy: float)
        self._galaxy_glow = {}        # pid -> frames_remaining for fork glow
        # Expanding-ring effect on newly-spotted PIDs. Maps pid → number
        # of frames since the bubble was first seen (0..5). When the
        # counter exceeds 5, the entry is popped.
        self._galaxy_fork_rings = {}
        # Heat trails: a 3-frame ring buffer of past positions so each
        # bubble leaves a fading trail of `·` glyphs as it drifts.
        self._galaxy_trails = collections.deque(maxlen=3)
        # Heartbeat animation phase counter for tier-4+ bubbles. Cycles
        # 0..5 — the first half (0,1,2) is bold-fill, the second half
        # (3,4,5) drops the bold so the bubble pulses on a 3-frame
        # heartbeat.
        self._galaxy_pulse_phase = 0
        self._galaxy_known_pids = set()
        self._galaxy_node_cap = 80
        self._galaxy_iter_step = 0.5  # spring step length
        # Test-only TUI report capture. This is intentionally opt-in so the
        # normal user-facing UI stays unchanged. The harness uses it to export
        # the exact detail-pane buffer for post-run assertions.
        self._test_mode = os.environ.get("MAC_TUI_PROCMON_TEST_MODE", "").lower() not in (
            "", "0", "false", "no")
        self._tui_capture_dir = os.environ.get("MAC_TUI_PROCMON_CAPTURE_DIR", "").strip()
        self._tui_capture_action = os.environ.get("MAC_TUI_PROCMON_CAPTURE_ACTION", "").strip()
        self._test_start_action = os.environ.get("MAC_TUI_PROCMON_TEST_ACTION", "").strip()
        self._test_select_pid = int(os.environ.get("MAC_TUI_PROCMON_TEST_SELECT_PID", "0") or 0)
        self._test_start_action_done = False
        if self._tui_capture_dir:
            try:
                os.makedirs(self._tui_capture_dir, exist_ok=True)
            except OSError:
                self._tui_capture_dir = ""

        curses.curs_set(0)
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_GREEN, -1)
        curses.init_pair(2, curses.COLOR_BLACK, curses.COLOR_CYAN)
        curses.init_pair(3, curses.COLOR_YELLOW, -1)
        curses.init_pair(4, curses.COLOR_BLACK, curses.COLOR_WHITE)
        curses.init_pair(5, curses.COLOR_RED, -1)
        curses.init_pair(6, 208, -1)   # orange (256-color)
        curses.init_pair(7, curses.COLOR_CYAN, -1)
        curses.init_pair(8, curses.COLOR_MAGENTA, -1)
        curses.init_pair(9, 75, -1)    # steel blue (256-color)
        curses.init_pair(10, 251, -1)  # light grey
        curses.init_pair(11, 156, -1)  # light green (256-color)
        curses.init_pair(12, 203, -1)  # salmon/light red (256-color)
        curses.init_pair(13, curses.COLOR_CYAN, 236)  # dialog box: cyan on dark grey
        curses.init_pair(14, curses.COLOR_WHITE, 236)  # dialog box: white on dark grey (selected)
        stdscr.timeout(100)
        self._load_config()

    _CONFIG_PATH = os.path.expanduser("~/.mac-tui-procmon.json")

    def _load_config(self):
        """Load saved config from ~/.mac-tui-procmon.json if it exists."""
        try:
            with open(self._CONFIG_PATH) as f:
                cfg = _json.loads(f.read())
            for k, v in cfg.get("alert_thresholds", {}).items():
                if k in self._alert_thresholds:
                    self._alert_thresholds[k] = v
            self._alert_interval = cfg.get("alert_interval", self._alert_interval)
            self._alert_max_count = cfg.get("alert_max_count", self._alert_max_count)
            self._dynamic_sort = cfg.get("dynamic_sort", self._dynamic_sort)
            self._vendor_grouped = cfg.get("vendor_grouped", self._vendor_grouped)
        except (FileNotFoundError, ValueError, KeyError):
            pass

    def _save_config(self):
        """Save current config to ~/.mac-tui-procmon.json."""
        cfg = {
            "alert_thresholds": self._alert_thresholds,
            "alert_interval": self._alert_interval,
            "alert_max_count": self._alert_max_count,
            "dynamic_sort": self._dynamic_sort,
            "vendor_grouped": self._vendor_grouped,
        }
        try:
            with open(self._CONFIG_PATH, "w") as f:
                f.write(_json.dumps(cfg, indent=2))
        except OSError:
            pass

    def _test_detail_metadata(self, title):
        """Return metadata for the active detail pane when test mode is on."""
        if self._audit_mode:
            return ("audit", self._audit_type or "unknown", title,
                    self._audit_loading, self._audit_findings_structured)
        if self._inspect_mode:
            return ("forensic", "inspect", title,
                    self._inspect_loading, None)
        if self._events_mode:
            return ("forensic", "events", title, False, None)
        if self._traffic_mode:
            return ("forensic", "traffic", title, self._traffic_loading, None)
        if self._net_mode:
            return ("forensic", "network", title, self._net_loading, None)
        return ("detail", "selected_process", title, False, None)

    def _test_summary_marker(self, findings):
        """Build a stable machine-readable summary line for structured reports."""
        if findings is None:
            return None
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "INFO": 0, "OK": 0}
        actionable = 0
        for finding in findings:
            sev = finding.get("severity", "INFO")
            if sev in counts:
                counts[sev] += 1
            actionable += 1 if finding.get("action") else 0
        parts = [f"{sev.lower()}={counts[sev]}"
                 for sev in ("CRITICAL", "HIGH", "MEDIUM", "INFO", "OK")]
        parts.append(f"actionable={actionable}")
        parts.append(f"findings={len(findings)}")
        return "[SUMMARY] " + " ".join(parts)

    def _capture_enabled(self):
        """Return True when terminal-capture export is enabled."""
        return bool(getattr(self, "_tui_capture_dir", "")
                    and getattr(self, "_tui_capture_action", ""))

    def _capture_path(self, suffix=""):
        """Build the JSON capture path for the requested test artifact."""
        return os.path.join(
            getattr(self, "_tui_capture_dir", ""),
            f"{getattr(self, '_tui_capture_action', '')}{suffix}.json")

    def _decorate_test_detail_lines(self, title, lines):
        """Prefix test-only markers so the pane can be parsed deterministically."""
        if not self._capture_enabled():
            return lines
        scope, action, title, _, findings = self._test_detail_metadata(title)
        marked = [f"[REPORT] scope={scope} action={action} title={title}"]
        summary = self._test_summary_marker(findings)
        if summary:
            marked.append(summary)
        marked.append("")
        marked.extend(lines)
        return marked

    def _detail_ready_state(self):
        """Return ('ready'|'loading', ready_bool) for the active detail pane."""
        if self._audit_mode:
            ready = bool(self._audit_lines) and not self._audit_loading
        elif self._inspect_mode:
            ready = bool(self._inspect_lines) and not self._inspect_loading
        elif self._events_mode:
            ready = True
        elif self._traffic_mode:
            ready = not self._traffic_loading
        elif self._net_mode:
            ready = bool(self._net_entries) or not self._net_loading
        else:
            ready = True
        return ("ready" if ready else "loading", ready)

    def _capture_detail_snapshot(self, start_y, w, title, lines, scroll):
        """Write the current detail pane to a JSON file for TUI assertions."""
        if not self._capture_enabled():
            return
        try:
            h, _ = self.stdscr.getmaxyx()
        except Exception:
            h = 40
        inner_w = max(1, w - 4)
        inner_h = max(1, h - start_y - 3)
        wrapped = []
        line_map = []
        for orig_idx, line in enumerate(lines):
            text = line or ""
            if not text:
                wrapped.append("")
                line_map.append(orig_idx)
                continue
            while text:
                chunk = text[:inner_w]
                text = text[inner_w:]
                wrapped.append(chunk)
                line_map.append(orig_idx)
        max_scroll = max(0, len(wrapped) - inner_h)
        clamped_scroll = min(max(scroll, 0), max_scroll)
        visible = wrapped[clamped_scroll:clamped_scroll + inner_h]
        scope, action, _, loading, findings = self._test_detail_metadata(title)
        state, ready = self._detail_ready_state()
        payload = {
            "scope": scope,
            "action": action,
            "requested_action": getattr(self, "_tui_capture_action", ""),
            "title": title,
            "state": state,
            "ready": ready,
            "loading": loading,
            "raw_lines": lines,
            "wrapped_lines": wrapped,
            "visible_lines": visible,
            "scroll": clamped_scroll,
            "inner_width": inner_w,
            "inner_height": inner_h,
            "finding_count": len(findings) if findings is not None else None,
        }
        out_path = self._capture_path()
        tmp_path = out_path + ".tmp"
        try:
            with open(tmp_path, "w", encoding="utf-8") as fh:
                fh.write(_json.dumps(payload, indent=2))
            os.replace(tmp_path, out_path)
        except OSError:
            pass

    def _capture_screen_snapshot(self, surface, title="", focus_box=None):
        """Write the currently visible curses screen to JSON for TUI assertions."""
        if not self._capture_enabled():
            return
        try:
            h, w = self.stdscr.getmaxyx()
        except Exception:
            h, w = (0, 0)
        lines = []
        for row in range(max(0, h)):
            text = ""
            try:
                raw = self.stdscr.instr(row, 0, max(1, w))
            except Exception:
                raw = b""
            if isinstance(raw, bytes):
                text = raw.decode("utf-8", errors="ignore")
            elif raw is not None:
                text = str(raw)
            lines.append(text.replace("\x00", "").rstrip())
        payload = {
            "scope": "screen",
            "action": surface,
            "requested_action": getattr(self, "_tui_capture_action", ""),
            "title": title,
            "state": "ready",
            "ready": True,
            "height": h,
            "width": w,
            "visible_lines": lines,
        }
        if focus_box is not None:
            box_y, box_x, box_h, box_w = focus_box
            payload["focus_box"] = {
                "y": max(0, int(box_y)),
                "x": max(0, int(box_x)),
                "height": max(0, int(box_h)),
                "width": max(0, int(box_w)),
            }
        out_path = self._capture_path(".screen")
        tmp_path = out_path + ".tmp"
        try:
            with open(tmp_path, "w", encoding="utf-8") as fh:
                fh.write(_json.dumps(payload, indent=2))
            os.replace(tmp_path, out_path)
        except OSError:
            pass

    def _capture_chat_snapshot(self, wrapped_lines, conv_h):
        """Write the current chat overlay to a JSON file for TUI assertions."""
        if not self._capture_enabled():
            return
        total = len(wrapped_lines)
        tail_start = max(0, total - conv_h)
        start = max(0, tail_start - self._chat_scroll)
        end = start + conv_h
        visible = [text for text, _ in wrapped_lines[start:end]]
        payload = {
            "scope": "chat",
            "action": "ask_claude",
            "requested_action": getattr(self, "_tui_capture_action", ""),
            "context_label": self._chat_context_label,
            "loading": self._chat_loading,
            "ready": (not self._chat_loading)
            and any(m.get("role") == "assistant" for m in self._chat_messages),
            "state": ("loading" if self._chat_loading else "ready"),
            "messages": list(self._chat_messages),
            "input": self._chat_input,
            "visible_lines": visible,
        }
        out_path = self._capture_path(".chat")
        tmp_path = out_path + ".tmp"
        try:
            with open(tmp_path, "w", encoding="utf-8") as fh:
                fh.write(_json.dumps(payload, indent=2))
            os.replace(tmp_path, out_path)
        except OSError:
            pass

    def _maybe_run_test_action(self):
        """Auto-open a test action once data is available."""
        action = getattr(self, "_test_start_action", "")
        if (not action) or getattr(self, "_test_start_action_done", False):
            return False
        if not self.rows:
            return False
        target_pid = getattr(self, "_test_select_pid", 0) or 0
        if target_pid > 0:
            if not self._select_test_pid(target_pid):
                return False
        self._test_start_action_done = True
        if action.startswith("audit:"):
            self._toggle_audit_mode(action.split(":", 1)[1])
            return True
        if action == "inspect":
            self._toggle_inspect_mode()
        elif action == "triage":
            self._toggle_process_triage_mode()
        elif action == "events":
            self._toggle_events_mode()
        elif action == "traffic":
            self._toggle_traffic_mode()
        elif action == "network":
            self._toggle_net_mode()
        return True

    def _select_test_pid(self, target_pid):
        """Best-effort selection helper for test-start actions.

        The requested PID may be hidden under a collapsed parent in the tree,
        so expand its ancestor chain first and then try the lookup again.
        """
        for idx, row in enumerate(self.rows):
            if row.get("pid") == target_pid:
                self.selected = idx
                return True

        all_procs = self._all_procs or get_all_processes()
        by_pid = {p.get("pid"): p for p in all_procs if p.get("pid")}
        cursor = target_pid
        seen = set()
        expanded = set()
        while cursor in by_pid and cursor not in seen:
            seen.add(cursor)
            ppid = int(by_pid[cursor].get("ppid", 0) or 0)
            if ppid <= 0:
                break
            expanded.add(ppid)
            cursor = ppid
        if expanded:
            self._expanded.update(expanded)
            self._resort()
            for idx, row in enumerate(self.rows):
                if row.get("pid") == target_pid:
                    self.selected = idx
                    return True
        return False

    def _audit_title(self):
        """Return the user-facing title of the current audit pane."""
        if self._audit_title_override:
            return self._audit_title_override
        return self._AUDIT_SCANS.get(
            self._audit_type, (None, "Process Triage"))[1]

    def _exceeds_threshold(self, p):
        """Check if a process (or its aggregates) exceeds any alert threshold."""
        t = self._alert_thresholds
        if not any(v > 0 for v in t.values()):
            return False
        agg_cpu = p.get("agg_cpu", p.get("cpu", 0))
        agg_mem_mb = p.get("agg_rss_kb", p.get("rss_kb", 0)) / 1024.0
        agg_thr = p.get("agg_threads", p.get("threads", 0))
        fds = p.get("fds", 0)
        forks = p.get("forks", 0)
        net_in = p.get("agg_net_in", max(p.get("net_in", 0), 0)) / 1024.0
        net_out = p.get("agg_net_out", max(p.get("net_out", 0), 0)) / 1024.0
        recv_mb = p.get("agg_bytes_in", p.get("bytes_in", 0)) / (1024 * 1024)
        sent_mb = p.get("agg_bytes_out", p.get("bytes_out", 0)) / (1024 * 1024)
        return (
            (t["cpu"] > 0 and agg_cpu >= t["cpu"])
            or (t["mem_mb"] > 0 and agg_mem_mb >= t["mem_mb"])
            or (t["threads"] > 0 and agg_thr > t["threads"])
            or (t["fds"] > 0 and fds > t["fds"])
            or (t["forks"] > 0 and forks > t["forks"])
            or (t["net_in"] > 0 and net_in > t["net_in"])
            or (t["net_out"] > 0 and net_out > t["net_out"])
            or (t["recv_mb"] > 0 and recv_mb > t["recv_mb"])
            or (t["sent_mb"] > 0 and sent_mb > t["sent_mb"])
        )

    # ── Feature 1: Process Event Ripples ──────────────────────────────

    def _update_row_pulses(self, all_procs):
        """Diff this tick's per-PID CPU / net / disk against the previous
        snapshot and arm a colored pulse on rows whose deltas exceed the
        configured thresholds.

        - CPU spike (delta >= cpu_delta points)        → color_pair(12) salmon
        - I/O burst (net + disk delta >= io_delta_mbps) → color_pair(11) light green
        - Net burst (delta >= net_delta_mbps)           → color_pair(11) light green

        The pulse decays one frame per render and is popped at zero.
        """
        # Decay first so pulses that didn't re-arm this tick fade out.
        self._decay_row_pulses()
        thresholds = self._pulse_thresholds
        cpu_thr = float(thresholds.get("cpu_delta", 20.0))
        net_thr = float(thresholds.get("net_delta_mbps", 1.0)) * 1024 * 1024
        io_thr = float(thresholds.get("io_delta_mbps", 5.0)) * 1024 * 1024
        new_prev = {}
        for p in all_procs:
            pid = p["pid"]
            cpu = float(p.get("cpu", 0.0) or 0.0)
            net_in = max(float(p.get("net_in", 0) or 0), 0.0)
            net_out = max(float(p.get("net_out", 0) or 0), 0.0)
            net_total = net_in + net_out
            disk_in = max(float(p.get("disk_in", 0) or 0), 0.0)
            disk_out = max(float(p.get("disk_out", 0) or 0), 0.0)
            io_total = disk_in + disk_out
            new_prev[pid] = {"cpu": cpu, "net": net_total, "io": io_total}
            prev = self._pulse_prev.get(pid)
            if not prev:
                continue
            cpu_delta = cpu - prev["cpu"]
            net_delta = net_total - prev["net"]
            io_delta = io_total - prev["io"]
            if cpu_delta >= cpu_thr and cpu_thr > 0:
                # CPU spike → salmon
                self._row_pulses[pid] = (12, self._pulse_frames)
            elif io_delta >= io_thr and io_thr > 0:
                # Disk-I/O burst → light green
                self._row_pulses[pid] = (11, self._pulse_frames)
            elif net_delta >= net_thr and net_thr > 0:
                # Net burst → light green
                self._row_pulses[pid] = (11, self._pulse_frames)
        self._pulse_prev = new_prev
        # Drop pulses for pids that are gone
        live_pids = set(new_prev.keys())
        stale = [pid for pid in self._row_pulses if pid not in live_pids]
        for pid in stale:
            self._row_pulses.pop(pid, None)

    def _row_pulse_attr(self, pid):
        """Return the curses attr for an active pulse on this pid, or 0.

        Read-only; decay is driven by `_decay_row_pulses` once per refresh
        (called from collect_data) so multiple intra-tick re-renders all
        see the same pulse intensity.
        """
        info = self._row_pulses.get(pid)
        if not info:
            return 0
        color_pair_id, frames_remaining = info
        if frames_remaining <= 0:
            return 0
        try:
            attr = curses.color_pair(int(color_pair_id)) | curses.A_BOLD
        except Exception:
            attr = curses.A_BOLD
        return attr

    def _decay_row_pulses(self):
        """Decrement every active pulse and pop entries that hit zero."""
        if not self._row_pulses:
            return
        new_pulses = {}
        for pid, (color_pair_id, frames_remaining) in self._row_pulses.items():
            if frames_remaining > 1:
                new_pulses[pid] = (color_pair_id, frames_remaining - 1)
        self._row_pulses = new_pulses

    def _secondary_sort_key(self):
        """Return the sort key for the user-selected sort mode."""
        if self.sort_mode == SORT_CPU:
            return lambda p: p.get("agg_cpu", p["cpu"])
        if self.sort_mode == SORT_NET:
            return lambda p: p.get("agg_net_in", 0) + p.get("agg_net_out", 0)
        if self.sort_mode == SORT_BYTES_IN:
            return lambda p: p.get("agg_bytes_in", 0)
        if self.sort_mode == SORT_BYTES_OUT:
            return lambda p: p.get("agg_bytes_out", 0)
        if self.sort_mode == SORT_VENDOR:
            return lambda p: _short_command(p["command"]).split("[")[-1] if "[" in _short_command(p["command"]) else "zzz"
        if self.sort_mode == SORT_ALPHA:
            return lambda p: _short_command(p["command"]).lower()
        return lambda p: p.get("agg_rss_kb", p["rss_kb"])

    def _sort_key(self):
        secondary = self._secondary_sort_key()
        if not self._dynamic_sort:
            return secondary
        # Dynamic sort: threshold-exceeding processes get priority (appear first).
        # Since the caller applies reverse=True for descending numeric sorts,
        # we flip the group flag so exceeding processes always come first.
        exceeds = self._exceeds_threshold
        reverse = self._sort_reverse()

        def dynamic_key(p):
            val = secondary(p)
            # When reverse=True, higher tuples come first → exceeding = 1, normal = 0
            # When reverse=False, lower tuples come first → exceeding = 0, normal = 1
            if reverse:
                group = 1 if exceeds(p) else 0
            else:
                group = 0 if exceeds(p) else 1
            return (group, val)
        return dynamic_key

    def _set_sort(self, mode):
        if self.sort_mode == mode:
            self._sort_inverted = not self._sort_inverted
        else:
            self.sort_mode = mode
            self._sort_inverted = False
        self._resort()

    def _sort_reverse(self):
        """Whether current sort should be descending (True) or ascending (False)."""
        default = self.sort_mode not in (SORT_ALPHA, SORT_VENDOR)
        return not default if self._sort_inverted else default

    def _compute_cpu_deltas(self, all_procs):
        """Compute instantaneous CPU % from cumulative Mach tick deltas."""
        now = time.monotonic()
        for p in all_procs:
            cpu_ns = _mach_to_ns(p["cpu_ticks"])
            prev = self._prev_cpu.get(p["pid"])
            if prev:
                prev_ns, prev_t = prev
                dt = now - prev_t
                if dt > 0.1:
                    p["cpu"] = max(0.0, (cpu_ns - prev_ns) / (dt * 1e9) * 100.0)
            self._prev_cpu[p["pid"]] = (cpu_ns, now)
        # Prune dead PIDs
        current_pids = {p["pid"] for p in all_procs}
        stale = [k for k in self._prev_cpu if k not in current_pids]
        for k in stale:
            del self._prev_cpu[k]

    def collect_data(self):
        sel_pid = self.rows[self.selected]["pid"] if self.rows and self.selected < len(self.rows) else None
        all_procs = get_all_processes()
        self._compute_cpu_deltas(all_procs)

        # Probe + (re)kick the GPU sampler if applicable. The probe is
        # idempotent and costs essentially nothing after the first call;
        # the actual powermetrics subprocess is only spawned at most once
        # per _gpu_sample_interval seconds and runs in a background thread
        # so it can't stall the refresh.
        try:
            self._probe_gpu_supported()
            self._maybe_start_gpu_sampler()
            self._poll_gpu_result()
        except Exception:
            pass

        # Compute net rates first so they're available for tree aggregation
        net_snap = get_net_snapshot()
        now = time.monotonic()
        # Capture dt against the *previous* snapshot before we clobber
        # self.prev_time below. Disk-I/O sampling uses the same dt.
        prev_time = self.prev_time
        if prev_time is not None and prev_time < now:
            tick_dt = now - prev_time
        else:
            tick_dt = 0.0
        if self.prev_net and self.prev_time:
            dt = tick_dt
            if dt > 0:
                new_rates = {}
                for p in all_procs:
                    pid = p["pid"]
                    curr = net_snap.get(pid)
                    prev = self.prev_net.get(pid)
                    if curr and prev:
                        new_rates[pid] = (
                            max(0, (curr[0] - prev[0]) / dt),
                            max(0, (curr[1] - prev[1]) / dt),
                        )
                self.net_rates = new_rates
        self.prev_net = net_snap
        self.prev_time = now

        # Attach net rates and cumulative bytes before tree building
        # (and per-PID GPU% from the most recent powermetrics sample).
        gpu_snap = {}
        if self._gpu_supported:
            with self._gpu_samples_lock:
                gpu_snap = dict(self._gpu_samples)
        for p in all_procs:
            rates = self.net_rates.get(p["pid"])
            p["net_in"] = rates[0] if rates else -1
            p["net_out"] = rates[1] if rates else -1
            snap = net_snap.get(p["pid"])
            p["bytes_in"] = snap[0] if snap else 0
            p["bytes_out"] = snap[1] if snap else 0
            p["gpu_pct"] = gpu_snap.get(p["pid"])

        # Per-process disk I/O — sample cumulative bytes via libproc rusage,
        # then derive a B/s rate by diffing against the prior snapshot. Same
        # dt as the net rates above so the two columns line up.
        new_disk_snap = {}
        new_disk_rates = {}
        prev_disk = self._prev_disk_io
        disk_dt = tick_dt
        for p in all_procs:
            pid = p["pid"]
            br, bw = _get_disk_io(pid)
            if br is None or bw is None:
                p["disk_bytes_in"] = 0
                p["disk_bytes_out"] = 0
                p["disk_in"] = -1
                p["disk_out"] = -1
                continue
            new_disk_snap[pid] = (br, bw)
            p["disk_bytes_in"] = br
            p["disk_bytes_out"] = bw
            prev = prev_disk.get(pid)
            if prev and disk_dt > 0:
                rate_in = max(0.0, (br - prev[0]) / disk_dt)
                rate_out = max(0.0, (bw - prev[1]) / disk_dt)
                new_disk_rates[pid] = (rate_in, rate_out)
                p["disk_in"] = rate_in
                p["disk_out"] = rate_out
            else:
                p["disk_in"] = -1
                p["disk_out"] = -1
        self._prev_disk_io = new_disk_snap
        self._disk_io_rates = new_disk_rates

        # Per-PID metric ring buffer (drives the Inspect TREND panel).
        # Snapshot CPU%, RSS_KB, net_in (B/s), net_out (B/s) for every
        # currently visible PID, then evict any PID that hasn't been seen
        # for _metric_history_max_age seconds so the dict can't grow
        # without bound. Done under a lock because the inspect render
        # path (potentially on the run thread) may iterate the same dict.
        seen_now = time.monotonic()
        with self._metric_history_lock:
            for p in all_procs:
                pid = p["pid"]
                hist = self._metric_history.setdefault(pid, {})
                for k in ("cpu", "rss_kb", "net_in", "net_out"):
                    dq = hist.get(k)
                    if dq is None:
                        dq = collections.deque(
                            maxlen=self._metric_history_max)
                        hist[k] = dq
                    val = p.get(k, 0)
                    if val is None:
                        val = 0
                    # Rates can be -1 ("no sample yet"); coerce.
                    if k in ("net_in", "net_out") and val < 0:
                        val = 0
                    dq.append(float(max(0.0, float(val))))
                self._metric_history_seen[pid] = seen_now
            # Eviction pass — drop pids not seen recently.
            stale = [pid for pid, last in self._metric_history_seen.items()
                     if seen_now - last > self._metric_history_max_age]
            for pid in stale:
                self._metric_history.pop(pid, None)
                self._metric_history_seen.pop(pid, None)

        matched = [p for p in all_procs
                   if p["pid"] not in _PHANTOM_TREE_PARENTS
                   and (not self.patterns or any(pat in p["command"].lower() for pat in self.patterns))
                   and not any(pat in p["command"].lower() for pat in self.exclude_patterns)]

        _build = build_vendor_tree if self._vendor_grouped else build_tree
        tree = _build(matched, all_procs, self._sort_key(), self._sort_reverse())
        flat = flatten_tree(tree, self._expanded)
        matched_pids = [p["pid"] for p in matched]
        all_display_pids = [r["pid"] for r in flat]

        fd_map = {} if self.skip_fd else get_fd_counts(matched_pids)
        cwd_map = get_cwds(all_display_pids)

        for p in matched:
            p["fds"] = fd_map.get(p["pid"], -1)

        for r in flat:
            r["fds"] = fd_map.get(r["pid"], -1)
            r["cwd"] = short_cwd(cwd_map.get(r["pid"], "-"))

        # Compute agg_fds by walking the flat list bottom-up
        # Each row at depth d is a child of the nearest preceding row at depth d-1
        for r in flat:
            r["agg_fds"] = max(r["fds"], 0)
        for i in range(len(flat) - 1, 0, -1):
            r = flat[i]
            for j in range(i - 1, -1, -1):
                if flat[j]["depth"] < r["depth"]:
                    flat[j]["agg_fds"] += r["agg_fds"]
                    break

        self.rows = flat
        self._all_procs = matched
        self.matched_count = len(matched)

        # Feature 1: Process Event Ripples — compute deltas vs the last
        # tick and arm a pulse on rows whose CPU%, net rate, or disk-I/O
        # rate jumped above the configured thresholds. Decay happens in
        # the row renderer.
        try:
            self._update_row_pulses(all_procs)
        except Exception:
            pass

        # Restore selection by PID
        if sel_pid is not None:
            for i, r in enumerate(self.rows):
                if r["pid"] == sel_pid:
                    self.selected = i
                    break
        if self.selected >= len(self.rows):
            self.selected = max(0, len(self.rows) - 1)

        # Background hidden process check (every 2 intervals)
        now_h = time.monotonic()
        if now_h - self._last_hidden_check >= self.interval * 2:
            self._last_hidden_check = now_h
            libproc_pids = [p["pid"] for p in all_procs]
            try:
                hidden = _check_hidden_pids_quick(libproc_pids)
                self._hidden_pids = hidden
                self._hidden_alert_count = len(hidden)
            except Exception:
                pass

    def render(self):
        self.stdscr.erase()
        h, w = self.stdscr.getmaxyx()
        if h < 10 or w < 40:
            self._put(0, 0, "Terminal too small")
            self.stdscr.refresh()
            self._capture_screen_snapshot("main", "Main view")
            return

        # Fullscreen modes — galaxy takes over the entire screen rather
        # than rendering inside the bottom detail pane. Header + shortcut
        # bar still wrap it; everything in between is the galaxy canvas.
        if self._galaxy_mode:
            self._galaxy_render_fullscreen(w, h)
            self._render_shortcut_bar(h, w)
            self.stdscr.refresh()
            return

        y = 0

        # ── Header ──
        ts = time.strftime("%H:%M:%S")
        n = self.matched_count
        sort_label = {"m": "mem", "c": "cpu", "n": "net", "R": "recv", "O": "sent", "V": "vendor", "A": "a-z"}.get(self.sort_mode, "mem")
        filter_parts = []
        if self.name:
            filter_parts.append(f"+'{self.name}'")
        if self.exclude_name:
            filter_parts.append(f"-'{self.exclude_name}'")
        filter_str = f" [{' '.join(filter_parts)}]" if filter_parts else ""
        # Render header with colored segments
        self._put(y, 0, " " * w, curses.color_pair(1))
        x = 0
        brand = " mac-tui-procmon "
        self._put(y, x, brand, curses.color_pair(1) | curses.A_BOLD)
        x += len(brand)
        proc_str = f"\u2014 {n} process{'es' if n != 1 else ''}{filter_str} "
        self._put(y, x, proc_str, curses.color_pair(7))
        x += len(proc_str)
        self._put(y, x, f"\u2014 {ts} ", curses.color_pair(11))
        x += len(f"\u2014 {ts} ")
        self._put(y, x, f"\u2014 every {self.interval:.0f}s ", curses.color_pair(10))
        x += len(f"\u2014 every {self.interval:.0f}s ")
        sort_color = {SORT_MEM: curses.color_pair(3), SORT_CPU: curses.color_pair(5),
                      SORT_NET: curses.color_pair(9)}.get(self.sort_mode, curses.color_pair(3))
        sort_arrow = "\u2191" if not self._sort_reverse() else "\u2193"
        dyn_tag = " [dyn]" if self._dynamic_sort else ""
        grp_tag = " [vendor]" if self._vendor_grouped else ""
        self._put(y, x, f"\u2014 sort: {sort_label}{sort_arrow}{dyn_tag}{grp_tag} ", sort_color | curses.A_BOLD)
        x += len(f"\u2014 sort: {sort_label}{sort_arrow}{dyn_tag}{grp_tag} ")
        if self._hidden_alert_count > 0:
            alert_str = f"[HIDDEN: {self._hidden_alert_count}] "
            self._put(y, x, alert_str, curses.color_pair(5) | curses.A_BOLD | curses.A_BLINK)
        y += 1

        # ── Totals ──
        if self.rows:
            totals_source = self._all_procs or self.rows
            tc = sum(r.get("cpu", 0.0) for r in totals_source)
            tm = sum(r.get("rss_kb", 0) for r in totals_source)
            tf = sum(r.get("fds", 0) for r in totals_source if r.get("fds", -1) >= 0)
            tt = sum(r.get("threads", 0) for r in totals_source)
            ti = sum(r.get("net_in", 0) for r in totals_source if r.get("net_in", -1) >= 0)
            to_ = sum(r.get("net_out", 0) for r in totals_source if r.get("net_out", -1) >= 0)
            # Render totals with per-value colors
            x = 0
            self._put(y, x, " Totals: ", curses.color_pair(10) | curses.A_BOLD)
            x = 9
            # CPU — green/yellow/red
            cpu_color = curses.color_pair(5) if tc > 200 else curses.color_pair(6) if tc > 50 else curses.color_pair(1)
            cpu_str = f"CPU {tc:.1f}%  "
            self._put(y, x, cpu_str, cpu_color | curses.A_BOLD)
            x += len(cpu_str)
            # MEM — green/yellow/red — show used/total (percent)
            mem_color = curses.color_pair(5) if tm > 8*1024*1024 else curses.color_pair(6) if tm > 2*1024*1024 else curses.color_pair(1)
            mem_pct = (tm / self._total_mem_kb * 100) if self._total_mem_kb > 0 else 0
            mem_str = f"MEM {fmt_mem(tm)}/{fmt_mem(self._total_mem_kb)} ({mem_pct:.1f}%)  "
            self._put(y, x, mem_str, mem_color | curses.A_BOLD)
            x += len(mem_str)
            # Threads
            self._put(y, x, f"Threads {tt}  ", curses.color_pair(7))
            x += len(f"Threads {tt}  ")
            if not self.skip_fd:
                self._put(y, x, f"FDs {tf}  ", curses.color_pair(7))
                x += len(f"FDs {tf}  ")
            # Net
            self._put(y, x, f"\u2193{fmt_rate(ti)}  \u2191{fmt_rate(to_)}", curses.color_pair(9))
        y += 1

        # ── Column header ──
        col_hdr = self._col_header(w)
        self._put(y, 0, col_hdr.ljust(w)[:w], curses.color_pair(4) | curses.A_BOLD)
        y += 1

        if not self.rows:
            msg = f"No processes matching '{self.name}' found. Waiting..." if self.name else "No processes found. Waiting..."
            self._put(y + 1, 1, msg)
            self.stdscr.refresh()
            self._capture_screen_snapshot("main", "Main view")
            return

        # ── Compute detail box content and height ──
        if self._galaxy_mode:
            detail_all_lines = self._build_galaxy_lines(w, h)
            detail_title = (f"Process Galaxy — {len(self._galaxy_positions)} "
                             f"nodes")
            max_detail_h = max(10, (h - y) * 4 // 5)
            detail_h = min(len(detail_all_lines) + 2, max_detail_h)
        elif self._inspect_mode:
            if self._inspect_lines and not self._consensus_running:
                detail_all_lines = list(self._inspect_lines)
                summary = (self._llm_summary.get("inspect")
                           or self._llm_summary_loading_banner("inspect"))
                if summary:
                    detail_all_lines = summary + detail_all_lines
            elif self._inspect_loading and self._consensus_running:
                # Feature 4: Three-Model Consensus Race \u2014 render side-by-
                # side lanes while the LLMs stream their analyses.
                detail_all_lines = self._build_consensus_race_lines(w)
            elif self._inspect_loading:
                phase = self._inspect_phase
                if phase == "collecting":
                    detail_all_lines = [" Collecting forensic artifacts\u2026"]
                elif phase == "analyzing":
                    detail_all_lines = [" Running Claude + Codex + Gemini in parallel\u2026"]
                elif phase == "synthesizing":
                    detail_all_lines = [" Synthesizing consensus\u2026"]
                else:
                    detail_all_lines = [" Loading\u2026"]
            else:
                detail_all_lines = [" No inspect data"]
            detail_title = f"Inspect \u2014 {self._inspect_cmd} ({self._inspect_pid})"
            max_detail_h = max(8, (h - y) * 2 // 3)
            detail_h = min(len(detail_all_lines) + 2, max_detail_h)
        elif self._audit_mode:
            if self._audit_lines:
                result = self._audit_action_result
                panel = self._format_action_panel(result, w - 6) if result else []
                detail_all_lines = list(self._audit_lines)
                cur_finding = None
                if self._audit_findings_structured and self._audit_line_for_finding:
                    cursor_idx = self._audit_cursor
                    if 0 <= cursor_idx < len(self._audit_line_for_finding):
                        line_idx = self._audit_line_for_finding[cursor_idx]
                        if line_idx < len(detail_all_lines):
                            original = detail_all_lines[line_idx]
                            if len(original) >= 4:
                                detail_all_lines[line_idx] = (
                                    "  \u25b6 " + original[4:])
                    if 0 <= cursor_idx < len(self._audit_findings_structured):
                        cur_finding = self._audit_findings_structured[cursor_idx]
                # Append the DETAIL pane for the cursored finding
                if cur_finding is not None:
                    detail_all_lines.extend(
                        self._format_finding_detail(cur_finding, w - 6))
                # Prepend AI SUMMARY panel (finished or loading-banner).
                # This has to shift the cursor-line-map indices because all
                # finding rows move down by len(summary). We patch the
                # mapping in-place for this render frame only; the underlying
                # _audit_line_for_finding list is rebuilt by
                # _format_audit_report on every scan so we don't corrupt it
                # across frames — it's the display-time view that's shifted.
                summary = (self._llm_summary.get("audit")
                           or self._llm_summary_loading_banner("audit"))
                if summary:
                    detail_all_lines = summary + detail_all_lines
                detail_all_lines = panel + detail_all_lines
            elif self._audit_loading:
                detail_all_lines = [" Running deep process triage\u2026"]
                progress_lines = self._audit_progress_view()
                if progress_lines:
                    detail_all_lines.extend([""] + progress_lines)
            else:
                detail_all_lines = [" No audit results"]
            detail_title = self._audit_title()
            # If a rescan is in flight on top of an already-populated list
            # (e.g. after a remediation), suffix the title so the user knows
            # the visible data is about to be replaced with fresher data.
            if self._audit_loading and self._audit_lines:
                detail_title = detail_title + " \u2014 rescanning\u2026"
            max_detail_h = max(8, (h - y) * 2 // 3)
            detail_h = min(len(detail_all_lines) + 2, max_detail_h)
        elif self._events_mode:
            detail_all_lines = self._format_events_view()
            summary = (self._llm_summary.get("events")
                       or self._llm_summary_loading_banner("events"))
            if summary:
                detail_all_lines = summary + detail_all_lines
            detail_title = "Security Timeline"
            if self._events_awaiting_summary:
                detail_title += " \u2014 stream stopped, Esc again to close"
            max_detail_h = max(8, (h - y) * 2 // 3)
            detail_h = min(len(detail_all_lines) + 2, max_detail_h)
        elif self._replay_mode:
            detail_all_lines = self._format_replay_view(w)
            n = len(self._replay_events)
            detail_title = (f"Attack Chain Replay \u2014 "
                             f"{self._replay_cursor + 1} / {n}")
            max_detail_h = max(10, (h - y) * 3 // 4)
            detail_h = min(len(detail_all_lines) + 2, max_detail_h)
        elif self._traffic_mode:
            detail_all_lines = self._format_traffic_view()
            detail_title = "Traffic Inspector (experimental)"
            max_detail_h = max(8, (h - y) * 2 // 3)
            detail_h = min(len(detail_all_lines) + 2, max_detail_h)
        elif self._unified_log_mode:
            detail_all_lines = self._format_unified_log_view()
            detail_title = (f"Unified Log — {self._unified_log_cmd} "
                            f"(PID {self._unified_log_pid})")
            max_detail_h = max(8, (h - y) * 2 // 3)
            detail_h = min(len(detail_all_lines) + 2, max_detail_h)
        elif self._net_mode:
            if self._orbit_mode and self._net_entries:
                # Feature 6: Network Orbit / Constellation render.
                detail_all_lines = self._build_orbit_lines(w, h)
            elif self._net_entries:
                detail_all_lines = []
                for idx, e in enumerate(self._net_entries):
                    line = e["display"]
                    if idx == self._net_selected and e.get("org"):
                        line += f"  org: {e['org']}"
                    detail_all_lines.append(line)
            elif self._net_loading:
                detail_all_lines = [" Loading network connections\u2026"]
            else:
                detail_all_lines = [" No active network connections"]
            detail_title = f"Network \u2014 {self._net_cmd} ({self._net_pid})"
            max_detail_h = max(8, (h - y) // 2)
            detail_h = min(len(detail_all_lines) + 2, max_detail_h)
        else:
            detail_all_lines = self._detail_lines(w) if self.rows else []
            detail_title = "Details"
            detail_h = len(detail_all_lines) + 2

        detail_all_lines = self._decorate_test_detail_lines(
            detail_title, detail_all_lines)

        # ── Process tree (scrollable region) ──
        # Reserve last row for shortcut bar
        detail_y = max(y + 3, h - detail_h - 1)
        list_h = detail_y - y

        if self.selected < self.scroll_offset:
            self.scroll_offset = self.selected
        if self.selected >= self.scroll_offset + list_h:
            self.scroll_offset = self.selected - list_h + 1

        visible = self.rows[self.scroll_offset : self.scroll_offset + list_h]
        t = self._alert_thresholds
        # Precompute right-side column widths for per-cell coloring
        # right_parts order: PID(7) PPID(7) MEM(9) CPU(7) THR(4) [FDs(5)] Forks(6) In(10) Out(10) Recv(10) Sent(10)
        col_widths = [7, 7, 9, 7, 4]
        if not self.skip_fd:
            col_widths.append(5)
        col_widths += [6, 10, 10, 10, 10]
        # Total right width including separating spaces
        right_total = sum(col_widths) + len(col_widths) - 1
        right_start = w - right_total - 1  # x where right columns begin

        for i, r in enumerate(visible):
            idx = self.scroll_offset + i
            line = self._fmt_row(r, w)
            agg_mem = r.get("agg_rss_kb", r["rss_kb"])
            agg_cpu = r.get("agg_cpu", r["cpu"])
            agg_mem_mb = agg_mem / 1024.0
            r_thr = r.get("agg_threads", r["threads"])
            r_fds = r.get("fds", 0)
            r_forks = r.get("forks", 0)
            r_net_in_kb = r.get("agg_net_in", max(r.get("net_in", 0), 0)) / 1024.0
            r_net_out_kb = r.get("agg_net_out", max(r.get("net_out", 0), 0)) / 1024.0
            r_recv_mb = r.get("agg_bytes_in", r.get("bytes_in", 0)) / (1024 * 1024)
            r_sent_mb = r.get("agg_bytes_out", r.get("bytes_out", 0)) / (1024 * 1024)

            # Base row color (no longer full-row red)
            if idx == self.selected:
                self._put(y, 0, line.ljust(w)[:w], curses.color_pair(2))
            elif r["depth"] > 0:
                self._put(y, 0, line[:w], curses.color_pair(10))
            elif agg_cpu > 5 or agg_mem > 512 * 1024:
                self._put(y, 0, line[:w], curses.color_pair(11))
            else:
                self._put(y, 0, line[:w], curses.A_NORMAL)

            # Feature 1: Process Event Ripples — overlay an active pulse
            # by repainting the *unselected* row text with the pulse
            # color. Selected rows keep their highlight so the cursor
            # never gets lost during a spike.
            if idx != self.selected:
                pulse_attr = self._row_pulse_attr(r["pid"])
                if pulse_attr:
                    self._put(y, 0, line[:w], pulse_attr)

            # Overlay per-cell red/yellow for individual metrics that exceed thresholds
            if idx != self.selected:
                # Build list: (column_index, exceeds, warning)
                # Column indices: 0=PID 1=PPID 2=MEM 3=CPU 4=THR 5=FDs(opt) 6/5=Forks 7/6=In 8/7=Out 9/8=Recv 10/9=Sent
                fd_offset = 1 if not self.skip_fd else 0
                checks = []
                if t["mem_mb"] > 0:
                    checks.append((2, agg_mem_mb >= t["mem_mb"], agg_mem_mb >= t["mem_mb"] * 0.8))
                if t["cpu"] > 0:
                    checks.append((3, agg_cpu >= t["cpu"], agg_cpu >= t["cpu"] * 0.8))
                if t["threads"] > 0:
                    checks.append((4, r_thr > t["threads"], r_thr >= t["threads"] * 0.8))
                if t["fds"] > 0 and not self.skip_fd:
                    checks.append((5, r_fds > t["fds"], r_fds >= t["fds"] * 0.8))
                if t["forks"] > 0:
                    checks.append((5 + fd_offset, r_forks > t["forks"], r_forks >= t["forks"] * 0.8))
                if t["net_in"] > 0:
                    checks.append((6 + fd_offset, r_net_in_kb > t["net_in"], r_net_in_kb >= t["net_in"] * 0.8))
                if t["net_out"] > 0:
                    checks.append((7 + fd_offset, r_net_out_kb > t["net_out"], r_net_out_kb >= t["net_out"] * 0.8))
                if t["recv_mb"] > 0:
                    checks.append((8 + fd_offset, r_recv_mb > t["recv_mb"], r_recv_mb >= t["recv_mb"] * 0.8))
                if t["sent_mb"] > 0:
                    checks.append((9 + fd_offset, r_sent_mb > t["sent_mb"], r_sent_mb >= t["sent_mb"] * 0.8))

                for col_idx, exceeds, warning in checks:
                    if not warning:
                        continue
                    # Compute x position of this column
                    cx = right_start
                    for ci in range(col_idx):
                        cx += col_widths[ci] + 1  # +1 for separator space
                    cw = col_widths[col_idx]
                    cell_text = line[cx:cx + cw] if cx < len(line) else ""
                    if cell_text:
                        attr = curses.color_pair(5) | curses.A_BOLD if exceeds else curses.color_pair(6) | curses.A_BOLD
                        self._put(y, cx, cell_text[:w - cx], attr)

            # Overlay colored tree prefix and collapse indicator
            prefix = r["prefix"]
            if prefix:
                self._put(y, 1, prefix[:w-1], curses.color_pair(9))
            if r["has_children"]:
                ind = "\u25b6" if r["is_collapsed"] else "\u25bc"
                ind_x = 1 + len(prefix)
                if idx == self.selected:
                    self._put(y, ind_x, ind, curses.color_pair(2) | curses.A_BOLD)
                else:
                    self._put(y, ind_x, ind, curses.color_pair(3) | curses.A_BOLD)
            # Overlay vendor tag color
            if idx != self.selected:
                short = _short_command(r["command"])
                bracket = short.find(" [")
                if bracket != -1:
                    tag = short[bracket + 1:]
                    tag_x = 1 + len(prefix) + 2 + bracket + 1
                    self._put(y, tag_x, tag, curses.color_pair(9) | curses.A_DIM)
            # Hidden process marker
            if r["pid"] in self._hidden_pids and idx != self.selected:
                self._put(y, 0, "!", curses.color_pair(5) | curses.A_BOLD)
            y += 1

        # ── Scroll indicator ──
        total = len(self.rows)
        if total > list_h:
            indicator = f" [{self.scroll_offset + 1}-{min(self.scroll_offset + list_h, total)} of {total}]"
            self._put(detail_y - 1, max(0, w - len(indicator) - 1), indicator[:w], curses.A_DIM)

        # ── Detail box ──
        if self._inspect_mode:
            scroll = self._inspect_scroll
            sel_line = -1
        elif self._audit_mode:
            scroll = self._audit_scroll
            sel_line = -1
        elif self._events_mode:
            scroll = self._events_scroll
            sel_line = -1
        elif self._traffic_mode:
            scroll = self._traffic_scroll
            sel_line = -1
        elif self._unified_log_mode:
            scroll = self._unified_log_scroll
            sel_line = -1
        elif self._net_mode:
            scroll = self._net_scroll
            sel_line = self._net_selected if self._detail_focus else -1
        else:
            scroll = 0
            sel_line = -1
        self._capture_detail_snapshot(detail_y, w, detail_title,
                                      detail_all_lines, scroll)
        # Galaxy short-circuits at the top of render() to take over the
        # whole screen; we never reach this branch with _galaxy_mode set.
        self._render_detail(detail_y, w, detail_all_lines,
                            detail_title, scroll, self._detail_focus,
                            sel_line)

        # ── Shortcut bar (mc-style) ──
        self._render_shortcut_bar(h, w)
        # Debug log sits on top of EVERYTHING, including chat.
        if self._log_mode:
            self._render_log()
        # Chat overlay sits on top of whatever mode is underneath
        elif self._chat_mode:
            self._render_chat()
        else:
            # Hide the cursor again when the chat isn't active (the chat
            # turns it on for the input field; other modes don't want it).
            try:
                curses.curs_set(0)
            except curses.error:
                pass
        self.stdscr.refresh()
        if self._log_mode:
            surface = "log_overlay"
            title = "Debug log"
        elif self._chat_mode:
            surface = "chat_overlay"
            title = self._chat_context_label
        elif self._inspect_mode:
            surface = "inspect_view"
            title = detail_title
        elif self._audit_mode:
            surface = "audit_view"
            title = detail_title
        elif self._events_mode:
            surface = "events_view"
            title = detail_title
        elif self._traffic_mode:
            surface = "traffic_view"
            title = detail_title
        elif self._unified_log_mode:
            surface = "unified_log_view"
            title = detail_title
        elif self._net_mode:
            surface = "network_view"
            title = detail_title
        else:
            surface = "main"
            title = "Main view"
        self._capture_screen_snapshot(surface, title)

    def _col_header(self, w):
        sort_ind_c = "*" if self.sort_mode == SORT_CPU else " "
        sort_ind_m = "*" if self.sort_mode == SORT_MEM else " "
        sort_ind_n = "*" if self.sort_mode == SORT_NET else " "
        sort_ind_bi = "*" if self.sort_mode == SORT_BYTES_IN else " "
        sort_ind_bo = "*" if self.sort_mode == SORT_BYTES_OUT else " "
        right_parts = [f"{'PID':>7}", f"{'PPID':>7}", f"{'MEM':>8}{sort_ind_m}", f"{'CPU%':>6}{sort_ind_c}", f"{'THR':>4}"]
        if not self.skip_fd:
            right_parts.append(f"{'FDs':>5}")
        net_in_header = "\u2193 In"
        net_out_header = "\u2191 Out"
        bytes_in_header = "\u2193Recv"
        bytes_out_header = "\u2191Sent"
        right_parts += [f"{'Forks':>6}", f"{net_in_header:>9}{sort_ind_n}", f"{net_out_header:>10}",
                        f"{bytes_in_header:>9}{sort_ind_bi}", f"{bytes_out_header:>9}{sort_ind_bo}"]
        right = " ".join(right_parts)
        left_w = w - len(right) - 2
        if left_w <= 0:
            return f" PROCESS {right}"
        return f" {'PROCESS':<{left_w}} {right}"

    def _fmt_row(self, r, w):
        mem = r.get("agg_rss_kb", r["rss_kb"])
        cpu = r.get("agg_cpu", r["cpu"])
        thr = r.get("agg_threads", r["threads"])
        net_in = r.get("agg_net_in", max(r.get("net_in", 0), 0))
        net_out = r.get("agg_net_out", max(r.get("net_out", 0), 0))
        b_in = r.get("agg_bytes_in", r.get("bytes_in", 0))
        b_out = r.get("agg_bytes_out", r.get("bytes_out", 0))
        right_parts = [f"{r['pid']:7}", f"{r['ppid']:7}", f"{fmt_mem(mem):>8} ", f"{cpu:6.1f} ", f"{thr:4}"]
        if not self.skip_fd:
            right_parts.append(f"{r['fds']:5}" if r.get("fds", -1) >= 0 else f"{'?':>5}")
        right_parts += [
            f"{r['forks']:6}",
            f"{fmt_rate(net_in):>10}",
            f"{fmt_rate(net_out):>10}",
            f"{fmt_bytes(b_in):>9} ",
            f"{fmt_bytes(b_out):>9} ",
        ]
        right = " ".join(right_parts)
        left_w = w - len(right) - 2
        if r["has_children"]:
            indicator = "\u25b6 " if r["is_collapsed"] else "\u25bc "
        else:
            indicator = "  "
        short = _short_command(r["command"])
        count = r.get("sibling_count", 0)
        if count > 1:
            short += f" ({count})"
        left = r["prefix"] + indicator + short
        if left_w <= 0:
            return f" {left} {right}"
        if len(left) > left_w:
            left = left[: left_w - 1] + "\u2026"
        return f" {left:<{left_w}} {right}"

    def _detail_lines(self, w):
        """Build the detail content lines for the selected row, wrapping long values."""
        if not self.rows:
            return []
        r = self.rows[self.selected]
        box_w = w
        inner = box_w - 4  # "│ " prefix + " │" suffix

        agg_mem = r.get("agg_rss_kb", r["rss_kb"])
        agg_cpu = r.get("agg_cpu", r["cpu"])
        agg_thr = r.get("agg_threads", r["threads"])
        agg_ni = r.get("agg_net_in", 0)
        agg_no = r.get("agg_net_out", 0)
        has_ch = r.get("has_children", False)

        pid_line = f"PID: {r['pid']}  PPID: {r['ppid']}  Forks: {r['forks']}  Threads: {r['threads']}"
        if has_ch:
            pid_line += f" (group: {agg_thr})"
        if not self.skip_fd:
            fd_val = r.get('fds', -1)
            pid_line += f"  FDs: {fd_val if fd_val >= 0 else '?'}"

        mem_line = f"CPU: {r['cpu']:.1f}%   MEM: {fmt_mem(r['rss_kb'])} ({r['rss_kb']:,} KB)"
        if has_ch:
            mem_line += f"  [group: CPU {agg_cpu:.1f}%  MEM {fmt_mem(agg_mem)}]"
        gpu_pct = r.get("gpu_pct")
        if gpu_pct is not None:
            mem_line += f"   GPU: {gpu_pct:.1f}%"

        net_in = r.get("net_in", -1)
        net_out = r.get("net_out", -1)
        net_line = f"Net: \u2193 {fmt_rate(net_in)}  \u2191 {fmt_rate(net_out)}"
        if has_ch:
            net_line += f"  [group: \u2193 {fmt_rate(agg_ni)}  \u2191 {fmt_rate(agg_no)}]"

        # Per-process disk I/O rate (proc_pid_rusage). Only show the line if
        # we have a successful sample \u2014 otherwise it's noise.
        disk_in = r.get("disk_in", -1)
        disk_out = r.get("disk_out", -1)
        dbi = r.get("disk_bytes_in", 0)
        dbo = r.get("disk_bytes_out", 0)
        disk_line = None
        if disk_in >= 0 or disk_out >= 0 or dbi or dbo:
            rate_part = (f"\u2193 {fmt_rate(max(disk_in, 0))}  "
                         f"\u2191 {fmt_rate(max(disk_out, 0))}")
            total_part = (f"  [total: read {fmt_mem(dbi // 1024)} / "
                          f"written {fmt_mem(dbo // 1024)}]")
            disk_line = f"Disk: {rate_part}{total_part}"

        raw = [
            pid_line,
            mem_line,
            net_line,
        ]
        if disk_line is not None:
            raw.append(disk_line)
        raw.extend([
            f"CWD: {r.get('cwd', '-')}",
            f"CMD: {r['command']}",
        ])

        return raw

    def _render_detail(self, start_y, w, lines, title="Details",
                       scroll=0, focused=False, selected_line=-1):
        h, _ = self.stdscr.getmaxyx()
        if start_y >= h - 2 or not self.rows:
            return
        box_w = w  # full terminal width
        inner_w = box_w - 4  # "│ " prefix + " │" suffix
        inner_h = h - start_y - 2
        inner_h = max(1, inner_h - 1)  # -1 for shortcut bar

        # Wrap long lines to fit the box
        wrapped = []
        line_map = []  # maps wrapped index -> original line index
        for orig_idx, line in enumerate(lines):
            first = True
            remaining = line
            while remaining:
                chunk = remaining[:inner_w]
                remaining = remaining[inner_w:]
                wrapped.append(chunk)
                line_map.append(orig_idx)
                if first:
                    first = False

        # Clamp scroll
        max_scroll = max(0, len(wrapped) - inner_h)
        if scroll > max_scroll:
            scroll = max_scroll
        visible = wrapped[scroll:scroll + inner_h]
        visible_map = line_map[scroll:scroll + inner_h]

        border_attr = curses.color_pair(2) | curses.A_BOLD if focused else curses.A_BOLD
        title_str = f"\u250c\u2500 {title} "
        top = title_str + "\u2500" * max(0, box_w - len(title_str) - 1) + "\u2510"
        self._put(start_y, 0, top[:w], border_attr)

        y = start_y + 1
        for i, line in enumerate(visible):
            if y >= h - 2:
                break
            orig_idx = visible_map[i]
            is_sel = orig_idx == selected_line
            # Clear line, draw borders
            self._put(y, 0, "\u2502", border_attr if is_sel else curses.A_DIM)
            fill = " " * (box_w - 2)
            self._put(y, 1, fill, curses.color_pair(2) if is_sel else 0)
            if box_w - 1 < w:
                self._put(y, box_w - 1, "\u2502", border_attr if is_sel else curses.A_DIM)
            # Draw content with colors
            self._render_colored_line(y, 2, line, inner_w, is_sel)
            y += 1

        if y < h - 1:
            if len(wrapped) > inner_h:
                total_orig = len(lines)
                pos_str = f" {scroll + 1}-{min(scroll + len(visible), len(wrapped))}/{len(wrapped)} ({total_orig} entries) "
                bot_fill = max(0, box_w - 2 - len(pos_str))
                bottom = "\u2514" + "\u2500" * (bot_fill // 2) + pos_str + "\u2500" * (bot_fill - bot_fill // 2) + "\u2518"
            else:
                bottom = "\u2514" + "\u2500" * (box_w - 2) + "\u2518"
            self._put(y, 0, bottom[:w], border_attr)

    def _tag_color(self, tag):
        """Return curses attr for a [tag] based on content."""
        content = tag[1:-1]  # strip brackets
        # Severity tags used by audit + keyscan reports. Matches both
        # `[CRITICAL]` and `[CRITICAL 5]` (count-suffixed summary form).
        sev_base = content.split(" ", 1)[0] if " " in content else content
        if sev_base == "CRITICAL":
            return curses.color_pair(12) | curses.A_BOLD  # salmon/bright red
        if sev_base == "HIGH":
            return curses.color_pair(5) | curses.A_BOLD   # red
        if sev_base == "MEDIUM":
            return curses.color_pair(6) | curses.A_BOLD   # orange
        if sev_base == "INFO":
            return curses.color_pair(7)                    # cyan
        if sev_base == "OK":
            return curses.color_pair(1) | curses.A_BOLD   # green
        if content == "x":
            # "[x]" marker on actionable audit findings — bright green
            return curses.color_pair(11) | curses.A_BOLD
        # Inspect mode risk tags
        if content.startswith("!RISK:") or content.startswith("!"):
            return curses.color_pair(5) | curses.A_BOLD   # red for HIGH/CRITICAL/warnings
        if content.startswith("RISK:"):
            return curses.color_pair(1) | curses.A_BOLD   # green for LOW/MEDIUM
        if content == "INSPECT":
            return curses.color_pair(7) | curses.A_BOLD   # cyan
        if content in ("TCP",):
            return curses.color_pair(1) | curses.A_BOLD   # green
        if content in ("UDP",):
            return curses.color_pair(3) | curses.A_BOLD   # yellow
        if content in _PORT_SERVICES.values():
            return curses.color_pair(7) | curses.A_BOLD   # cyan
        if "/" in content and len(content) < 30:          # City/CC
            return curses.color_pair(8)                    # magenta
        if content.startswith("group:"):
            return curses.color_pair(3)                    # yellow
        # Byte counts
        for suffix in ("B", "KB", "MB", "GB"):
            if content.endswith(suffix):
                # Color by size: green < 1MB, yellow < 100MB, red >= 100MB
                try:
                    val = float(content.split()[0])
                    if "GB" in content or ("MB" in content and val >= 100):
                        return curses.color_pair(12) | curses.A_BOLD  # red
                    if "MB" in content:
                        return curses.color_pair(6) | curses.A_BOLD   # orange
                    return curses.color_pair(11)                       # light green
                except ValueError:
                    return curses.color_pair(11)
        return curses.color_pair(10)  # default grey

    def _render_colored_line(self, y, x_start, text, max_w, is_selected):
        """Render text with colored [tags], → arrow, and labels."""
        if is_selected:
            self._put(y, x_start, text[:max_w], curses.color_pair(2))
            return
        x = x_start
        i = 0
        while i < len(text) and (x - x_start) < max_w:
            avail = max_w - (x - x_start)
            if avail <= 0:
                break
            ch = text[i]
            if ch == '[':
                # Find closing bracket
                j = text.find(']', i)
                if j == -1:
                    self._put(y, x, text[i:i + avail], curses.A_DIM)
                    break
                tag = text[i:j + 1]
                color = self._tag_color(tag)
                self._put(y, x, tag[:avail], color)
                x += min(len(tag), avail)
                i = j + 1
            elif ch == '\u2192':  # →
                self._put(y, x, '\u2192', curses.color_pair(9) | curses.A_BOLD)
                x += 1
                i += 1
            else:
                # Plain text — find next special char
                next_bracket = text.find('[', i)
                next_arrow = text.find('\u2192', i)
                ends = [e for e in (next_bracket, next_arrow) if e != -1]
                end = min(ends) if ends else len(text)
                segment = text[i:end]
                # Color labels (PID:, CPU:, etc.) in cyan
                if segment.rstrip().endswith(':') or ': ' in segment[:6]:
                    self._put(y, x, segment[:avail], curses.color_pair(7))
                else:
                    self._put(y, x, segment[:avail], curses.color_pair(10))
                x += min(len(segment), avail)
                i = end

    def _render_shortcut_bar(self, h, w):
        """Render mc-style shortcut bar on the last line."""
        if self._detail_focus:
            if self._inspect_mode:
                shortcuts = [
                    ("\u2191\u2193", "Scroll"),
                    ("PgU/D", "Page"),
                    ("?", "Ask"),
                    ("I", "Close"),
                    ("Tab", "Procs"),
                    ("Esc", "Back"),
                    ("q", "Quit"),
                ]
            elif self._audit_mode:
                shortcuts = [
                    ("\u2191\u2193", "Select"),
                    ("PgU/D", "Page"),
                    ("D", "Remediate"),
                    ("R", "Rescan"),
                    ("L", "Log"),
                    ("?", "Ask"),
                    ("Esc", "Close"),
                    ("q", "Quit"),
                ]
            elif self._events_mode:
                # First Esc stops the stream and kicks the LLM summary;
                # a second Esc actually closes. Reflect the stage so the
                # user knows what pressing Esc will do next.
                esc_label = ("Close" if self._events_awaiting_summary
                             else "Stop+Summarize")
                shortcuts = [
                    ("\u2191\u2193", "Scroll"),
                    ("PgU/D", "Page"),
                    ("c", "Clear"),
                    ("?", "Ask"),
                    ("Esc", esc_label),
                    ("Tab", "Procs"),
                    ("q", "Quit"),
                ]
            elif self._traffic_mode:
                shortcuts = [
                    ("\u2191\u2193", "Scroll"),
                    ("PgU/D", "Page"),
                    ("c", "Clear"),
                    ("?", "Ask"),
                    ("Esc", "Stop+Close"),
                    ("Tab", "Procs"),
                    ("q", "Quit"),
                ]
            elif self._unified_log_mode:
                shortcuts = [
                    ("\u2191\u2193", "Scroll"),
                    ("PgU/D", "Page"),
                    ("c", "Clear"),
                    ("?", "Ask"),
                    ("Esc", "Stop+Close"),
                    ("Tab", "Procs"),
                    ("q", "Quit"),
                ]
            else:
                shortcuts = [
                    ("\u2191\u2193", "Select"),
                    ("k", "Kill proc"),
                    ("?", "Ask"),
                    ("N", "Close"),
                    ("Tab", "Procs"),
                    ("Esc", "Back"),
                    ("q", "Quit"),
                ]
        elif self._net_mode:
            shortcuts = [
                ("Tab", "Conns"),
                ("g", "Orbit"),
                ("k", "Kill proc"),
                ("?", "Ask"),
                ("N", "Close"),
                ("Esc", "Back"),
                ("q", "Quit"),
            ]
        else:
            shortcuts = [
                ("s", "Sort"),
                ("F", "Process"),
                ("N", "Net"),
                ("T", "Triage"),
                ("G", "Galaxy"),
                ("r", "Replay"),
                ("?", "Ask"),
                ("U", "PIDlog"),
                ("L", "Log"),
                ("f", "Filter"),
                ("C", "Config"),
                ("PgU/D", "Page"),
                ("k", "Kill"),
                ("q", "Quit"),
            ]
        y = h - 1
        x = 0
        for key, label in shortcuts:
            if x >= w:
                break
            key_str = f" {key}"
            label_str = f"{label} "
            # Key part: bold/highlighted
            self._put(y, x, key_str[:w - x], curses.color_pair(4) | curses.A_BOLD)
            x += len(key_str)
            if x >= w:
                break
            # Label part: normal on black
            self._put(y, x, label_str[:w - x], curses.color_pair(3))
            x += len(label_str)
        # Fill remainder
        if x < w:
            self._put(y, x, " " * (w - x), curses.color_pair(3))

    def _put(self, y, x, text, attr=0):
        h, w = self.stdscr.getmaxyx()
        if 0 <= y < h and x < w:
            try:
                self.stdscr.addnstr(y, x, text, w - x, attr)
            except curses.error:
                pass

    def _page_size(self):
        """Visible list height for page up/down."""
        h, _ = self.stdscr.getmaxyx()
        # header(1) + totals(1) + col_header(1) + shortcut_bar(1) + detail_box(~7)
        return max(1, h - 12)

    def handle_input(self, key):
        # Log overlay intercepts next — so you can pop it open and see
        # what went wrong without losing the underlying context.
        if self._log_mode:
            return self._handle_log_input(key)
        # Chat overlay intercepts everything so it works from any window
        if self._chat_mode:
            return self._handle_chat_input(key)
        # `L` opens the debug log from anywhere.
        if key == ord("L"):
            self._toggle_log_mode()
            return True
        # `?` opens the chat overlay from anywhere (main list, detail focus,
        # any forensic mode). Auto-captures the current context as system
        # prompt so follow-ups stay grounded in what's on screen.
        if key == ord("?"):
            self._enter_chat_mode()
            return True
        # Detail box has focus — dispatch to the active mode
        if self._detail_focus:
            if self._inspect_mode:
                if key == curses.KEY_UP:
                    self._inspect_scroll = max(0, self._inspect_scroll - 1)
                elif key == curses.KEY_DOWN:
                    self._inspect_scroll += 1
                elif key == curses.KEY_PPAGE:
                    self._inspect_scroll = max(0, self._inspect_scroll - self._page_size())
                elif key == curses.KEY_NPAGE:
                    self._inspect_scroll += self._page_size()
                elif key == ord("I"):
                    self._toggle_inspect_mode()
                elif key == ord("\t"):
                    self._detail_focus = False
                elif key == 27:
                    self._inspect_mode = False
                    self._detail_focus = False
                elif key == ord("q"):
                    return False
                return True
            elif self._audit_mode:
                if key == curses.KEY_UP:
                    if self._audit_findings_structured:
                        self._audit_move_cursor(-1)
                    else:
                        self._audit_scroll = max(0, self._audit_scroll - 1)
                elif key == curses.KEY_DOWN:
                    if self._audit_findings_structured:
                        self._audit_move_cursor(1)
                    else:
                        self._audit_scroll += 1
                elif key == curses.KEY_PPAGE:
                    self._audit_scroll = max(0, self._audit_scroll - self._page_size())
                elif key == curses.KEY_NPAGE:
                    self._audit_scroll += self._page_size()
                elif key in (ord("D"), ord("d")):
                    self._audit_remediate_current()
                elif key in (ord("r"), ord("R")):
                    self._start_audit()  # rescan
                elif key == ord("\t"):
                    self._detail_focus = False
                elif key == 27:
                    self._audit_mode = False
                    self._detail_focus = False
                elif key == ord("q"):
                    return False
                return True
            elif self._events_mode:
                if key == curses.KEY_UP:
                    self._events_scroll = max(0, self._events_scroll - 1)
                elif key == curses.KEY_DOWN:
                    self._events_scroll += 1
                elif key == curses.KEY_PPAGE:
                    self._events_scroll = max(0, self._events_scroll - self._page_size())
                elif key == curses.KEY_NPAGE:
                    self._events_scroll += self._page_size()
                elif key == ord("c"):  # clear buffer
                    with self._events_lock:
                        self._events.clear()
                elif key == ord("\t"):
                    self._detail_focus = False
                elif key == 27:
                    # Two-stage close: first Esc triggers the LLM summary,
                    # a second Esc actually closes. Skip the two-stage flow
                    # when there are no events (nothing to analyse).
                    with self._events_lock:
                        n_events = len(self._events)
                    if (not self._events_awaiting_summary
                            and n_events > 0):
                        self._stop_events_stream()
                        self._events_awaiting_summary = True
                        self._start_events_llm_summary()
                    else:
                        self._stop_events_stream()
                        self._events_mode = False
                        self._detail_focus = False
                        self._events_awaiting_summary = False
                elif key == ord("q"):
                    self._stop_events_stream()
                    return False
                return True
            elif self._traffic_mode:
                if key == curses.KEY_UP:
                    self._traffic_scroll = max(0, self._traffic_scroll - 1)
                elif key == curses.KEY_DOWN:
                    self._traffic_scroll += 1
                elif key == curses.KEY_PPAGE:
                    self._traffic_scroll = max(
                        0, self._traffic_scroll - self._page_size())
                elif key == curses.KEY_NPAGE:
                    self._traffic_scroll += self._page_size()
                elif key == ord("c"):
                    with self._traffic_flows_lock:
                        self._traffic_flows.clear()
                elif key == ord("\t"):
                    self._detail_focus = False
                elif key == 27:
                    self._stop_traffic_stream()
                    self._traffic_mode = False
                    self._detail_focus = False
                elif key == ord("q"):
                    self._stop_traffic_stream()
                    return False
                return True
            elif self._unified_log_mode:
                if key == curses.KEY_UP:
                    self._unified_log_scroll = max(
                        0, self._unified_log_scroll - 1)
                elif key == curses.KEY_DOWN:
                    self._unified_log_scroll += 1
                elif key == curses.KEY_PPAGE:
                    self._unified_log_scroll = max(
                        0, self._unified_log_scroll - self._page_size())
                elif key == curses.KEY_NPAGE:
                    self._unified_log_scroll += self._page_size()
                elif key == ord("c"):
                    with self._unified_log_lock:
                        self._unified_log_lines.clear()
                elif key == ord("\t"):
                    self._detail_focus = False
                elif key == 27:
                    self._stop_unified_log_stream()
                    self._unified_log_mode = False
                    self._detail_focus = False
                elif key == ord("q"):
                    self._stop_unified_log_stream()
                    return False
                return True
            elif self._replay_mode:
                # Feature 5: Attack Chain Replay scrubbing.
                if key == curses.KEY_LEFT:
                    self._replay_step(-1)
                elif key == curses.KEY_RIGHT:
                    self._replay_step(1)
                elif key == curses.KEY_PPAGE:
                    self._replay_step(-10)
                elif key == curses.KEY_NPAGE:
                    self._replay_step(10)
                elif key == ord(" "):
                    self._replay_toggle_play()
                elif key == ord("\t"):
                    self._detail_focus = False
                elif key == 27:
                    self._exit_replay_mode()
                elif key == ord("q"):
                    return False
                return True
            else:
                # Net mode detail focus
                n = len(self._net_entries) or 1
                if key == curses.KEY_UP and self._net_selected > 0:
                    self._net_selected -= 1
                    self._scroll_net_to_selected()
                elif key == curses.KEY_DOWN and self._net_selected < n - 1:
                    self._net_selected += 1
                    self._scroll_net_to_selected()
                elif key == curses.KEY_PPAGE:
                    self._net_selected = max(0, self._net_selected - self._page_size())
                    self._scroll_net_to_selected()
                elif key == curses.KEY_NPAGE:
                    self._net_selected = min(n - 1, self._net_selected + self._page_size())
                    self._scroll_net_to_selected()
                elif key == ord("k"):
                    self._kill_net_connection_owner_process()
                elif key == ord("N"):
                    self._toggle_net_mode()
                elif key == ord("g"):
                    self._toggle_orbit_mode()
                elif key == ord("\t"):
                    self._detail_focus = False
                elif key == 27:  # Escape — close net mode
                    if self._orbit_mode:
                        self._orbit_mode = False
                    else:
                        self._net_mode = False
                        self._detail_focus = False
                elif key == ord("q"):
                    return False
                return True

        # Main process list has focus
        if key == curses.KEY_UP and self.selected > 0:
            self.selected -= 1
        elif key == curses.KEY_DOWN and self.selected < len(self.rows) - 1:
            self.selected += 1
        elif key == curses.KEY_PPAGE:
            self.selected = max(0, self.selected - self._page_size())
        elif key == curses.KEY_NPAGE:
            self.selected = min(len(self.rows) - 1, self.selected + self._page_size())
        elif key == curses.KEY_LEFT:
            self._collapse_selected()
        elif key == curses.KEY_RIGHT:
            self._expand_selected()
        elif key == ord("m"):
            self._set_sort(SORT_MEM)
        elif key == ord("c"):
            self._set_sort(SORT_CPU)
        elif key == ord("n"):
            self._set_sort(SORT_NET)
        elif key == ord("A"):
            self._set_sort(SORT_ALPHA)
        elif key == ord("V"):
            self._set_sort(SORT_VENDOR)
        elif key == ord("R"):
            self._set_sort(SORT_BYTES_IN)
        elif key == ord("O"):
            self._set_sort(SORT_BYTES_OUT)
        elif key == ord("d"):
            self._dynamic_sort = not self._dynamic_sort
            self._resort()
        elif key == ord("g"):
            self._vendor_grouped = not self._vendor_grouped
            self._resort()
        elif key == ord("s"):
            self._prompt_sort()
        elif key == ord("F"):
            self._prompt_forensic()
        elif key == ord("E"):
            self._prompt_telemetry()
        elif key == ord("N"):
            self._toggle_net_mode()
        elif key == ord("I"):
            self._toggle_inspect_mode()
        elif key == ord("T"):
            self._toggle_process_triage_mode()
        elif key == ord("U"):
            self._toggle_unified_log_mode()
        elif key == ord("G"):
            self._toggle_galaxy_mode()
        elif key == ord("r"):
            # Feature 5: enter Attack Chain Replay if a buffer was captured.
            if self._replay_mode:
                self._exit_replay_mode()
            else:
                self._start_replay_mode()
        elif key == ord("\t"):
            if (self._inspect_mode or self._net_mode
                    or self._events_mode
                    or self._audit_mode or self._traffic_mode
                    or self._unified_log_mode
                    or self._replay_mode
                    or self._galaxy_mode):
                self._detail_focus = True
        elif key == ord("C"):  # Shift+C — alert config
            self._prompt_config()
        elif key == ord("f"):
            self._prompt_filter()
        elif key == ord("k"):
            self._kill_selected()
        elif key == 27:  # Escape
            if self._galaxy_mode:
                self._galaxy_mode = False
                self._detail_focus = False
            elif self._replay_mode:
                self._exit_replay_mode()
            elif self._inspect_mode:
                self._inspect_mode = False
                self._detail_focus = False
            elif self._events_mode:
                self._stop_events_stream()
                self._events_mode = False
                self._detail_focus = False
            elif self._net_mode:
                self._net_mode = False
                self._detail_focus = False
            elif self._audit_mode:
                self._audit_mode = False
                self._detail_focus = False
            elif self._traffic_mode:
                self._stop_traffic_stream()
                self._traffic_mode = False
                self._detail_focus = False
            elif self._unified_log_mode:
                self._stop_unified_log_stream()
                self._unified_log_mode = False
                self._detail_focus = False
            else:
                return False
        elif key == ord("q"):
            return False
        return True

    def _collapse_selected(self):
        """Collapse the selected node's children (left arrow)."""
        if not self.rows:
            return
        r = self.rows[self.selected]
        if r["has_children"] and not r["is_collapsed"]:
            # Collapse this node
            self._expanded.discard(r["pid"])
            self._resort()
        elif r["depth"] > 0:
            # No children or already collapsed — jump to parent
            parent_depth = r["depth"] - 1
            for i in range(self.selected - 1, -1, -1):
                if self.rows[i]["depth"] == parent_depth:
                    self.selected = i
                    break

    def _expand_selected(self):
        """Expand the selected node's children (right arrow)."""
        if not self.rows:
            return
        r = self.rows[self.selected]
        if r["is_collapsed"]:
            self._expanded.add(r["pid"])
            self._resort()

    def _scroll_net_to_selected(self):
        """Ensure the selected net entry is visible."""
        h, _ = self.stdscr.getmaxyx()
        inner_h = max(1, h // 3)
        if self._net_selected < self._net_scroll:
            self._net_scroll = self._net_selected
        elif self._net_selected >= self._net_scroll + inner_h:
            self._net_scroll = self._net_selected - inner_h + 1

    def _kill_net_connection_owner_process(self):
        """SIGKILL the process that owns the selected network connection.

        NOTE: macOS user-space has no portable way to kill *just* one open
        socket / flow without root + pfctl/tcpkill, so this terminates the
        entire owning process. The action is gated behind a y/N confirmation
        modal so the user can't fat-finger a SIGKILL.
        """
        if not self._net_entries or self._net_selected >= len(self._net_entries):
            return
        entry = self._net_entries[self._net_selected]
        pid = entry["pid"]
        if pid <= 0:
            return
        display = entry.get("display", "")
        prompt = (
            f"SIGKILL the process owning this connection?\n"
            f"PID {pid} — entire process will be terminated, not just\n"
            f"this single flow (no per-socket kill exists in user-space\n"
            f"on macOS without pfctl/tcpkill + root).\n"
            f"\n"
            f"  {display[:80]}"
        )
        if not self._confirm_action(prompt):
            return
        try:
            os.kill(pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        # Refresh connections in background
        self._start_net_fetch(self._net_pid)

    # Backward-compatible alias kept for any external callers / tests that
    # reach in by the old name. New code should call the renamed helper.
    _kill_net_connection = _kill_net_connection_owner_process

    def _do_refresh_net_bytes(self, root_pid):
        """Fetch nettop flow data + re-fetch connections. Called from background thread."""
        pids = self._get_subtree_pids(root_pid)
        try:
            cmd = ["nettop", "-L", "1", "-x", "-J", "bytes_in,bytes_out", "-n"]
            for p in pids:
                cmd += ["-p", str(p)]
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            try:
                stdout, _ = proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
                stdout = b""
        except (FileNotFoundError, OSError):
            stdout = b""

        # Parse per-flow lines
        flow_bytes = {}
        for line in stdout.decode("utf-8", errors="replace").splitlines():
            if line.startswith(",") or not line.strip():
                continue
            parts = line.rstrip(",").split(",")
            if len(parts) < 3:
                continue
            flow_id = parts[0].strip()
            try:
                b_in = int(parts[1])
                b_out = int(parts[2])
            except (ValueError, IndexError):
                continue
            if "<->" in flow_id:
                addr_part = flow_id.split(None, 1)[-1] if " " in flow_id else flow_id
                addr_key = addr_part.replace("<->", "->")
                flow_bytes[addr_key] = (b_in, b_out)

        # Update byte cache (safe — only this thread writes these keys)
        for e in self._net_entries:
            addr = e.get("addr_key", "")
            if addr in flow_bytes:
                key = (e["pid"], e["fd"])
                self._net_bytes[key] = flow_bytes[addr]

        # Re-fetch connections and store as pending result
        result = self._fetch_net_connections(root_pid)
        self._net_pending = result

    # ── Feature 6: Network Orbit / Constellation ───────────────────────

    def _toggle_orbit_mode(self):
        """Toggle orbit (constellation) view of remote endpoints.

        Only valid while net mode is active — pressing `g` from net mode.
        """
        if not self._net_mode:
            return
        self._orbit_mode = not self._orbit_mode

    @staticmethod
    def _orbit_layout(n_remotes, center, radius):
        """Place `n_remotes` nodes evenly on a circle around `center`.

        Returns a list of (x, y) integer tuples.
        """
        import math
        cx, cy = center
        out = []
        if n_remotes <= 0:
            return out
        for i in range(n_remotes):
            angle = (i / n_remotes) * 2 * math.pi
            x = int(round(cx + radius * 2.0 * math.cos(angle)))
            y = int(round(cy + radius * math.sin(angle)))
            out.append((x, y))
        return out

    @staticmethod
    def _orbit_particle_position(start, end, tick, length=None):
        """Compute the particle's (x, y) position along an edge for tick.

        The particle wraps around with period max(1, length); when length
        is None the path length is the chebyshev distance between start
        and end.
        """
        sx, sy = start
        ex, ey = end
        dx = ex - sx
        dy = ey - sy
        path_len = max(abs(dx), abs(dy)) or 1
        if length is None:
            length = path_len
        t = (tick % max(1, length)) / max(1, length)
        x = int(round(sx + dx * t))
        y = int(round(sy + dy * t))
        return (x, y)

    @staticmethod
    def _orbit_edge_color(proto, service):
        """Return a color_pair for the edge based on proto + service."""
        s = (service or "").lower()
        if "https" in s or s == "443":
            return 9   # blue
        if "http" in s:
            return 3   # yellow
        if "ssh" in s:
            return 7   # cyan
        if (proto or "").upper() == "UDP":
            return 8   # magenta
        return 10  # default grey/white

    def _build_orbit_lines(self, w, h):
        """Render the orbit constellation as text lines (no curses calls)."""
        # Box dimensions: leave 1-cell padding all around.
        if w < 30 or h < 10:
            return [" Orbit view needs a larger window"]
        # Render onto a 2D character grid.
        grid_h = max(10, h - 4)
        grid_w = max(30, w - 6)
        grid = [[" "] * grid_w for _ in range(grid_h)]
        labels = []  # (y, x, text) drawn after edges so they sit on top
        cx, cy = grid_w // 2, grid_h // 2
        radius = min(grid_w // 4, grid_h // 3)

        # Center node — selected PID
        grid[cy][cx] = "●"
        center_text = f"PID {self._net_pid}"
        # Place center label below the dot
        if cy + 1 < grid_h:
            for i, ch in enumerate(center_text[:grid_w - cx]):
                if cx + i < grid_w:
                    grid[cy + 1][cx + i] = ch

        # Remote endpoints
        remotes = list(self._net_entries[:16])  # cap so it stays readable
        positions = self._orbit_layout(len(remotes), (cx, cy), radius)

        for (rx, ry), entry in zip(positions, remotes):
            rx = max(1, min(grid_w - 2, rx))
            ry = max(1, min(grid_h - 2, ry))
            # Draw edge line with Bresenham, picking color glyph based on
            # service.
            self._orbit_draw_line(grid, (cx, cy), (rx, ry))
            # Endpoint dot
            grid[ry][rx] = "○"
            # Label: service[:port] [Org]
            port = ""
            ak = entry.get("addr_key", "")
            if "->" in ak:
                dst = ak.split("->", 1)[1]
                if ":" in dst:
                    port = dst.rsplit(":", 1)[1]
            svc = entry.get("service", "") or ""
            org = entry.get("org", "") or ""
            short_org = (org[:14]) if org else ""
            text = svc or port
            if short_org:
                text += f" [{short_org}]"
            labels.append((ry, rx, text))

        # Animated particles — one per edge.
        self._orbit_tick = (self._orbit_tick + 1) % 1000
        for (rx, ry), entry in zip(positions, remotes):
            if rx < 0 or ry < 0:
                continue
            rx2 = max(1, min(grid_w - 2, rx))
            ry2 = max(1, min(grid_h - 2, ry))
            px, py = self._orbit_particle_position(
                (cx, cy), (rx2, ry2), self._orbit_tick)
            if 0 <= px < grid_w and 0 <= py < grid_h:
                # Don't overwrite endpoints
                if (px, py) != (cx, cy) and (px, py) != (rx2, ry2):
                    grid[py][px] = "●"

        # Overlay labels — clip if they would run off the right edge.
        for ly, lx, text in labels:
            for i, ch in enumerate(text):
                tx = lx + 2 + i
                ty = ly
                if 0 <= tx < grid_w and 0 <= ty < grid_h:
                    grid[ty][tx] = ch

        # Convert to lines.
        return ["".join(row) for row in grid]

    @staticmethod
    def _orbit_draw_line(grid, start, end):
        """Bresenham line with light Braille-block glyphs."""
        h = len(grid)
        w = len(grid[0]) if grid else 0
        x0, y0 = start
        x1, y1 = end
        dx = abs(x1 - x0)
        dy = abs(y1 - y0)
        sx = 1 if x0 < x1 else -1
        sy = 1 if y0 < y1 else -1
        err = dx - dy
        steps = 0
        while True:
            if 0 <= x0 < w and 0 <= y0 < h and grid[y0][x0] == " ":
                grid[y0][x0] = "·"
            if x0 == x1 and y0 == y1:
                break
            e2 = 2 * err
            if e2 > -dy:
                err -= dy
                x0 += sx
            if e2 < dx:
                err += dx
                y0 += sy
            steps += 1
            if steps > 4 * (w + h):  # safety guard
                break

    # ── Feature 7: Process Galaxy ──────────────────────────────────────

    def _toggle_galaxy_mode(self):
        """Toggle the force-directed process galaxy view."""
        if self._galaxy_mode:
            self._galaxy_mode = False
            self._detail_focus = False
            return
        self._galaxy_mode = True
        # Close mutually-exclusive modes
        self._inspect_mode = False
        self._net_mode = False
        self._audit_mode = False
        if getattr(self, "_events_mode", False):
            self._stop_events_stream()
            self._events_mode = False
        self._detail_focus = True
        # Reset positions so a fresh layout settles in.
        self._galaxy_positions = {}
        self._galaxy_velocity = {}
        self._galaxy_glow = {}
        self._galaxy_fork_rings = {}
        self._galaxy_trails = collections.deque(maxlen=3)
        self._galaxy_pulse_phase = 0
        self._galaxy_known_pids = set()

    def _galaxy_select_nodes(self):
        """Pick up to `_galaxy_node_cap` PIDs ranked by combined load
        (CPU + memory share), AND drop pure-idle processes so the
        canvas isn't clogged with dim dots that have no story to tell.

        A process qualifies if it has a non-trivial load score (>= 0.05)
        OR is a parent/child of a qualifying process (so the tree
        topology of an active subtree stays visible). Anything else is
        hidden from the galaxy entirely; the count is summarised in
        the panel header.
        """
        total_mem = max(1, self._total_mem_kb)
        def _score(r):
            cpu = r.get("agg_cpu", r.get("cpu", 0)) or 0
            rss = r.get("agg_rss_kb", r.get("rss_kb", 0)) or 0
            return cpu + (rss / total_mem) * 100.0
        scored = [(r, _score(r)) for r in self.rows]
        # Stage 1: keep all scored ≥ 0.05 (the "interesting" set)
        threshold = 0.05
        interesting_pids = {r["pid"] for r, s in scored if s >= threshold}
        # Stage 2: include direct parents/children of interesting
        # so chains of active subtree members stay connected.
        by_pid = {r["pid"]: r for r in self.rows}
        connect = set()
        for pid in interesting_pids:
            r = by_pid.get(pid)
            if r:
                ppid = r.get("ppid", 0)
                if ppid and ppid in by_pid and ppid not in interesting_pids:
                    connect.add(ppid)
        for r in self.rows:
            if r.get("ppid") in interesting_pids and r["pid"] not in interesting_pids:
                connect.add(r["pid"])
        kept = interesting_pids | connect
        sorted_rows = sorted(
            (r for r, _ in scored if r["pid"] in kept),
            key=lambda r: _score(r),
            reverse=True,
        )
        # Track how many we hid so the header can advertise it.
        self._galaxy_hidden_count = len(self.rows) - len(sorted_rows)
        return sorted_rows[: self._galaxy_node_cap]

    @staticmethod
    def _galaxy_short_name(row):
        """Crypto-bubble-style ticker for a process row.

        Caveat: app-bundle paths legitimately contain spaces
        (`/Applications/Google Chrome.app/...`), so we can't just
        split on whitespace to drop args — we look for " -" or " --"
        as the conventional flag separator instead.

        For app bundles, prefer the bundle name when the binary
        basename matches it; otherwise prefer the binary basename
        (so a `Google Chrome Helper` binary inside a `Google Chrome`
        bundle keeps its more specific label). Cap to 12 chars so
        the longest bubble label still fits.
        """
        cmd = (row.get("command") or "").strip()
        if not cmd:
            return "?"
        # Strip flag-style arguments (`--foo`, `-x`). Bundle paths can
        # contain spaces, so this is more reliable than `split()`.
        arg_split = cmd.find(" -")
        if arg_split > 0:
            cmd = cmd[:arg_split].rstrip()
        # App bundle: parse out the bundle name
        if ".app/" in cmd:
            bundle_part = cmd.split(".app/")[0]
            bundle_name = bundle_part.rsplit("/", 1)[-1]
            binary = cmd.rsplit("/", 1)[-1]
            if (binary != bundle_name
                    and bundle_name.lower() not in binary.lower()):
                name = binary
            else:
                name = bundle_name
        else:
            name = cmd.rsplit("/", 1)[-1]
        for ext in (".app", ".framework", ".bundle"):
            if name.endswith(ext):
                name = name[: -len(ext)]
        name = name.replace("_", " ").strip()
        if not name:
            return "?"
        return name[:12]

    def _galaxy_bubble_size(self, row):
        """Map a process's combined load to a bubble (w, h) in cells.

        Floors bumped from earlier 5×3 → 9×3 minimum so the smallest
        bubble's inner row still has 7 cells of name space — enough
        to render `Chrome`, `Slack`, `Docker`, etc. without truncation.

        Sizing tiers:
          tier 1 (faint):    9 × 3 cells  → name only (7-char inner)
          tier 2 (light):   11 × 3 cells  → 9-char inner
          tier 3 (active):  13 × 4 cells  → name + cpu%
          tier 4 (busy):    15 × 5 cells  → name + cpu% + rss
          tier 5 (heavy):   17 × 5 cells  → bigger heading, room for "Google Chrome"
        """
        total_mem = max(1, self._total_mem_kb)
        cpu = row.get("agg_cpu", row.get("cpu", 0)) or 0
        rss_kb = row.get("agg_rss_kb", row.get("rss_kb", 0)) or 0
        mem_pct = (rss_kb / total_mem) * 100.0
        score = cpu + mem_pct
        if score >= 30.0:
            return (17, 5)
        if score >= 10.0:
            return (15, 5)
        if score >= 3.0:
            return (13, 4)
        if score >= 0.5:
            return (11, 3)
        return (9, 3)

    @staticmethod
    def _galaxy_load_tier(row, total_mem_kb):
        """Quantise a row's load into a tier 0..4 used for color theming.

        Mirrors `_galaxy_bubble_size`'s tiers but returns an integer so
        the renderer can pick `(border_color, fill_color)` from a small
        lookup rather than re-deriving thresholds inline.
        """
        cpu = row.get("agg_cpu", row.get("cpu", 0)) or 0
        rss_kb = row.get("agg_rss_kb", row.get("rss_kb", 0)) or 0
        mem_pct = (rss_kb / max(1, total_mem_kb)) * 100.0
        score = cpu + mem_pct
        if score >= 30.0:
            return 4   # heavy
        if score >= 10.0:
            return 3   # busy
        if score >= 3.0:
            return 2   # active
        if score >= 0.5:
            return 1   # light
        return 0       # faint

    def _galaxy_vendor_label(self, row):
        """Best-effort vendor classification for color theming. Returns a
        short tag like 'apple' / 'google' / 'microsoft' / 'mozilla' /
        'jetbrains' / 'docker' / 'discord' / 'figma' / 'unknown'. Used
        only by the galaxy renderer to pick a fill color; for everything
        else, the existing vendor logic still applies."""
        cmd = (row.get("command") or "").lower()
        if "/applications/" in cmd or ".app/" in cmd:
            if "google chrome" in cmd or "/chrome" in cmd:
                return "google"
            if "/firefox" in cmd or "mozilla" in cmd:
                return "mozilla"
            if "microsoft " in cmd or "/teams" in cmd or "edge" in cmd:
                return "microsoft"
            if "/slack" in cmd:
                return "slack"
            if "discord" in cmd:
                return "discord"
            if "spotify" in cmd:
                return "spotify"
            if "/figma" in cmd:
                return "figma"
            if "docker" in cmd:
                return "docker"
            if "jetbrains" in cmd or "/idea" in cmd or "/pycharm" in cmd:
                return "jetbrains"
            if "code helper" in cmd or "visual studio code" in cmd or "/code" in cmd:
                return "vscode"
        if cmd.startswith("/system/") or cmd.startswith("/usr/libexec/"):
            return "apple"
        if cmd.startswith("/usr/bin/") or cmd.startswith("/sbin/"):
            return "apple"
        if cmd.startswith("/bin/") or cmd.startswith("/usr/sbin/"):
            return "apple"
        return "unknown"

    def _galaxy_step(self, w, h):
        """Crypto-bubble floating cluster layout.

        Each tick we (1) drift every bubble by its small random velocity
        (vertical drift dampened by ~50% so the cluster looks stable
        rather than jittery), (2) bounce off the canvas walls, (3) run
        a few iterations of overlap-resolution that push intersecting
        rectangles apart along the smallest-overlap axis. New bubbles
        spawn near the center with a gaussian scatter; heavier bubbles
        drift more slowly so they anchor the centre of mass like the
        big coins on coin360. Glow + position persistence still carry
        over.
        """
        import random
        # Tick the pulse phase counter (0..5, wrapping).
        self._galaxy_pulse_phase = (self._galaxy_pulse_phase + 1) % 6
        # Heat trail snapshot: capture the positions AT THIS POINT
        # (i.e. the result of the previous tick) so the renderer can
        # draw a fading trail behind each moving bubble. The deque is
        # capped at 3 entries by the maxlen so memory is bounded.
        if self._galaxy_positions:
            self._galaxy_trails.append(
                {pid: tuple(pos)
                 for pid, pos in self._galaxy_positions.items()})
        nodes = self._galaxy_select_nodes()
        node_pids = [r["pid"] for r in nodes]
        node_set = set(node_pids)

        # Glow / known-pid tracking (same lifecycle as before).
        for pid in node_pids:
            if pid not in self._galaxy_known_pids:
                self._galaxy_glow[pid] = 6
                # Fork ring counter starts at 0; advances with each
                # tick so the renderer can draw expanding concentric
                # rings around the newly-born bubble.
                self._galaxy_fork_rings[pid] = 0
        for pid in list(self._galaxy_glow.keys()):
            if pid not in node_set:
                self._galaxy_glow.pop(pid, None)
                continue
            if self._galaxy_glow[pid] > 0:
                self._galaxy_glow[pid] -= 1
            else:
                self._galaxy_glow.pop(pid, None)
        # Advance fork ring counters; pop after 5 frames or if the PID
        # disappears entirely.
        for pid in list(self._galaxy_fork_rings.keys()):
            if pid not in node_set:
                self._galaxy_fork_rings.pop(pid, None)
                continue
            self._galaxy_fork_rings[pid] += 1
            if self._galaxy_fork_rings[pid] > 5:
                self._galaxy_fork_rings.pop(pid, None)
        self._galaxy_known_pids = node_set

        # Drop positions/velocities for PIDs that left the snapshot.
        for pid in list(self._galaxy_positions.keys()):
            if pid not in node_set:
                self._galaxy_positions.pop(pid, None)
                self._galaxy_velocity.pop(pid, None)

        if not node_pids:
            return

        bound_w = max(20, w - 2)
        bound_h = max(6, h - 2)
        sizes = {r["pid"]: self._galaxy_bubble_size(r) for r in nodes}

        # Initial placement for new PIDs: center-biased gaussian, which
        # gives a clustered look right away rather than a uniform random
        # field. Velocity is small + heavier bubbles drift slower so the
        # heaviest cards anchor the cluster.
        cx = bound_w / 2.0
        cy = bound_h / 2.0
        # Aspect correction: terminal cells are ~2:1 (h:w), so for an
        # initial cluster that *looks* round, sigma on x should be
        # roughly twice sigma on y. Cap by canvas extent so the spawn
        # never lands outside the visible area.
        radius = min(bound_w / 4.0, bound_h / 2.0)
        sigma_x = max(4.0, radius)
        sigma_y = max(2.0, radius / 2.0)
        for r in nodes:
            pid = r["pid"]
            bw, bh = sizes[pid]
            if pid not in self._galaxy_positions:
                x = cx + random.gauss(0, sigma_x)
                y = cy + random.gauss(0, sigma_y)
                x = max(bw / 2.0, min(bound_w - bw / 2.0, x))
                y = max(bh / 2.0, min(bound_h - bh / 2.0, y))
                self._galaxy_positions[pid] = (x, y)
                # Heavier = slower drift. Use bubble area as mass.
                mass = bw * bh
                speed_x = 0.35 / (mass / 60.0 + 1.0)
                speed_y = 0.18 / (mass / 60.0 + 1.0)
                self._galaxy_velocity[pid] = (
                    random.uniform(-speed_x, speed_x),
                    random.uniform(-speed_y, speed_y),
                )

        # 1) Drift + wall bounce
        for pid in node_pids:
            x, y = self._galaxy_positions[pid]
            vx, vy = self._galaxy_velocity.get(pid, (0.0, 0.0))
            bw, bh = sizes[pid]
            x += vx
            y += vy
            if x < bw / 2.0:
                x = bw / 2.0
                vx = -vx
            elif x > bound_w - bw / 2.0:
                x = bound_w - bw / 2.0
                vx = -vx
            if y < bh / 2.0:
                y = bh / 2.0
                vy = -vy
            elif y > bound_h - bh / 2.0:
                y = bound_h - bh / 2.0
                vy = -vy
            self._galaxy_positions[pid] = (x, y)
            self._galaxy_velocity[pid] = (vx, vy)

        # 2) Overlap resolution — separate intersecting rectangles
        # along the axis where they overlap less. Heavier bubbles
        # absorb less of the push (mass-weighted split) so they stay
        # roughly where they are while light ones get nudged out.
        # Terminal cells are ~2:1 (h:w), so visually a "1 cell tall"
        # gap reads as twice the size of a "1 cell wide" gap. We bias
        # the smallest-overlap axis selection by scaling Y separation
        # by 2.0, which makes the cluster spread vertically as well
        # as horizontally and looks roughly circular on screen.
        for _ in range(4):
            for i, p in enumerate(node_pids):
                px, py = self._galaxy_positions[p]
                pw, ph = sizes[p]
                p_mass = pw * ph
                for j in range(i + 1, len(node_pids)):
                    q = node_pids[j]
                    qx, qy = self._galaxy_positions[q]
                    qw, qh = sizes[q]
                    q_mass = qw * qh
                    dx = px - qx
                    dy = py - qy
                    min_dx = (pw + qw) / 2.0 + 1.0
                    # Aspect correction: terminal cells are ~2:1
                    # (h:w), so 1 cell of vertical drift reads as
                    # ~2 cells of horizontal drift on screen. To get
                    # a visually-circular cluster, scale required
                    # vertical separation by ~2 so bubbles stack
                    # taller before they crowd each other out.
                    min_dy = ((ph + qh) / 2.0 + 1.0) * 2.0
                    ox = abs(dx) - min_dx
                    oy = abs(dy) - min_dy
                    # Both must be negative for the rectangles to
                    # actually overlap — the bigger of the two
                    # negatives is the smaller-overlap axis (push
                    # along that one to minimise displacement).
                    if ox >= 0 or oy >= 0:
                        continue
                    if -ox < -oy:
                        push = -ox + 0.001
                        total_mass = p_mass + q_mass
                        share_p = q_mass / total_mass
                        share_q = p_mass / total_mass
                        if dx >= 0:
                            px += push * share_p
                            qx -= push * share_q
                        else:
                            px -= push * share_p
                            qx += push * share_q
                    else:
                        push = -oy + 0.001
                        total_mass = p_mass + q_mass
                        share_p = q_mass / total_mass
                        share_q = p_mass / total_mass
                        if dy >= 0:
                            py += push * share_p
                            qy -= push * share_q
                        else:
                            py -= push * share_p
                            qy += push * share_q
                    # Clamp into canvas bounds after push.
                    px = max(pw / 2.0, min(bound_w - pw / 2.0, px))
                    py = max(ph / 2.0, min(bound_h - ph / 2.0, py))
                    qx = max(qw / 2.0, min(bound_w - qw / 2.0, qx))
                    qy = max(qh / 2.0, min(bound_h - qh / 2.0, qy))
                    self._galaxy_positions[p] = (px, py)
                    self._galaxy_positions[q] = (qx, qy)

    def _galaxy_render_bubble(self, row, bw, bh):
        """Render a single bubble as a list of `bh` strings of width `bw`.

        Uses Unicode rounded box-drawing for the border and centers
        the abbreviated process name inside. For larger tiers, also
        renders a CPU% (and RSS for the largest tier) so the bubble
        carries useful at-a-glance information like a crypto-bubble
        widget. Glowing (newly-spawned) processes get a `★` prefix
        on their label.
        """
        name = self._galaxy_short_name(row)
        glow = bool(self._galaxy_glow.get(row.get("pid")))
        if glow:
            name = "★" + name
            name = name[: max(1, bw - 2)]
        # Vendor glyph: prepend a single-cell logo so the cluster has
        # an at-a-glance vendor cue even before colors register. Trim
        # the name by 2 cells (glyph + space) to make room.
        vendor = self._galaxy_vendor_label(row)
        vendor_glyph = self._GALAXY_VENDOR_GLYPHS.get(
            vendor, self._GALAXY_VENDOR_GLYPHS["unknown"])
        # Reserve glyph + space for it; only when the bubble is wide
        # enough to fit (otherwise just keep the name centered).
        if bw - 2 >= 4:
            name = name[: max(1, bw - 2 - 2)]
            name = f"{vendor_glyph} {name}"
        cpu = row.get("agg_cpu", row.get("cpu", 0)) or 0
        rss_kb = row.get("agg_rss_kb", row.get("rss_kb", 0)) or 0

        def _center(text, width):
            text = text[:width]
            pad = width - len(text)
            left = pad // 2
            right = pad - left
            return " " * left + text + " " * right

        inner_w = max(1, bw - 2)
        # Build the inner content lines (between the top/bottom borders).
        inner_lines = []
        if bh <= 3:
            inner_lines.append(_center(name, inner_w))
        elif bh == 4:
            inner_lines.append(_center(name, inner_w))
            inner_lines.append(_center(f"{cpu:.0f}%", inner_w))
        else:
            # bh >= 5: name, cpu, rss
            inner_lines.append(_center(name, inner_w))
            inner_lines.append(_center(f"{cpu:.0f}%", inner_w))
            if rss_kb >= 1024 * 1024:
                rss_label = f"{rss_kb / (1024 * 1024):.1f}G"
            elif rss_kb >= 1024:
                rss_label = f"{rss_kb / 1024:.0f}M"
            else:
                rss_label = f"{rss_kb}K"
            inner_lines.append(_center(rss_label, inner_w))
            # Pad to exactly bh - 2 inner rows
            while len(inner_lines) < bh - 2:
                inner_lines.append(" " * inner_w)
        # Trim if we somehow generated extra
        inner_lines = inner_lines[: bh - 2]

        # Mini-sparkline on the bottom inner row for tier ≥3 bubbles
        # (size 13+). Pulls the recent CPU history from the per-PID
        # ring buffer the existing TREND code already populates. Brand
        # new PIDs with no samples render a blank row, no crash.
        if bw >= 13 and len(inner_lines) >= 1:
            pid = row.get("pid")
            spark_chars = ""
            hist = self._metric_history.get(pid) if pid is not None else None
            if hist:
                cpu_dq = hist.get("cpu")
                if cpu_dq:
                    samples = list(cpu_dq)[-inner_w:]
                    spark_chars = _sparkline(samples, width=inner_w)
            spark_line = _center(spark_chars, inner_w) if spark_chars \
                else " " * inner_w
            inner_lines[-1] = spark_line
        top = "╭" + "─" * inner_w + "╮"
        bot = "╰" + "─" * inner_w + "╯"
        return [top] + ["│" + line + "│" for line in inner_lines] + [bot]

    @staticmethod
    def _galaxy_trend_badge(samples):
        """Pick a trend glyph from a list of recent CPU samples.

        Compares the median of the newest 3 vs the median of the
        oldest 3 (out of the last 5 samples). Returns one of:
          - ('↑', 1)  rising    → green (color pair 1)
          - ('↓', 5)  falling   → red   (color pair 5)
          - ('→', 10) flat      → light grey, dim
          - (None, 0)           if too few samples to call it
        """
        if not samples or len(samples) < 5:
            return (None, 0)
        last5 = list(samples)[-5:]
        oldest3 = sorted(last5[:3])
        newest3 = sorted(last5[-3:])
        med_old = oldest3[len(oldest3) // 2]
        med_new = newest3[len(newest3) // 2]
        delta = med_new - med_old
        if delta > 2.0:
            return ("↑", 1)
        if delta < -2.0:
            return ("↓", 5)
        return ("→", 10)

    # Vendor → single-cell logo glyph rendered before the bubble's
    # centered name. Emoji widths in curses are unreliable, so we use
    # ASCII-safe glyphs that always occupy exactly one cell.
    _GALAXY_VENDOR_GLYPHS = {
        "google":     "@",
        "apple":      "*",
        "microsoft":  "W",
        "mozilla":    "F",
        "slack":      "#",
        "discord":    "D",
        "spotify":    "S",
        "figma":      "+",
        "docker":     "D",
        "jetbrains":  "J",
        "vscode":     "C",
        "unknown":    "~",
    }

    # Vendor → curses color_pair_id (declared in __init__'s init_pair table).
    _GALAXY_VENDOR_COLORS = {
        "google":     9,   # steel blue
        "apple":      1,   # green
        "microsoft":  7,   # cyan
        "mozilla":    6,   # orange
        "slack":      8,   # magenta
        "discord":    8,   # magenta
        "spotify":    1,   # green (Spotify brand)
        "figma":     12,   # salmon
        "docker":     9,   # steel blue
        "jetbrains":  3,   # yellow
        "vscode":     9,   # steel blue
        "unknown":   10,   # light grey
    }
    # Load tier → color when vendor is unknown.
    _GALAXY_TIER_COLORS = {
        0: 10,   # faint: light grey
        1:  1,   # light: green
        2:  7,   # active: cyan
        3:  6,   # busy: orange
        4:  5,   # heavy: red
    }

    def _galaxy_render_fullscreen(self, w, h):
        """Render the galaxy as the entire screen (header + bubble grid +
        shortcut bar). Bypasses the split-view layout so heavy bubbles
        get all the room they need.

        The header at row 0 carries the title + cull count + a hint
        about how to exit (`G` toggles, `Esc` closes). Rows 1 → h-2 are
        the bubble canvas. The caller is responsible for rendering the
        shortcut bar at row h-1.
        """
        # Header row
        nodes = self._galaxy_select_nodes()
        hidden = getattr(self, "_galaxy_hidden_count", 0)
        title = (f" Process Galaxy — {len(nodes)} bubbles"
                 + (f"  (+{hidden} idle hidden)" if hidden else "")
                 + "  · sized by load · grouped by vendor color")

        # Totals strip computed from the current visible cluster.
        total_cpu = sum(
            (r.get("agg_cpu", r.get("cpu", 0)) or 0) for r in nodes)
        total_rss_kb = sum(
            (r.get("agg_rss_kb", r.get("rss_kb", 0)) or 0) for r in nodes)
        if total_rss_kb >= 1024 * 1024:
            rss_label = f"{total_rss_kb / (1024 * 1024):.1f}G"
        elif total_rss_kb >= 1024:
            rss_label = f"{total_rss_kb / 1024:.0f}M"
        else:
            rss_label = f"{total_rss_kb}K"
        vendor_count = len({self._galaxy_vendor_label(r) for r in nodes})
        totals = (f" · {len(nodes)} procs · {total_cpu:.0f}% CPU"
                  f" · {rss_label} RSS · {vendor_count} vendors ")

        try:
            self._put(0, 0, " " * w, curses.color_pair(2) | curses.A_BOLD)
            self._put(0, 0, title[:w], curses.color_pair(2) | curses.A_BOLD)
            hint = " G/Esc to close "
            # Place totals to the right of the title (left-aligned),
            # but only if there's room for both totals + hint.
            totals_x = len(title) + 1
            if w - len(hint) - totals_x >= len(totals):
                self._put(0, totals_x, totals,
                          curses.color_pair(2) | curses.A_BOLD)
            if w > len(hint) + len(title) + 4:
                self._put(0, w - len(hint),
                          hint, curses.color_pair(2) | curses.A_BOLD)
        except curses.error:
            pass

        # Body bounds — rows 1 .. h-3 inclusive (h-2 is the vendor
        # legend row, h-1 is the global shortcut bar).
        body_top = 1
        body_h = max(6, h - 3 - body_top + 1)
        body_w = w
        if w < 30 or body_h < 6:
            try:
                self._put(body_top, 0,
                          " Galaxy view needs a larger window".ljust(w),
                          curses.color_pair(10))
            except curses.error:
                pass
            return

        # Lay out the grid for this canvas size.
        self._galaxy_step(body_w, body_h)

        # Cell grid: (char, color_pair_id, extra_attrs).
        EMPTY = (" ", 0, 0)
        grid = [[EMPTY for _ in range(body_w)] for _ in range(body_h)]

        # Starfield: deterministic procedural background painted before
        # bubbles, so visible stars only show in empty regions. Pattern
        # is keyed on (canvas_x, canvas_y) so it doesn't shimmer between
        # frames (no random state to manage).
        for sy in range(body_h):
            for sx in range(body_w):
                k = (sx * 73 + sy * 131) & 0xFFFF
                if k % 17 == 0:
                    grid[sy][sx] = ("·", 10, curses.A_DIM)
                elif k % 31 == 0:
                    grid[sy][sx] = ("⋅", 10, curses.A_DIM)

        # Heat trails: paint past-frame positions of each PID as
        # progressively dimmer dots so the cluster looks like it's
        # drifting rather than teleporting. Older snapshots are at
        # lower indices in the deque, so they should fade more.
        trail_attrs = [curses.A_DIM, curses.A_DIM, 0]
        for ti, snapshot in enumerate(self._galaxy_trails):
            attr = trail_attrs[min(ti, len(trail_attrs) - 1)]
            for pid, (tx, ty) in snapshot.items():
                ix = int(round(tx))
                iy = int(round(ty))
                if 0 <= ix < body_w and 0 <= iy < body_h:
                    grid[iy][ix] = ("·", 10, attr)

        # Fork-ring pulse: for each newly-spotted PID, draw an
        # expanding concentric ring of `·` glyphs that grows by one
        # cell per frame for 5 frames, then fades and is popped. We
        # paint these BEFORE the bubbles so the ring appears around
        # (not inside) each bubble.
        import math as _ring_math
        for r in nodes:
            ring_pid = r["pid"]
            frames = self._galaxy_fork_rings.get(ring_pid)
            if frames is None or frames > 5:
                continue
            pos = self._galaxy_positions.get(ring_pid)
            if pos is None:
                continue
            cx_r, cy_r = pos
            bw_r, bh_r = self._galaxy_bubble_size(r)
            half = max(bw_r, bh_r * 2) // 2  # diagonal-ish half size
            radius = half + frames
            ring_extra = curses.A_BOLD if frames < 3 else curses.A_DIM
            # Sweep around the ring; quantise to grid cells.
            steps = max(8, int(2 * _ring_math.pi * radius))
            seen = set()
            for s in range(steps):
                ang = (2 * _ring_math.pi) * s / steps
                # Compress y by 2 to compensate for terminal aspect.
                rx = int(round(cx_r + radius * _ring_math.cos(ang)))
                ry = int(round(cy_r + (radius / 2.0) * _ring_math.sin(ang)))
                if (rx, ry) in seen:
                    continue
                seen.add((rx, ry))
                if 0 <= ry < body_h and 0 <= rx < body_w:
                    grid[ry][rx] = ("·", 3, ring_extra)

        # Bubbles. In grid-fill mode we don't draw parent-child edges
        # (they'd cross other bubbles awkwardly and detract from the
        # crypto-bubble look). Edges live in the legacy split-view path.
        sized = []
        for r in nodes:
            bw, bh = self._galaxy_bubble_size(r)
            sized.append((bw * bh, r, bw, bh))
        # Smallest first so heavy ones overdraw.
        sized.sort(key=lambda t: t[0])
        total_mem = max(1, self._total_mem_kb)
        for _area, r, bw, bh in sized:
            pid = r["pid"]
            pos = self._galaxy_positions.get(pid)
            if pos is None:
                continue
            x, y = pos
            x0 = int(x) - bw // 2
            y0 = int(y) - bh // 2
            # In grid-fill mode the layout is already row-aligned; just
            # clamp to canvas bounds in case of a tight overflow.
            x0 = max(0, min(body_w - bw, x0))
            y0 = max(0, min(body_h - bh, y0))
            tier = self._galaxy_load_tier(r, total_mem)
            vendor = self._galaxy_vendor_label(r)
            fill_pair = self._GALAXY_VENDOR_COLORS.get(
                vendor, self._GALAXY_TIER_COLORS[tier])
            border_pair = self._GALAXY_TIER_COLORS[tier]
            border_extra = curses.A_BOLD if tier >= 3 else 0
            inner_extra = curses.A_REVERSE
            # Pulse animation on tier-4+ bubbles: bold for 3 frames,
            # plain reverse for 3 frames, on a 6-tick cycle. Drives a
            # visible heartbeat on the heavy bubbles only.
            if tier >= 4 and self._galaxy_pulse_phase < 3:
                inner_extra |= curses.A_BOLD
            glow = bool(self._galaxy_glow.get(pid))
            if glow:
                border_pair = 3
                border_extra |= curses.A_BOLD | curses.A_BLINK
            cpu_val = r.get("agg_cpu", r.get("cpu", 0)) or 0
            anomaly = cpu_val >= 80.0
            lines = self._galaxy_render_bubble(r, bw, bh)
            for dy, line in enumerate(lines):
                row_y = y0 + dy
                if not (0 <= row_y < body_h):
                    continue
                is_top_or_bot = (dy == 0 or dy == bh - 1)
                for dx, ch in enumerate(line):
                    col_x = x0 + dx
                    if not (0 <= col_x < body_w):
                        continue
                    is_side = (dx == 0 or dx == bw - 1) and not is_top_or_bot
                    if is_top_or_bot or is_side:
                        grid[row_y][col_x] = (ch, border_pair, border_extra)
                    else:
                        attr_extra = inner_extra
                        if anomaly:
                            attr_extra |= curses.A_BLINK
                        grid[row_y][col_x] = (ch, fill_pair, attr_extra)

            # Trend badge: replace the rightmost cell of the top
            # border with an ↑/↓/→ glyph based on recent CPU history.
            badge_x = x0 + bw - 1
            badge_y = y0
            if 0 <= badge_y < body_h and 0 <= badge_x < body_w:
                hist = self._metric_history.get(pid)
                samples = []
                if hist and hist.get("cpu"):
                    samples = list(hist["cpu"])
                glyph, badge_pair = self._galaxy_trend_badge(samples)
                if glyph:
                    badge_attr = curses.A_BOLD if glyph in ("↑", "↓") \
                        else curses.A_DIM
                    grid[badge_y][badge_x] = (glyph, badge_pair, badge_attr)

        # Paint the grid into curses, coalescing adjacent same-attr runs.
        for row_y, row in enumerate(grid):
            screen_y = body_top + row_y
            if screen_y >= h - 1:
                break
            x_pos = 0
            run_start = None
            run_attr = None
            run_chars = []
            for col_x, (ch, pair, extra) in enumerate(row):
                attr = (curses.color_pair(pair) | extra) if pair else extra
                if run_attr is None or attr == run_attr:
                    if run_start is None:
                        run_start = col_x
                    run_chars.append(ch)
                    run_attr = attr
                else:
                    try:
                        self._put(screen_y, run_start,
                                  "".join(run_chars), run_attr)
                    except curses.error:
                        pass
                    run_start = col_x
                    run_chars = [ch]
                    run_attr = attr
            if run_start is not None and run_chars:
                try:
                    self._put(screen_y, run_start,
                              "".join(run_chars), run_attr)
                except curses.error:
                    pass

        # Vendor legend: list every vendor present in the current
        # cluster as a colored ■ + name. Rendered on the canvas row
        # just above the shortcut bar so it doesn't overlap bubbles.
        legend_y = h - 2
        if legend_y > body_top:
            present = []
            seen = set()
            for r in nodes:
                v = self._galaxy_vendor_label(r)
                if v in seen:
                    continue
                seen.add(v)
                present.append(v)
            try:
                self._put(legend_y, 0, " " * w, 0)
                cursor = 1
                for v in present:
                    label = v.title()
                    pair = self._GALAXY_VENDOR_COLORS.get(v, 10)
                    seg_glyph = "■ "
                    seg_total = len(seg_glyph) + len(label) + 2
                    if cursor + seg_total > w - 1:
                        break
                    self._put(legend_y, cursor, seg_glyph,
                              curses.color_pair(pair) | curses.A_BOLD)
                    self._put(legend_y, cursor + len(seg_glyph),
                              label, curses.color_pair(10))
                    cursor += seg_total
            except curses.error:
                pass

    def _galaxy_render_direct(self, start_y, w):
        """Render the galaxy view directly into curses with full color
        + visual-effect support (vendor fills, load-tier borders, glow
        on new PIDs, blink on heavy load). Bypasses the generic
        `_render_detail` path so we can paint background fills via
        `A_REVERSE` and pick per-bubble attributes individually.

        Returns the y where rendering ended so the caller can place
        anything below the panel.
        """
        h, _ = self.stdscr.getmaxyx()
        if start_y >= h - 2 or not self.rows:
            return start_y

        # Match the detail-pane geometry so the title/border align with
        # the rest of the app's chrome.
        box_w = w
        inner_h = max(6, h - start_y - 3)

        # Title row: borrow the existing detail-box style.
        nodes = self._galaxy_select_nodes()
        hidden = getattr(self, "_galaxy_hidden_count", 0)
        title = (f" Process Galaxy — {len(nodes)} bubbles"
                 + (f"  (+{hidden} idle hidden)" if hidden else ""))
        title_str = f"┌─{title} "
        top = title_str + "─" * max(0, box_w - len(title_str) - 1) + "┐"
        try:
            self._put(start_y, 0, top[:w],
                      curses.color_pair(2) | curses.A_BOLD)
        except curses.error:
            pass

        # Compute layout into a virtual grid first (chars + per-cell attrs).
        bound_w = max(10, w - 4)
        bound_h = max(6, inner_h)
        if w < 30 or inner_h < 10:
            try:
                self._put(start_y + 1, 0,
                          " Galaxy view needs a larger window".ljust(w),
                          curses.color_pair(2))
            except curses.error:
                pass
            return start_y + 2

        self._galaxy_step(w, bound_h)
        node_set = {r["pid"] for r in nodes}

        # 2-D grid: each cell is (char, color_pair_id, extra_attrs).
        EMPTY = (" ", 0, 0)
        grid = [[EMPTY for _ in range(bound_w)] for _ in range(bound_h)]

        # 1) Edges first (faint dotted lines between parent and child).
        edge_attr = curses.color_pair(10) | curses.A_DIM
        for r in nodes:
            ppid = r.get("ppid", 0)
            pid = r["pid"]
            if ppid not in node_set or ppid == pid:
                continue
            x1, y1 = self._galaxy_positions[ppid]
            x2, y2 = self._galaxy_positions[pid]
            self._galaxy_draw_edge_into_grid(
                grid, (int(x1), int(y1)), (int(x2), int(y2)),
                bound_w, bound_h, edge_attr)

        # 2) Bubbles, smallest first so heavy ones overdraw lighter ones.
        sized = []
        total_mem = max(1, self._total_mem_kb)
        for r in nodes:
            bw, bh = self._galaxy_bubble_size(r)
            sized.append((bw * bh, r, bw, bh))
        sized.sort(key=lambda t: t[0])
        for _area, r, bw, bh in sized:
            pid = r["pid"]
            x, y = self._galaxy_positions[pid]
            x0 = int(x) - bw // 2
            y0 = int(y) - bh // 2
            x0 = max(0, min(bound_w - bw, x0))
            y0 = max(0, min(bound_h - bh, y0))
            tier = self._galaxy_load_tier(r, total_mem)
            vendor = self._galaxy_vendor_label(r)
            fill_pair = self._GALAXY_VENDOR_COLORS.get(
                vendor, self._GALAXY_TIER_COLORS[tier])
            border_pair = self._GALAXY_TIER_COLORS[tier]
            border_extra = curses.A_BOLD if tier >= 3 else 0
            inner_extra = curses.A_REVERSE  # solid filled bubble
            if tier >= 4:
                inner_extra |= curses.A_BOLD
            # Glow on newly-spawned PIDs: brighten the border, blink it.
            glow = bool(self._galaxy_glow.get(pid))
            if glow:
                border_pair = 3   # bright yellow
                border_extra |= curses.A_BOLD | curses.A_BLINK
            # Anomaly blink on cpu > 80%.
            cpu_val = r.get("agg_cpu", r.get("cpu", 0)) or 0
            anomaly = cpu_val >= 80.0
            lines = self._galaxy_render_bubble(r, bw, bh)
            for dy, line in enumerate(lines):
                row_y = y0 + dy
                if not (0 <= row_y < bound_h):
                    continue
                is_border = (dy == 0 or dy == bh - 1)
                for dx, ch in enumerate(line):
                    col_x = x0 + dx
                    if not (0 <= col_x < bound_w):
                        continue
                    is_side = (dx == 0 or dx == bw - 1) and not is_border
                    if is_border or is_side:
                        grid[row_y][col_x] = (ch, border_pair, border_extra)
                    else:
                        attr_extra = inner_extra
                        if anomaly:
                            attr_extra |= curses.A_BLINK
                        grid[row_y][col_x] = (ch, fill_pair, attr_extra)

        # 3) Paint the grid into curses, row by row.
        for row_y, row in enumerate(grid):
            screen_y = start_y + 1 + row_y
            if screen_y >= h - 2:
                break
            # Left border
            try:
                self._put(screen_y, 0, "│", curses.A_DIM)
            except curses.error:
                pass
            # Cell-by-cell; coalesce runs of the same attr into single
            # writes to keep the per-frame syscall count down.
            x = 1
            run_start = None
            run_attr = None
            run_chars = []
            def _flush(run_start_local, run_chars_local, run_attr_local):
                if run_start_local is None or not run_chars_local:
                    return
                try:
                    self._put(screen_y, run_start_local + 1,
                              "".join(run_chars_local), run_attr_local)
                except curses.error:
                    pass
            for col_x, (ch, pair, extra) in enumerate(row):
                attr = (curses.color_pair(pair) | extra) if pair else extra
                if run_attr is None or attr == run_attr:
                    if run_start is None:
                        run_start = col_x
                    run_chars.append(ch)
                    run_attr = attr
                else:
                    _flush(run_start, run_chars, run_attr)
                    run_start = col_x
                    run_chars = [ch]
                    run_attr = attr
            _flush(run_start, run_chars, run_attr)
            # Right border
            if box_w - 1 < w:
                try:
                    self._put(screen_y, box_w - 1, "│", curses.A_DIM)
                except curses.error:
                    pass

        # Bottom border
        bot_y = start_y + 1 + bound_h
        if bot_y < h - 1:
            bot = "└" + "─" * max(0, box_w - 2) + "┘"
            try:
                self._put(bot_y, 0, bot[:w], curses.A_DIM)
            except curses.error:
                pass
        return bot_y + 1

    @staticmethod
    def _galaxy_draw_edge_into_grid(grid, p1, p2, w, h, attr):
        """Bresenham-ish line into a (char, pair, extra) cell grid."""
        x1, y1 = p1
        x2, y2 = p2
        dx = abs(x2 - x1)
        dy = abs(y2 - y1)
        sx = 1 if x1 < x2 else -1
        sy = 1 if y1 < y2 else -1
        err = dx - dy
        x, y = x1, y1
        # Pick a middling glyph that reads as a line at any angle.
        glyph = "·"
        steps = 0
        while steps < 200:
            if 0 <= x < w and 0 <= y < h:
                grid[y][x] = (glyph, 10, curses.A_DIM)
            if x == x2 and y == y2:
                return
            e2 = 2 * err
            if e2 > -dy:
                err -= dy
                x += sx
            if e2 < dx:
                err += dx
                y += sy
            steps += 1

    def _build_galaxy_lines(self, w, h):
        """Render the galaxy graph as text lines, crypto-bubble-style.

        Each process node is a sized rectangular bubble (5×3 → 13×5
        cells) with the abbreviated process name centered inside.
        Heavier processes get bigger bubbles. Edges between parent
        and child PIDs are drawn faintly behind the bubbles. The
        spring solver still runs one iteration per render so the
        layout settles in front of you.
        """
        if w < 30 or h < 10:
            return [" Galaxy view needs a larger window"]
        # Run one solver step per render to animate.
        self._galaxy_step(w, h)
        nodes = self._galaxy_select_nodes()
        node_set = {r["pid"] for r in nodes}
        bound_w = max(10, w - 4)
        bound_h = max(6, h - 6)
        grid = [[" "] * bound_w for _ in range(bound_h)]
        # Edges first (so bubbles paint over them).
        for r in nodes:
            ppid = r.get("ppid", 0)
            pid = r["pid"]
            if ppid not in node_set or ppid == pid:
                continue
            x1, y1 = self._galaxy_positions[ppid]
            x2, y2 = self._galaxy_positions[pid]
            self._orbit_draw_line(
                grid, (int(x1), int(y1)), (int(x2), int(y2)))
        # Bubbles, smallest first so heavy ones paint over light ones.
        sized = []
        for r in nodes:
            bw, bh = self._galaxy_bubble_size(r)
            sized.append((bw * bh, r, bw, bh))
        sized.sort(key=lambda t: t[0])
        for _area, r, bw, bh in sized:
            pid = r["pid"]
            x, y = self._galaxy_positions[pid]
            # Center the bubble on the position; clamp into bounds.
            x0 = int(x) - bw // 2
            y0 = int(y) - bh // 2
            x0 = max(0, min(bound_w - bw, x0))
            y0 = max(0, min(bound_h - bh, y0))
            lines = self._galaxy_render_bubble(r, bw, bh)
            for dy, line in enumerate(lines):
                row_y = y0 + dy
                if not (0 <= row_y < bound_h):
                    continue
                for dx, ch in enumerate(line):
                    col_x = x0 + dx
                    if 0 <= col_x < bound_w:
                        grid[row_y][col_x] = ch
        return ["".join(row) for row in grid]

    def _toggle_net_mode(self):
        """Toggle network connection view in the detail box."""
        if self._net_mode:
            self._net_mode = False
            self._detail_focus = False
            return
        if not self.rows:
            return
        sel = self.rows[self.selected]
        self._net_pid = sel["pid"]
        self._net_cmd = sel["command"].split()[0].rsplit("/", 1)[-1][:20]
        self._net_entries = []
        self._net_selected = 0
        self._net_scroll = 0
        self._net_mode = True
        self._inspect_mode = False
        if getattr(self, "_events_mode", False):
            self._stop_events_stream()
            self._events_mode = False
        self._detail_focus = True
        self._net_loading = True
        self._start_net_fetch(sel["pid"])

    def _start_net_fetch(self, root_pid):
        """Launch a background thread to fetch network connections."""
        if self._net_worker and self._net_worker.is_alive():
            return  # already running
        self._net_loading = True
        self._net_pending = None

        def _worker():
            try:
                result = self._fetch_net_connections(root_pid)
            except Exception:
                result = []
            self._net_pending = result

        self._net_worker = threading.Thread(target=_worker, daemon=True)
        self._net_worker.start()

    def _start_net_refresh(self):
        """Launch a background thread to refresh net bytes + connections."""
        if self._net_worker and self._net_worker.is_alive():
            return
        self._net_loading = True
        self._net_pending = None
        pid = self._net_pid

        def _worker():
            try:
                self._do_refresh_net_bytes(pid)
            except Exception:
                self._net_pending = []  # ensure loading state clears on error

        self._net_worker = threading.Thread(target=_worker, daemon=True)
        self._net_worker.start()

    def _poll_net_result(self):
        """Check if background net fetch completed and apply results. Call from main loop."""
        if self._net_pending is None:
            return False
        if not self._net_mode:
            # User closed net mode while fetch was in flight
            self._net_pending = None
            self._net_loading = False
            return False
        # Preserve selection by fd
        sel_fd = None
        if self._net_entries and self._net_selected < len(self._net_entries):
            sel_fd = self._net_entries[self._net_selected]["fd"]
        self._net_entries = self._net_pending
        self._net_pending = None
        self._net_loading = False
        if sel_fd:
            for i, e in enumerate(self._net_entries):
                if e["fd"] == sel_fd:
                    self._net_selected = i
                    break
        if self._net_selected >= len(self._net_entries):
            self._net_selected = max(0, len(self._net_entries) - 1)
        return True  # data changed, needs re-render

    # ── Shared report layout (audits + keyscan) ────────────────────────

    _SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2,
                      "INFO": 3, "OK": 4}

    def _format_structured_report(self, title, findings, line_map,
                                  empty_message="No findings.",
                                  subtitle=""):
        """Shared layout: TITLE bar → SUMMARY (severity counts + actionable)
        → FINDINGS grouped by severity. Per-finding evidence/action are NOT
        included here; the render path appends a dynamic DETAIL pane for the
        row under the cursor via `_format_finding_detail`.

        `line_map` is populated with the display-line index of each finding
        so the cursor overlay and `_scroll_*_to_cursor` keep working.

        Lines are shaped `"    [x] [SEV]  message"` for actionable rows and
        `"        [SEV]  message"` for info-only ones — 4-space indent plus
        a 3-char marker column. The cursor overlay swaps the first 4 chars
        with `"  \u25b6 "` so it aligns cleanly across both shapes.
        """
        # Normalize tuples to dicts + sort worst-first
        normalized = []
        for f in findings:
            if isinstance(f, dict):
                normalized.append(f)
            else:
                severity, msg = f
                normalized.append({"severity": severity, "message": msg,
                                   "action": None})
        normalized.sort(key=lambda f: self._SEVERITY_RANK.get(
            f.get("severity", "INFO"), 99))

        # Severity counts + actionable total
        counts = {}
        for f in normalized:
            s = f.get("severity", "INFO")
            counts[s] = counts.get(s, 0) + 1
        actionable = sum(1 for f in normalized if f.get("action"))

        lines = []
        # Title bar
        bar = "\u2501" * max(0, 64 - len(title))
        lines.append(f"  \u2501\u2501 {title.upper()} {bar}")
        lines.append("")

        # Severity bar — only show severities that have hits
        parts = []
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "INFO", "OK"):
            if counts.get(sev, 0):
                parts.append(f"[{sev} {counts[sev]}]")
        if parts:
            lines.append("  Severity:    " + "  ".join(parts))
        if actionable:
            lines.append(
                f"  Actionable:  {actionable} \u2014 press [D] on a "
                f"[x]-marked row to remediate")
        else:
            lines.append("  Actionable:  (none)")
        if subtitle:
            lines.append("")
            for s in subtitle.split("\n"):
                lines.append(f"  {s}")
        lines.append("")

        if not normalized:
            lines.append(f"  {empty_message}")
            return lines

        # Findings — grouped by severity, one line each (no inline evidence)
        bar = "\u2500" * 60
        lines.append(f"  \u2500\u2500 FINDINGS {bar}")
        lines.append("")
        current_sev = None
        for f in normalized:
            sev = f["severity"]
            msg = f["message"]
            # Visual gap between severity groups
            if current_sev is not None and sev != current_sev:
                lines.append("")
            current_sev = sev
            mark = "[x]" if f.get("action") else "   "
            line_map.append(len(lines))
            lines.append(f"    {mark} [{sev}]  {msg}")
        return lines

    def _format_finding_detail(self, finding, width):
        """Render the DETAIL pane shown below the findings list.

        Dynamic — regenerated each render frame for the finding under the
        cursor. Width is the available inner width so we can word-wrap
        long evidence lines without clipping.
        """
        if finding is None:
            return []
        width = max(20, width)
        lines = []
        lines.append("")
        bar = "\u2500" * 60
        lines.append(f"  \u2500\u2500 DETAIL {bar}")
        lines.append("")
        sev = finding.get("severity", "INFO")
        msg = finding.get("message", "")
        lines.append(f"    [{sev}]  {msg}")
        evidence = (finding.get("evidence") or "").strip()
        if evidence:
            lines.append("")
            wrap_w = max(10, width - 10)
            for el in evidence.splitlines():
                if not el:
                    lines.append("")
                    continue
                # Soft wrap on the available width
                start = 0
                while start < len(el):
                    chunk = el[start:start + wrap_w]
                    lines.append(f"      {chunk}")
                    start += wrap_w
        action = finding.get("action") or {}
        a_type = action.get("type")
        if a_type:
            lines.append("")
            lines.append(
                f"    \u25b6 Action: [{a_type}] \u2014 press [D] to run "
                f"this remediation")
        return lines

    # ── Shared LLM Executive Summary ───────────────────────────────────

    _LLM_SUMMARY_PROMPT = (
        "You are analyzing a macOS security scan. Return a 3–5 bullet "
        "executive summary. Each bullet ≤20 words, starts with one of: "
        "TOP_CONCERN:, SIGNAL:, NOISE:, ACTION:.\n"
        "- TOP_CONCERN: the single most important finding (CRITICAL/HIGH).\n"
        "- SIGNAL: one or two notable items worth investigating.\n"
        "- NOISE: optional — legitimate/benign findings the user can ignore.\n"
        "- ACTION: the single highest-impact thing to do right now.\n"
        "If every finding is OK/INFO-only, respond with one bullet: "
        "TOP_CONCERN: No issues detected.")

    def _build_findings_summary_body(self, title, findings):
        """Flatten findings into a compact textual input for the summarizer."""
        counts = {}
        for f in findings:
            s = f.get("severity", "INFO")
            counts[s] = counts.get(s, 0) + 1
        body = [f"SCAN: {title}",
                f"TOTAL FINDINGS: {len(findings)}",
                f"SEVERITY: {counts}", "", "FINDINGS:"]
        # Cap input so we don't blow past Claude's context on huge reports.
        for f in findings[:40]:
            body.append(f"  [{f.get('severity')}] {f.get('message')}")
            ev = (f.get("evidence") or "").strip()
            if ev:
                for ln in ev.splitlines()[:2]:
                    body.append(f"      | {ln}")
        if len(findings) > 40:
            body.append(f"  (+ {len(findings) - 40} more findings omitted)")
        return "\n".join(body)

    def _summary_panel_severities(self, findings):
        """Pick summary severity badges from the underlying findings."""
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "INFO": 0, "OK": 0}
        for finding in findings or []:
            sev = str(finding.get("severity") or "INFO").upper()
            if sev in counts:
                counts[sev] += 1
        top = "INFO"
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "INFO", "OK"):
            if counts.get(sev):
                top = "INFO" if sev == "OK" else sev
                break
        if top == "CRITICAL":
            signal = "HIGH" if counts.get("HIGH") else (
                "MEDIUM" if counts.get("MEDIUM") else "INFO")
        elif top == "HIGH":
            signal = "MEDIUM" if counts.get("MEDIUM") else "INFO"
        elif top == "MEDIUM":
            signal = "INFO"
        else:
            signal = "INFO"
        return top, signal

    def _format_llm_summary_panel(
            self,
            text,
            width=120,
            top_concern_severity="CRITICAL",
            signal_severity="HIGH"):
        """Render a Claude-returned summary as a bordered top-of-report panel."""
        lines = []
        bar = "\u2501" * 60
        lines.append(f"  \u2501\u2501 AI SUMMARY {bar}")
        lines.append("")
        for line in (text or "").splitlines():
            s = line.rstrip()
            if not s:
                continue
            # Tag the bullet type so _tag_color can paint it
            if s.strip().startswith("TOP_CONCERN:"):
                body = s.strip()[len("TOP_CONCERN:"):].strip()
                lines.append(f"    [{top_concern_severity}]  {body}")
            elif s.strip().startswith("SIGNAL:"):
                body = s.strip()[len("SIGNAL:"):].strip()
                lines.append(f"    [{signal_severity}]  {body}")
            elif s.strip().startswith("ACTION:"):
                body = s.strip()[len("ACTION:"):].strip()
                lines.append(f"    \u25b6  Fix first: {body}")
            elif s.strip().startswith("NOISE:"):
                body = s.strip()[len("NOISE:"):].strip()
                lines.append(f"    [INFO]  (benign) {body}")
            else:
                lines.append(f"    {s.strip()}")
        lines.append("")
        return lines

    def _start_llm_summary(self, scope, title, findings):
        """Kick off a Claude summary of `findings`. Stores lines in
        self._llm_summary_pending[scope] on completion. No-op if a worker
        is already in flight or claude is not available (best-effort).

        `scope` is one of: "audit", "inspect", "events".
        """
        if (getattr(self, "_test_mode", False)
                and os.environ.get("MAC_TUI_PROCMON_TEST_ALLOW_LLM", "").lower()
                not in ("1", "true", "yes", "on")):
            self._llm_summary[scope] = None
            self._llm_summary_pending[scope] = None
            self._llm_summary_loading[scope] = False
            return
        existing = self._llm_summary_worker.get(scope)
        if existing and existing.is_alive():
            return
        if not findings:
            # Clear slot so stale summary doesn't persist.
            self._llm_summary[scope] = None
            self._llm_summary_loading[scope] = False
            return
        self._llm_summary[scope] = None
        self._llm_summary_pending[scope] = None
        self._llm_summary_loading[scope] = True

        def _worker():
            try:
                body = self._build_findings_summary_body(title, findings)
                resp = None
                errors = []
                for tool in ("claude", "codex", "gemini"):
                    candidate = self._run_llm(
                        tool, self._LLM_SUMMARY_PROMPT, body, timeout=60)
                    if not candidate.startswith("["):
                        resp = candidate
                        break
                    errors.append(candidate)
                if resp is None:
                    self._llm_summary_pending[scope] = [
                        f"  \u2501\u2501 AI SUMMARY \u2501\u2501",
                        "",
                        f"    [INFO]  Summary unavailable: "
                        f"{' | '.join(errors)[:120]}",
                        ""]
                else:
                    top_sev, signal_sev = self._summary_panel_severities(findings)
                    self._llm_summary_pending[scope] = (
                        self._format_llm_summary_panel(
                            resp,
                            top_concern_severity=top_sev,
                            signal_severity=signal_sev,
                        ))
            except Exception as e:
                self._llm_summary_pending[scope] = [
                    f"  \u2501\u2501 AI SUMMARY \u2501\u2501",
                    "",
                    f"    [INFO]  Summary error: {e}",
                    ""]

        t = threading.Thread(target=_worker, daemon=True)
        self._llm_summary_worker[scope] = t
        t.start()

    def _poll_llm_summary(self, scope):
        """Apply completed summary for `scope`. Returns True on state change."""
        pending = self._llm_summary_pending.get(scope)
        if pending is None:
            return False
        self._llm_summary[scope] = pending
        self._llm_summary_pending[scope] = None
        self._llm_summary_loading[scope] = False
        return True

    def _llm_summary_loading_banner(self, scope):
        """Returns panel lines for an in-flight summary (shown while the
        Claude call runs). Keeps a consistent layout with the final panel."""
        if not self._llm_summary_loading.get(scope):
            return []
        bar = "\u2501" * 60
        return [
            f"  \u2501\u2501 AI SUMMARY {bar}",
            "",
            "    [INFO]  \u27f3 Generating executive summary with Claude\u2026",
            "",
        ]

    # ── Keyboard-Hook / Keylogger Scan ──────────────────────────────────






    # ── Process Triage (only remaining audit-mode driver) ────────────────

    _AUDIT_SCANS = {
        "process_triage": (None, "Deep Process Triage"),
    }

    def _toggle_audit_mode(self, audit_type):
        """Enter the structured-findings panel for a process-scoped report."""
        if audit_type not in self._AUDIT_SCANS:
            return
        # Re-pressing the same audit key closes it; a different key switches.
        if self._audit_mode and self._audit_type == audit_type:
            self._audit_mode = False
            self._detail_focus = False
            return
        if audit_type != "process_triage":
            self._audit_context_pid = None
            self._audit_context_cmd = ""
            self._audit_title_override = ""
        self._audit_type = audit_type
        self._audit_mode = True
        self._audit_lines = []
        self._audit_scroll = 0
        self._audit_action_result = None
        self._reset_audit_progress()
        # Wipe any stale AI summary — we'll regenerate for the new audit.
        self._llm_summary["audit"] = None
        self._llm_summary_pending["audit"] = None
        self._llm_summary_loading["audit"] = False
        # Close mutually-exclusive modes
        self._inspect_mode = False
        self._net_mode = False
        if getattr(self, "_events_mode", False):
            self._stop_events_stream()
            self._events_mode = False
        self._detail_focus = True
        self._audit_loading = True
        self._start_audit()

    def _ensure_audit_progress_state(self):
        if not hasattr(self, "_audit_progress_lines"):
            self._audit_progress_lines = []
        if not hasattr(self, "_audit_progress_lock"):
            self._audit_progress_lock = threading.Lock()

    def _reset_audit_progress(self):
        self._ensure_audit_progress_state()
        with self._audit_progress_lock:
            self._audit_progress_lines = []

    def _audit_progress(self, message):
        self._ensure_audit_progress_state()
        line = f"{time.strftime('%H:%M:%S')} {message}"
        with self._audit_progress_lock:
            self._audit_progress_lines.append(line)
            self._audit_progress_lines = self._audit_progress_lines[-60:]

    def _audit_progress_view(self):
        self._ensure_audit_progress_state()
        with self._audit_progress_lock:
            lines = list(self._audit_progress_lines[-12:])
        if not lines:
            return []
        return [" Progress:"] + [f"  {line}" for line in lines]

    def _start_audit(self):
        """Launch the background scan for the current audit_type."""
        if self._audit_worker and self._audit_worker.is_alive():
            return
        if self._audit_type not in self._AUDIT_SCANS:
            return
        self._audit_loading = True
        self._audit_pending = None

        def _worker():
            try:
                if getattr(self, "_test_mode", False):
                    findings = [{
                        "severity": "HIGH",
                        "message": "Test mode deep triage placeholder: selected process shows live DYLD injection and user-writable dylibs",
                        "evidence": ("pid: 4242\n"
                                     "exe: /tmp/suspicious\n"
                                     "DYLD_INSERT_LIBRARIES=/tmp/libinject.dylib\n"
                                     "user_writable_dylib: /tmp/libinject.dylib"),
                        "action": None,
                    }]
                else:
                    findings = self._build_process_triage_findings(
                        self._audit_context_pid,
                        self._audit_context_cmd,
                    )
                lines = self._format_audit_report(findings)
            except Exception as e:
                lines = [f"[audit error: {e}]"]
            self._audit_pending = lines

        self._audit_worker = threading.Thread(target=_worker, daemon=True)
        self._audit_worker.start()



    def _poll_audit_result(self):
        """Apply completed audit results. Returns True on state change."""
        if self._audit_pending is None:
            return False
        if not self._audit_mode:
            self._audit_pending = None
            self._audit_loading = False
            return False
        self._audit_lines = self._audit_pending
        self._audit_pending = None
        self._audit_loading = False
        self._audit_cursor = 0
        for i, f in enumerate(self._audit_findings_structured):
            if f.get("action"):
                self._audit_cursor = i
                break
        self._audit_scroll = 0
        self._scroll_audit_to_cursor()
        # Kick off the AI executive summary in the background. It's
        # best-effort; if Claude isn't installed / times out, the panel
        # just doesn't appear.
        title = self._audit_title()
        self._start_llm_summary(
            "audit", title, self._audit_findings_structured)
        return True

    def _format_audit_report(self, findings):
        """Format audit findings. Delegates to _format_structured_report.

        Side effect: populates _audit_findings_structured and
        _audit_line_for_finding so the cursor can map to display lines.
        Evidence/action details are NOT included in these lines — they're
        rendered dynamically as a DETAIL pane under the cursored finding
        via _format_finding_detail at render time.
        """
        normalized = []
        for f in findings:
            if isinstance(f, dict):
                normalized.append(f)
            else:
                severity, msg = f
                normalized.append({"severity": severity, "message": msg,
                                   "action": None})
        normalized.sort(key=lambda f: self._SEVERITY_RANK.get(
            f.get("severity", "INFO"), 99))
        self._audit_findings_structured = normalized
        self._audit_line_for_finding = []
        title = self._audit_title()
        return self._format_structured_report(
            title=title, findings=normalized,
            line_map=self._audit_line_for_finding,
            empty_message="No findings.")

    def _audit_move_cursor(self, delta):
        n = len(self._audit_findings_structured)
        if n == 0:
            return
        self._audit_cursor = max(0, min(n - 1, self._audit_cursor + delta))
        self._audit_action_result = None
        self._scroll_audit_to_cursor()

    def _scroll_audit_to_cursor(self):
        """Keep the cursor visible as it moves through findings."""
        if not self._audit_line_for_finding:
            return
        idx = self._audit_cursor
        if not (0 <= idx < len(self._audit_line_for_finding)):
            return
        panel_height = 0
        if self._audit_action_result:
            try:
                _, w = self.stdscr.getmaxyx()
            except Exception:
                w = 120
            panel_height = len(self._format_action_panel(
                self._audit_action_result, w - 6))
        # AI SUMMARY panel also pushes the findings down at render time.
        summary = (self._llm_summary.get("audit")
                   or self._llm_summary_loading_banner("audit"))
        if summary:
            panel_height += len(summary)
        target_line = self._audit_line_for_finding[idx] + panel_height
        try:
            h, _ = self.stdscr.getmaxyx()
        except Exception:
            h = 40
        inner_h = max(4, h * 2 // 3 - 4)
        if target_line < self._audit_scroll:
            self._audit_scroll = max(0, target_line - 1)
        elif target_line >= self._audit_scroll + inner_h:
            self._audit_scroll = max(0, target_line - inner_h + 2)

    def _audit_current_finding(self):
        idx = self._audit_cursor
        if 0 <= idx < len(self._audit_findings_structured):
            return self._audit_findings_structured[idx]
        return None





    def _wrap_text(self, text, width):
        """Word-wrap a multi-line string to the given width.

        Preserves existing newlines as hard breaks; wraps overlong lines
        on word boundaries. Used by the action panel so error messages
        aren't truncated at the detail-box edge.
        """
        out = []
        for para in text.split("\n"):
            if len(para) <= width:
                out.append(para)
                continue
            words = para.split(" ")
            current = ""
            for w in words:
                if not current:
                    current = w
                elif len(current) + 1 + len(w) <= width:
                    current += " " + w
                else:
                    out.append(current)
                    current = w
            if current:
                out.append(current)
        return out

    def _format_action_panel(self, result, width):
        """Render a structured action result into display lines for the
        action panel above the findings list. The panel has a visible
        separator so it's obviously distinct from the findings below."""
        width = max(20, width)
        level = result.get("level", "info")
        summary = result.get("summary", "")
        detail = result.get("detail_text", "")

        icon = {"ok": "\u2714", "error": "\u2718", "info": "\u2794"}.get(level, "\u2794")
        label = {
            "ok": "LAST ACTION — Success",
            "error": "LAST ACTION — Failed",
            "info": "LAST ACTION",
        }.get(level, "LAST ACTION")

        border = "\u2500" * min(max(20, width - 2), 120)
        lines = []
        lines.append(f" \u2502 {label}")
        lines.append(f" \u2502 {icon} {summary[:width - 6]}")
        if detail:
            lines.append(f" \u2502")
            for paragraph_line in self._wrap_text(detail, width - 6):
                lines.append(f" \u2502   {paragraph_line}")
        lines.append(f" \u2514{border}")
        lines.append("")
        return lines

    def _build_action_result(self, level, summary, detail_text=""):
        """Return a structured action result for the keyscan action panel.

        `level`:     "ok" | "error" | "info"
        `summary`:   a short one-line headline
        `detail_text`: optional multi-line explanation (raw newlines OK;
                     the renderer word-wraps further to box width)
        """
        return {
            "level": level,
            "summary": summary,
            "detail_text": detail_text,
        }

    @staticmethod
    def _sip_explanation(euid, message):
        """Build the multi-line explanation shown when a TCC removal
        hits SIP. Spells out the sudo-vs-FDA distinction explicitly so
        the user doesn't spend another 20 minutes wondering why `sudo`
        alone isn't enough."""
        lines = []
        if "SIP" in message or "readonly" in message.lower() \
                or "read-only" in message.lower() \
                or "authorization" in message.lower() \
                or "Full Disk Access" in message:
            if euid == 0:
                lines.append(
                    "You ARE running as root (euid=0) — but sudo alone "
                    "is not enough on modern macOS. SIP protects TCC.db "
                    "from writes even for root.")
            else:
                lines.append(
                    f"You are running as uid={euid}, not root. Use "
                    f"`sudo mac-tui-procmon` — but note that sudo alone won't "
                    f"fix this: SIP protects TCC.db from writes even for "
                    f"root.")
            lines.append("")
            lines.append("To remove TCC grants you need Full Disk Access on")
            lines.append("your terminal app (not on mac-tui-procmon itself):")
            lines.append("  System Settings → Privacy & Security →")
            lines.append("  Full Disk Access → add your terminal app")
            lines.append("  → quit and relaunch the terminal → retry")
            lines.append("")
        lines.append("Raw error:")
        lines.append(f"  {message}")
        lines.append("")
        lines.append("Press L to see the full debug log.")
        return "\n".join(lines)






    def _confirm_action(self, prompt):
        """Modal yes/no prompt. Returns True if user confirmed."""
        h, w = self.stdscr.getmaxyx()
        lines = prompt.split("\n")
        box_w = min(max(max(len(l) for l in lines) + 4, 50), w - 4)
        box_h = len(lines) + 4
        box_y = max(0, (h - box_h) // 2)
        box_x = max(0, (w - box_w) // 2)

        self.stdscr.timeout(-1)
        try:
            while True:
                for row in range(box_h):
                    self._put(box_y + row, box_x, " " * box_w,
                              curses.color_pair(13))
                self._put(box_y, box_x,
                          " Confirm \u2014 y to proceed, any other key to cancel ".ljust(box_w)[:box_w],
                          curses.color_pair(14) | curses.A_BOLD)
                for i, line in enumerate(lines):
                    self._put(box_y + 2 + i, box_x + 2, line[:box_w - 4],
                              curses.color_pair(13))
                self.stdscr.refresh()
                ch = self.stdscr.getch()
                if ch in (ord("y"), ord("Y")):
                    return True
                if ch != -1:
                    return False
        finally:
            self.stdscr.timeout(100)

    # ── Security Timeline (Endpoint Security / dtrace / praudit) ─────────

    _ES_TIMELINE_EVENTS = (
        "exec",
        "fork",
        "exit",
        "authentication",
        "login_login",
        "login_logout",
        "lw_session_login",
        "lw_session_logout",
        "openssh_login",
        "openssh_logout",
        "su",
        "sudo",
        "tcc_modify",
        "btm_launch_item_add",
        "btm_launch_item_remove",
        "profile_add",
        "profile_remove",
        "gatekeeper_user_override",
        "xp_malware_detected",
        "xp_malware_remediated",
        "screensharing_attach",
        "screensharing_detach",
        "kextload",
        "kextunload",
    )

    _EVENT_KIND_LABELS = {
        "exec": "Exec",
        "fork": "Fork",
        "exit": "Exit",
        "authentication": "Authentication",
        "login_login": "Login",
        "login_logout": "Logout",
        "lw_session_login": "Local session login",
        "lw_session_logout": "Local session logout",
        "openssh_login": "OpenSSH login",
        "openssh_logout": "OpenSSH logout",
        "su": "su",
        "sudo": "sudo",
        "tcc_modify": "TCC modify",
        "btm_launch_item_add": "Launch item add",
        "btm_launch_item_remove": "Launch item remove",
        "profile_add": "Profile add",
        "profile_remove": "Profile remove",
        "gatekeeper_user_override": "Gatekeeper override",
        "xp_malware_detected": "XProtect detect",
        "xp_malware_remediated": "XProtect remediate",
        "screensharing_attach": "Screen sharing attach",
        "screensharing_detach": "Screen sharing detach",
        "kextload": "Kext load",
        "kextunload": "Kext unload",
        "error": "Error",
    }

    _EVENT_KIND_SEVERITY = {
        "exec": "INFO",
        "fork": "INFO",
        "exit": "INFO",
        "authentication": "MEDIUM",
        "login_login": "MEDIUM",
        "login_logout": "INFO",
        "lw_session_login": "INFO",
        "lw_session_logout": "INFO",
        "openssh_login": "HIGH",
        "openssh_logout": "INFO",
        "su": "HIGH",
        "sudo": "HIGH",
        "tcc_modify": "HIGH",
        "btm_launch_item_add": "HIGH",
        "btm_launch_item_remove": "MEDIUM",
        "profile_add": "HIGH",
        "profile_remove": "MEDIUM",
        "gatekeeper_user_override": "HIGH",
        "xp_malware_detected": "CRITICAL",
        "xp_malware_remediated": "HIGH",
        "screensharing_attach": "MEDIUM",
        "screensharing_detach": "INFO",
        "kextload": "HIGH",
        "kextunload": "MEDIUM",
        "error": "HIGH",
    }

    def _event_scalar_text(self, value):
        """Normalize nested ES JSON values into a short display string."""
        if value in (None, "", [], {}):
            return ""
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, (int, float)):
            return str(value)
        if isinstance(value, str):
            return value.strip()
        if isinstance(value, list):
            parts = [self._event_scalar_text(v) for v in value[:4]]
            return ", ".join(p for p in parts if p)
        if isinstance(value, dict):
            for key in ("path", "identifier", "name", "username", "user"):
                text = self._event_scalar_text(value.get(key))
                if text:
                    return text
            return _json.dumps(value, ensure_ascii=True)[:160]
        return str(value).strip()

    def _event_path_value(self, node, *paths):
        """Return the first non-empty value from nested dict paths."""
        for path in paths:
            cur = node
            for key in path:
                if not isinstance(cur, dict):
                    cur = None
                    break
                cur = cur.get(key)
            text = self._event_scalar_text(cur)
            if text:
                return text
        return ""

    def _event_first_named_value(self, node, *names):
        """Return the first scalar value whose key matches one of `names`."""
        wanted = {name.lower() for name in names}
        stack = [node]
        while stack:
            cur = stack.pop(0)
            if isinstance(cur, dict):
                for key, value in cur.items():
                    if key.lower() in wanted:
                        text = self._event_scalar_text(value)
                        if text:
                            return text
                    if isinstance(value, (dict, list)):
                        stack.append(value)
            elif isinstance(cur, list):
                stack.extend(cur)
        return ""

    def _event_int_value(self, node, *paths):
        """Return the first nested value parsed as an integer, else 0."""
        text = self._event_path_value(node, *paths)
        if not text:
            return 0
        try:
            return int(str(text), 10)
        except (TypeError, ValueError):
            return 0

    def _fallback_event_summary(self, payload, data):
        """Build a generic compact summary when no specific formatter matches."""
        proc_path = self._event_path_value(
            data,
            ("process", "executable", "path"),
            ("process", "signing_id"),
        )
        parts = [proc_path] if proc_path else []
        for name in (
            "username",
            "user",
            "account_name",
            "client",
            "service",
            "identifier",
            "hostname",
            "remote_address",
            "source_address",
            "path",
            "result",
        ):
            value = self._event_first_named_value(payload, name)
            if value and value not in parts:
                parts.append(f"{name}={value}")
            if len(parts) >= 4:
                break
        if parts:
            return " ".join(parts)
        return _json.dumps(payload, ensure_ascii=True)[:180]

    def _summarize_es_event(self, kind, payload, data):
        """Return a short, analyst-friendly summary for one ES event."""
        proc_path = self._event_path_value(
            data,
            ("process", "executable", "path"),
            ("instigator", "executable", "path"),
        )
        if kind == "exec":
            return (
                self._event_path_value(
                    payload,
                    ("target", "executable", "path"),
                    ("target", "path"),
                )
                or proc_path
                or "(unknown executable)"
            )
        if kind == "fork":
            child_pid = self._event_path_value(
                payload,
                ("child", "audit_token", "pid"),
                ("child", "pid"),
            )
            child_path = self._event_path_value(
                payload,
                ("child", "executable", "path"),
                ("child", "path"),
            )
            bits = []
            if child_pid:
                bits.append(f"child={child_pid}")
            if child_path:
                bits.append(child_path)
            elif proc_path:
                bits.append(proc_path)
            return " ".join(bits) or "(fork)"
        if kind == "exit":
            status = self._event_first_named_value(payload, "stat", "status", "code")
            return (f"{proc_path} status={status}" if status and proc_path
                    else proc_path or f"status={status}" if status else "(exit)")
        if kind in (
            "authentication",
            "login_login",
            "login_logout",
            "lw_session_login",
            "lw_session_logout",
            "openssh_login",
            "openssh_logout",
            "su",
            "sudo",
            "screensharing_attach",
            "screensharing_detach",
        ):
            who = self._event_first_named_value(
                payload,
                "username",
                "user",
                "account_name",
                "to_username",
                "from_username",
            )
            remote = self._event_first_named_value(
                payload,
                "remote_address",
                "source_address",
                "hostname",
                "client_address",
            )
            result = self._event_first_named_value(
                payload,
                "success",
                "authenticated",
                "result",
                "type",
            )
            parts = [part for part in (who, proc_path) if part]
            if remote:
                parts.append(f"remote={remote}")
            if result:
                parts.append(f"result={result}")
            return " ".join(parts) or self._fallback_event_summary(payload, data)
        if kind == "tcc_modify":
            client = self._event_first_named_value(
                payload,
                "client",
                "bundle_id",
                "identifier",
            )
            service = self._event_first_named_value(payload, "service")
            value = self._event_first_named_value(payload, "auth_value", "result", "value")
            parts = [part for part in (client, service) if part]
            if value:
                parts.append(f"value={value}")
            return " ".join(parts) or self._fallback_event_summary(payload, data)
        if kind in ("btm_launch_item_add", "btm_launch_item_remove"):
            item = self._event_path_value(
                payload,
                ("item", "url", "path"),
                ("item", "path"),
                ("app", "path"),
            ) or self._event_first_named_value(payload, "identifier", "name")
            return item or self._fallback_event_summary(payload, data)
        if kind in ("profile_add", "profile_remove"):
            ident = self._event_first_named_value(payload, "identifier", "uuid", "name")
            org = self._event_first_named_value(payload, "organization", "display_name")
            return " ".join(part for part in (ident, org) if part) or self._fallback_event_summary(payload, data)
        if kind == "gatekeeper_user_override":
            path = self._event_path_value(payload, ("file", "path"), ("target", "path"))
            return path or self._fallback_event_summary(payload, data)
        if kind in ("xp_malware_detected", "xp_malware_remediated"):
            path = self._event_path_value(
                payload,
                ("file", "path"),
                ("target", "path"),
                ("malware", "path"),
            )
            sig = self._event_first_named_value(
                payload,
                "signature_identifier",
                "malware_identifier",
                "malware_name",
                "identifier",
            )
            return " ".join(part for part in (sig, path) if part) or self._fallback_event_summary(payload, data)
        if kind in ("kextload", "kextunload"):
            ident = self._event_first_named_value(payload, "identifier", "bundle_id")
            path = self._event_path_value(payload, ("kext", "path"), ("path",))
            return " ".join(part for part in (ident, path) if part) or self._fallback_event_summary(payload, data)
        return self._fallback_event_summary(payload, data)

    def _eslogger_select_prefixes(self):
        """Return optional `eslogger --select` prefixes from the environment."""
        raw = os.environ.get("MAC_TUI_PROCMON_ES_SELECT_PREFIXES", "").strip()
        if not raw:
            return []
        normalized = raw.replace(",", os.pathsep).replace(";", os.pathsep)
        prefixes = []
        for item in normalized.split(os.pathsep):
            item = item.strip()
            if item and item not in prefixes:
                prefixes.append(item)
        return prefixes[:16]

    def _pick_event_source(self):
        """Return (source_name, argv) for the best available live event tool."""
        if shutil.which("eslogger"):
            argv = ["eslogger", "--format", "json"]
            for prefix in self._eslogger_select_prefixes():
                argv.extend(["--select", prefix])
            argv.extend(self._ES_TIMELINE_EVENTS)
            return (
                "eslogger",
                argv,
            )
        if shutil.which("dtrace"):
            script = (
                "proc:::exec-success { "
                "printf(\"%Y|%d|%d|%s\\n\", walltimestamp, pid, ppid, curpsinfo->pr_psargs); "
                "}"
            )
            return ("dtrace", ["dtrace", "-q", "-n", script])
        if shutil.which("praudit") and os.path.exists("/dev/auditpipe"):
            # praudit -l streams one event per line from the audit pipe.
            return ("praudit", ["praudit", "-l", "/dev/auditpipe"])
        return (None, None)

    def _parse_event_line(self, source, line):
        """Parse one line of output from the chosen event source.

        Returns a dict with keys: ts, kind, pid, ppid, cmd, raw.
        Returns None if the line is noise (headers, empty, etc.).
        """
        import json as _json
        line = line.rstrip()
        if not line:
            return None
        if source == "eslogger":
            try:
                data = _json.loads(line)
            except ValueError:
                return None
            event = data.get("event") or {}
            if not isinstance(event, dict) or not event:
                return None
            kind = next(iter(event.keys()))
            payload = event.get(kind) or {}
            if kind == "exec":
                pid = self._event_int_value(
                    payload,
                    ("target", "audit_token", "pid"),
                    ("target", "pid"),
                )
                ppid = self._event_int_value(
                    payload,
                    ("target", "parent_audit_token", "pid"),
                    ("target", "parent", "audit_token", "pid"),
                )
            elif kind == "fork":
                pid = self._event_int_value(
                    payload,
                    ("child", "audit_token", "pid"),
                    ("child", "pid"),
                )
                ppid = self._event_int_value(
                    data,
                    ("process", "audit_token", "pid"),
                    ("process", "pid"),
                )
            else:
                pid = self._event_int_value(
                    data,
                    ("process", "audit_token", "pid"),
                    ("process", "pid"),
                )
                ppid = self._event_int_value(
                    data,
                    ("process", "parent_audit_token", "pid"),
                    ("process", "ppid"),
                )
            return {
                "ts": data.get("time") or "",
                "kind": kind,
                "label": self._EVENT_KIND_LABELS.get(
                    kind, kind.replace("_", " ").title()),
                "severity": self._EVENT_KIND_SEVERITY.get(kind, "INFO"),
                "pid": pid,
                "ppid": ppid,
                "cmd": self._summarize_es_event(kind, payload, data)[:200],
                "raw": line[:200],
            }
        if source == "dtrace":
            # Format: "YYYY MMM DD HH:MM:SS|PID|PPID|args..."
            parts = line.split("|", 3)
            if len(parts) < 4:
                return None
            try:
                pid = int(parts[1].strip())
                ppid = int(parts[2].strip())
            except ValueError:
                return None
            return {
                "ts": parts[0].strip(),
                "kind": "exec",
                "label": self._EVENT_KIND_LABELS["exec"],
                "severity": self._EVENT_KIND_SEVERITY["exec"],
                "pid": pid,
                "ppid": ppid,
                "cmd": parts[3].strip()[:200],
                "raw": line[:200],
            }
        if source == "praudit":
            # praudit -l emits tokens separated by commas; the header
            # token includes the event name e.g. "execve(2)".
            if "execve" not in line and "exec" not in line:
                return None
            return {
                "ts": "",
                "kind": "exec",
                "label": self._EVENT_KIND_LABELS["exec"],
                "severity": self._EVENT_KIND_SEVERITY["exec"],
                "pid": 0,
                "ppid": 0,
                "cmd": line[:200],
                "raw": line[:200],
            }
        return None

    # ── Feature 5: Attack Chain Replay ─────────────────────────────────

    def _detect_driveby_pairs(self, events):
        """Heuristic linking: flag (parent_pid, child_pid) pairs where a
        curl/wget exec is followed by a `bash -c` exec within the
        configured window.

        Returns a set of (parent_pid, child_pid) tuples.
        """
        pairs = set()
        downloaders = []  # (idx, pid, ts_monotonic)
        for idx, evt in enumerate(events):
            kind = evt.get("kind", "")
            if kind != "exec":
                continue
            cmd = (evt.get("cmd") or "").lower()
            pid = evt.get("pid", 0)
            ppid = evt.get("ppid", 0)
            ts_mono = evt.get("ts_mono")
            if ts_mono is None:
                ts_mono = idx * 1.0  # fallback ordering when no clock
            # Identify a shell-with-command exec first — catches the
            # `bash -c "curl x | sh"` case where curl appears inside the
            # shell command line, not as a separate exec.
            is_shell = any(s in cmd for s in (
                "bash -c", "sh -c", "zsh -c", "/bin/bash ", "/bin/sh "))
            if is_shell:
                pass  # fall through to pair-up logic below
            elif any(tok in cmd for tok in ("curl", "wget")):
                # Standalone downloader (the parent in a multi-exec
                # drive-by). Stash and move on.
                downloaders.append((idx, pid, ts_mono))
                continue
            else:
                continue
            for d_idx, d_pid, d_ts in downloaders:
                # Same ancestry (the shell is invoked by the downloader's
                # parent or descendant chain) is the strict version; in
                # practice curl spawning a shell is the obvious one. We
                # accept either ppid==d_pid OR within the window.
                if ts_mono - d_ts > self._replay_driveby_window_secs:
                    continue
                if ppid == d_pid or pid == d_pid:
                    pairs.add((d_pid, pid))
                else:
                    # Looser match: same parent process tree within window.
                    pairs.add((d_pid, pid))
        return pairs

    def _start_replay_mode(self):
        """Snapshot the captured event buffer and enter replay mode."""
        with self._events_lock:
            snap = list(self._events)
        if not snap:
            return False
        # Annotate each event with monotonic-ish ordering for the linker.
        for idx, evt in enumerate(snap):
            evt.setdefault("ts_mono", idx * 1.0)
        self._replay_events = snap
        self._replay_cursor = 0
        self._replay_playing = False
        self._replay_driveby_pairs = self._detect_driveby_pairs(snap)
        self._replay_mode = True
        self._detail_focus = True
        return True

    def _exit_replay_mode(self):
        self._replay_mode = False
        self._replay_playing = False
        self._detail_focus = False

    def _replay_step(self, delta):
        """Advance / rewind the replay cursor; clamp to bounds."""
        if not self._replay_events:
            return
        n = len(self._replay_events)
        self._replay_cursor = max(0, min(n - 1, self._replay_cursor + delta))

    def _replay_toggle_play(self):
        self._replay_playing = not self._replay_playing

    def _replay_advance_if_playing(self):
        if not (self._replay_mode and self._replay_playing):
            return False
        n = len(self._replay_events)
        if n <= 0:
            return False
        if self._replay_cursor >= n - 1:
            self._replay_playing = False
            return False
        self._replay_cursor = min(n - 1,
                                   self._replay_cursor + max(1, int(self._replay_speed)))
        return True

    def _replay_density_timeline(self, width):
        """Render an event-density bar with a marker for current cursor."""
        n = len(self._replay_events)
        if n == 0 or width <= 4:
            return ""
        buckets = max(1, min(width, 80))
        counts = [0] * buckets
        for i, _ in enumerate(self._replay_events):
            b = min(buckets - 1, int(i / max(1, n) * buckets))
            counts[b] += 1
        peak = max(counts) or 1
        glyphs = " ▁▂▃▄▅▆▇█"
        bar_chars = []
        for c in counts:
            idx = min(len(glyphs) - 1, int(c / peak * (len(glyphs) - 1)))
            bar_chars.append(glyphs[idx])
        bar = "".join(bar_chars)
        # Marker for cursor.
        marker_pos = min(buckets - 1,
                          int(self._replay_cursor / max(1, n - 1) * (buckets - 1)))
        marker_line = list(" " * buckets)
        marker_line[marker_pos] = "▲"
        return bar + "\n" + "".join(marker_line)

    def _format_replay_view(self, width):
        """Build display lines for replay mode."""
        lines = []
        n = len(self._replay_events)
        if n == 0:
            lines.append(" No replay events captured yet — start an"
                         " events stream first.")
            return lines
        cur = self._replay_events[max(0, min(n - 1, self._replay_cursor))]
        kind = cur.get("kind", "")
        sev = cur.get("severity") or self._EVENT_KIND_SEVERITY.get(
            kind, "INFO")
        label = cur.get("label") or self._EVENT_KIND_LABELS.get(kind, kind)
        cmd = (cur.get("cmd") or "")[:width - 20]
        pid = cur.get("pid", 0)
        ppid = cur.get("ppid", 0)
        playing = "▶ playing" if self._replay_playing else "⏸ paused"
        lines.append(f" Replay {playing}  [{self._replay_cursor + 1} / {n}]")
        lines.append("")
        lines.append(f" [{sev}] {label}")
        lines.append(f"  pid={pid}  ppid={ppid}")
        lines.append(f"  {cmd}")
        # Drive-by tag: if this event is the child in a flagged pair, or
        # the parent curl in such a pair, highlight it.
        flagged = any(pid == p or pid == c
                       for (p, c) in self._replay_driveby_pairs)
        if flagged:
            lines.append("")
            lines.append(" ⚠ Potential drive-by — curl→shell pattern flagged")
        lines.append("")
        timeline = self._replay_density_timeline(min(80, width - 4))
        if timeline:
            for tl in timeline.split("\n"):
                lines.append(" " + tl)
        lines.append("")
        lines.append(" ←/→  step    space toggle play    Esc close")
        return lines

    def _toggle_events_mode(self):
        """Toggle live security timeline mode."""
        if self._events_mode:
            # Persist the captured buffer so the user can replay it.
            if self._events_persist_on_close:
                with self._events_lock:
                    self._replay_events = list(self._events)
                # Annotate ordering for the heuristic linker.
                for idx, evt in enumerate(self._replay_events):
                    evt.setdefault("ts_mono", idx * 1.0)
                self._replay_driveby_pairs = self._detect_driveby_pairs(
                    self._replay_events)
            self._stop_events_stream()
            self._events_mode = False
            self._detail_focus = False
            return
        self._events = []
        self._events_scroll = 0
        self._events_mode = True
        self._events_awaiting_summary = False
        self._llm_summary["events"] = None
        self._llm_summary_pending["events"] = None
        self._llm_summary_loading["events"] = False
        self._inspect_mode = False
        self._net_mode = False
        self._detail_focus = True
        self._start_events_stream()

    def _append_event(self, kind, cmd, raw=""):
        """Thread-safe helper to append an event into the ring buffer."""
        with self._events_lock:
            self._events.append({
                "ts": "", "kind": kind, "pid": 0, "ppid": 0,
                "cmd": cmd, "raw": raw,
            })
            if len(self._events) > self._events_max:
                del self._events[:len(self._events) - self._events_max]

    def _start_events_stream(self):
        """Spawn the event source subprocess and reader threads."""
        if self._events_worker and self._events_worker.is_alive():
            return
        source, argv = self._pick_event_source()
        self._events_source = source or ""
        if not source:
            self._append_event(
                "error",
                "[no telemetry source available — install/use eslogger for "
                "the full security timeline, or fall back to dtrace/praudit]",
            )
            return

        if os.geteuid() != 0:
            self._append_event(
                "error",
                f"[{source} typically requires root + Full Disk Access on "
                f"macOS \u2014 re-run with: sudo mac-tui-procmon]",
            )

        try:
            self._events_proc = subprocess.Popen(
                argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                bufsize=0,  # unbuffered so line-oriented readline works promptly
            )
        except (FileNotFoundError, OSError) as e:
            self._append_event("error", f"[failed to start {source}: {e}]")
            self._events_proc = None
            return
        self._events_cancel = False

        def _reader():
            """Consume stdout line by line and parse into events."""
            proc = self._events_proc
            if not proc or not proc.stdout:
                return
            try:
                for raw in iter(proc.stdout.readline, b""):
                    if self._events_cancel:
                        break
                    line = raw.decode("utf-8", errors="replace")
                    evt = self._parse_event_line(source, line)
                    if evt is None:
                        continue
                    with self._events_lock:
                        self._events.append(evt)
                        if len(self._events) > self._events_max:
                            del self._events[:len(self._events) - self._events_max]
            except Exception as e:
                self._append_event("error", f"[reader error: {e}]")

        def _stderr_reader():
            """Surface anything the source writes to stderr as an error event.

            Without this, failures like 'Not privileged to create an ES
            client' are invisible and the view just shows 'no events yet'
            forever.
            """
            proc = self._events_proc
            if not proc or not proc.stderr:
                return
            try:
                for raw in iter(proc.stderr.readline, b""):
                    if self._events_cancel:
                        break
                    line = raw.decode("utf-8", errors="replace").rstrip()
                    if line:
                        self._append_event("error", f"[{source} stderr] {line}")
            except Exception:
                pass

        def _exit_watcher():
            """Detect if the subprocess dies early and report it.

            Most of the time the event source runs forever; an early exit
            means it crashed or was denied. The user needs to know — otherwise
            the view looks hung.
            """
            proc = self._events_proc
            if not proc:
                return
            try:
                rc = proc.wait()
            except Exception:
                return
            if self._events_cancel:
                return
            self._append_event(
                "error",
                f"[{source} exited with code {rc} \u2014 "
                f"security timeline stopped]",
            )

        self._events_worker = threading.Thread(target=_reader, daemon=True)
        self._events_worker.start()
        threading.Thread(target=_stderr_reader, daemon=True).start()
        threading.Thread(target=_exit_watcher, daemon=True).start()

    def _stop_events_stream(self):
        """Terminate the event source subprocess and reader thread."""
        self._events_cancel = True
        proc = self._events_proc
        if proc:
            try:
                proc.terminate()
                try:
                    proc.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
            except Exception:
                pass
        self._events_proc = None

    # ── Unified Logging per-process stream ─────────────────────────────

    def _toggle_unified_log_mode(self):
        """Start/stop streaming `log stream --process <pid>` for the row.

        Writes the result lines into a bounded ring buffer that the
        detail panel renders. The subprocess is killed cleanly on Esc
        and on TUI exit (see _shutdown).
        """
        if self._unified_log_mode:
            self._stop_unified_log_stream()
            self._unified_log_mode = False
            self._detail_focus = False
            return
        if not self.rows:
            return
        sel = self.rows[self.selected]
        pid = sel["pid"]
        cmd = sel.get("command", "").split()[0].rsplit("/", 1)[-1][:20]
        # Close any other detail mode to avoid conflicting subprocesses.
        if self._events_mode:
            self._stop_events_stream()
            self._events_mode = False
        self._inspect_mode = False
        self._net_mode = False
        self._unified_log_pid = pid
        self._unified_log_cmd = cmd
        with self._unified_log_lock:
            self._unified_log_lines = collections.deque(
                maxlen=self._unified_log_max)
        self._unified_log_scroll = 0
        self._unified_log_mode = True
        self._unified_log_loading = True
        self._detail_focus = True
        self._start_unified_log_stream(pid)

    def _start_unified_log_stream(self, pid):
        """Spawn `log stream` for the given pid and a reader thread."""
        if (self._unified_log_worker
                and self._unified_log_worker.is_alive()):
            return
        argv = [
            "log", "stream",
            "--process", str(pid),
            "--level", "info",
            "--style", "compact",
        ]
        env = {**os.environ,
               "PATH": _USER_TOOL_PATH,
               "HOME": _EFFECTIVE_HOME}
        try:
            self._unified_log_proc = subprocess.Popen(
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=0,
                env=env,
            )
        except (FileNotFoundError, OSError) as e:
            self._append_unified_log_line(
                f"[failed to start log stream: {e}]")
            self._unified_log_proc = None
            self._unified_log_loading = False
            return
        self._unified_log_cancel = False

        def _reader():
            proc = self._unified_log_proc
            if not proc or not proc.stdout:
                return
            try:
                for raw in iter(proc.stdout.readline, b""):
                    if self._unified_log_cancel:
                        break
                    line = raw.decode(
                        "utf-8", errors="replace").rstrip("\n")
                    if line:
                        self._append_unified_log_line(line)
            except Exception as e:
                self._append_unified_log_line(f"[reader error: {e}]")

        def _stderr_reader():
            proc = self._unified_log_proc
            if not proc or not proc.stderr:
                return
            try:
                for raw in iter(proc.stderr.readline, b""):
                    if self._unified_log_cancel:
                        break
                    line = raw.decode(
                        "utf-8", errors="replace").rstrip()
                    if line:
                        self._append_unified_log_line(
                            f"[log stream stderr] {line}")
            except Exception:
                pass

        self._unified_log_worker = threading.Thread(
            target=_reader, daemon=True)
        self._unified_log_worker.start()
        threading.Thread(
            target=_stderr_reader, daemon=True).start()

    def _append_unified_log_line(self, line):
        with self._unified_log_lock:
            self._unified_log_lines.append(line)

    def _stop_unified_log_stream(self):
        """Kill the `log stream` subprocess. Safe to call repeatedly."""
        self._unified_log_cancel = True
        proc = self._unified_log_proc
        if proc:
            try:
                proc.terminate()
                try:
                    proc.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
            except Exception:
                pass
        self._unified_log_proc = None
        self._unified_log_loading = False

    # ── GPU / Metal per-process utilization ────────────────────────────

    def _probe_gpu_supported(self):
        """Decide whether per-PID GPU sampling is feasible on this run.

        We need both root (powermetrics requires it) AND the
        `powermetrics` binary on PATH. If either is missing we set
        _gpu_supported=False and never spawn the sampler — the GPU%
        column simply doesn't render.
        """
        if self._gpu_supported_probed:
            return
        self._gpu_supported_probed = True
        if os.geteuid() != 0:
            self._gpu_supported = False
            self._gpu_status = "needs root"
            return
        try:
            pm = shutil.which("powermetrics", path=_USER_TOOL_PATH) or \
                shutil.which("powermetrics")
        except Exception:
            pm = None
        if not pm:
            self._gpu_supported = False
            self._gpu_status = "unsupported"
            return
        self._gpu_supported = True
        self._gpu_status = ""

    def _maybe_start_gpu_sampler(self):
        """Kick the background powermetrics sampler if the gate is open."""
        if not self._gpu_supported:
            return
        if self._gpu_worker and self._gpu_worker.is_alive():
            return
        now = time.monotonic()
        if (now - self._gpu_last_sample_ts) < self._gpu_sample_interval:
            return
        self._gpu_last_sample_ts = now
        self._gpu_loading = True
        self._gpu_worker = threading.Thread(
            target=self._gpu_sampler_worker, daemon=True)
        self._gpu_worker.start()

    def _gpu_sampler_worker(self):
        """Run a single powermetrics --samplers tasks pass and parse JSON.

        The sampler writes a 1-second window of per-task GPU activity in
        plist/JSON form. We capture the JSON via --format plist | plutil
        is unreliable; we use --format json directly. Failures degrade
        silently (most likely because the kernel revoked our access).
        """
        env = {**os.environ,
               "PATH": _USER_TOOL_PATH,
               "HOME": _EFFECTIVE_HOME}
        argv = [
            "powermetrics",
            "--samplers", "tasks",
            "--show-process-gpu",
            "-i", "1000",
            "-n", "1",
            "--format", "json",
        ]
        try:
            proc = subprocess.Popen(
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
            )
            try:
                out, _err = proc.communicate(timeout=8)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
                self._gpu_pending = {}
                self._gpu_loading = False
                return
        except (FileNotFoundError, OSError):
            self._gpu_supported = False
            self._gpu_pending = {}
            self._gpu_loading = False
            return
        samples = self._parse_powermetrics_gpu_json(out)
        self._gpu_pending = samples
        self._gpu_loading = False

    @staticmethod
    def _parse_powermetrics_gpu_json(blob):
        """Parse powermetrics JSON output into pid -> gpu_pct (0..100).

        powermetrics in --format json mode emits one self-contained JSON
        object per sample window. The 'tasks' array contains per-process
        entries with 'pid' and (when --show-process-gpu is on) a
        'gputime_ms_per_s' field that we treat as 'GPU activity ms in the
        last 1000 ms', i.e. essentially a GPU% value already.

        Robust to: empty input, missing tasks key, missing pid, type
        coercion failures.
        """
        if not blob:
            return {}
        try:
            text = (blob.decode("utf-8", errors="replace")
                    if isinstance(blob, (bytes, bytearray)) else blob)
        except Exception:
            return {}
        # powermetrics may emit multiple JSON docs concatenated for -n>1.
        # We requested -n 1, but be permissive and accept the first
        # parseable doc.
        text = text.strip()
        if not text:
            return {}
        try:
            data = _json.loads(text)
        except Exception:
            # Fall back to slicing off everything after the first
            # top-level '}' — works for the common single-sample case.
            try:
                end = text.rfind("}")
                if end > 0:
                    data = _json.loads(text[:end + 1])
                else:
                    return {}
            except Exception:
                return {}
        tasks = data.get("tasks") or []
        out = {}
        for t in tasks:
            try:
                pid = int(t.get("pid", -1))
            except (TypeError, ValueError):
                continue
            if pid <= 0:
                continue
            ms = t.get("gputime_ms_per_s")
            if ms is None:
                ms = t.get("gputime_ms_per_s_total")
            if ms is None:
                continue
            try:
                pct = float(ms) / 10.0  # ms in 1000 ms → /10 for %
            except (TypeError, ValueError):
                continue
            pct = max(0.0, min(100.0, pct))
            out[pid] = pct
        return out

    def _poll_gpu_result(self):
        """If a sampler pass completed, swap its results into _gpu_samples."""
        if self._gpu_pending is None:
            return False
        with self._gpu_samples_lock:
            self._gpu_samples = self._gpu_pending or {}
        self._gpu_pending = None
        return True

    # ── Traffic Inspector (experimental mitmproxy wrapper) ────────────

    _MITM_SHIM = (
        "from mitmproxy import http\n"
        "import json, sys\n"
        "def response(flow):\n"
        "    try:\n"
        "        sys.stdout.write(json.dumps({\n"
        "            'method': flow.request.method,\n"
        "            'url': flow.request.pretty_url,\n"
        "            'host': flow.request.host,\n"
        "            'scheme': flow.request.scheme,\n"
        "            'status': flow.response.status_code "
        "if flow.response else 0,\n"
        "            'content_type': flow.response.headers.get("
        "'content-type', '') if flow.response else '',\n"
        "            'req_size': len(flow.request.raw_content or b''),\n"
        "            'resp_size': len(flow.response.raw_content or b'') "
        "if flow.response else 0,\n"
        "        }) + '\\n')\n"
        "        sys.stdout.flush()\n"
        "    except Exception:\n"
        "        pass\n"
        "def error(flow):\n"
        "    try:\n"
        "        sys.stdout.write(json.dumps({\n"
        "            'method': getattr(flow.request, 'method', '?') "
        "if flow.request else '?',\n"
        "            'url': getattr(flow.request, 'pretty_url', '') "
        "if flow.request else '',\n"
        "            'host': getattr(flow.request, 'host', '') "
        "if flow.request else '',\n"
        "            'status': -1,\n"
        "            'error': str(flow.error) if flow.error else "
        "'(unknown)',\n"
        "        }) + '\\n')\n"
        "        sys.stdout.flush()\n"
        "    except Exception:\n"
        "        pass\n")

    def _toggle_traffic_mode(self):
        """Open/close the experimental Traffic Inspector backend."""
        if self._traffic_mode:
            self._stop_traffic_stream()
            self._traffic_mode = False
            self._detail_focus = False
            return
        # Preflight — mitmdump must be on PATH
        mitm = shutil.which("mitmdump")
        if not mitm:
            self._traffic_error = (
                "experimental backend unavailable: mitmdump not found. "
                "Install via: brew install mitmproxy")
            self._traffic_mode = True
            self._detail_focus = True
            return
        self._traffic_error = ""
        self._traffic_flows = []
        self._traffic_scroll = 0
        self._traffic_mode = True
        self._inspect_mode = False
        self._net_mode = False
        if self._events_mode:
            self._stop_events_stream()
            self._events_mode = False
        if self._audit_mode:
            self._audit_mode = False
        self._detail_focus = True
        self._start_traffic_stream(mitm)

    def _start_traffic_stream(self, mitm_path):
        """Launch mitmdump with the inline shim script that emits one
        JSON flow record per line. Streams stdout into a reader thread
        that populates the ring buffer."""
        # Write the shim to a temp file keyed by our pid so multiple
        # mac-tui-procmon instances don't stomp on each other.
        shim_path = f"/tmp/mac-tui-procmon-mitm-shim-{os.getpid()}.py"
        try:
            with open(shim_path, "w") as f:
                f.write(self._MITM_SHIM)
        except OSError as e:
            self._traffic_error = f"could not write shim: {e}"
            return
        self._traffic_shim_path = shim_path

        argv = [mitm_path, "-q", "-s", shim_path,
                "--listen-port", str(self._traffic_port)]
        self._traffic_loading = True
        try:
            self._traffic_proc = subprocess.Popen(
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                bufsize=1,  # line-buffered
                text=True,
            )
        except (FileNotFoundError, OSError) as e:
            self._traffic_error = f"mitmdump launch failed: {e}"
            self._traffic_proc = None
            self._traffic_loading = False
            return

        def _reader():
            proc = self._traffic_proc
            if proc is None or proc.stdout is None:
                return
            import json as _j
            for raw in proc.stdout:
                line = raw.rstrip()
                if not line:
                    continue
                try:
                    flow = _j.loads(line)
                except ValueError:
                    # mitmdump emits non-JSON status lines too; skip them
                    continue
                with self._traffic_flows_lock:
                    self._traffic_flows.append(flow)
                    # Cap the ring buffer so we don't eat memory on long
                    # captures.
                    if len(self._traffic_flows) > self._traffic_flows_max:
                        del self._traffic_flows[:
                            len(self._traffic_flows)
                            - self._traffic_flows_max]

        self._traffic_reader_thread = threading.Thread(
            target=_reader, daemon=True)
        self._traffic_reader_thread.start()
        self._traffic_loading = False

    def _stop_traffic_stream(self):
        """Terminate mitmdump + its reader thread and clean up the shim."""
        proc = self._traffic_proc
        if proc:
            try:
                proc.terminate()
                try:
                    proc.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
            except Exception:
                pass
        self._traffic_proc = None
        self._traffic_loading = False
        if self._traffic_shim_path:
            try:
                os.unlink(self._traffic_shim_path)
            except OSError:
                pass
            self._traffic_shim_path = ""

    def _format_traffic_view(self):
        """Build display lines for the Traffic Inspector detail box."""
        lines = [f"Traffic Inspector (experimental) \u2014 mitmdump on :"
                 f"{self._traffic_port}"]
        if self._traffic_error:
            lines.append("")
            lines.append(f"  [!]  {self._traffic_error}")
            if "not found" in self._traffic_error:
                lines.append("")
                lines.append("  After install:")
                lines.append("    1. Start mac-tui-procmon again and open Traffic Inspector")
                lines.append("    2. Trust mitmproxy's CA:")
                lines.append("       ~/.mitmproxy/mitmproxy-ca-cert.pem")
                lines.append("    3. Route only the suspect app through "
                             "127.0.0.1:8080")
            return lines
        lines.append("")
        lines.append("  Route the suspect app through "
                     f"127.0.0.1:{self._traffic_port} when you explicitly")
        lines.append("  need decrypted proxy visibility. Host-wide transparent")
        lines.append("  interception is intentionally out of scope here.")
        lines.append("  For HTTPS: install ~/.mitmproxy/mitmproxy-ca-cert.pem "
                     "as a trusted root.")
        lines.append("")
        with self._traffic_flows_lock:
            snap = list(self._traffic_flows)
        lines.append(f"  [INFO]  Captured {len(snap)} flow(s)")
        lines.append("")
        if not snap:
            lines.append("    (waiting for traffic — no flows yet)")
            return lines
        # Render newest-first so active traffic stays visible
        for flow in snap[-200:][::-1]:
            method = flow.get("method", "?")
            host = flow.get("host", "")
            url = flow.get("url", "")
            status = flow.get("status", 0)
            req = flow.get("req_size", 0)
            resp = flow.get("resp_size", 0)
            ct = flow.get("content_type", "")
            err = flow.get("error")
            status_tag = (f"[HIGH]" if err
                          else f"[INFO]" if 200 <= status < 400
                          else f"[MEDIUM]")
            if err:
                lines.append(f"    {status_tag}  {method:<6} {host}  "
                             f"ERROR: {err[:80]}")
            else:
                size_str = f"req={req}B resp={resp}B"
                ct_short = (ct.split(";")[0] if ct else "")
                lines.append(f"    {status_tag}  {method:<6} "
                             f"{status:>3} {url[:80]}")
                if ct_short or size_str:
                    lines.append(f"              {ct_short}  {size_str}")
        return lines

    # ── End Traffic Inspector ──────────────────────────────────────────

    def _start_events_llm_summary(self):
        """Snapshot the captured security timeline and feed it to Claude."""
        with self._events_lock:
            events = list(self._events)
        if not events:
            return

        # Compact textual representation so Claude sees one line per event.
        body_lines = [f"macOS security timeline from source: "
                      f"{self._events_source}",
                      f"Total events captured: {len(events)}", ""]
        for evt in events[-300:]:  # cap so we don't blow past context
            ts = (evt.get("ts") or "")[:19]
            pid = evt.get("pid", 0)
            ppid = evt.get("ppid", 0)
            kind = evt.get("kind", "")
            label = evt.get("label") or self._EVENT_KIND_LABELS.get(kind, kind)
            sev = evt.get("severity") or self._EVENT_KIND_SEVERITY.get(kind, "INFO")
            cmd = (evt.get("cmd") or "")[:180]
            body_lines.append(
                f"  {ts} {sev} pid={pid} ppid={ppid} {label}: {cmd}")
        body = "\n".join(body_lines)

        self._llm_summary["events"] = None
        self._llm_summary_pending["events"] = None
        self._llm_summary_loading["events"] = True

        prompt = (
            "You are analyzing a macOS security timeline. Return a "
            "3–6 bullet narrative. Each bullet ≤25 words and starts with "
            "one of: TOP_CONCERN:, SIGNAL:, NOISE:, ACTION:.\n"
            "- TOP_CONCERN: the strongest operator-risk signal in the "
            "timeline (XProtect, TCC changes, launch-item adds, auth abuse, "
            "privileged process chains, Gatekeeper overrides).\n"
            "- SIGNAL: notable but inconclusive observations the user "
            "should investigate.\n"
            "- NOISE: recurring legitimate system activity the user can "
            "safely ignore (spotlight, backupd, softwareupdated, etc.).\n"
            "- ACTION: the single most valuable next step.")

        def _worker():
            try:
                resp = self._run_llm(
                    "claude", prompt, body, timeout=90)
                if resp.startswith("["):
                    self._llm_summary_pending["events"] = [
                        "  \u2501\u2501 AI SUMMARY \u2501\u2501",
                        "",
                        f"    [INFO]  Summary unavailable: {resp[:120]}",
                        ""]
                else:
                    event_findings = [
                        {"severity": evt.get("severity") or "INFO"}
                        for evt in events
                    ]
                    top_sev, signal_sev = self._summary_panel_severities(
                        event_findings)
                    self._llm_summary_pending["events"] = (
                        self._format_llm_summary_panel(
                            resp,
                            top_concern_severity=top_sev,
                            signal_severity=signal_sev,
                        ))
            except Exception as e:
                self._llm_summary_pending["events"] = [
                    "  \u2501\u2501 AI SUMMARY \u2501\u2501",
                    "",
                    f"    [INFO]  Summary error: {e}",
                    ""]

        t = threading.Thread(target=_worker, daemon=True)
        self._llm_summary_worker["events"] = t
        t.start()

    def _format_unified_log_view(self):
        """Build display lines for the unified-log detail box."""
        with self._unified_log_lock:
            snapshot = list(self._unified_log_lines)
        header = (f"`log stream --process {self._unified_log_pid} "
                  f"--level info --style compact`")
        lines = [header, ""]
        if not snapshot:
            if self._unified_log_loading:
                lines.append("  Connecting to unified log…")
            else:
                lines.append("  (no log entries yet)")
            return lines
        # Cap displayed depth so very chatty processes don't blow up render.
        for ln in snapshot[-1000:]:
            lines.append(ln)
        return lines

    def _format_events_view(self):
        """Build display lines for the events detail box."""
        header = f"Security timeline \u2014 source: {self._events_source or '(none)'}"
        if self._events_source == "eslogger":
            header += " \u2014 exec/auth/login/TCC/XProtect/launch items"
            prefixes = self._eslogger_select_prefixes()
            if prefixes:
                header += " \u2014 scope: " + ", ".join(prefixes[:3])
        elif self._events_source:
            header += " \u2014 exec-only fallback"
        if self._events_source and os.geteuid() != 0:
            header += " \u2014 NOT ROOT (source likely inert)"
        lines = [header, ""]
        with self._events_lock:
            snapshot = list(self._events)
        f = self._events_filter.lower()
        if f:
            snapshot = [e for e in snapshot if f in e.get("cmd", "").lower()]
        if not snapshot:
            lines.append("  (no security events yet — waiting for process activity)")
            if self._events_source and os.geteuid() != 0:
                lines.append("")
                lines.append("  [!] Most macOS event sources require root.")
                lines.append("      Quit mac-tui-procmon and re-run with: sudo mac-tui-procmon")
            return lines
        for evt in snapshot[-200:]:
            ts = evt.get("ts", "")[:19]
            pid = evt.get("pid", 0)
            ppid = evt.get("ppid", 0)
            cmd = evt.get("cmd", "")[:120]
            kind = evt.get("kind", "")
            label = evt.get("label") or self._EVENT_KIND_LABELS.get(kind, kind)
            sev = evt.get("severity") or self._EVENT_KIND_SEVERITY.get(kind, "INFO")
            mark = {
                "OK": "[OK]",
                "INFO": "[INFO]",
                "MEDIUM": "[MEDIUM]",
                "HIGH": "[HIGH]",
                "CRITICAL": "[CRITICAL]",
            }.get(sev, "[INFO]")
            if pid:
                lines.append(
                    f"  {mark:<10} {ts} pid={pid} ppid={ppid} {label}: {cmd}")
            else:
                lines.append(f"  {mark:<10} {ts} {label}: {cmd}")
        return lines

    # ── Process Inspect Mode ────────────────────────────────────────────

    def _collect_inspect_artifacts(self, pid, exe_path):
        """Collect forensic artifacts for a process. Runs in background thread."""
        artifacts = {}
        is_root = os.geteuid() == 0

        def _run_cmd(cmd, timeout=10):
            try:
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE)
                try:
                    stdout, stderr = proc.communicate(timeout=timeout)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
                    return "[timed out]"
                out = stdout.decode("utf-8", errors="replace").strip()
                err = stderr.decode("utf-8", errors="replace").strip()
                return out if out else err
            except (FileNotFoundError, OSError) as e:
                return f"[error: {e}]"

        # 1. Code signature verification (--deep recurses into every
        # nested binary in the bundle, so for Chrome / Electron apps with
        # hundreds of helpers this can take 30–50s on a cold cache. 60s
        # covers the worst case; 10s was timing out on first inspect.)
        artifacts["codesign_verify"] = _run_cmd(
            ["codesign", "-vvv", "--deep", exe_path], timeout=60)

        # 2. Entitlements
        artifacts["entitlements"] = _run_cmd(
            ["codesign", "-d", "--entitlements", ":-", exe_path])

        # 3. Linked dylibs (otool walks the LC_LOAD_DYLIB chain — fast
        # for normal binaries, slow for Chrome which links a lot)
        artifacts["dylibs"] = _run_cmd(["otool", "-L", exe_path], timeout=20)

        # 4. Binary hash (large binaries — Chrome is ~200 MB — can take
        # 10–20s for shasum to compute on cold cache)
        artifacts["sha256"] = _run_cmd(
            ["shasum", "-a", "256", exe_path], timeout=30)

        # 5. All open files (not just network)
        artifacts["lsof"] = _run_cmd(["lsof", "-p", str(pid)], timeout=15)

        # 6. Environment variables (no fork — uses ctypes with thread-local buffer)
        try:
            env = _get_proc_env(pid)
            artifacts["env"] = env
        except Exception:
            artifacts["env"] = {}

        # 7. Process lineage (walk PPID chain with thread-local buffer)
        lineage = []
        current_pid = pid
        seen = set()
        local_bsdinfo = proc_bsdinfo()
        while current_pid > 0 and current_pid not in seen and len(lineage) < 20:
            seen.add(current_pid)
            path = _get_proc_path(current_pid)
            lineage.append((current_pid, path or "[unknown]"))
            ret = _libproc.proc_pidinfo(
                current_pid, PROC_PIDTBSDINFO, 0,
                ctypes.byref(local_bsdinfo), ctypes.sizeof(local_bsdinfo))
            if ret <= 0:
                break
            current_pid = local_bsdinfo.pbi_ppid
        artifacts["lineage"] = lineage

        # 8. vmmap (root only)
        if is_root:
            artifacts["vmmap"] = _run_cmd(["vmmap", str(pid)], timeout=15)
        else:
            artifacts["vmmap"] = "[skipped \u2014 requires root]"

        # 9. Structured codesign parse (team id, authority, requirements)
        artifacts["codesign_structured"] = _codesign_structured(exe_path)

        # 10. Gatekeeper/notarization assessment
        artifacts["gatekeeper"] = _check_gatekeeper(exe_path)

        # 11. Persistence-path hits in open files
        artifacts["persistence_hits"] = _lsof_hits_persistence(artifacts["lsof"])

        # 12. User-writable dylib hits
        artifacts["user_writable_dylibs"] = _otool_user_writable_dylibs(
            artifacts["dylibs"])

        # 13. YARA scan on the on-disk binary
        artifacts["yara_file"] = _yara_scan_file(exe_path)

        # 15. YARA scan on a memory snapshot (only if root — lldb needs perms)
        if is_root:
            artifacts["yara_memory"] = _yara_scan_memory(pid)
        else:
            artifacts["yara_memory"] = {"success": False,
                                        "error": "skipped — requires root"}

        # 16. Mach file-port count (IPC handle enumeration). Doesn't need
        # task_for_pid, so works without root for any pid we can already
        # see; -1 means libproc rejected it (zombie / restricted).
        try:
            artifacts["mach_ports"] = _get_mach_port_count(pid)
        except Exception:
            artifacts["mach_ports"] = -1

        artifacts["exe_path"] = exe_path
        artifacts["pid"] = pid
        return artifacts

    def _build_trend_section(self, pid):
        """Render per-PID metric trend (CPU%, RSS, net I/O) as sparklines.

        Returns a list of strings to splice into the inspect/detail panel,
        or an empty list when no history exists for the pid.
        """
        if pid is None:
            return []
        with self._metric_history_lock:
            hist = self._metric_history.get(pid)
            if not hist:
                return []
            cpu_vals = list(hist.get("cpu", []))
            rss_vals = list(hist.get("rss_kb", []))
            ni_vals = list(hist.get("net_in", []))
            no_vals = list(hist.get("net_out", []))

        sample_count = max(len(cpu_vals), len(rss_vals),
                           len(ni_vals), len(no_vals))
        if sample_count == 0:
            return []

        lines = []
        lines.append(f"\u2500\u2500 TREND (last {sample_count} samples) \u2500\u2500")
        if cpu_vals:
            peak = max(cpu_vals)
            spark = _sparkline(cpu_vals, width=24)
            lines.append(f"  CPU%:    {spark}  peak {peak:.1f}%")
        if rss_vals:
            peak_kb = max(rss_vals)
            spark = _sparkline(rss_vals, width=24)
            lines.append(f"  MEM:     {spark}  peak {fmt_mem(peak_kb)}")
        if ni_vals:
            peak = max(ni_vals)
            spark = _sparkline(ni_vals, width=24)
            lines.append(f"  Net \u2193:   {spark}  peak {fmt_rate(peak)}")
        if no_vals:
            peak = max(no_vals)
            spark = _sparkline(no_vals, width=24)
            lines.append(f"  Net \u2191:   {spark}  peak {fmt_rate(peak)}")
        lines.append("")
        return lines

    def _format_inspect_report(self, artifacts):
        """Format collected artifacts into display lines."""
        lines = []
        pid = artifacts.get("pid", "?")
        exe = artifacts.get("exe_path", "?")
        lines.append(f"[INSPECT] PID {pid} \u2014 {exe}")
        # Top-of-report scan-coverage badges so the user can see at a glance
        # what was / wasn't inspected. Memory scan is gated on root + lldb.
        ym = artifacts.get("yara_memory") or {}
        if ym.get("success"):
            hits = len(ym.get("matches", []))
            size_mb = (ym.get("core_size", 0) or 0) / (1024 * 1024)
            lines.append(f"  [MEMORY-DUMPED] {size_mb:.1f} MB core, "
                         f"{hits} YARA hit{'s' if hits != 1 else ''} "
                         f"(core deleted after scan)")
        else:
            reason = (ym.get("error") or "not attempted").strip()
            lines.append(f"  [MEMORY-SKIPPED] {reason[:120]}")
        yf = artifacts.get("yara_file") or []
        lines.append(f"  [DISK-YARA] {len(yf)} hit{'s' if len(yf) != 1 else ''} on on-disk binary")
        lines.append("")

        # Per-PID metric sparklines (rolling-window trend)
        try:
            trend = self._build_trend_section(
                artifacts.get("pid") if isinstance(artifacts.get("pid"), int)
                else None)
            if trend:
                lines.extend(trend)
        except Exception:
            pass

        # Mach file ports (IPC handle count). Always populated when the
        # selected row's mach_ports field is non-negative; -1 means
        # libproc rejected the call (process exited or restricted).
        mp_count = artifacts.get("mach_ports")
        if isinstance(mp_count, int) and mp_count >= 0:
            lines.append(
                f"── IPC: {mp_count} Mach file port"
                f"{'s' if mp_count != 1 else ''} ──")
            lines.append("")

        # Code signature
        lines.append("\u2500\u2500 Code Signature \u2500\u2500")
        for l in (artifacts.get("codesign_verify", "") or "").splitlines():
            lines.append(f"  {l}")
        lines.append("")

        # SHA256
        sha = artifacts.get("sha256", "")
        sha_val = sha.split()[0] if sha and not sha.startswith("[") else sha
        lines.append(f"\u2500\u2500 SHA-256: {sha_val} \u2500\u2500")
        lines.append("")

        # Entitlements (abbreviated)
        lines.append("\u2500\u2500 Entitlements \u2500\u2500")
        ent = artifacts.get("entitlements", "")
        ent_lines = ent.splitlines()
        for l in ent_lines[:30]:
            lines.append(f"  {l}")
        if len(ent_lines) > 30:
            lines.append(f"  ... ({len(ent_lines) - 30} more lines)")
        lines.append("")

        # Dylibs
        lines.append("\u2500\u2500 Linked Dylibs \u2500\u2500")
        for l in (artifacts.get("dylibs", "") or "").splitlines()[:50]:
            lines.append(f"  {l}")
        lines.append("")

        # Process Lineage
        lines.append("\u2500\u2500 Process Lineage \u2500\u2500")
        for i, (lpid, lpath) in enumerate(artifacts.get("lineage", [])):
            indent = "  " + "  \u2514\u2500 " * i
            lines.append(f"{indent}PID {lpid}: {lpath}")
        lines.append("")

        # Open files (abbreviated)
        lines.append("\u2500\u2500 Open Files (top 40) \u2500\u2500")
        lsof_lines = (artifacts.get("lsof", "") or "").splitlines()
        for l in lsof_lines[:41]:
            lines.append(f"  {l}")
        if len(lsof_lines) > 41:
            lines.append(f"  ... ({len(lsof_lines) - 41} more)")
        lines.append("")

        # Environment (security-relevant subset)
        lines.append("\u2500\u2500 Environment (filtered) \u2500\u2500")
        env = artifacts.get("env", {})
        security_keys = {"DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH",
                         "DYLD_FRAMEWORK_PATH", "LD_PRELOAD",
                         "CFNETWORK_DIAGNOSTICS", "MallocStackLogging",
                         "NSZombieEnabled", "DYLD_PRINT_LIBRARIES"}
        for k in sorted(env.keys()):
            if k in security_keys or k.startswith("DYLD_"):
                lines.append(f"  [!] {k}={env[k]}")
            elif k in ("HOME", "USER", "PATH", "SHELL", "TMPDIR", "LANG"):
                lines.append(f"  {k}={env[k]}")
        if not env:
            lines.append("  [no access or empty]")
        lines.append("")

        # vmmap
        lines.append("\u2500\u2500 Memory Regions \u2500\u2500")
        vmmap = artifacts.get("vmmap", "")
        vmmap_lines = vmmap.splitlines()
        for l in vmmap_lines[:40]:
            lines.append(f"  {l}")
        if len(vmmap_lines) > 40:
            lines.append(f"  ... ({len(vmmap_lines) - 40} more lines)")
        lines.append("")

        # Structured signature
        cs = artifacts.get("codesign_structured") or {}
        trust = _binary_trust_profile(
            exe,
            cs,
            artifacts.get("gatekeeper") or {},
        )
        if cs:
            lines.append("\u2500\u2500 Signature Details \u2500\u2500")
            lines.append(f"  Trust tier: {trust['label']}")
            lines.append(f"  Team ID: {cs.get('team_id') or '(none)'}")
            lines.append(f"  Identifier: {cs.get('identifier') or '(none)'}")
            lines.append(f"  Hardened Runtime: {cs.get('hardened_runtime')}")
            lines.append(f"  Flags: {cs.get('flags') or '(none)'}")
            auth = cs.get("authority") or []
            if auth:
                lines.append(f"  Authority chain:")
                for a in auth[:5]:
                    lines.append(f"    \u2514\u2500 {a}")
            if cs.get("requirements"):
                lines.append(f"  Designated: {cs['requirements'][:120]}")
            lines.append("")

        # Gatekeeper
        gate = artifacts.get("gatekeeper") or {}
        if gate:
            lines.append("\u2500\u2500 Gatekeeper (spctl) \u2500\u2500")
            lines.append(f"  Accepted: {gate.get('accepted')}")
            lines.append(f"  Notarized: {gate.get('notarized')}")
            if gate.get("origin"):
                lines.append(f"  Origin: {gate['origin']}")
            if not gate.get("accepted") and gate.get("reason"):
                lines.append(f"  [!] Reason: {gate['reason'][:120]}")
            lines.append("")

        # Persistence hits
        persist = artifacts.get("persistence_hits") or []
        if persist:
            lines.append("\u2500\u2500 Persistence Path Hits \u2500\u2500")
            for path, cat in persist[:10]:
                lines.append(f"  [!] {cat}: {path}")
            lines.append("")

        # User-writable dylibs
        bad_dylibs = artifacts.get("user_writable_dylibs") or []
        if bad_dylibs:
            lines.append("\u2500\u2500 Dylibs from user-writable paths \u2500\u2500")
            for d in bad_dylibs[:10]:
                lines.append(f"  [!] {d}")
            lines.append("")


        # YARA file matches
        yf = artifacts.get("yara_file") or []
        if yf:
            lines.append("\u2500\u2500 YARA (on-disk) \u2500\u2500")
            for rule in yf[:10]:
                lines.append(f"  [!] {rule}")
            lines.append("")

        # YARA memory matches
        ym = artifacts.get("yara_memory") or {}
        if ym.get("success"):
            lines.append("\u2500\u2500 YARA (memory) \u2500\u2500")
            mem_matches = ym.get("matches", [])
            lines.append(f"  Core dump: {ym.get('core_size', 0)} bytes, scanned")
            for rule in mem_matches[:10]:
                lines.append(f"  [!] {rule}")
            if not mem_matches:
                lines.append("  No matches")
            lines.append("")
        elif ym.get("error"):
            lines.append("\u2500\u2500 YARA (memory) \u2500\u2500")
            lines.append(f"  [skipped: {ym['error']}]")
            lines.append("")

        return lines

    def _build_analysis_input(self, artifacts):
        """Build the structured artifact text sent to every LLM."""
        sections = []
        sections.append(f"Process: PID {artifacts['pid']}, Path: {artifacts['exe_path']}")
        sections.append(f"\n=== CODE SIGNATURE ===\n{artifacts.get('codesign_verify', 'N/A')}")
        sections.append(f"\n=== ENTITLEMENTS ===\n{artifacts.get('entitlements', 'N/A')}")
        sections.append(f"\n=== SHA-256 ===\n{artifacts.get('sha256', 'N/A')}")
        sections.append(f"\n=== LINKED DYLIBS ===\n{artifacts.get('dylibs', 'N/A')}")

        lineage_str = " \u2192 ".join(
            f"{lpid}:{lpath}" for lpid, lpath in artifacts.get("lineage", []))
        sections.append(f"\n=== PROCESS LINEAGE ===\n{lineage_str}")

        lsof_lines = (artifacts.get("lsof", "") or "").splitlines()[:100]
        sections.append(f"\n=== OPEN FILES (first 100) ===\n" + "\n".join(lsof_lines))

        env = artifacts.get("env", {})
        env_str = "\n".join(f"{k}={v}" for k, v in sorted(env.items()))
        sections.append(f"\n=== ENVIRONMENT ===\n{env_str or 'N/A'}")

        vmmap = artifacts.get("vmmap", "")
        if vmmap and not vmmap.startswith("["):
            vmmap_truncated = "\n".join(vmmap.splitlines()[:80])
            sections.append(f"\n=== MEMORY REGIONS (first 80 lines) ===\n{vmmap_truncated}")

        # Deterministic findings the LLMs should factor in
        cs = artifacts.get("codesign_structured") or {}
        trust = _binary_trust_profile(
            artifacts.get("exe_path", ""),
            cs,
            artifacts.get("gatekeeper") or {},
        )
        if cs:
            cs_summary = (
                f"trust_tier={trust.get('tier')}\n"
                f"trust_label={trust.get('label')}\n"
                f"team_id={cs.get('team_id') or '(none)'}\n"
                f"identifier={cs.get('identifier') or '(none)'}\n"
                f"hardened_runtime={cs.get('hardened_runtime')}\n"
                f"flags={cs.get('flags') or '(none)'}\n"
                f"authority={' | '.join(cs.get('authority') or [])}\n"
                f"designated={cs.get('requirements') or '(none)'}"
            )
            sections.append(f"\n=== CODESIGN STRUCTURED ===\n{cs_summary}")

        gate = artifacts.get("gatekeeper") or {}
        if gate:
            sections.append(
                f"\n=== GATEKEEPER ===\n"
                f"accepted={gate.get('accepted')} "
                f"notarized={gate.get('notarized')} "
                f"origin={gate.get('origin')}\n"
                f"raw:\n{gate.get('raw', '')}")

        persist = artifacts.get("persistence_hits") or []
        if persist:
            sections.append("\n=== PERSISTENCE PATH HITS ===\n" +
                            "\n".join(f"{c}: {p}" for p, c in persist))

        bad_dylibs = artifacts.get("user_writable_dylibs") or []
        if bad_dylibs:
            sections.append("\n=== DYLIBS FROM USER-WRITABLE PATHS ===\n" +
                            "\n".join(bad_dylibs))


        yf = artifacts.get("yara_file") or []
        if yf:
            sections.append(f"\n=== YARA MATCHES (on-disk) ===\n" + "\n".join(yf))

        ym = artifacts.get("yara_memory") or {}
        if ym.get("success") and ym.get("matches"):
            sections.append(f"\n=== YARA MATCHES (memory) ===\n" + "\n".join(ym["matches"]))

        return "\n".join(sections)

    _ANALYSIS_PROMPT = (
        "You are a macOS security analyst. Analyze the following process "
        "artifacts and provide a concise security assessment. Check for:\n"
        "1. Unsigned or ad-hoc signed binaries (missing or invalid code signature)\n"
        "2. Suspicious entitlements (com.apple.security.cs.disable-library-validation, "
        "com.apple.security.cs.allow-dyld-environment-variables, etc.)\n"
        "3. Unusual DYLD_* environment variables (injection vectors)\n"
        "4. Suspicious dylib loading (non-system paths, injection libraries)\n"
        "5. Suspicious open files (raw sockets, /dev/ access, keychain access)\n"
        "6. Anomalous memory regions (RWX pages, suspicious mappings)\n"
        "7. Known malware indicators or suspicious process lineage\n"
        "8. Process masquerading (name doesn't match expected path)\n\n"
        "Format your response as:\n"
        "RISK: [LOW|MEDIUM|HIGH|CRITICAL]\n"
        "SUMMARY: one-line summary\n"
        "FINDINGS:\n- bullet points\n"
        "RECOMMENDATION: one-line action\n\n"
        "Be concise. Only flag genuine concerns, not normal system behavior."
    )

    # Per-tool CLI command builders. Each returns (argv, uses_stdin).
    # uses_stdin=True means input_text is piped via stdin; False means it's
    # appended to the prompt argument.
    _LLM_TOOLS = {
        "claude": {
            "argv": lambda prompt: ["claude", "-p", prompt],
            "uses_stdin": True,
            "install_hint": "npm install -g @anthropic-ai/claude-code",
        },
        "codex": {
            "argv": lambda prompt: ["codex", "exec", prompt],
            "uses_stdin": True,
            "install_hint": "npm install -g @openai/codex",
        },
        "gemini": {
            "argv": lambda prompt: ["gemini", "-p", prompt],
            "uses_stdin": True,
            "install_hint": "npm install -g @google/gemini-cli",
        },
    }

    def _run_llm(self, tool, prompt, input_text, timeout=120):
        """Invoke a single LLM CLI. Returns response text or error-tagged string.

        Under sudo, we rewrite $HOME to the invoking user's home so each CLI
        finds its own per-user credentials (~/.claude, ~/.codex, ~/.gemini).
        Without this, sudo's $HOME is /var/root — the CLIs see no auth token
        and exit non-zero with an empty stderr.
        """
        cfg = self._LLM_TOOLS.get(tool)
        if cfg is None:
            return f"[unknown tool: {tool}]"
        argv = cfg["argv"](prompt)
        env = {
            **os.environ,
            "PATH": _USER_TOOL_PATH,
            "HOME": _EFFECTIVE_HOME,
        }
        sudo_user = os.environ.get("SUDO_USER")
        if sudo_user:
            env["USER"] = sudo_user
            env["LOGNAME"] = sudo_user
        try:
            proc = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE if cfg["uses_stdin"] else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
            )
            try:
                stdin_data = input_text.encode("utf-8") if cfg["uses_stdin"] else None
                stdout, stderr = proc.communicate(input=stdin_data, timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
                return f"[{tool} analysis timed out after {timeout}s]"
            if proc.returncode != 0:
                err = stderr.decode("utf-8", errors="replace").strip()
                out = stdout.decode("utf-8", errors="replace").strip()
                # Some CLIs emit nothing on stderr and put the failure on
                # stdout; show whichever has content so the user can diagnose.
                detail = err or out or "(no output)"
                return f"[{tool} CLI error (rc={proc.returncode}): {detail[:200]}]"
            return stdout.decode("utf-8", errors="replace").strip()
        except FileNotFoundError:
            return f"[{tool} CLI not found \u2014 install: {cfg['install_hint']}]"
        except OSError as e:
            return f"[{tool} CLI error: {e}]"

    def _run_llms_parallel(self, artifacts):
        """Run Claude, Codex, Gemini in parallel. Returns dict tool -> response.

        When the consensus race is enabled at the inspect-mode level,
        the inspect worker calls `_run_llms_parallel_streaming` instead
        and the lanes get populated live.
        """
        input_text = self._build_analysis_input(artifacts)
        results = {}
        threads = []

        def _worker(tool):
            results[tool] = self._run_llm(tool, self._ANALYSIS_PROMPT, input_text)

        for tool in ("claude", "codex", "gemini"):
            t = threading.Thread(target=_worker, args=(tool,), daemon=True)
            t.start()
            threads.append(t)
        for t in threads:
            t.join(timeout=180)
        # Anything still running past 180s gets a timeout tag
        for tool in ("claude", "codex", "gemini"):
            if tool not in results:
                results[tool] = f"[{tool} join timeout]"
        return results

    def _run_llms_parallel_streaming(self, artifacts):
        """Streaming variant of `_run_llms_parallel` for the consensus race.

        Output of each tool lands in `_consensus_lanes[tool]` in real
        time so the UI can render the race. Lane state is reset on
        entry so a fresh inspect doesn't show stale lines.
        """
        input_text = self._build_analysis_input(artifacts)
        results = {}
        threads = []
        with self._consensus_lane_lock:
            self._consensus_lanes = {"claude": [], "codex": [], "gemini": []}
            self._consensus_lane_done = {"claude": False, "codex": False,
                                          "gemini": False}
        self._consensus_risk_bar = 0
        self._consensus_running = True

        def _on_chunk(label, line):
            with self._consensus_lane_lock:
                lane = self._consensus_lanes.setdefault(label, [])
                lane.append(line.rstrip("\n"))
                if len(lane) > self._consensus_lane_max_lines:
                    del lane[:len(lane) - self._consensus_lane_max_lines]

        def _worker(tool):
            try:
                results[tool] = self._run_llm_streaming(
                    tool, self._ANALYSIS_PROMPT, input_text, _on_chunk)
            finally:
                with self._consensus_lane_lock:
                    self._consensus_lane_done[tool] = True
                done_count = sum(1 for v in self._consensus_lane_done.values()
                                  if v)
                self._consensus_risk_bar = int(done_count / 3.0 * 100)

        for tool in ("claude", "codex", "gemini"):
            t = threading.Thread(target=_worker, args=(tool,), daemon=True)
            t.start()
            threads.append(t)
        for t in threads:
            t.join(timeout=180)
        for tool in ("claude", "codex", "gemini"):
            if tool not in results:
                results[tool] = f"[{tool} join timeout]"
        self._consensus_running = False
        return results

    def _run_llm_streaming(self, tool, prompt, input_text, on_chunk):
        """Streaming variant of _run_llm.

        Reads stdout *line by line* via `proc.stdout.readline()` so the
        UI sees output as it arrives. `on_chunk(tool, line)` is called
        for each emitted line. Returns the full concatenated text.
        """
        cfg = self._LLM_TOOLS.get(tool)
        if cfg is None:
            return f"[unknown tool: {tool}]"
        argv = cfg["argv"](prompt)
        env = {
            **os.environ,
            "PATH": _USER_TOOL_PATH,
            "HOME": _EFFECTIVE_HOME,
        }
        sudo_user = os.environ.get("SUDO_USER")
        if sudo_user:
            env["USER"] = sudo_user
            env["LOGNAME"] = sudo_user
        try:
            proc = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE if cfg["uses_stdin"] else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                bufsize=0,  # unbuffered binary stream → readline() flushes promptly
            )
        except FileNotFoundError:
            err = f"[{tool} CLI not found — install: {cfg['install_hint']}]"
            on_chunk(tool, err)
            return err
        except OSError as e:
            err = f"[{tool} CLI error: {e}]"
            on_chunk(tool, err)
            return err

        # Send stdin (best effort, in a thread so a slow CLI can't deadlock us).
        def _writer():
            try:
                if cfg["uses_stdin"] and proc.stdin:
                    proc.stdin.write(input_text.encode("utf-8"))
                    proc.stdin.close()
            except Exception:
                pass
        threading.Thread(target=_writer, daemon=True).start()

        collected = []
        try:
            for raw in iter(proc.stdout.readline, b""):
                if not raw:
                    break
                line = raw.decode("utf-8", errors="replace")
                collected.append(line)
                try:
                    on_chunk(tool, line)
                except Exception:
                    pass
        except Exception:
            pass
        try:
            proc.wait(timeout=180)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            timeout_msg = f"[{tool} streaming timeout]"
            on_chunk(tool, timeout_msg)
            return "".join(collected) + timeout_msg
        if proc.returncode != 0:
            try:
                err = proc.stderr.read().decode("utf-8", errors="replace") if proc.stderr else ""
            except Exception:
                err = ""
            tag = f"[{tool} CLI error rc={proc.returncode}: {err.strip()[:200]}]"
            on_chunk(tool, tag)
            return "".join(collected) + tag
        return "".join(collected).strip()

    def _consensus_lane_divergence(self):
        """Inspect lane content for RISK lines and report divergence.

        Returns (divergent: bool, level_set: set[str]). When fewer than
        two lanes have emitted a RISK line yet, returns (False, set()).
        """
        levels = set()
        with self._consensus_lane_lock:
            for tool, lane in self._consensus_lanes.items():
                for line in lane:
                    if "RISK:" in line:
                        # Last RISK line wins (LLMs sometimes restate it)
                        try:
                            level = line.split("RISK:", 1)[1].strip().split()[0]
                        except IndexError:
                            level = ""
                        if level:
                            levels.add(level.upper())
                            break
        if len(levels) < 2:
            return False, levels
        return True, levels

    def _build_consensus_race_lines(self, width):
        """Render claude/codex/gemini lane state as side-by-side panels."""
        lanes_order = ("claude", "codex", "gemini")
        lane_w = max(20, (width - 6) // 3)
        spinner = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
        spin_idx = int(time.monotonic() * 8) % len(spinner)
        with self._consensus_lane_lock:
            lanes = {k: list(self._consensus_lanes.get(k, []))
                     for k in lanes_order}
            done = dict(self._consensus_lane_done)
        # Header row
        headers = []
        for tool in lanes_order:
            mark = "✓" if done.get(tool) else spinner[spin_idx]
            headers.append(f"{mark} {tool}".ljust(lane_w))
        out = [" " + " ".join(headers)]
        out.append(" " + " ".join("─" * lane_w for _ in lanes_order))
        # Body — last N lines per lane.
        max_body = 14
        body_per = {tool: lanes[tool][-max_body:] for tool in lanes_order}
        body_h = max(len(v) for v in body_per.values()) if any(body_per.values()) else 1
        for ri in range(body_h):
            row_parts = []
            for tool in lanes_order:
                lane = body_per[tool]
                ln = lane[ri] if ri < len(lane) else ""
                row_parts.append(ln[:lane_w].ljust(lane_w))
            out.append(" " + " ".join(row_parts))
        out.append("")
        # Risk bar.
        bar_total = max(20, width - 30)
        filled = int(bar_total * self._consensus_risk_bar / 100)
        bar = "█" * filled + "·" * (bar_total - filled)
        finished = sum(1 for v in done.values() if v)
        out.append(f" CONSENSUS_RISK [{bar}] {finished}/3 ready")
        # Divergence flasher.
        diverge, levels = self._consensus_lane_divergence()
        if diverge:
            out.append(" ⚠ DIVERGENCE — lanes disagree: "
                       + ", ".join(sorted(levels)))
        return out

    def _synthesize_analyses(self, analyses):
        """Ask one LLM to consolidate the three reports into a consensus.

        Tries claude, codex, gemini in order. Falls back to a simple text
        summary if all three are unavailable.
        """
        combined = []
        for tool in ("claude", "codex", "gemini"):
            resp = analyses.get(tool, "")
            combined.append(f"=== {tool.upper()} ===\n{resp}")
        input_text = "\n\n".join(combined)

        synth_prompt = (
            "You are a senior security analyst reviewing three independent "
            "assessments of the same macOS process (from Claude, Codex, and Gemini). "
            "Produce a consensus report. Output format:\n"
            "CONSENSUS_RISK: [LOW|MEDIUM|HIGH|CRITICAL]\n"
            "AGREEMENT: one line on how much the three agree\n"
            "COMMON FINDINGS:\n- points all 3 (or 2) flagged\n"
            "DIVERGENT:\n- points where they disagreed\n"
            "FINAL RECOMMENDATION: one line\n\n"
            "Ignore error tags like [claude CLI not found] \u2014 treat those "
            "sources as missing. Be concise."
        )

        # Try each tool in order; use the first one that works
        for tool in ("claude", "codex", "gemini"):
            resp = analyses.get(tool, "")
            if resp.startswith("["):  # error-tagged response
                continue
            synth = self._run_llm(tool, synth_prompt, input_text, timeout=60)
            if not synth.startswith("["):
                return tool, synth

        # All three errored or unavailable — simple fallback
        return None, self._local_consensus_fallback(analyses)

    def _local_consensus_fallback(self, analyses):
        """Simple text-based fallback if no LLM is available for synthesis."""
        risks = []
        for tool in ("claude", "codex", "gemini"):
            resp = analyses.get(tool, "")
            for line in resp.splitlines():
                if line.startswith("RISK:"):
                    level = line.split(":", 1)[1].strip().upper()
                    risks.append((tool, level))
                    break
        if not risks:
            return "CONSENSUS_RISK: UNKNOWN\nAGREEMENT: no tools produced parseable output"
        levels = [r[1] for r in risks]
        rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        worst = max(levels, key=lambda l: rank.get(l, -1))
        agreement = "unanimous" if len(set(levels)) == 1 else "mixed"
        detail = ", ".join(f"{t}={l}" for t, l in risks)
        return (
            f"CONSENSUS_RISK: {worst}\n"
            f"AGREEMENT: {agreement} ({detail})\n"
            "COMMON FINDINGS: [fallback — no LLM available for synthesis]\n"
            "FINAL RECOMMENDATION: review individual reports above"
        )

    def _inspect_worker_fn(self, pid, exe_path):
        """Background worker: collect artifacts, run 3 LLMs in parallel, synthesize."""
        try:
            if getattr(self, "_test_mode", False):
                artifacts = {
                    "pid": pid,
                    "exe_path": exe_path,
                    "yara_memory": {
                        "success": False,
                        "error": "skipped in test mode",
                    },
                    "yara_file": [],
                    "codesign_verify": "[test mode] artifact collection skipped",
                    "sha256": "[test mode]",
                    "entitlements": "[test mode]",
                    "dylibs": "[test mode]",
                    "lineage": [(pid, exe_path)],
                    "lsof": "",
                    "env": {},
                    "vmmap": "",
                    "codesign_structured": {},
                    "gatekeeper": {},
                    "persistence_hits": [],
                    "user_writable_dylibs": [],
                }
                report_lines = self._format_inspect_report(artifacts)
                self._inspect_pending = (
                    "complete",
                    report_lines + [
                        "",
                        "══ Test Mode Analysis ══",
                        "",
                        "  External LLM CLI analysis skipped in test mode.",
                        "  The TUI harness validates the rendered artifact report",
                        "  and pane structure instead of third-party model output.",
                    ],
                )
                return

            self._inspect_phase = "collecting"
            artifacts = self._collect_inspect_artifacts(pid, exe_path)

            # Intermediate: show raw artifacts while LLMs analyze
            report_lines = self._format_inspect_report(artifacts)
            self._inspect_pending = ("artifacts", report_lines)

            # Run all three LLMs in parallel. The streaming variant
            # populates `_consensus_lanes` so the UI shows the race
            # while the analyses are coming in. Falls through to the
            # existing synthesis path with the same dict shape.
            self._inspect_phase = "analyzing"
            analyses = self._run_llms_parallel_streaming(artifacts)

            # Append each per-tool analysis
            analysis_lines = []
            for tool in ("claude", "codex", "gemini"):
                resp = analyses.get(tool, "[no response]")
                analysis_lines.append("")
                analysis_lines.append(f"\u2550\u2550 {tool.capitalize()} Security Analysis \u2550\u2550")
                analysis_lines.append("")
                for line in resp.splitlines():
                    if line.startswith("RISK:"):
                        level = line.split(":", 1)[1].strip()
                        if level in ("HIGH", "CRITICAL"):
                            analysis_lines.append(f"  [!RISK: {level}]")
                        else:
                            analysis_lines.append(f"  [RISK: {level}]")
                    else:
                        analysis_lines.append(f"  {line}")

            # Intermediate update so user sees per-tool reports immediately
            self._inspect_pending = ("analyzing", report_lines + analysis_lines)

            # Synthesize consensus
            self._inspect_phase = "synthesizing"
            synth_tool, consensus = self._synthesize_analyses(analyses)

            consensus_lines = ["", "\u2550\u2550 Consensus"]
            if synth_tool:
                consensus_lines[-1] += f" (synthesized by {synth_tool})"
            consensus_lines[-1] += " \u2550\u2550"
            consensus_lines.append("")
            for line in consensus.splitlines():
                if line.startswith("CONSENSUS_RISK:"):
                    level = line.split(":", 1)[1].strip()
                    if level in ("HIGH", "CRITICAL"):
                        consensus_lines.append(f"  [!RISK: {level}]")
                    else:
                        consensus_lines.append(f"  [RISK: {level}]")
                else:
                    consensus_lines.append(f"  {line}")

            self._inspect_pending = (
                "complete", report_lines + analysis_lines + consensus_lines)

            # Also fire a short TL;DR summary panel derived from the
            # per-tool analyses + consensus so the top-of-view matches the
            # other forensic/audit commands.
            try:
                pseudo = []
                # Elevate RISK/CONSENSUS_RISK lines into pseudo-findings
                for tool, resp in analyses.items():
                    for line in resp.splitlines():
                        if line.startswith("RISK:"):
                            level = line.split(":", 1)[1].strip().upper()
                            sev = ("CRITICAL" if level == "CRITICAL"
                                   else "HIGH" if level == "HIGH"
                                   else "MEDIUM" if level == "MEDIUM"
                                   else "INFO")
                            pseudo.append({
                                "severity": sev,
                                "message": f"{tool}: RISK={level}",
                                "action": None})
                for line in consensus.splitlines():
                    if line.startswith("CONSENSUS_RISK:"):
                        level = line.split(":", 1)[1].strip().upper()
                        sev = ("CRITICAL" if level == "CRITICAL"
                               else "HIGH" if level == "HIGH"
                               else "MEDIUM" if level == "MEDIUM"
                               else "INFO")
                        pseudo.append({
                            "severity": sev,
                            "message": f"Consensus: {level}",
                            "action": None})
                    elif line.strip():
                        pseudo.append({"severity": "INFO",
                                       "message": line.strip()[:200],
                                       "action": None})
                self._start_llm_summary(
                    "inspect",
                    f"Inspect PID {artifacts.get('pid')} — {artifacts.get('exe_path','')}",
                    pseudo)
            except Exception:
                pass
        except Exception as e:
            self._inspect_pending = ("error", [f"[Inspect error: {e}]"])
        finally:
            self._inspect_phase = ""

    def _toggle_inspect_mode(self):
        """Toggle process inspect mode (I key)."""
        if self._inspect_mode:
            self._inspect_mode = False
            self._detail_focus = False
            return
        if not self.rows:
            return
        sel = self.rows[self.selected]
        self._inspect_pid = sel["pid"]
        self._inspect_cmd = sel["command"].split()[0].rsplit("/", 1)[-1][:20]
        exe_path = _get_proc_path(sel["pid"]) or sel["command"].split()[0]
        # Lazy sample: enumerate Mach file-port count once per inspect
        # toggle (instead of every refresh — proc_pidinfo on
        # PROC_PIDLISTFILEPORTS is cheap but we still don't want it on
        # every PID every tick).
        try:
            sel["mach_ports"] = _get_mach_port_count(sel["pid"])
        except Exception:
            sel["mach_ports"] = -1
        self._inspect_lines = []
        self._inspect_scroll = 0
        self._inspect_mode = True
        self._llm_summary["inspect"] = None
        self._llm_summary_pending["inspect"] = None
        self._llm_summary_loading["inspect"] = False
        if getattr(self, "_events_mode", False):
            self._stop_events_stream()
            self._events_mode = False
        self._net_mode = False
        self._detail_focus = True
        self._inspect_loading = True
        self._start_inspect_fetch(sel["pid"], exe_path)

    def _start_inspect_fetch(self, pid, exe_path):
        """Launch background thread for inspect artifact collection."""
        if self._inspect_worker and self._inspect_worker.is_alive():
            return
        self._inspect_loading = True
        self._inspect_pending = None

        def _worker():
            self._inspect_worker_fn(pid, exe_path)

        self._inspect_worker = threading.Thread(target=_worker, daemon=True)
        self._inspect_worker.start()

    def _poll_inspect_result(self):
        """Check if background inspect fetch completed and apply results."""
        if self._inspect_pending is None:
            return False
        if not self._inspect_mode:
            self._inspect_pending = None
            self._inspect_loading = False
            return False
        status, lines = self._inspect_pending
        self._inspect_lines = lines
        if status in ("complete", "error"):
            self._inspect_loading = False
        self._inspect_pending = None
        return True

    def _toggle_process_triage_mode(self):
        """Run a deeper triage report for the currently selected process."""
        if not self.rows:
            return
        sel = self.rows[self.selected]
        pid = sel["pid"]
        cmd = sel.get("command", "")
        if self._audit_mode and self._audit_type == "process_triage":
            if self._audit_context_pid == pid:
                self._audit_mode = False
                self._detail_focus = False
                self._audit_context_pid = None
                self._audit_context_cmd = ""
                self._audit_title_override = ""
                return
            self._audit_mode = False
        self._audit_context_pid = pid
        self._audit_context_cmd = cmd
        base = cmd.split()[0].rsplit("/", 1)[-1][:28] if cmd else str(pid)
        self._audit_title_override = f"Deep Process Triage — PID {pid} ({base})"
        self._toggle_audit_mode("process_triage")

    def _build_process_triage_findings(self, pid, command, triage_context=None):
        """Collect a structured deep-triage report for one selected process."""
        exe_path = _get_proc_path(pid) or ""
        if not exe_path and command:
            exe_path = command.split()[0]
        if not exe_path:
            return [{
                "severity": "MEDIUM",
                "message": f"PID {pid} exited before triage could resolve its executable",
                "action": None,
            }]

        triage_context = triage_context or {}
        findings = []
        if "osquery_rows" in triage_context or "osquery_err" in triage_context:
            osquery_rows = triage_context.get("osquery_rows") or {}
            osquery_err = triage_context.get("osquery_err", "")
        else:
            osquery_rows, osquery_err = _osquery_process_snapshot(timeout=12)
        osq = osquery_rows.get(pid) or {}
        basename = os.path.basename(exe_path) or str(pid)
        artifacts = self._collect_inspect_artifacts(pid, exe_path)
        cs = artifacts.get("codesign_structured") or {}
        gatekeeper = artifacts.get("gatekeeper") or {}
        trust = _binary_trust_profile(exe_path, cs, gatekeeper)
        apple = _is_apple_signed(exe_path, cs)
        identity = [
            f"command: {command or exe_path}",
            f"exe: {exe_path}",
            f"trust: {trust['label']}",
            f"team: {cs.get('team_id') or '(none)'}",
            f"apple_signed: {apple}",
        ]
        if osq:
            identity.append(
                f"osquery: path={osq.get('path') or exe_path} "
                f"on_disk={osq.get('on_disk', '?')}"
            )
        findings.append({
            "severity": "INFO",
            "message": f"Selected process identity: PID {pid} {basename}",
            "evidence": "\n".join(identity),
            "action": None,
        })

        inj = _audit_injection_antidebug_pid(
            pid,
            osquery_rows=osquery_rows,
            taskexplorer_enabled=False,
        )
        if inj:
            findings.append(inj)

        if osquery_err:
            findings.append({
                "severity": "INFO",
                "message": f"osquery telemetry backend unavailable for PID {pid}",
                "evidence": osquery_err,
                "action": None,
            })

        sig_rc = cs.get("rc")
        if sig_rc not in (None, 0):
            evidence = []
            verify = (artifacts.get("codesign_verify") or "").strip()
            if verify:
                evidence.append(verify[:400])
            authority = cs.get("authority") or []
            if authority:
                evidence.append("authority: " + ", ".join(authority[:4]))
            findings.append({
                "severity": "HIGH",
                "message": (
                    "Code signature is missing, ad-hoc, or unverifiable "
                    f"({trust['label']})"
                ),
                "evidence": "\n".join(evidence),
                "action": None,
            })
        elif not apple and cs.get("team_id"):
            findings.append({
                "severity": "INFO",
                "message": (
                    f"Third-party signature present "
                    f"(team={cs.get('team_id')}, {trust['label']})"
                ),
                "evidence": ", ".join(cs.get("authority") or [])[:400],
                "action": None,
            })

        if gatekeeper:
            if not gatekeeper.get("accepted"):
                reason = gatekeeper.get("reason") or gatekeeper.get("raw") or "rejected"
                sev = "HIGH"
                if "does not seem to be an app" in reason.lower():
                    sev = "INFO"
                findings.append({
                    "severity": sev,
                    "message": "Gatekeeper assessment rejected the selected binary",
                    "evidence": reason[:400],
                    "action": None,
                })
            elif not gatekeeper.get("notarized") and not apple:
                findings.append({
                    "severity": "INFO",
                    "message": "Gatekeeper accepted the binary but notarization was not explicit",
                    "evidence": (gatekeeper.get("raw") or "")[:400],
                    "action": None,
                })

        user_writable = artifacts.get("user_writable_dylibs") or []
        if user_writable:
            findings.append({
                "severity": "HIGH",
                "message": f"{len(user_writable)} user-writable dylib path(s) are linked into the binary",
                "evidence": "\n".join(user_writable[:8]),
                "action": None,
            })

        persist = artifacts.get("persistence_hits") or []
        if persist:
            findings.append({
                "severity": "MEDIUM",
                "message": f"Open files intersect persistence-sensitive paths ({len(persist)})",
                "evidence": "\n".join(persist[:8]),
                "action": None,
            })

        yara_file = artifacts.get("yara_file") or []
        if yara_file:
            findings.append({
                "severity": "HIGH",
                "message": f"YARA matched {len(yara_file)} on-disk rule(s) against the binary",
                "evidence": "\n".join(yara_file[:8]),
                "action": None,
            })

        yara_mem = artifacts.get("yara_memory") or {}
        if yara_mem.get("success") and yara_mem.get("matches"):
            findings.append({
                "severity": "HIGH",
                "message": (
                    f"Memory YARA matched {len(yara_mem.get('matches') or [])} "
                    f"rule(s) in the live process"
                ),
                "evidence": "\n".join((yara_mem.get("matches") or [])[:8]),
                "action": None,
            })

        env = artifacts.get("env") or {}
        dyld_live = [f"{k}={v}" for k, v in sorted(env.items()) if k.startswith("DYLD_")]
        if dyld_live and not inj:
            findings.append({
                "severity": "HIGH",
                "message": "Live DYLD environment variables are present on the selected process",
                "evidence": "\n".join(dyld_live[:8]),
                "action": None,
            })

        task_timeout = triage_context.get("taskexplorer_timeout", 12)
        task = _taskexplorer_pid_snapshot(pid, timeout=task_timeout)
        if task.get("signals"):
            findings.append({
                "severity": "HIGH",
                "message": "TaskExplorer corroborated unusual mappings or injection indicators",
                "evidence": "\n".join(task.get("signals", [])[:8]),
                "action": None,
            })
        elif task.get("error"):
            findings.append({
                "severity": "INFO",
                "message": "TaskExplorer corroboration backend unavailable for selected process",
                "evidence": task.get("error", ""),
                "action": None,
            })

        net_entries = self._fetch_net_connections(pid)
        if net_entries:
            listeners = sum(1 for entry in net_entries if entry.get("state") == "LISTEN")
            remote = len([entry for entry in net_entries if "→" in entry.get("display", "")])
            findings.append({
                "severity": "INFO",
                "message": (
                    f"Selected process has {len(net_entries)} active network "
                    f"connection(s) across its subtree"
                ),
                "evidence": "\n".join(
                    [f"listeners={listeners} remote={remote}"]
                    + [entry.get("display", "") for entry in net_entries[:8]]
                ),
                "action": None,
            })

        kk = triage_context.get("knockknock")
        if kk is None:
            kk = _run_knockknock_scan(timeout=120)
        if kk.get("raw") and basename.lower() in kk["raw"].lower():
            findings.append({
                "severity": "HIGH" if kk.get("flagged_items", 0) else "MEDIUM",
                "message": "KnockKnock output references the selected binary or bundle",
                "evidence": "\n".join(
                    line for line in kk["raw"].splitlines()
                    if basename.lower() in line.lower()
                )[:800],
                "action": None,
            })

        bb = triage_context.get("blockblock")
        if bb is None:
            bb = _read_blockblock_summary(limit=10)
        if any(basename.lower() in sample.lower() for sample in bb.get("samples", [])):
            findings.append({
                "severity": "HIGH",
                "message": "BlockBlock recent telemetry references the selected binary or path",
                "evidence": "\n".join(
                    sample for sample in bb.get("samples", [])
                    if basename.lower() in sample.lower()
                )[:800],
                "action": None,
            })

        if not any(
            f.get("severity") in ("MEDIUM", "HIGH", "CRITICAL")
            for f in findings
        ):
            findings.append({
                "severity": "OK",
                "message": "No obvious deep-triage red flags for the selected process",
                "action": None,
            })
        return findings

    def _get_subtree_pids(self, root_pid):
        """Get root_pid and all descendant PIDs from the live process table."""
        all_procs = get_all_processes()
        children_of = {}
        for p in all_procs:
            children_of.setdefault(p["ppid"], []).append(p["pid"])
        pids = []
        stack = [root_pid]
        while stack:
            pid = stack.pop()
            pids.append(pid)
            stack.extend(children_of.get(pid, []))
        return pids

    def _fetch_net_connections(self, root_pid):
        """Fetch network connections for a process and its subtree via lsof."""
        pids = self._get_subtree_pids(root_pid)
        try:
            proc = subprocess.Popen(
                ["lsof", "+c0", "-a", "-i", "-n", "-P", "-p",
                 ",".join(str(p) for p in pids)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            try:
                stdout, _ = proc.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
                return []
        except (FileNotFoundError, OSError):
            return []

        # First pass: parse connections and collect remote IPs
        parsed = []
        seen = set()
        remote_ips = set()
        for raw_line in stdout.decode("utf-8", errors="replace").splitlines()[1:]:
            parts = raw_line.split()
            if len(parts) < 9:
                continue
            pid_str = parts[1]
            fd_str = parts[3]
            proto = parts[7]
            name = " ".join(parts[8:])

            if name.startswith("*:*") or name == "*":
                continue

            state = ""
            if name.endswith(")") and "(" in name:
                addr_part, state_part = name.rsplit("(", 1)
                addr_part = addr_part.strip()
                state = state_part.rstrip(")")
            else:
                addr_part = name

            try:
                conn_pid = int(pid_str)
            except ValueError:
                conn_pid = 0

            dedup_key = (conn_pid, proto, addr_part)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            dst_ip = ""
            if "->" in addr_part:
                dst = addr_part.split("->", 1)[1]
                dst_ip = dst.rsplit(":", 1)[0] if ":" in dst else dst
                if not _is_local_ip(dst_ip):
                    remote_ips.add(dst_ip)

            parsed.append((pid_str, fd_str, proto, addr_part, state, conn_pid, dst_ip))

        # Batch GeoIP lookup for all remote IPs
        if remote_ips:
            _lookup_geoip(remote_ips)

        # Second pass: build entries, only established connections
        entries = []
        for pid_str, fd_str, proto, addr_part, state, conn_pid, dst_ip in parsed:
            # Only show established / active connections
            if state and state not in ("ESTABLISHED", "SYN_SENT", "SYN_RECEIVED"):
                continue
            if "->" not in addr_part:
                continue  # skip listeners like *:5353

            src, dst = addr_part.split("->", 1)
            service = _port_service(_extract_port(dst)) or _port_service(_extract_port(src))
            resolved_dst = _resolve_addr(dst)
            geo = _get_geo(dst_ip)
            org = _get_org(dst_ip)

            short = _short_org(org)

            tags = f"[{proto}]"
            if service:
                tags += f" [{service}]"
            if short:
                tags += f" [{short}]"
            if geo:
                tags += f" [{geo}]"

            # Per-connection bytes from nettop flow data
            conn_key = (conn_pid, fd_str)
            prev = self._net_bytes.get(conn_key, (0, 0))
            if isinstance(prev, (int, float)):
                prev = (prev, 0)  # migrate old format
            b_in, b_out = prev
            total = b_in + b_out

            bytes_tag = ""
            if total > 0:
                bytes_tag = f" [\u2193{fmt_bytes(b_in)} \u2191{fmt_bytes(b_out)}]"

            display = f" {src} \u2192 {resolved_dst}  {tags}{bytes_tag}"

            entries.append({
                "pid": conn_pid,
                "fd": fd_str,
                "proto": proto,
                "state": state,
                "service": service,
                "org": org,
                "addr_key": addr_part,
                "bytes_in": b_in,
                "bytes_out": b_out,
                "bytes_total": total,
                "display": display,
            })

        # Sort by total bytes descending
        entries.sort(key=lambda e: e["bytes_total"], reverse=True)
        return entries

    def _prompt_config(self):
        """Show alert threshold configuration screen (Shift+C)."""
        h, w = self.stdscr.getmaxyx()
        fields = [
            ("CPU %", "cpu"),
            ("MEM (MB)", "mem_mb"),
            ("Threads", "threads"),
            ("FDs", "fds"),
            ("Forks", "forks"),
            ("↓ In (KB/s)", "net_in"),
            ("↑ Out (KB/s)", "net_out"),
            ("↓ Recv (MB)", "recv_mb"),
            ("↑ Sent (MB)", "sent_mb"),
            ("", ""),  # separator
            ("Interval (s)", "_interval"),
            ("Max alerts", "_max_count"),
        ]
        # Initialize buffers from current thresholds
        bufs = []
        for label, key in fields:
            if not key:
                bufs.append([])
                continue
            if key == "_interval":
                v = self._alert_interval
            elif key == "_max_count":
                v = self._alert_max_count
            else:
                v = self._alert_thresholds[key]
            bufs.append(list(str(int(v)) if v == int(v) else str(v)) if v else [])

        selected = 0
        cursors = [len(b) for b in bufs]

        curses.curs_set(1)
        self.stdscr.timeout(-1)

        title = " Alert Thresholds (0 = off) — ↑↓ navigate, Enter save, Esc cancel "
        box_w = min(max(len(title) + 4, 60), w - 4)
        box_h = len(fields) + 4  # title + fields + blank + hint
        box_y = max(0, (h - box_h) // 2)
        box_x = max(0, (w - box_w) // 2)

        while True:
            # Draw box background
            for row in range(box_h):
                self._put(box_y + row, box_x, " " * box_w, curses.color_pair(13))
            # Title
            self._put(box_y, box_x, title[:box_w], curses.color_pair(14) | curses.A_BOLD)
            # Fields
            for i, (label, key) in enumerate(fields):
                fy = box_y + 2 + i
                if not key:  # separator
                    self._put(fy, box_x + 2, "─" * (box_w - 4), curses.color_pair(13) | curses.A_DIM)
                    continue
                val_str = "".join(bufs[i])
                if i == selected:
                    self._put(fy, box_x + 2, f"▸ {label:>14}: ", curses.color_pair(14) | curses.A_BOLD)
                    field_x = box_x + 2 + 2 + 14 + 2
                    # Show value with cursor
                    self._put(fy, field_x, val_str.ljust(10)[:10], curses.color_pair(2))
                    cx = min(field_x + cursors[i], box_x + box_w - 2)
                    try:
                        self.stdscr.move(fy, cx)
                    except curses.error:
                        pass
                else:
                    display_val = val_str if val_str and val_str != "0" else "off"
                    self._put(fy, box_x + 2, f"  {label:>14}: {display_val}", curses.color_pair(13))
            # Hint
            self._put(box_y + box_h - 1, box_x + 2, "Sound plays when system-wide totals exceed threshold", curses.color_pair(13) | curses.A_DIM)
            self.stdscr.refresh()
            self._capture_screen_snapshot(
                "config_dialog",
                title.strip(),
                focus_box=(box_y, box_x, box_h, box_w),
            )

            ch = self.stdscr.getch()
            if ch in (curses.KEY_ENTER, 10, 13):
                break
            elif ch == 27:
                curses.curs_set(0)
                self.stdscr.timeout(100)
                return
            elif ch == curses.KEY_UP:
                selected = (selected - 1) % len(fields)
                if not fields[selected][1]:  # skip separator
                    selected = (selected - 1) % len(fields)
            elif ch == curses.KEY_DOWN:
                selected = (selected + 1) % len(fields)
                if not fields[selected][1]:
                    selected = (selected + 1) % len(fields)
            elif ch == ord("\t"):
                selected = (selected + 1) % len(fields)
                if not fields[selected][1]:
                    selected = (selected + 1) % len(fields)
            elif ch in (curses.KEY_BACKSPACE, 127, 8):
                if cursors[selected] > 0:
                    bufs[selected].pop(cursors[selected] - 1)
                    cursors[selected] -= 1
            elif ch == curses.KEY_DC:
                if cursors[selected] < len(bufs[selected]):
                    bufs[selected].pop(cursors[selected])
            elif ch == curses.KEY_LEFT:
                if cursors[selected] > 0:
                    cursors[selected] -= 1
            elif ch == curses.KEY_RIGHT:
                if cursors[selected] < len(bufs[selected]):
                    cursors[selected] += 1
            elif ch == curses.KEY_HOME or ch == 1:
                cursors[selected] = 0
            elif ch == curses.KEY_END or ch == 5:
                cursors[selected] = len(bufs[selected])
            elif ch == 21:  # Ctrl-U
                bufs[selected].clear()
                cursors[selected] = 0
            elif 32 <= ch <= 126:
                c = chr(ch)
                if c in "0123456789.":
                    bufs[selected].insert(cursors[selected], c)
                    cursors[selected] += 1

        # Apply thresholds
        for i, (label, key) in enumerate(fields):
            if not key:
                continue
            val_str = "".join(bufs[i]).strip()
            try:
                v = float(val_str) if val_str else 0.0
            except ValueError:
                v = 0.0
            if key == "_interval":
                self._alert_interval = max(1, v)
            elif key == "_max_count":
                self._alert_max_count = int(max(0, v))
            else:
                self._alert_thresholds[key] = v
        self._alert_count = 0  # reset count on config change
        self._save_config()

        curses.curs_set(0)
        self.stdscr.timeout(100)

    def _check_alerts(self):
        """Check if any process exceeds alert thresholds and play system sound."""
        t = self._alert_thresholds
        # Quick check: any threshold set?
        if not any(v > 0 for v in t.values()):
            return
        now = time.monotonic()
        # System-wide totals from all matched processes (not just visible rows)
        procs = getattr(self, "_all_procs", self.rows)
        total_cpu = sum(p.get("cpu", 0) for p in procs)
        total_mem_mb = sum(p.get("rss_kb", 0) for p in procs) / 1024.0
        total_thr = sum(p.get("threads", 0) for p in procs)
        total_fds = sum(max(p.get("fds", 0), 0) for p in procs)
        total_forks = sum(p.get("forks", 0) for p in procs)
        total_net_in = sum(max(p.get("net_in", 0), 0) for p in procs) / 1024.0
        total_net_out = sum(max(p.get("net_out", 0), 0) for p in procs) / 1024.0
        total_recv_mb = sum(p.get("bytes_in", 0) for p in procs) / (1024 * 1024)
        total_sent_mb = sum(p.get("bytes_out", 0) for p in procs) / (1024 * 1024)

        triggered = (
            (t["cpu"] > 0 and total_cpu > t["cpu"])
            or (t["mem_mb"] > 0 and total_mem_mb > t["mem_mb"])
            or (t["threads"] > 0 and total_thr > t["threads"])
            or (t["fds"] > 0 and total_fds > t["fds"])
            or (t["forks"] > 0 and total_forks > t["forks"])
            or (t["net_in"] > 0 and total_net_in > t["net_in"])
            or (t["net_out"] > 0 and total_net_out > t["net_out"])
            or (t["recv_mb"] > 0 and total_recv_mb > t["recv_mb"])
            or (t["sent_mb"] > 0 and total_sent_mb > t["sent_mb"])
        )
        if not triggered:
            # Only reset after a sustained period of non-triggering (one full interval)
            # so that brief dips below threshold don't reset the counter
            if self._alert_last_sound > 0 and now - self._alert_last_sound >= self._alert_interval:
                self._alert_count = 0
                self._alert_last_sound = 0.0
            return
        # Respect max count (checked after triggered so reset above always runs)
        if self._alert_max_count > 0 and self._alert_count >= self._alert_max_count:
            return
        # Cooldown based on configured interval
        if now - self._alert_last_sound < self._alert_interval:
            return
        self._alert_last_sound = now
        self._alert_count += 1
        try:
            subprocess.Popen(
                ["afplay", "/System/Library/Sounds/Glass.aiff"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        except OSError:
            pass

    def _prompt_filter(self):
        """Show filter dialog with include and exclude fields."""
        h, w = self.stdscr.getmaxyx()
        curses.curs_set(1)
        self.stdscr.timeout(-1)

        fields = [
            (" Include: ", self.name),
            (" Exclude: ", self.exclude_name),
        ]
        bufs = [list(f[1]) for f in fields]
        cursors = [len(b) for b in bufs]
        selected = 0
        hint = " e.g. claude,node  — Tab switch, Enter save, Esc cancel"

        while True:
            for i, (prompt, _) in enumerate(fields):
                y = h - 3 + i
                text = "".join(bufs[i])
                display = prompt + text
                attr = curses.color_pair(14) | curses.A_BOLD if i == selected else curses.color_pair(13)
                self._put(y, 0, display.ljust(w)[:w], attr)
            self._put(h - 1, 0, hint[:w].ljust(w), curses.color_pair(13) | curses.A_DIM)
            cx = min(len(fields[selected][0]) + cursors[selected], w - 1)
            try:
                self.stdscr.move(h - 3 + selected, cx)
            except curses.error:
                pass
            self.stdscr.refresh()
            self._capture_screen_snapshot(
                "filter_prompt",
                "Filter",
                focus_box=(h - 3, 0, 3, w),
            )

            ch = self.stdscr.getch()
            if ch in (curses.KEY_ENTER, 10, 13):
                break
            elif ch == 27:
                curses.curs_set(0)
                self.stdscr.timeout(100)
                return
            elif ch == ord("\t") or ch == curses.KEY_UP or ch == curses.KEY_DOWN:
                selected = 1 - selected
            elif ch in (curses.KEY_BACKSPACE, 127, 8):
                if cursors[selected] > 0:
                    bufs[selected].pop(cursors[selected] - 1)
                    cursors[selected] -= 1
            elif ch == curses.KEY_DC:
                if cursors[selected] < len(bufs[selected]):
                    bufs[selected].pop(cursors[selected])
            elif ch == curses.KEY_LEFT:
                if cursors[selected] > 0:
                    cursors[selected] -= 1
            elif ch == curses.KEY_RIGHT:
                if cursors[selected] < len(bufs[selected]):
                    cursors[selected] += 1
            elif ch == curses.KEY_HOME or ch == 1:
                cursors[selected] = 0
            elif ch == curses.KEY_END or ch == 5:
                cursors[selected] = len(bufs[selected])
            elif ch == 21:  # Ctrl-U
                bufs[selected].clear()
                cursors[selected] = 0
            elif 32 <= ch <= 126:
                bufs[selected].insert(cursors[selected], chr(ch))
                cursors[selected] += 1

        curses.curs_set(0)
        self.stdscr.timeout(100)

        self.name = "".join(bufs[0]).strip()
        self.patterns = [p.strip().lower() for p in self.name.split(",") if p.strip()] if self.name else []
        self.exclude_name = "".join(bufs[1]).strip()
        self.exclude_patterns = [p.strip().lower() for p in self.exclude_name.split(",") if p.strip()] if self.exclude_name else []
        self.selected = 0
        self.scroll_offset = 0
        self._expanded.clear()
        self.collect_data()

    def _kill_selected(self):
        if not self.rows:
            return

        # Walk up to find the root of this subtree (depth 0 ancestor)
        root_idx = self.selected
        while root_idx > 0 and self.rows[root_idx]["depth"] > 0:
            root_idx -= 1

        # Collect all PIDs in this subtree (root + its indented children below it)
        root_depth = self.rows[root_idx]["depth"]
        pids = [self.rows[root_idx]["pid"]]
        for i in range(root_idx + 1, len(self.rows)):
            if self.rows[i]["depth"] > root_depth:
                pids.append(self.rows[i]["pid"])
            else:
                break

        # Kill children first (deepest first), then parent
        for pid in reversed(pids):
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except PermissionError:
                pass

        # Refresh immediately
        self.collect_data()
        if self.selected >= len(self.rows):
            self.selected = max(0, len(self.rows) - 1)

    def _prompt_sort(self):
        """Show a dialog to pick a sort mode and toggle Dynamic / Group (s key)."""
        h, w = self.stdscr.getmaxyx()
        # Rows: (label, kind, payload)
        # kind: "sort" = pick sort mode (closes), "toggle" = flip flag (stays open), "sep" = divider
        rows = [
            ("Memory", "sort", SORT_MEM),
            ("CPU", "sort", SORT_CPU),
            ("Network rate", "sort", SORT_NET),
            ("Bytes received", "sort", SORT_BYTES_IN),
            ("Bytes sent", "sort", SORT_BYTES_OUT),
            ("Alphabetical", "sort", SORT_ALPHA),
            ("Vendor", "sort", SORT_VENDOR),
            ("", "sep", None),
            ("Dynamic sort", "toggle", "dynamic"),
            ("Group by vendor", "toggle", "group"),
        ]
        # Start on currently active sort mode
        try:
            selected = next(i for i, (_, k, v) in enumerate(rows)
                            if k == "sort" and v == self.sort_mode)
        except StopIteration:
            selected = 0

        self.stdscr.timeout(-1)
        title = " Sort \u2014 \u2191\u2193 navigate, Enter select/toggle, Esc close "
        box_w = min(max(len(title) + 4, 44), w - 4)
        box_h = len(rows) + 4
        box_y = max(0, (h - box_h) // 2)
        box_x = max(0, (w - box_w) // 2)

        def _toggle_state(payload):
            if payload == "dynamic":
                return "[on]" if self._dynamic_sort else "[off]"
            if payload == "group":
                return "[on]" if self._vendor_grouped else "[off]"
            return ""

        while True:
            for row in range(box_h):
                self._put(box_y + row, box_x, " " * box_w, curses.color_pair(13))
            self._put(box_y, box_x, title[:box_w], curses.color_pair(14) | curses.A_BOLD)
            for i, (label, kind, payload) in enumerate(rows):
                fy = box_y + 2 + i
                if kind == "sep":
                    self._put(fy, box_x + 2, "\u2500" * (box_w - 4),
                              curses.color_pair(13) | curses.A_DIM)
                    continue
                if kind == "sort":
                    suffix = "  (current)" if payload == self.sort_mode else ""
                elif kind == "toggle":
                    suffix = f"  {_toggle_state(payload)}"
                else:
                    suffix = ""
                line = f"\u25b8 {label}{suffix}" if i == selected else f"  {label}{suffix}"
                attr = curses.color_pair(14) | curses.A_BOLD if i == selected else curses.color_pair(13)
                self._put(fy, box_x + 2, line.ljust(box_w - 4), attr)
            self._put(box_y + box_h - 1, box_x + 2,
                      "Enter on a toggle flips it without closing",
                      curses.color_pair(13) | curses.A_DIM)
            self.stdscr.refresh()
            self._capture_screen_snapshot(
                "sort_dialog",
                title.strip(),
                focus_box=(box_y, box_x, box_h, box_w),
            )

            ch = self.stdscr.getch()
            if ch in (curses.KEY_ENTER, 10, 13):
                label, kind, payload = rows[selected]
                if kind == "sort":
                    self.stdscr.timeout(100)
                    self._set_sort(payload)
                    return
                elif kind == "toggle":
                    if payload == "dynamic":
                        self._dynamic_sort = not self._dynamic_sort
                    elif payload == "group":
                        self._vendor_grouped = not self._vendor_grouped
                    self._resort()
                    continue
            elif ch == 27 or ch == ord("q"):
                self.stdscr.timeout(100)
                return
            elif ch == ord("d"):
                self._dynamic_sort = not self._dynamic_sort
                self._resort()
            elif ch == ord("g"):
                self._vendor_grouped = not self._vendor_grouped
                self._resort()
            elif ch == curses.KEY_UP:
                # Skip separator rows
                for _ in range(len(rows)):
                    selected = (selected - 1) % len(rows)
                    if rows[selected][1] != "sep":
                        break
            elif ch == curses.KEY_DOWN:
                for _ in range(len(rows)):
                    selected = (selected + 1) % len(rows)
                    if rows[selected][1] != "sep":
                        break

    # ── Universal Chat Overlay (Ask Claude) ─────────────────────────────

    def _summarize_chat_lines(self, lines, max_lines=80, tail_lines=20,
                              max_line_width=240):
        """Compact long rendered reports before handing them to chat LLMs."""
        if not lines:
            return ""

        clipped = []
        for line in lines:
            s = str(line)
            if len(s) > max_line_width:
                s = s[:max_line_width - 3] + "..."
            clipped.append(s)

        if len(clipped) <= max_lines:
            return "\n".join(clipped)

        tail_lines = max(0, min(tail_lines, max_lines - 1))
        head_lines = max(1, max_lines - tail_lines - 1)
        omitted = len(clipped) - head_lines - tail_lines
        body = clipped[:head_lines]
        body.append(f"... [{omitted} lines omitted for chat context] ...")
        if tail_lines:
            body.extend(clipped[-tail_lines:])
        return "\n".join(body)

    def _collect_chat_context(self):
        """Build (label, text) describing what the user is currently looking at.

        The text is fed into Claude as system context so follow-up questions
        ("what does this mean?", "is this suspicious?", etc.) stay grounded in
        what's actually on screen rather than requiring the user to re-explain.
        """
        label = "mac-tui-procmon"
        parts = []

        if self._inspect_mode and self._inspect_lines:
            label = f"Inspect: PID {self._inspect_pid} ({self._inspect_cmd})"
            parts.append(
                f"The user is looking at a forensic inspect report for "
                f"PID {self._inspect_pid} ({self._inspect_cmd}). Full report:")
            parts.append(self._summarize_chat_lines(self._inspect_lines))
        elif self._audit_mode and self._audit_lines:
            title = self._audit_title()
            label = title
            if self._audit_type == "process_triage":
                parts.append(
                    f"The user is looking at the '{title}' report "
                    f"(audit_type={self._audit_type!r}). This is a deep, "
                    f"selected-process triage report built from live host "
                    f"telemetry, not a generic host audit. Answer in that "
                    f"frame. Full report:")
            else:
                parts.append(
                    f"The user is looking at the '{title}' audit "
                    f"(audit_type={self._audit_type!r}). This is a host-level "
                    f"security posture report, not a per-process inspect — "
                    f"answer in that frame. Full report:")
            parts.append(self._summarize_chat_lines(self._audit_lines))
            cur = self._audit_current_finding()
            if cur:
                parts.append("")
                parts.append(
                    "The cursor is on this finding (most likely what the "
                    "user is asking about):")
                parts.append(f"  severity: {cur.get('severity', 'INFO')}")
                parts.append(f"  message:  {cur.get('message', '')}")
                ev = (cur.get('evidence') or '').strip()
                if ev:
                    parts.append("  evidence:")
                    for ln in ev.splitlines():
                        parts.append(f"    {ln}")
                act = cur.get('action')
                if act:
                    parts.append(f"  action:   {act}")
        elif self._net_mode and self._net_entries:
            label = f"Network: PID {self._net_pid} ({self._net_cmd})"
            parts.append(
                f"The user is looking at network connections for "
                f"PID {self._net_pid} ({self._net_cmd}). Connections:")
            for e in self._net_entries[:80]:
                parts.append(f"  {e.get('display', '')}")
        elif self._events_mode:
            label = "Security timeline"
            with self._events_lock:
                snap = list(self._events)[-50:]
            parts.append(
                f"The user is watching the macOS security timeline "
                f"(source: {self._events_source}). Recent events:")
            for e in snap:
                sev = e.get("severity") or self._EVENT_KIND_SEVERITY.get(
                    e.get("kind", ""), "INFO")
                event_label = e.get("label") or self._EVENT_KIND_LABELS.get(
                    e.get("kind", ""), e.get("kind", "event"))
                parts.append(
                    f"  [{sev}] pid={e.get('pid')} ppid={e.get('ppid')} "
                    f"{event_label}: {e.get('cmd', '')}")
        elif self._unified_log_mode:
            label = (f"Unified Log: PID {self._unified_log_pid} "
                     f"({self._unified_log_cmd})")
            with self._unified_log_lock:
                snap = list(self._unified_log_lines)[-50:]
            parts.append(
                f"The user is watching the macOS unified-log feed for "
                f"PID {self._unified_log_pid} ({self._unified_log_cmd}) "
                f"via `log stream --process {self._unified_log_pid} "
                f"--level info --style compact`. Recent log lines (last "
                f"{len(snap)}):")
            for ln in snap:
                parts.append(f"  {ln[:300]}")
        elif self.rows and self.selected < len(self.rows):
            r = self.rows[self.selected]
            label = f"Process: PID {r['pid']} ({r['command'][:40]})"
            parts.append(
                f"The user is looking at the main process list with "
                f"PID {r['pid']} selected. Selected process details:")
            disk_in = r.get("disk_in", -1)
            disk_out = r.get("disk_out", -1)
            disk_line = ""
            if disk_in >= 0 or disk_out >= 0:
                disk_line = (
                    f"\n  disk_io_rate: ↓ {max(disk_in, 0):.0f} B/s "
                    f"↑ {max(disk_out, 0):.0f} B/s")
            disk_total = ""
            dbi = r.get("disk_bytes_in", 0)
            dbo = r.get("disk_bytes_out", 0)
            if dbi or dbo:
                disk_total = (
                    f"\n  disk_io_total: read {dbi:,} B / "
                    f"written {dbo:,} B")
            gpu_pct = r.get("gpu_pct")
            gpu_line = (f"\n  gpu: {gpu_pct:.1f}%"
                        if gpu_pct is not None else "")
            mach = r.get("mach_ports")
            mach_line = ""
            if isinstance(mach, int) and mach >= 0:
                mach_line = f"\n  mach_file_ports: {mach}"
            parts.append(
                f"  command: {r['command']}\n"
                f"  ppid: {r.get('ppid')}\n"
                f"  cpu: {r.get('cpu', 0):.1f}%\n"
                f"  memory: {r.get('rss_kb', 0)} KB\n"
                f"  threads: {r.get('threads', 0)}\n"
                f"  fds: {r.get('fds', '?')}"
                f"{gpu_line}{mach_line}{disk_line}{disk_total}")
        else:
            label = "Process list"
            parts.append("The user is looking at the main process list.")

        return label, "\n".join(parts)

    def _enter_chat_mode(self):
        """Enter chat overlay. The underlying mode state is preserved so Esc
        returns the user to whatever they were looking at."""
        if self._chat_mode:
            return
        label, text = self._collect_chat_context()
        # New context → fresh history. Users expect "a new question about this"
        # to not bleed into the answer for "a new question about something else."
        self._chat_context_label = label
        self._chat_context_text = text
        self._chat_messages = []
        self._chat_input = ""
        self._chat_cursor = 0
        self._chat_scroll = 0
        self._chat_mode = True
        self._chat_send("Tell me more about this item.", auto_open=True)

    def _exit_chat_mode(self):
        """Close the chat overlay. Leaves conversation history in place so
        re-opening within the same context can resume — we explicitly reset
        it in _enter_chat_mode when the context itself changes."""
        self._chat_mode = False

    def _chat_send(self, question=None, auto_open=False):
        """Send the current input line as a new user message."""
        if question is None:
            question = self._chat_input.strip()
        else:
            question = str(question).strip()
        if not question or self._chat_loading:
            return
        self._chat_messages.append({"role": "user", "content": question})
        self._chat_input = ""
        self._chat_cursor = 0
        self._chat_loading = True
        self._chat_pending = None
        self._chat_scroll = 0  # reset scroll so the new user msg is visible

        context = self._chat_context_text
        history = list(self._chat_messages)

        def _worker():
            try:
                self._chat_send_worker(context, history, auto_open)
            except Exception as e:
                self._chat_pending = f"[unexpected error: {e}]"

        self._chat_worker = threading.Thread(target=_worker, daemon=True)
        self._chat_worker.start()

    def _chat_send_worker(self, context, history, auto_open):
        """Build the prompt and try each assistant CLI in turn until one
        responds successfully. Updates `self._chat_status` between attempts
        so the UI shows "claude thinking…" → "trying with codex…" →
        "trying with gemini…". Final response (or combined error if all
        three fail) lands in `self._chat_pending` for the main loop's
        `_poll_chat_result` to render.
        """
        system_prompt = (
            "You are a macOS security and process-analysis assistant "
            "embedded in mac-tui-procmon, a Security Process Monitor. Answer the "
            "user's question concisely and grounded in the context "
            "they're looking at. Prefer bullet-point answers for "
            "anything longer than two sentences. If the user asks "
            "about a process / scan output / network connections, "
            "reason specifically about what's in the context — don't "
            "give generic advice. Start with the visible context and "
            "answer immediately when that is enough. You have "
            "permission to inspect the local machine directly, "
            "including files and commands outside the current project "
            "directory, but only do extra investigation when the "
            "screen context is insufficient or the user explicitly "
            "asks you to dig deeper. When host inspection helps, do "
            "it yourself; do not ask the user to run routine "
            "read-only inspection commands for you."
        )
        if auto_open:
            system_prompt += (
                " This is the automatic opener triggered by the '?' "
                "shortcut. For this first automatic reply, explain "
                "the current item using only the on-screen context. "
                "Do not inspect the host or run commands unless the "
                "user explicitly asks you to dig deeper in a "
                "follow-up."
            )
        body = [f"=== CONTEXT ===\n{context}\n"]
        body.append("=== CONVERSATION ===")
        for msg in history:
            role = "USER" if msg["role"] == "user" else "ASSISTANT"
            body.append(f"{role}: {msg['content']}")
        body.append("ASSISTANT:")
        stdin_text = "\n".join(body)

        env = {
            **os.environ,
            "PATH": _USER_TOOL_PATH,
            "HOME": _EFFECTIVE_HOME,
        }
        sudo_user = os.environ.get("SUDO_USER")
        if sudo_user:
            env["USER"] = sudo_user
            env["LOGNAME"] = sudo_user

        attempts = [
            ("claude", [
                "claude", "-p", "--no-session-persistence",
                "--dangerously-skip-permissions", "--add-dir", "/",
                system_prompt,
            ]),
            ("codex", [
                "codex", "exec",
                "--dangerously-bypass-approvals-and-sandbox",
                "--color", "never", system_prompt,
            ]),
            ("gemini", [
                "gemini", "-p", system_prompt, "-y",
            ]),
        ]

        errors = []
        for i, (label, argv) in enumerate(attempts):
            if i == 0:
                self._chat_status = f"[{label} thinking…]"
            else:
                self._chat_status = f"[trying with {label}…]"
            ok, result = self._run_assistant_attempt(
                argv, stdin_text, env, _CHAT_TIMEOUT_SECS, label)
            if ok:
                self._chat_pending = result
                return
            errors.append(f"{label}: {result}")

        self._chat_pending = (
            "[all assistants failed]\n" + "\n".join(errors))

    @staticmethod
    def _wrap_argv_for_invoking_user(argv):
        """If we're root with SUDO_USER set, wrap argv with
        `sudo -n -E -u $SUDO_USER --` so the assistant runs as the
        invoking user.

        Why: claude's OAuth/keychain reads gate on the process UID, not
        HOME. Even with HOME pointed at the user's home dir, claude
        running as EUID=0 can't read the per-user keychain and ends up
        hanging on auth — which is exactly the symptom the user hit.
        Spawning under the original UID via `sudo -u` sidesteps it. On
        macOS, root → any-user via sudo doesn't require a password.
        """
        if os.geteuid() != 0:
            return argv
        sudo_user = os.environ.get("SUDO_USER")
        if not sudo_user:
            return argv
        return ["sudo", "-n", "-E", "-u", sudo_user, "--"] + list(argv)

    def _run_assistant_attempt(self, argv, stdin_text, env, timeout, label):
        """Invoke one assistant CLI. Returns (ok, text_or_error_message).

        Kept as a method (not a closure) so tests can patch it per-attempt
        to drive the fallback chain deterministically.
        """
        actual_argv = self._wrap_argv_for_invoking_user(argv)
        try:
            proc = subprocess.Popen(
                actual_argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
            )
        except FileNotFoundError:
            return False, f"{label} CLI not found"
        except OSError as e:
            return False, f"{label} error: {e}"
        except Exception as e:
            return False, f"{label} unexpected: {e}"

        try:
            stdout, stderr = proc.communicate(
                input=stdin_text.encode("utf-8"), timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            return False, f"{label} timed out after {timeout}s"
        except Exception as e:
            return False, f"{label} unexpected: {e}"

        if proc.returncode != 0:
            err = stderr.decode("utf-8", errors="replace").strip()
            out = stdout.decode("utf-8", errors="replace").strip()
            detail = err or out or "(no output)"
            return False, (
                f"{label} error rc={proc.returncode}: {detail[:200]}")
        text = stdout.decode("utf-8", errors="replace").strip()
        if not text:
            return False, f"{label} returned no output"
        return True, text

    def _poll_chat_result(self):
        """Pick up the worker's result. Returns True when there was a change."""
        if self._chat_pending is None:
            return False
        if not self._chat_mode:
            # User closed the overlay while the request was in flight — keep
            # the reply for when they re-open, but stop loading.
            self._chat_messages.append({"role": "assistant",
                                         "content": self._chat_pending})
            self._chat_pending = None
            self._chat_loading = False
            self._chat_status = None
            return False
        self._chat_messages.append({"role": "assistant",
                                     "content": self._chat_pending})
        self._chat_pending = None
        self._chat_loading = False
        self._chat_status = None
        return True

    def _handle_chat_input(self, key):
        """Keyboard handler while the chat overlay has focus."""
        if key == 27:  # Esc — close overlay
            self._exit_chat_mode()
            return True
        if key == ord("\n") or key == curses.KEY_ENTER or key == 10 or key == 13:
            self._chat_send()
            return True
        if key == curses.KEY_UP:
            self._chat_scroll += 1
            return True
        if key == curses.KEY_DOWN:
            self._chat_scroll = max(0, self._chat_scroll - 1)
            return True
        if key == curses.KEY_PPAGE:
            self._chat_scroll += self._page_size()
            return True
        if key == curses.KEY_NPAGE:
            self._chat_scroll = max(0, self._chat_scroll - self._page_size())
            return True
        if key in (curses.KEY_BACKSPACE, 127, 8):
            if self._chat_cursor > 0:
                self._chat_input = (
                    self._chat_input[:self._chat_cursor - 1]
                    + self._chat_input[self._chat_cursor:])
                self._chat_cursor -= 1
            return True
        if key == curses.KEY_DC:  # Delete
            if self._chat_cursor < len(self._chat_input):
                self._chat_input = (
                    self._chat_input[:self._chat_cursor]
                    + self._chat_input[self._chat_cursor + 1:])
            return True
        if key == curses.KEY_LEFT:
            self._chat_cursor = max(0, self._chat_cursor - 1)
            return True
        if key == curses.KEY_RIGHT:
            self._chat_cursor = min(len(self._chat_input),
                                     self._chat_cursor + 1)
            return True
        if key == 1:  # Ctrl-A → start of line
            self._chat_cursor = 0
            return True
        if key == 5:  # Ctrl-E → end of line
            self._chat_cursor = len(self._chat_input)
            return True
        if key == 21:  # Ctrl-U → clear input
            self._chat_input = ""
            self._chat_cursor = 0
            return True
        # Printable character
        if 32 <= key < 127:
            self._chat_input = (
                self._chat_input[:self._chat_cursor]
                + chr(key)
                + self._chat_input[self._chat_cursor:])
            self._chat_cursor += 1
            return True
        return True  # swallow everything else so underlying mode doesn't react

    # ── Debug log ──────────────────────────────────────────────────────

    def _log(self, category, text):
        """Append a diagnostic line to the debug log.

        `category` is a short tag (TCC / SUBPROC / VERIFY / UI / etc.)
        used purely for display. Thread-safe — the TCC dispatcher calls
        this from background threads.
        """
        ts = time.strftime("%H:%M:%S")
        with self._log_lock:
            self._log_messages.append((ts, category, text))
            if len(self._log_messages) > self._log_max:
                del self._log_messages[:len(self._log_messages) - self._log_max]

    def _toggle_log_mode(self):
        """Open / close the debug log overlay (L key)."""
        if self._log_mode:
            self._log_mode = False
            return
        self._log_mode = True
        self._log_scroll = 0

    def _render_log(self):
        """Render the debug log as a full-screen overlay, newest at bottom."""
        h, w = self.stdscr.getmaxyx()
        if h < 10 or w < 40:
            return
        box_x = 1
        box_y = 1
        box_w = w - 2
        box_h = h - 2
        for row in range(box_h):
            self._put(box_y + row, box_x, " " * box_w, curses.color_pair(13))
        with self._log_lock:
            entries = list(self._log_messages)
        title = f" Debug log \u2014 {len(entries)} entries "
        self._put(box_y, box_x, title.ljust(box_w)[:box_w],
                  curses.color_pair(14) | curses.A_BOLD)
        footer = (" Esc close  \u2191\u2193 scroll  PgU/D page  "
                  "c clear  L close ")
        self._put(box_y + box_h - 1, box_x, footer.ljust(box_w)[:box_w],
                  curses.color_pair(14) | curses.A_BOLD)

        # Render each entry, wrapping long lines
        inner_h = box_h - 2
        inner_w = box_w - 4
        if inner_h < 1 or not entries:
            if not entries:
                self._put(box_y + 2, box_x + 2,
                          " (log is empty — perform an action first)",
                          curses.color_pair(13) | curses.A_DIM)
            return

        wrapped = []
        for ts, cat, text in entries:
            # Colorize category
            attr = curses.color_pair(13)
            if cat in ("ERROR", "FAIL"):
                attr = curses.color_pair(5) | curses.A_BOLD
            elif cat in ("OK", "VERIFY"):
                attr = curses.color_pair(1)
            elif cat in ("TCC", "SUBPROC"):
                attr = curses.color_pair(7)
            header = f"[{ts}] {cat:8}"
            first_line = f"{header} {text}"
            remaining = first_line
            while remaining:
                chunk = remaining[:inner_w]
                remaining = remaining[inner_w:]
                wrapped.append((chunk, attr))
                if remaining:
                    # Indent wrapped continuations for readability
                    remaining = "    " + remaining

        total = len(wrapped)
        tail_start = max(0, total - inner_h)
        start = max(0, tail_start - self._log_scroll)
        end = start + inner_h
        for i, (text, attr) in enumerate(wrapped[start:end]):
            self._put(box_y + 1 + i, box_x + 2, text[:inner_w], attr)
        # Hide cursor (chat mode flips it on; it'd linger otherwise)
        try:
            curses.curs_set(0)
        except curses.error:
            pass

    def _handle_log_input(self, key):
        """Keyboard handler while the log overlay is focused."""
        if key == 27 or key == ord("L") or key == ord("l"):
            self._toggle_log_mode()
            return True
        if key == ord("q"):
            self._toggle_log_mode()
            return False
        if key == curses.KEY_UP:
            self._log_scroll += 1
            return True
        if key == curses.KEY_DOWN:
            self._log_scroll = max(0, self._log_scroll - 1)
            return True
        if key == curses.KEY_PPAGE:
            self._log_scroll += self._page_size()
            return True
        if key == curses.KEY_NPAGE:
            self._log_scroll = max(0, self._log_scroll - self._page_size())
            return True
        if key == ord("c"):
            with self._log_lock:
                self._log_messages.clear()
            self._log_scroll = 0
            return True
        return True  # swallow all keys — this is a modal overlay

    def _render_chat(self):
        """Draw the chat overlay on top of whatever is already rendered."""
        h, w = self.stdscr.getmaxyx()
        if h < 12 or w < 40:
            return
        # Full-screen-ish overlay with a 2-col margin
        box_x = 1
        box_y = 1
        box_w = w - 2
        box_h = h - 2

        # Clear the box
        for row in range(box_h):
            self._put(box_y + row, box_x, " " * box_w, curses.color_pair(13))

        # Title
        title = f" Ask Claude \u2014 {self._chat_context_label[:box_w - 20]} "
        self._put(box_y, box_x, title.ljust(box_w)[:box_w],
                  curses.color_pair(14) | curses.A_BOLD)

        # Footer shortcuts
        footer = " Enter send  Esc close  \u2191\u2193 scroll  PgU/D page  "
        self._put(box_y + box_h - 1, box_x, footer.ljust(box_w)[:box_w],
                  curses.color_pair(14) | curses.A_BOLD)

        # Input line (second-from-bottom)
        if self._chat_loading:
            loading_marker = f" {self._chat_status}" if self._chat_status \
                else " [thinking\u2026]"
        else:
            loading_marker = ""
        prompt_prefix = "> "
        input_y = box_y + box_h - 2
        input_line = prompt_prefix + self._chat_input + loading_marker
        self._put(input_y, box_x, " " * box_w, curses.color_pair(13))
        self._put(input_y, box_x + 1, input_line[:box_w - 2],
                  curses.color_pair(13))

        # Conversation area (between title and input)
        conv_y = box_y + 2
        conv_h = box_h - 4
        if conv_h < 1:
            return
        inner_w = box_w - 4

        # Build wrapped lines with per-line role/attr
        wrapped = []  # list of (text, attr)
        if not self._chat_messages:
            hint = (f"Ask a question about: {self._chat_context_label}")
            wrapped.append((hint, curses.color_pair(13) | curses.A_DIM))
            wrapped.append(("", 0))
            wrapped.append(("Example: \"What is this process doing?\" / "
                            "\"Is this suspicious?\" / \"Explain this finding\"",
                            curses.color_pair(13) | curses.A_DIM))
        else:
            for msg in self._chat_messages:
                role = msg["role"]
                text = msg["content"]
                header = "You:" if role == "user" else "Claude:"
                header_attr = (curses.color_pair(7) | curses.A_BOLD
                               if role == "user"
                               else curses.color_pair(1) | curses.A_BOLD)
                wrapped.append((header, header_attr))
                # Wrap message body
                for line in text.splitlines() or [""]:
                    remaining = line
                    if not remaining:
                        wrapped.append(("", curses.color_pair(13)))
                        continue
                    while remaining:
                        chunk = remaining[:inner_w]
                        remaining = remaining[inner_w:]
                        wrapped.append(("  " + chunk, curses.color_pair(13)))
                wrapped.append(("", 0))  # separator blank line

        # Apply scroll — user scrolls from the bottom
        total = len(wrapped)
        # By default show the newest content; scroll up hides the tail
        tail_start = max(0, total - conv_h)
        start = max(0, tail_start - self._chat_scroll)
        end = start + conv_h
        self._capture_chat_snapshot(wrapped, conv_h)
        for i, (text, attr) in enumerate(wrapped[start:end]):
            self._put(conv_y + i, box_x + 2,
                      text[:inner_w].ljust(inner_w), attr)

        # Move cursor into the input field so arrow keys / typing feel natural
        curses.curs_set(1)
        try:
            self.stdscr.move(input_y,
                             box_x + 1 + len(prompt_prefix) + self._chat_cursor)
        except curses.error:
            pass

    # Rows in the dialogs are (label, kind, payload):
    #   kind == "header"  → section heading, non-selectable (bold+dim)
    #   kind == "action"  → selectable; payload is the dispatch key
    # Process Investigation = selected-process actions only.
    # Live Telemetry        = per-process event / traffic views.

    _FORENSIC_ROWS = [
        ("Selected Process", "header", None),
        ("Inspect process (Claude + Codex + Gemini)", "action", "inspect"),
        ("Deep process triage (selected process)", "action", "triage"),
        ("Network connections (selected process)", "action", "network"),
    ]

    _TELEMETRY_ROWS = [
        ("Endpoint Security", "header", None),
        ("Security timeline (exec/auth/login/TCC/XProtect)", "action", "events"),
        ("Experimental", "header", None),
        ("Traffic Inspector (experimental, mitmproxy)", "action", "traffic"),
    ]


    def _run_sectioned_menu(self, rows, title, footer, on_select,
                            surface="menu"):
        """Render a sectioned menu (headers + actions), handling navigation.

        `rows` is a list of (label, kind, payload). Header rows are rendered
        non-selectable and skipped by Up/Down. Selecting an action calls
        `on_select(payload)`.

        Scrolls vertically when the dialog is taller than the terminal, so
        long menus stay usable on short screens.
        """
        h, w = self.stdscr.getmaxyx()
        # Start on the first actionable row
        try:
            selected = next(i for i, (_, k, _) in enumerate(rows)
                            if k == "action")
        except StopIteration:
            return

        self.stdscr.timeout(-1)
        box_w = min(max(len(title) + 4, 58), w - 4)
        box_h = min(len(rows) + 4, max(6, h - 2))
        box_y = max(0, (h - box_h) // 2)
        box_x = max(0, (w - box_w) // 2)
        visible_rows = max(1, box_h - 4)
        scroll = 0

        def _step(start, delta):
            """Move the cursor over actions, skipping headers. Wraps around."""
            idx = start
            for _ in range(len(rows)):
                idx = (idx + delta) % len(rows)
                if rows[idx][1] == "action":
                    return idx
            return start

        try:
            while True:
                # Keep selected in view
                if selected < scroll:
                    scroll = selected
                elif selected >= scroll + visible_rows:
                    scroll = selected - visible_rows + 1

                for row in range(box_h):
                    self._put(box_y + row, box_x, " " * box_w,
                              curses.color_pair(13))
                self._put(box_y, box_x, title[:box_w],
                          curses.color_pair(14) | curses.A_BOLD)

                for i in range(visible_rows):
                    idx = scroll + i
                    if idx >= len(rows):
                        break
                    label, kind, _ = rows[idx]
                    fy = box_y + 2 + i
                    if kind == "header":
                        heading = f" {label.upper()} "
                        hbar = heading + "\u2500" * max(
                            0, box_w - 4 - len(heading))
                        self._put(fy, box_x + 2, hbar[:box_w - 4],
                                  curses.color_pair(13)
                                  | curses.A_BOLD | curses.A_DIM)
                    else:
                        prefix = "\u25b8 " if idx == selected else "  "
                        line = prefix + label
                        attr = (curses.color_pair(14) | curses.A_BOLD
                                if idx == selected
                                else curses.color_pair(13))
                        self._put(fy, box_x + 4, line.ljust(box_w - 6), attr)

                if footer:
                    self._put(box_y + box_h - 1, box_x + 2,
                              footer[:box_w - 4],
                              curses.color_pair(13) | curses.A_DIM)
                self.stdscr.refresh()
                self._capture_screen_snapshot(
                    surface,
                    title.strip(),
                    focus_box=(box_y, box_x, box_h, box_w),
                )

                ch = self.stdscr.getch()
                if ch in (curses.KEY_ENTER, 10, 13):
                    payload = rows[selected][2]
                    on_select(payload)
                    return
                elif ch == 27 or ch == ord("q"):
                    return
                elif ch == curses.KEY_UP:
                    selected = _step(selected, -1)
                elif ch == curses.KEY_DOWN:
                    selected = _step(selected, 1)
                elif ch == curses.KEY_PPAGE:
                    target = max(0, selected - visible_rows)
                    # snap back to an action row
                    while target < len(rows) and rows[target][1] != "action":
                        target += 1
                    if target < len(rows):
                        selected = target
                elif ch == curses.KEY_NPAGE:
                    target = min(len(rows) - 1, selected + visible_rows)
                    while target >= 0 and rows[target][1] != "action":
                        target -= 1
                    if target >= 0:
                        selected = target
        finally:
            self.stdscr.timeout(100)

    def _dispatch_forensic_action(self, payload):
        """Handle a selection from the Process Investigation menu."""
        if payload == "inspect":
            self._toggle_inspect_mode()
        elif payload == "triage":
            self._toggle_process_triage_mode()
        elif payload == "network":
            self._toggle_net_mode()

    def _dispatch_telemetry_action(self, payload):
        """Handle a selection from the Live Telemetry menu."""
        if payload == "events":
            self._toggle_events_mode()
        elif payload == "traffic":
            self._toggle_traffic_mode()



    def _prompt_forensic(self):
        """Show the Process Investigation menu (F key)."""
        self._run_sectioned_menu(
            self._FORENSIC_ROWS,
            title=" Process Investigation \u2014 \u2191\u2193 navigate, Enter select, Esc cancel ",
            footer="Selected-process and scoped investigation actions.",
            on_select=self._dispatch_forensic_action,
            surface="forensic_menu",
        )

    def _prompt_telemetry(self):
        """Show the Live Telemetry menu (E key)."""
        self._run_sectioned_menu(
            self._TELEMETRY_ROWS,
            title=" Live Telemetry \u2014 \u2191\u2193 navigate, Enter select, Esc cancel ",
            footer="Endpoint Security timeline first; traffic interception is experimental.",
            on_select=self._dispatch_telemetry_action,
            surface="telemetry_menu",
        )


    def _resort(self):
        """Re-sort by re-collecting process data with the new sort key."""
        if not self.rows:
            return
        sel_pid = self.rows[self.selected]["pid"] if self.rows else None

        all_procs = get_all_processes()
        self._compute_cpu_deltas(all_procs)

        # Attach net rates and bytes for tree aggregation
        for p in all_procs:
            rates = self.net_rates.get(p["pid"])
            p["net_in"] = rates[0] if rates else -1
            p["net_out"] = rates[1] if rates else -1
            snap = self.prev_net.get(p["pid"])
            p["bytes_in"] = snap[0] if snap else 0
            p["bytes_out"] = snap[1] if snap else 0

        matched = [p for p in all_procs
                   if p["pid"] not in _PHANTOM_TREE_PARENTS
                   and (not self.patterns or any(pat in p["command"].lower() for pat in self.patterns))
                   and not any(pat in p["command"].lower() for pat in self.exclude_patterns)]

        _build = build_vendor_tree if self._vendor_grouped else build_tree
        tree = _build(matched, all_procs, self._sort_key(), self._sort_reverse())
        flat = flatten_tree(tree, self._expanded)
        matched_pids = [p["pid"] for p in matched]

        # Carry over fds and cwd from previous rows
        old = {r["pid"]: r for r in self.rows}
        fd_map = {} if self.skip_fd else get_fd_counts(matched_pids)
        for p in matched:
            prev = old.get(p["pid"], {})
            p["fds"] = fd_map.get(p["pid"], prev.get("fds", -1))
        for r in flat:
            prev = old.get(r["pid"], {})
            r["fds"] = fd_map.get(r["pid"], prev.get("fds", -1))
            r["cwd"] = prev.get("cwd", "-")

        self.rows = flat
        self._all_procs = matched
        self.matched_count = len(matched)

        # Restore selection
        if sel_pid is not None:
            for i, r in enumerate(self.rows):
                if r["pid"] == sel_pid:
                    self.selected = i
                    break
        if self.selected >= len(self.rows):
            self.selected = max(0, len(self.rows) - 1)

    def run(self):
        self.collect_data()
        self.render()
        last_refresh = time.monotonic()

        try:
            self._run_loop(last_refresh)
        finally:
            # Always clean up background work before returning — otherwise
            # running subprocesses (eslogger) and in-flight LLM calls can
            # keep the Python interpreter alive after curses.wrapper exits,
            # making the tool appear to hang on quit.
            self._shutdown()

    def _shutdown(self):
        """Tear down every background resource. Safe to call multiple times."""
        try:
            self._stop_events_stream()
        except Exception:
            pass
        try:
            self._stop_traffic_stream()
        except Exception:
            pass
        try:
            self._stop_unified_log_stream()
        except Exception:
            pass
        # Kill any still-running event subprocess explicitly
        proc = getattr(self, "_events_proc", None)
        if proc:
            try:
                proc.kill()
            except Exception:
                pass
        traffic_proc = getattr(self, "_traffic_proc", None)
        if traffic_proc:
            try:
                traffic_proc.kill()
            except Exception:
                pass

    def _run_loop(self, last_refresh):
        while True:
            if self._maybe_run_test_action():
                self.render()
            key = self.stdscr.getch()
            if key != -1:
                if not self.handle_input(key):
                    break
                self.render()

            # Poll for background fetch results
            if self._net_pending is not None:
                if self._poll_net_result():
                    self.render()
            if self._inspect_pending is not None:
                if self._poll_inspect_result():
                    self.render()
            if self._chat_pending is not None:
                if self._poll_chat_result():
                    self.render()
            if self._audit_pending is not None:
                if self._poll_audit_result():
                    self.render()
            # Feature 5: Attack Chain Replay — auto-advance when playing.
            try:
                if self._replay_advance_if_playing():
                    self.render()
            except Exception:
                pass
            # Poll per-scope LLM summaries (audit, inspect, events). Each slot
            # is independent; rendering the finished panel kicks the viewport
            # up by its height.
            for _scope in ("audit", "inspect", "events"):
                if self._llm_summary_pending.get(_scope) is not None:
                    if self._poll_llm_summary(_scope):
                        self.render()
            # Re-render long audits so live phase/progress lines are visible
            if self._audit_mode and self._audit_loading:
                self.render()
            # Re-render the events view as new events arrive
            if self._events_mode:
                self.render()
            # Re-render the unified-log view as new lines arrive
            if self._unified_log_mode:
                self.render()

            now = time.monotonic()
            if now - last_refresh >= self.interval:
                try:
                    self.collect_data()
                    # Auto-refresh net view if open (non-blocking)
                    if self._net_mode and self._net_pid:
                        self._start_net_refresh()
                except MemoryError:
                    gc.collect()
                    try:
                        self.collect_data()
                    except MemoryError:
                        pass
                self._check_alerts()
                self.render()
                last_refresh = now


def main():
    parser = argparse.ArgumentParser(
        prog="mac-tui-procmon",
        description=(
            "Resilient top-like process monitor filtered by name (macOS). "
            "Uses direct libproc/sysctl calls — no fork() required — so it "
            "survives fork bombs and memory exhaustion."
        ),
    )
    parser.add_argument("name", nargs="?", default="",
                        help="Process name to match (case-insensitive substring; omit to monitor all)")
    parser.add_argument("-i", "--interval", type=float, default=5.0,
                        help="Refresh interval in seconds (default: 5)")
    parser.add_argument("--no-fd", action="store_true",
                        help="Skip file descriptor counting (faster)")
    parser.add_argument("--skip-preflight", action="store_true",
                        help="Skip external tool dependency check at startup")
    args = parser.parse_args()

    if args.interval <= 0:
        parser.error("Interval must be positive")

    # Preflight: check external CLI dependencies before entering curses
    if not _preflight(skip=args.skip_preflight, scope="process"):
        return

    # Validate struct layout before starting
    if not _self_test():
        print("Continuing despite self-test warning...", file=sys.stderr)
        time.sleep(1)

    # Harden: lock memory, boost priority
    _harden_process()

    def _sigterm_handler(signum, frame):
        sys.exit(0)

    signal.signal(signal.SIGTERM, _sigterm_handler)
    signal.signal(signal.SIGHUP, _sigterm_handler)

    try:
        curses.wrapper(lambda stdscr: ProcMonUI(stdscr, args.name, args.interval, args.no_fd).run())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
