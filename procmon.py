#!/usr/bin/env python3
"""procmon - resilient process monitor for macOS.

Uses macOS libproc/sysctl directly via ctypes for process inspection,
avoiding fork()/exec() so the monitor survives fork bombs and memory
exhaustion. A single persistent process with locked memory and elevated
priority that continues monitoring even when the system cannot fork.
"""

import argparse
import ctypes
import ctypes.util
import curses
import gc
import os
import shutil
import signal
import subprocess
import sys
import threading
import time

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


# ── macOS Native Interface (ctypes) ──────────────────────────────────────

# libproc flavors
PROC_ALL_PIDS = 1
PROC_PIDTASKALLINFO = 2
PROC_PIDTBSDINFO = 3
PROC_PIDTASKINFO = 4
PROC_PIDLISTFDS = 1
PROC_PIDVNODEPATHINFO = 9
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
    ("lsof", "critical", "network connections, open file inspection",
     "usually preinstalled on macOS"),
    ("ps", "important", "hidden process detection (background + deep scan)",
     "preinstalled on macOS"),
    ("nettop", "important", "per-process network rates and cumulative bytes",
     "preinstalled on macOS"),
    ("codesign", "important", "inspect mode: signature verification and entitlements",
     "preinstalled on macOS"),
    ("otool", "important", "inspect mode: linked dylibs",
     "xcode-select --install"),
    ("shasum", "important", "inspect mode: binary hash",
     "preinstalled on macOS"),
    ("vmmap", "optional", "inspect mode: memory regions (root-only)",
     "preinstalled on macOS"),
    ("afplay", "optional", "alert sound playback",
     "preinstalled on macOS"),
    ("claude", "optional", "inspect mode: Claude security analysis",
     "npm install -g @anthropic-ai/claude-code"),
    ("codex", "optional", "inspect mode: Codex security analysis",
     "npm install -g @openai/codex"),
    ("gemini", "optional", "inspect mode: Gemini security analysis",
     "npm install -g @google/gemini-cli"),
    ("eslogger", "optional", "live event stream (macOS 12+ exec/fork)",
     "preinstalled on macOS 12+; grant Full Disk Access to Terminal if needed"),
    ("dtrace", "optional", "live event stream fallback (exec tracing)",
     "preinstalled on macOS"),
    ("yara", "optional", "on-disk and memory malware signature scanning",
     "brew install yara"),
    ("lldb", "optional", "memory snapshot for YARA memory scan",
     "xcode-select --install"),
]


def _check_external_tools():
    """Scan for missing external CLI dependencies via shutil.which (no fork).

    Uses the augmented user-tool PATH so sudo-run procmon doesn't falsely
    report claude/codex/gemini as missing just because sudo sanitized PATH.

    Returns a list of (tool, category, feature_desc, install_hint) tuples for
    tools that are NOT on PATH. Empty list means everything is present.
    """
    missing = []
    for tool, category, feature_desc, install_hint in _EXTERNAL_TOOLS:
        if shutil.which(tool, path=_USER_TOOL_PATH) is None:
            missing.append((tool, category, feature_desc, install_hint))
    return missing


def _render_preflight_report(missing, stream=None):
    """Print the preflight report for missing tools to `stream`."""
    if stream is None:
        stream = sys.stderr
    order = {"critical": 0, "important": 1, "optional": 2}
    missing_sorted = sorted(missing, key=lambda t: order.get(t[1], 99))
    print("", file=stream)
    print("procmon preflight \u2014 some external tools are missing", file=stream)
    print("", file=stream)
    for tool, category, feature_desc, install_hint in missing_sorted:
        print(f"  [{category}] {tool:<10} \u2014 {feature_desc}", file=stream)
        print(f"              install: {install_hint}", file=stream)
    print("", file=stream)
    print("procmon will run in DEGRADED mode. Missing features will be skipped", file=stream)
    print("at runtime with a short error message instead of an analysis result.", file=stream)
    print("", file=stream)


def _installable_command(install_hint):
    """Parse an install hint and return a runnable argv, or None.

    Only recognizes install commands we can safely invoke non-interactively
    and without sudo: `brew install ...`, `npm install -g ...`, and
    `xcode-select --install` (which pops up an interactive installer).
    Anything else (e.g. "preinstalled on macOS") returns None.
    """
    if not install_hint:
        return None
    hint = install_hint.strip()
    # Strip trailing comments (`# preinstalled` etc.)
    if "#" in hint:
        hint = hint.split("#", 1)[0].strip()
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


def _run_install(argv, stream=None):
    """Run an install command with the user watching. Inherits stdout/stderr
    so users see progress. Returns True on success.
    """
    if stream is None:
        stream = sys.stderr
    print(f"\n$ {' '.join(argv)}", file=stream)
    try:
        rc = subprocess.call(argv)
    except (FileNotFoundError, OSError) as e:
        print(f"  [!] failed to launch: {e}", file=stream)
        return False
    if rc != 0:
        print(f"  [!] command exited with code {rc}", file=stream)
        return False
    return True


def _preflight(skip=False):
    """Run the startup preflight. Blocks on Enter if stdin is a TTY.

    If any missing tools have a runnable install command, offer to run them.
    After a successful install pass, re-check so the user sees what (if
    anything) is still missing before continuing.

    Returns True on success (continue), False if the user aborted.
    """
    if skip:
        return True
    missing = _check_external_tools()
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


def _check_hidden_pids_network():
    """Get PIDs with network connections via lsof. Returns set of PIDs."""
    try:
        proc = subprocess.Popen(
            ["lsof", "-i", "-n", "-P", "+c0"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            stdout, _ = proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            return set()
    except (FileNotFoundError, OSError):
        return set()
    net_pids = set()
    for line in stdout.decode("utf-8", errors="replace").splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2:
            try:
                net_pids.add(int(parts[1]))
            except ValueError:
                pass
    return net_pids


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


def _check_secure_keyboard_entry():
    """Query whether any process currently holds Secure Keyboard Entry.

    Uses the public Carbon/HIToolbox `IsSecureEventInputEnabled()` symbol,
    and reads `kCGSSessionSecureInputPID` from `ioreg -c IOConsoleUsers -l`
    to attribute the holder PID.

    Returns {enabled: bool, pid: int (0 if not available)}.
    """
    result = {"enabled": False, "pid": 0}
    try:
        hitoolbox = ctypes.CDLL(
            "/System/Library/Frameworks/Carbon.framework/Frameworks/"
            "HIToolbox.framework/HIToolbox"
        )
        hitoolbox.IsSecureEventInputEnabled.restype = ctypes.c_bool
        hitoolbox.IsSecureEventInputEnabled.argtypes = []
        result["enabled"] = bool(hitoolbox.IsSecureEventInputEnabled())
    except (OSError, AttributeError):
        return result
    # Attribute the holder via ioreg
    rc, out, _ = _run_cmd_short(
        ["ioreg", "-c", "IOConsoleUsers", "-l"], timeout=3)
    if rc == 0:
        for line in out.splitlines():
            if "kCGSSessionSecureInputPID" in line and "=" in line:
                try:
                    result["pid"] = int(line.split("=", 1)[1].strip())
                except ValueError:
                    pass
                break
    return result


def _scan_keyboard_hooks():
    """Aggregate all keyboard-hook signals.

    Returns a list of dicts: {severity, message, action}. `action` is None
    for non-actionable findings (info notes), or a dict the TUI can dispatch
    on when the user hits `D` to remove the underlying hook:

      {"type": "delete_tcc",    "client": str, "service": str, "db": str}
      {"type": "kill_process",  "pid": int}
      {"type": "remove_bundle", "path": str}
    """
    findings = []

    # Event taps that listen to key events
    for tap in _enumerate_event_taps():
        if not tap["hooks_keys"]:
            continue
        pid = tap["pid"]
        exe = _get_proc_path(pid) or "(unknown)"
        apple = _is_apple_signed(exe, _codesign_structured(exe) or {})
        severity = "MEDIUM" if apple else "HIGH"
        target_desc = ("all processes" if tap["target_pid"] == 0
                       else f"PID {tap['target_pid']}")
        findings.append({
            "severity": severity,
            "message": (f"CGEventTap on key events: PID {pid} ({exe}) "
                        f"\u2192 {target_desc} "
                        f"[enabled={tap['enabled']}]"),
            # An event tap is owned by the process that installed it; the
            # only way to remove it is to terminate that process. Suppress
            # the action on Apple system daemons to avoid foot-gunning.
            "action": (None if apple
                       else {"type": "kill_process", "pid": pid, "exe": exe}),
        })

    # TCC Input Monitoring / Accessibility grants
    for entry in _query_tcc_input_monitoring():
        if entry["auth_value"] != 2:  # not allowed
            continue
        client = entry["client"]
        if client.startswith("com.apple.") or client.startswith("/System/"):
            continue  # Apple bundles
        service_name = {
            "kTCCServiceListenEvent": "Input Monitoring",
            "kTCCServiceAccessibility": "Accessibility (can read keys)",
            "kTCCServicePostEvent": "Post events (can synthesize keys)",
        }.get(entry["service"], entry["service"])
        findings.append({
            "severity": "HIGH",
            "message": f"TCC grant: {client} has {service_name}",
            "action": {
                "type": "delete_tcc",
                "client": client,
                "service": entry["service"],
                "db": entry["db"],
            },
        })

    # Third-party Input Methods
    for ime in _list_input_methods():
        path = ime["path"]
        if path.startswith("/System/"):
            continue
        findings.append({
            "severity": "MEDIUM",
            "message": (f"3rd-party Input Method installed: {path} "
                        f"(team={ime['team_id'] or 'none'})"),
            "action": {"type": "remove_bundle", "path": path},
        })

    # Secure Keyboard Entry — informational
    secure = _check_secure_keyboard_entry()
    if secure["enabled"] and secure["pid"]:
        exe = _get_proc_path(secure["pid"]) or "(unknown)"
        findings.append({
            "severity": "INFO",
            "message": f"Secure Keyboard Entry held by PID {secure['pid']}: {exe}",
            "action": None,
        })
    elif not secure["enabled"]:
        findings.append({
            "severity": "INFO",
            "message": ("Secure Keyboard Entry is OFF (terminal keystrokes "
                        "can be captured by any accessible CGEventTap)"),
            "action": None,
        })

    return findings


# ── Destructive remediation ───────────────────────────────────────────────

# Mapping from the raw TCC service string to the short name tccutil expects.
# tccutil(1) takes names like "Accessibility" and "ListenEvent", not the full
# kTCCService* constants. Keeping this as an explicit whitelist so an
# unexpected service (new macOS version) falls back cleanly to sqlite.
_TCC_SERVICE_SHORT_NAMES = {
    "kTCCServiceAccessibility": "Accessibility",
    "kTCCServiceListenEvent": "ListenEvent",
    "kTCCServicePostEvent": "PostEvent",
    "kTCCServiceCamera": "Camera",
    "kTCCServiceMicrophone": "Microphone",
    "kTCCServiceScreenCapture": "ScreenCapture",
    "kTCCServiceSystemPolicyAllFiles": "SystemPolicyAllFiles",
    "kTCCServiceSystemPolicyDeveloperFiles": "DeveloperTools",
}


def _tcc_grant_exists(client, service, db_path):
    """Return True iff the row is CONFIRMED present, False iff CONFIRMED
    absent, None if we can't tell (db unreadable, missing path, etc.).

    The three-valued result matters a lot: SIP can block reading TCC.db
    even for root when the terminal lacks Full Disk Access. If we
    collapse 'can't check' into 'confirmed absent', the caller thinks
    tccutil succeeded when it actually silently no-op'd — which is the
    exact bug that kept surviving Skype grants alive.
    """
    import sqlite3
    if not db_path:
        return None  # no way to verify
    if not os.path.exists(db_path):
        return False  # the db itself is gone → the row is definitely absent
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=2)
        cur = conn.cursor()
        cur.execute(
            "SELECT 1 FROM access WHERE client = ? AND service = ? LIMIT 1",
            (client, service))
        found = cur.fetchone() is not None
        conn.close()
        return found
    except sqlite3.Error:
        return None  # SIP or other sqlite failure — caller must not assume


def _delete_tcc_grant(client, service, db_path, logger=None):
    """Remove a TCC grant.

    Attempt order:
      1. `tccutil reset <short_service> <client>` — Apple's supported CLI.
         **We post-verify** by re-querying the db: tccutil can return 0
         without actually removing a grant (system DB, client_type=path
         vs bundle mismatch). If the grant is still present after a
         claimed success, treat it as failure and fall through.
      2. Raw `sqlite3 DELETE` against db_path. This only works when the
         process has write access to the db (root + Full Disk Access for
         the system TCC.db, or the owning user for per-user DBs).

    `logger` (if provided) is called as `logger(category, text)` for each
    sub-step so the TUI can show a detailed trace in its debug log.

    Returns (success: bool, message: str). The message always contains the
    actual command attempted and the exact error surface, so the user has
    something concrete to act on when both paths fail.
    """
    import sqlite3
    def _log(cat, text):
        if logger is not None:
            try:
                logger(cat, text)
            except Exception:
                pass  # never let logging kill the operation

    _log("TCC", f"_delete_tcc_grant(client={client!r}, service={service!r}, "
                f"db={db_path!r})")
    # Emit SIP + euid state so the user can see the environment the
    # operation is about to run in.
    try:
        rc_sip, sip_out, _ = _run_cmd_short(["csrutil", "status"], timeout=2)
        sip_line = (sip_out.strip().splitlines() or [""])[0] if rc_sip == 0 else "unknown"
        _log("TCC", f"environment: euid={os.geteuid()} SUDO_USER="
                    f"{os.environ.get('SUDO_USER')!r} HOME="
                    f"{os.environ.get('HOME')!r} — {sip_line}")
    except Exception:
        pass
    if not client or not service:
        _log("FAIL", "missing required field")
        return False, "missing required field"

    tccutil_err = None
    tccutil_lied = False
    short_name = _TCC_SERVICE_SHORT_NAMES.get(service)
    _log("TCC", f"service maps to tccutil short name: {short_name!r}")
    if short_name and shutil.which("tccutil"):
        # We try two env contexts because tccutil picks the TCC.db it
        # targets based on HOME/USER:
        #   1. Current env — when run via `sudo procmon` with HOME
        #      preserved, this targets the user's per-user TCC.db.
        #   2. Root env — HOME=/var/root, no USER/LOGNAME. Forces tccutil
        #      to target the SYSTEM TCC.db at /Library/Application Support/
        #      com.apple.TCC/TCC.db, which is where most grants actually
        #      live. Without this second attempt, resetting a system-level
        #      Skype grant silently does nothing even though rc=0.
        attempts = [
            ("user env", None),
            ("root env", {
                **{k: v for k, v in os.environ.items()
                   if k not in ("HOME", "USER", "LOGNAME", "SUDO_USER",
                                "SUDO_UID", "SUDO_GID")},
                "HOME": "/var/root",
                "USER": "root",
                "LOGNAME": "root",
            }),
        ]
        attempt_errors = []
        could_not_verify = False
        for label, env in attempts:
            env_desc = "inherit" if env is None else f"HOME={env.get('HOME')!r}"
            _log("SUBPROC",
                 f"tccutil reset {short_name} {client} ({label}: {env_desc})")
            rc, out, err = _run_cmd_short(
                ["tccutil", "reset", short_name, client],
                timeout=5, env=env)
            _log("SUBPROC",
                 f"tccutil ({label}) returned rc={rc} "
                 f"stdout={out.strip()!r} stderr={err.strip()!r}")
            if rc == 0:
                exists = _tcc_grant_exists(client, service, db_path)
                _log("VERIFY",
                     f"_tcc_grant_exists({client}, {service}, {db_path}) "
                     f"= {exists}")
                if exists is False:
                    # Confirmed: the row is actually gone.
                    _log("OK", f"{label} verified removal")
                    return True, (f"tccutil reset {short_name} {client} "
                                   f"({label}, verified)")
                if exists is None:
                    # tccutil said OK but we can't check — don't trust it
                    # (SIP usually blocks reads without Full Disk Access).
                    could_not_verify = True
                    _log("TCC",
                         f"{label}: could not verify (db unreadable); "
                         f"continuing to next attempt")
                    attempt_errors.append(
                        f"{label}: rc=0 but db unreadable — can't verify")
                    continue
                # exists is True → tccutil lied
                _log("TCC", f"{label}: tccutil rc=0 but grant still present")
                attempt_errors.append(
                    f"{label}: rc=0 but grant still present")
                continue
            msg_frag = (err.strip() or out.strip() or f"rc={rc}")
            _log("TCC", f"{label}: tccutil failed: {msg_frag}")
            attempt_errors.append(f"{label}: {msg_frag}")
        tccutil_err = "; ".join(attempt_errors)
        tccutil_lied = any("still present" in e or "can't verify" in e
                           for e in attempt_errors)
        if could_not_verify:
            tccutil_err += (
                f" — Terminal likely needs Full Disk Access to read "
                f"{db_path or 'TCC.db'}")

    # Fallback: raw sqlite DELETE
    _log("TCC", f"falling back to sqlite DELETE against {db_path!r}")
    if not db_path:
        msg = "no TCC.db path provided"
        if tccutil_err:
            msg = f"tccutil failed: {tccutil_err} (and no db fallback path)"
        _log("FAIL", msg)
        return False, msg
    if not os.path.exists(db_path):
        msg = f"TCC.db not found at {db_path}"
        if tccutil_err:
            msg = f"tccutil failed: {tccutil_err}; {msg}"
        _log("FAIL", msg)
        return False, msg
    try:
        conn = sqlite3.connect(db_path, timeout=3)
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM access WHERE client = ? AND service = ?",
            (client, service),
        )
        deleted = cursor.rowcount
        conn.commit()
        conn.close()
        _log("SUBPROC", f"sqlite DELETE affected {deleted} row(s)")
    except sqlite3.OperationalError as e:
        _log("FAIL", f"sqlite.OperationalError: {e}")
        msg_low = str(e).lower()
        hint = ""
        if short_name:
            hint = (f" Try manually: sudo tccutil reset {short_name} {client}")
        if "readonly" in msg_low or "read-only" in msg_low:
            return False, (
                ("tccutil silently no-op'd; " if tccutil_lied else "")
                + "TCC.db is SIP-protected."
                + hint
                + " (or grant Full Disk Access to your terminal in"
                  " System Settings → Privacy & Security)")
        if "authorization" in msg_low or "unable to open" in msg_low:
            return False, f"cannot open {db_path}: {e}.{hint}"
        return False, f"sqlite error: {e}.{hint}"
    except sqlite3.Error as e:
        return False, f"sqlite error: {e}"
    if deleted == 0:
        if tccutil_err:
            return False, f"tccutil failed: {tccutil_err}; sqlite found no matching row"
        return False, "no matching row found (already removed?)"
    prefix = ("tccutil lied; " if tccutil_lied else "")
    return True, f"{prefix}deleted {deleted} row(s) from {db_path}"


def _remove_bundle(path):
    """Recursively remove a bundle directory (used for 3rd-party Input Methods).

    Requires write permission on the parent directory (root for /Library/
    paths, owning user for ~/Library/). Returns (success, message).
    """
    import shutil as _shutil
    if not path:
        return False, "path is not a directory"
    # Sanity guard first — refuse system paths even if they don't exist, so a
    # caller can't be tricked into trying to rm /System/* via path traversal.
    forbidden_prefixes = ("/System/", "/usr/", "/bin/", "/sbin/")
    for pfx in forbidden_prefixes:
        if path.startswith(pfx):
            return False, f"refusing to remove path under {pfx}"
    if not os.path.isdir(path):
        return False, "path is not a directory"
    try:
        _shutil.rmtree(path)
    except PermissionError as e:
        return False, f"permission denied: {e}"
    except OSError as e:
        return False, f"remove failed: {e}"
    return True, f"removed {path}"


# ── Security Tool Integrations ────────────────────────────────────────────

def _effective_home():
    """Return the invoking user's HOME, respecting sudo.

    When procmon is launched with `sudo procmon`, $HOME resolves to /var/root
    — so anything living in the real user's home (YARA rules at
    ~/.procmon.yar, Claude's auth at ~/.claude, npm global bin, etc.) is
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


def _build_user_tool_path():
    """Return an augmented PATH so user-installed CLIs (claude, codex, gemini,
    yara, etc.) remain reachable when procmon is started with sudo.

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
    rc, out, err = _run_cmd_short(
        ["codesign", "-dvvv", "-r-", "--entitlements", ":-", exe_path],
        timeout=10,
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


# ── VirusTotal reputation lookup ───────────────────────────────────────────

_VT_API_URL = "https://www.virustotal.com/api/v3/files/"


def _virustotal_lookup(sha256, api_key=None, timeout=10):
    """Look up a SHA-256 on VirusTotal v3. Returns dict or None on failure.

    Keys returned (when found): malicious, suspicious, undetected, harmless,
    reputation, first_seen, last_seen, known_names, popular_threat_name.
    """
    import json as _json
    import urllib.request
    import urllib.error
    if not sha256 or len(sha256) != 64:
        return None
    if api_key is None:
        api_key = os.environ.get("VT_API_KEY")
    if not api_key:
        return None
    req = urllib.request.Request(
        _VT_API_URL + sha256,
        headers={"x-apikey": api_key, "accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read()
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"found": False}
        return {"error": f"HTTP {e.code}"}
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        return {"error": str(e)[:120]}
    try:
        data = _json.loads(body.decode("utf-8", errors="replace"))
    except Exception:
        return {"error": "invalid json"}
    attrs = (data.get("data") or {}).get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    names = attrs.get("names") or []
    threat = (attrs.get("popular_threat_classification") or {}).get(
        "suggested_threat_label", "")
    return {
        "found": True,
        "malicious": int(stats.get("malicious", 0)),
        "suspicious": int(stats.get("suspicious", 0)),
        "undetected": int(stats.get("undetected", 0)),
        "harmless": int(stats.get("harmless", 0)),
        "reputation": int(attrs.get("reputation", 0)),
        "first_seen": attrs.get("first_submission_date"),
        "last_seen": attrs.get("last_analysis_date"),
        "known_names": names[:5],
        "popular_threat_name": threat,
    }


# ── YARA scanning ──────────────────────────────────────────────────────────

_DEFAULT_YARA_RULES_PATH = os.path.join(_EFFECTIVE_HOME, ".procmon.yar")


def _yara_scan_file(path, rules_path=None, timeout=15):
    """Scan a file on disk with `yara`. Returns list of matched rule names.

    Shells out to `yara` CLI (no Python dep required). Uses
    `~/.procmon.yar` as the default rule file; gracefully returns [] if
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
    core_path = os.path.join(core_dir, f"procmon.core.{pid}")
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
#: procmon runs as root, so leaving it visible collapses everything under a
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


# ── Host Security Audits (Network / DNS / Persistence) ─────────────────────
#
# Each audit returns a list of finding dicts:
#   {"severity": "CRITICAL"|"HIGH"|"MEDIUM"|"INFO"|"OK",
#    "message":  str,
#    "evidence": str,   # optional, multi-line context shown under the finding
#    "action":   None | {"type": <remediation>, ...}}
#
# Remediation action types understood by ProcMonUI._dispatch_audit_action:
#   enable_alf              — socketfilterfw --setglobalstate on
#   disable_remote_login    — systemsetup -setremotelogin off
#   disable_sharing_service — launchctl disable + tell sharingd
#   remove_profile          — profiles remove -identifier <id>
#   flush_dns               — dscacheutil -flushcache; killall -HUP mDNSResponder
#   restore_hosts           — quarantine /etc/hosts and restore a stock file
#   bootout_launchitem      — launchctl bootout <domain> <plist>
#   quarantine_plist        — mv a LaunchAgent/Daemon plist into ~/.procmon-quarantine
#   kill_process            — SIGTERM the owning PID (shared with keyscan)
#   delete_tcc              — (shared with keyscan)
#   remove_bundle           — (shared with keyscan)


_QUARANTINE_DIR = os.path.join(_EFFECTIVE_HOME, ".procmon-quarantine")


# ---- Sharing / firewall state --------------------------------------------

def _alf_state():
    """Query the Application Layer Firewall state.

    Returns a dict: {enabled, block_all, stealth, raw}. All booleans are
    False when the command fails or the output is unexpected.
    """
    info = {"enabled": False, "block_all": False, "stealth": False, "raw": ""}
    rc, out, _ = _run_cmd_short(
        ["/usr/libexec/ApplicationFirewall/socketfilterfw",
         "--getglobalstate"], timeout=5)
    if rc is None:
        # Try the PATH-resolved form in case the absolute one doesn't exist
        rc, out, _ = _run_cmd_short(
            ["socketfilterfw", "--getglobalstate"], timeout=5)
    info["raw"] = out or ""
    low = (out or "").lower()
    if "enabled" in low and "disabled" not in low:
        info["enabled"] = True
    # block all incoming
    rc2, out2, _ = _run_cmd_short(
        ["/usr/libexec/ApplicationFirewall/socketfilterfw",
         "--getblockall"], timeout=5)
    if out2 and "block all" in out2.lower() and "enabled" in out2.lower():
        info["block_all"] = True
    rc3, out3, _ = _run_cmd_short(
        ["/usr/libexec/ApplicationFirewall/socketfilterfw",
         "--getstealthmode"], timeout=5)
    if out3 and "enabled" in out3.lower() and "disabled" not in out3.lower():
        info["stealth"] = True
    return info


def _parse_lsof_listen(text):
    """Parse `lsof -iTCP -sTCP:LISTEN -nP` output.

    Returns a list of dicts: {pid, command, name, addr, port, family}.
    """
    results = []
    for raw in (text or "").splitlines():
        line = raw.rstrip()
        if not line or line.startswith("COMMAND"):
            continue
        fields = line.split()
        if len(fields) < 9:
            continue
        command = fields[0]
        try:
            pid = int(fields[1])
        except ValueError:
            continue
        # "TYPE" column gives family hint (IPv4/IPv6)
        family = fields[4] if len(fields) > 4 else ""
        name = fields[-2]
        # lsof NAME column looks like "*:22", "127.0.0.1:8080", "[::1]:631"
        addr = ""
        port = ""
        if ":" in name:
            idx = name.rfind(":")
            addr = name[:idx]
            port = name[idx + 1:].split(" ")[0]
        results.append({
            "command": command, "pid": pid, "family": family,
            "name": name, "addr": addr, "port": port,
        })
    return results


def _list_listening_sockets():
    """Enumerate all listening TCP sockets. Returns list of dicts."""
    rc, out, _ = _run_cmd_short(
        ["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"], timeout=10)
    if rc is None:
        return []
    return _parse_lsof_listen(out)


def _addr_is_public_bind(addr):
    """True if an lsof NAME address represents a public bind (0.0.0.0 or ::).

    lsof uses '*' for wildcard binds; IPv6 dual-stack shows '*' or '[::]'.
    Loopback addresses (127.*, ::1) are private.
    """
    if not addr:
        return False
    a = addr.strip()
    if a in ("*", "0.0.0.0", "[*]", "[::]", "::"):
        return True
    if a.startswith("[") and a.endswith("]"):
        a = a[1:-1]
    # Loopback
    if a.startswith("127.") or a == "::1":
        return False
    # Link-local or private is still worth flagging as non-loopback
    return True


def _parse_sharing_list(text):
    """Parse `sharing -l` output.

    `sharing -l` prints stanzas like:
        name:          Public
        path:          /Users/...
        shared over:   AFP, SMB
    Returns a list of {name, path, protocols} dicts.
    """
    entries = []
    current = {}
    for line in (text or "").splitlines():
        s = line.strip()
        if not s:
            if current:
                entries.append(current)
                current = {}
            continue
        if ":" in s:
            k, _, v = s.partition(":")
            k = k.strip().lower()
            v = v.strip()
            if k == "name":
                if current:
                    entries.append(current)
                current = {"name": v, "path": "", "protocols": []}
            elif k == "path":
                current["path"] = v
            elif k in ("shared over", "protocols"):
                current["protocols"] = [p.strip() for p in v.split(",") if p.strip()]
    if current:
        entries.append(current)
    return entries


def _sharing_services_state():
    """Collect per-service sharing state.

    Returns a dict:
      {remote_login, screen_sharing, remote_management, afp, smb,
       internet_sharing, content_caching, airdrop_discoverable,
       shares: [...]}
    All booleans; `shares` is a list from `sharing -l`.
    """
    state = {
        "remote_login": False,
        "screen_sharing": False,
        "remote_management": False,
        "afp": False,
        "smb": False,
        "internet_sharing": False,
        "content_caching": False,
        "airdrop_discoverable": False,
        "shares": [],
        "raw_remote_login": "",
    }
    # Remote Login (SSH)
    rc, out, _ = _run_cmd_short(
        ["systemsetup", "-getremotelogin"], timeout=5)
    state["raw_remote_login"] = out or ""
    if out and ": on" in out.lower():
        state["remote_login"] = True

    # Shared files/printers
    rc, out, _ = _run_cmd_short(["sharing", "-l"], timeout=5)
    if out:
        state["shares"] = _parse_sharing_list(out)
        proto_union = set()
        for s in state["shares"]:
            for p in s.get("protocols", []):
                proto_union.add(p.upper())
        state["afp"] = "AFP" in proto_union
        state["smb"] = "SMB" in proto_union

    # Screen Sharing + Remote Management via launchctl
    rc, out, _ = _run_cmd_short(
        ["launchctl", "list"], timeout=5)
    if out:
        if "com.apple.screensharing" in out:
            state["screen_sharing"] = True
        if "com.apple.RemoteDesktop.agent" in out:
            state["remote_management"] = True
        if "com.apple.InternetSharing" in out:
            state["internet_sharing"] = True
        if "com.apple.AssetCache" in out:
            state["content_caching"] = True

    # AirDrop discoverable mode
    rc, out, _ = _run_cmd_short(
        ["defaults", "read", "com.apple.sharingd", "DiscoverableMode"],
        timeout=5)
    if out and "Everyone" in out:
        state["airdrop_discoverable"] = True
    return state


def _pfctl_rules():
    """Return current pfctl rule text, or '' if not available / empty."""
    rc, out, _ = _run_cmd_short(["pfctl", "-sr"], timeout=5)
    if rc is None:
        return ""
    return out or ""


def _audit_network_exposure():
    """Network-layer exposure audit (finding #1).

    Covers: ALF + stealth + block-all, listening TCP sockets (0.0.0.0/::) bound
    by non-Apple processes, Sharing services (Remote Login, Screen Sharing,
    Remote Management, AFP/SMB, Internet Sharing, Content Caching, AirDrop
    discoverable), pfctl rule surface.
    """
    findings = []

    # ---- ALF ----
    alf = _alf_state()
    if not alf["enabled"]:
        findings.append({
            "severity": "HIGH",
            "message": ("Application Firewall is OFF — any listening service "
                        "is reachable from the network"),
            "evidence": alf["raw"].strip(),
            "action": {"type": "enable_alf"},
        })
    else:
        if not alf["stealth"]:
            findings.append({
                "severity": "MEDIUM",
                "message": ("Application Firewall is ON but stealth mode is OFF "
                            "(your Mac responds to port probes)"),
                "action": {"type": "enable_alf_stealth"},
            })
        if not alf["block_all"]:
            findings.append({
                "severity": "INFO",
                "message": ("Application Firewall is ON, block-all-incoming "
                            "is OFF (signed apps can still listen)"),
                "action": None,
            })

    # ---- Sharing services ----
    sh = _sharing_services_state()
    if sh["remote_login"]:
        findings.append({
            "severity": "HIGH",
            "message": "Remote Login (SSH) is enabled — inbound shell access allowed",
            "evidence": sh["raw_remote_login"].strip(),
            "action": {"type": "disable_remote_login"},
        })
    if sh["screen_sharing"]:
        findings.append({
            "severity": "HIGH",
            "message": "Screen Sharing (VNC) is enabled — inbound desktop control allowed",
            "action": {"type": "disable_sharing_service",
                       "service": "com.apple.screensharing"},
        })
    if sh["remote_management"]:
        findings.append({
            "severity": "HIGH",
            "message": "Apple Remote Desktop agent is running",
            "action": {"type": "disable_sharing_service",
                       "service": "com.apple.RemoteDesktop.agent"},
        })
    if sh["afp"]:
        findings.append({
            "severity": "MEDIUM",
            "message": "AFP file sharing is advertised (deprecated protocol)",
            "action": None,
        })
    if sh["smb"]:
        findings.append({
            "severity": "MEDIUM",
            "message": "SMB file sharing is advertised",
            "action": None,
        })
    if sh["internet_sharing"]:
        findings.append({
            "severity": "HIGH",
            "message": "Internet Sharing is enabled — this Mac is acting as a router",
            "action": None,
        })
    if sh["content_caching"]:
        findings.append({
            "severity": "INFO",
            "message": "Content Caching is enabled (Apple asset cache)",
            "action": None,
        })
    if sh["airdrop_discoverable"]:
        findings.append({
            "severity": "MEDIUM",
            "message": ("AirDrop is set to 'Everyone' — anyone nearby can "
                        "discover this Mac"),
            "action": None,
        })

    # ---- Listening sockets ----
    sockets = _list_listening_sockets()
    seen = set()
    public_listeners = 0
    for s in sockets:
        key = (s["pid"], s["addr"], s["port"])
        if key in seen:
            continue
        seen.add(key)
        if not _addr_is_public_bind(s["addr"]):
            continue
        pid = s["pid"]
        exe = _get_proc_path(pid) or ""
        cs = _codesign_structured(exe) if exe else {}
        apple = _is_apple_signed(exe, cs)
        team = cs.get("team_id", "") if cs else ""
        notarized = bool(cs.get("rc") == 0) if cs else False
        sig_label = "Apple" if apple else (
            f"Team {team}" if team else "unsigned/ad-hoc")
        public_listeners += 1
        if apple:
            sev = "INFO"
            msg_tail = "(Apple signed)"
        elif team and notarized:
            sev = "MEDIUM"
            msg_tail = f"(third-party, team={team})"
        else:
            sev = "HIGH"
            msg_tail = "(UNSIGNED or ad-hoc)"
        findings.append({
            "severity": sev,
            "message": (f"Port {s['port']} listening on {s['addr']} — "
                        f"{s['command']} (PID {pid}) {msg_tail}"),
            "evidence": f"exe: {exe or '(unknown)'}\nsignature: {sig_label}",
            "action": (None if apple
                       else {"type": "kill_process", "pid": pid, "exe": exe}),
        })

    if public_listeners == 0:
        findings.append({
            "severity": "OK",
            "message": "No processes are listening on a public network address",
            "action": None,
        })

    # ---- pfctl surface ----
    pf = _pfctl_rules()
    if pf:
        rule_count = sum(1 for line in pf.splitlines()
                         if line.strip() and not line.startswith("#")
                         and "scrub-anchor" not in line
                         and "nat-anchor" not in line
                         and "rdr-anchor" not in line
                         and "anchor " not in line)
        if rule_count:
            findings.append({
                "severity": "INFO",
                "message": (f"pfctl has {rule_count} active rule(s) — custom "
                            f"packet filter present"),
                "evidence": pf[:800],
                "action": None,
            })
    return findings


# ---- DNS / Proxy / MDM ----------------------------------------------------

def _parse_scutil_dns(text):
    """Parse `scutil --dns` output to a list of resolver stanzas.

    Returns a list of dicts: {resolver_id, search_domains, nameservers,
    domain, flags}. Nameserver entries are "nameserver[0] : 1.1.1.1".
    """
    resolvers = []
    current = None
    for raw in (text or "").splitlines():
        line = raw.rstrip()
        if line.startswith("resolver #"):
            if current:
                resolvers.append(current)
            try:
                rid = int(line.split("#", 1)[1].strip())
            except ValueError:
                rid = -1
            current = {"resolver_id": rid, "nameservers": [],
                       "search": [], "domain": "", "flags": ""}
            continue
        if current is None:
            continue
        s = line.strip()
        if s.startswith("nameserver["):
            if ":" in s:
                ns = s.split(":", 1)[1].strip()
                current["nameservers"].append(ns)
        elif s.startswith("search domain["):
            if ":" in s:
                current["search"].append(s.split(":", 1)[1].strip())
        elif s.startswith("domain "):
            if ":" in s:
                current["domain"] = s.split(":", 1)[1].strip()
        elif s.startswith("flags "):
            if ":" in s:
                current["flags"] = s.split(":", 1)[1].strip()
    if current:
        resolvers.append(current)
    return resolvers


def _parse_scutil_proxy(text):
    """Parse `scutil --proxy` output (plist-ish dict).

    Returns a dict with relevant keys: HTTPEnable (bool), HTTPProxy, HTTPPort,
    HTTPSEnable, HTTPSProxy, HTTPSPort, SOCKSEnable, SOCKSProxy, SOCKSPort,
    ProxyAutoConfigEnable, ProxyAutoConfigURLString. Missing keys are empty.
    """
    info = {}
    for raw in (text or "").splitlines():
        line = raw.strip()
        # lines look like "  HTTPEnable : 1" or "  HTTPProxy : 10.0.0.1"
        if " : " in line:
            k, _, v = line.partition(" : ")
            info[k.strip()] = v.strip()
    return info


def _read_hosts_file(path="/etc/hosts"):
    """Return `(extra_entries, raw_bytes)` from /etc/hosts.

    `extra_entries` is a list of {ip, host} for non-default host definitions.
    Default lines (127.0.0.1 localhost / ::1 localhost / 255.255.255.255 ...)
    are filtered out. Missing file → ([], b"").
    """
    extras = []
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except (FileNotFoundError, PermissionError, OSError):
        return [], b""
    text = raw.decode("utf-8", errors="replace")
    default_hosts = {
        "localhost", "broadcasthost", "ip6-localhost", "ip6-loopback",
        "ip6-allnodes", "ip6-allrouters", "ip6-localnet", "ip6-mcastprefix",
    }
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        parts = s.split()
        if len(parts) < 2:
            continue
        ip = parts[0]
        for h in parts[1:]:
            if h.startswith("#"):
                break
            if h.lower() in default_hosts:
                continue
            extras.append({"ip": ip, "host": h})
    return extras, raw


def _list_resolver_dir(path="/etc/resolver"):
    """List /etc/resolver/* configs. Returns list of (name, body_text)."""
    results = []
    try:
        names = sorted(os.listdir(path))
    except (FileNotFoundError, NotADirectoryError, PermissionError):
        return []
    for name in names:
        if name.startswith("."):
            continue
        full = os.path.join(path, name)
        try:
            with open(full) as f:
                results.append((name, f.read()))
        except (PermissionError, OSError):
            continue
    return results


def _list_config_profiles():
    """Return a list of installed configuration-profile entries.

    Tries `profiles show -type configuration -output stdout-xml` first so
    the payload types are machine-parseable; falls back to plain text
    `profiles list` when XML isn't available (older macOS / non-root).
    Each entry: {identifier, display_name, payload_types, raw_block}.
    """
    entries = []
    rc, out, err = _run_cmd_short(
        ["profiles", "show", "-type", "configuration"], timeout=10)
    if rc is None:
        return []
    # Text-mode output. Stanzas look like:
    #   _computerlevel[1] attribute: profileIdentifier: com.example.cfg
    #   _computerlevel[1] attribute: profileDisplayName: Example
    #   _computerlevel[1] attribute: ProfileItems:
    #     _computerlevel[1] PayloadType = "com.apple.dnsSettings.managed"
    current = {"identifier": "", "display_name": "",
               "payload_types": [], "raw_block": []}

    def _flush():
        if current["identifier"] or current["display_name"]:
            entries.append({
                "identifier": current["identifier"],
                "display_name": current["display_name"],
                "payload_types": list(current["payload_types"]),
                "raw_block": "\n".join(current["raw_block"]),
            })

    prev_key = ""
    for line in (out or "").splitlines():
        s = line.strip()
        # Each profile stanza starts with "_computerlevel[N]" or "_userlevel[N]"
        if "attribute: profileIdentifier:" in s:
            _flush()
            current = {"identifier": s.split(":")[-1].strip(),
                       "display_name": "", "payload_types": [],
                       "raw_block": [s]}
            prev_key = "id"
            continue
        current["raw_block"].append(line)
        if "attribute: profileDisplayName:" in s:
            current["display_name"] = s.split(":")[-1].strip()
        elif "PayloadType" in s and "=" in s:
            val = s.split("=", 1)[1].strip().strip('"; ')
            if val:
                current["payload_types"].append(val)
    _flush()
    return entries


def _list_custom_root_cas():
    """Enumerate admin-added root CAs via `security find-certificate`.

    Returns a list of subject-CN strings for certs in the admin / System
    keychain that aren't part of Apple's trusted roots. Best-effort — on
    failure returns []. The key signal: a CA that isn't in System Roots is
    an MITM candidate.
    """
    rc, out, _ = _run_cmd_short(
        ["security", "find-certificate", "-a", "-c", "",
         "/Library/Keychains/System.keychain"], timeout=10)
    if rc is None or not out:
        return []
    cns = []
    for line in out.splitlines():
        s = line.strip()
        if s.startswith('"labl"<blob>='):
            val = s.split("=", 1)[1].strip().strip('"')
            if val and val not in cns:
                cns.append(val)
    return cns


# Payload types that indicate a profile can redirect traffic or inject trust.
_MDM_REDIRECTING_PAYLOADS = {
    "com.apple.dnsSettings.managed":
        "forces a DNS resolver on this Mac",
    "com.apple.webcontent-filter":
        "filters every TCP/HTTP(S) request",
    "com.apple.vpn.managed":
        "forces all traffic through a VPN",
    "com.apple.vpn.managed.applayer":
        "forces per-app traffic through a VPN",
    "com.apple.security.root":
        "installs an additional trusted root CA",
    "com.apple.security.pkcs1":
        "installs a managed certificate",
    "com.apple.proxy.http.global":
        "forces a global HTTP proxy",
}


def _audit_dns_proxy_mdm():
    """DNS / proxy / MDM traffic-redirection audit (finding #2)."""
    findings = []

    # ---- scutil --dns ----
    rc, dns_text, _ = _run_cmd_short(["scutil", "--dns"], timeout=5)
    resolvers = _parse_scutil_dns(dns_text or "")
    # Non-default nameservers are those not in the well-known defaults/ISP ranges.
    # We surface any configured nameserver so the user can tell.
    nameservers_seen = set()
    for r in resolvers:
        for ns in r.get("nameservers", []):
            nameservers_seen.add(ns)
    # Apple / well-known DNS; not a hard trust list but reduces noise.
    apple_or_known = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
                       "9.9.9.9", "149.112.112.112"}
    third_party_dns = [ns for ns in nameservers_seen
                       if ns in apple_or_known]
    unknown_dns = [ns for ns in nameservers_seen
                   if ns not in apple_or_known
                   and not ns.startswith("fe80::")
                   and not ns.startswith("192.168.")
                   and not ns.startswith("10.")
                   and not ns.startswith("172.")
                   and ns not in ("127.0.0.1", "::1")]
    if third_party_dns:
        findings.append({
            "severity": "MEDIUM",
            "message": ("Third-party DNS in use: "
                        + ", ".join(sorted(third_party_dns))),
            "action": {"type": "flush_dns"},
        })
    if unknown_dns:
        findings.append({
            "severity": "HIGH",
            "message": ("Non-default, non-RFC1918 DNS servers configured: "
                        + ", ".join(sorted(unknown_dns))),
            "evidence": ("Every DNS query may be observed or manipulated by "
                         "this resolver. Verify it's trusted."),
            "action": {"type": "flush_dns"},
        })

    # ---- scutil --proxy ----
    rc, proxy_text, _ = _run_cmd_short(["scutil", "--proxy"], timeout=5)
    proxies = _parse_scutil_proxy(proxy_text or "")

    def _on(k):
        v = proxies.get(k, "0")
        return v.strip() == "1"

    if _on("HTTPEnable"):
        findings.append({
            "severity": "CRITICAL",
            "message": (f"HTTP proxy set: {proxies.get('HTTPProxy', '?')}:"
                        f"{proxies.get('HTTPPort', '?')} — all plain HTTP "
                        f"traffic is routed through it"),
            "action": None,
        })
    if _on("HTTPSEnable"):
        findings.append({
            "severity": "CRITICAL",
            "message": (f"HTTPS proxy set: {proxies.get('HTTPSProxy', '?')}:"
                        f"{proxies.get('HTTPSPort', '?')} — every TLS "
                        f"connection goes through a middlebox"),
            "action": None,
        })
    if _on("SOCKSEnable"):
        findings.append({
            "severity": "CRITICAL",
            "message": (f"SOCKS proxy set: {proxies.get('SOCKSProxy', '?')}:"
                        f"{proxies.get('SOCKSPort', '?')}"),
            "action": None,
        })
    if _on("ProxyAutoConfigEnable"):
        findings.append({
            "severity": "HIGH",
            "message": (f"PAC proxy configuration in use: "
                        f"{proxies.get('ProxyAutoConfigURLString', '?')}"),
            "evidence": ("A Proxy Auto-Config URL decides per-host proxy "
                         "routing — verify the URL is trusted."),
            "action": None,
        })

    # ---- /etc/hosts ----
    extras, _ = _read_hosts_file()
    if extras:
        summary = ", ".join(f"{e['ip']} {e['host']}" for e in extras[:5])
        if len(extras) > 5:
            summary += f", +{len(extras) - 5} more"
        # Heuristic: any redirection of apple/icloud/microsoft/google domains
        # is very likely a blocklist or credential-theft redirect.
        hot_domains = [
            e for e in extras
            if any(tld in e["host"].lower() for tld in
                   ("apple.com", "icloud.com", "microsoft.com", "google.com",
                    "github.com", "cloudflare.com"))
        ]
        if hot_domains:
            findings.append({
                "severity": "CRITICAL",
                "message": ("/etc/hosts redirects sensitive domains: "
                            + ", ".join(f"{e['ip']} {e['host']}"
                                        for e in hot_domains[:5])),
                "evidence": "Remove the entries or restore a stock /etc/hosts.",
                "action": {"type": "restore_hosts"},
            })
        else:
            findings.append({
                "severity": "MEDIUM",
                "message": (f"/etc/hosts has {len(extras)} extra entr"
                            f"{'y' if len(extras) == 1 else 'ies'}: "
                            f"{summary}"),
                "action": None,
            })

    # ---- /etc/resolver/ (per-domain DNS overrides) ----
    resolver_overrides = _list_resolver_dir()
    for name, body in resolver_overrides:
        findings.append({
            "severity": "MEDIUM",
            "message": (f"/etc/resolver/{name} overrides DNS for this domain"),
            "evidence": body.strip()[:400],
            "action": None,
        })

    # ---- Configuration profiles ----
    profiles = _list_config_profiles()
    seen_profile_ids = set()
    for prof in profiles:
        pid_ = prof["identifier"]
        if pid_ in seen_profile_ids:
            continue
        seen_profile_ids.add(pid_)
        red_payloads = [p for p in prof["payload_types"]
                        if p in _MDM_REDIRECTING_PAYLOADS]
        if red_payloads:
            desc = "; ".join(_MDM_REDIRECTING_PAYLOADS[p] for p in red_payloads)
            findings.append({
                "severity": "CRITICAL",
                "message": (f"Config profile '{prof['display_name'] or pid_}' "
                            f"{desc}"),
                "evidence": (f"identifier: {pid_}\npayloads: "
                             + ", ".join(red_payloads)),
                "action": {"type": "remove_profile", "identifier": pid_},
            })
        else:
            findings.append({
                "severity": "INFO",
                "message": (f"Config profile installed: "
                            f"{prof['display_name'] or pid_}"),
                "evidence": f"identifier: {pid_}",
                "action": {"type": "remove_profile", "identifier": pid_},
            })
    if not profiles:
        findings.append({
            "severity": "OK",
            "message": "No configuration profiles installed",
            "action": None,
        })

    # ---- MDM enrollment ----
    rc, out, _ = _run_cmd_short(
        ["profiles", "status", "-type", "enrollment"], timeout=5)
    if out and "MDM enrollment: Yes" in out:
        findings.append({
            "severity": "INFO",
            "message": "Device is MDM-enrolled",
            "evidence": out.strip(),
            "action": None,
        })

    if not findings:
        findings.append({
            "severity": "OK",
            "message": "No DNS / proxy / MDM redirection detected",
            "action": None,
        })
    return findings


# ---- Persistence ----------------------------------------------------------

_LAUNCH_ROOTS = [
    "/Library/LaunchAgents",
    "/Library/LaunchDaemons",
    "/System/Library/LaunchAgents",
    "/System/Library/LaunchDaemons",
    os.path.join(_EFFECTIVE_HOME, "Library/LaunchAgents"),
]


def _parse_plist_file(path):
    """Return a dict parsed from a plist at `path`.

    Tries `plutil -convert xml1 -o - <path>` first (handles binary plists),
    then Python's plistlib. Returns {} on any failure.
    """
    import plistlib
    # plutil first — it handles binary plists that plistlib can't on older Pythons
    rc, out, _ = _run_cmd_short(
        ["plutil", "-convert", "xml1", "-o", "-", path], timeout=5)
    if rc == 0 and out:
        try:
            return plistlib.loads(out.encode("utf-8"))
        except (ValueError, TypeError, plistlib.InvalidFileException):
            pass
    # Fallback — plistlib handles XML plists natively
    try:
        with open(path, "rb") as f:
            return plistlib.load(f)
    except (FileNotFoundError, PermissionError, OSError,
            ValueError, plistlib.InvalidFileException):
        return {}


def _extract_launch_program(plist):
    """Return the resolved executable path from a launchd plist dict.

    Looks at `Program` first, then the first element of `ProgramArguments`.
    Returns '' when neither yields something.
    """
    if not plist:
        return ""
    prog = plist.get("Program")
    if isinstance(prog, str) and prog:
        return prog
    args = plist.get("ProgramArguments")
    if isinstance(args, list) and args and isinstance(args[0], str):
        return args[0]
    return ""


def _enumerate_launch_items():
    """Walk every launch-agent / launch-daemon directory.

    Returns a list of dicts:
      {path, label, program, domain, system_signed}
    """
    results = []
    for root in _LAUNCH_ROOTS:
        if not os.path.isdir(root):
            continue
        try:
            entries = sorted(os.listdir(root))
        except (PermissionError, OSError):
            continue
        is_system = root.startswith("/System/")
        # Map root → launchd domain string
        if root.startswith("/System/Library/LaunchDaemons") \
                or root.startswith("/Library/LaunchDaemons"):
            domain = "system"
        elif root.startswith("/System/Library/LaunchAgents") \
                or root.startswith("/Library/LaunchAgents"):
            domain = "gui"
        else:
            domain = "user"
        for name in entries:
            if not name.endswith(".plist"):
                continue
            path = os.path.join(root, name)
            try:
                plist = _parse_plist_file(path)
            except Exception:
                plist = {}
            results.append({
                "path": path,
                "label": plist.get("Label", "") or name[:-6],
                "program": _extract_launch_program(plist),
                "domain": domain,
                "system_signed": is_system,
                "run_at_load": bool(plist.get("RunAtLoad", False)),
                "keep_alive": bool(plist.get("KeepAlive", False)),
            })
    return results


def _list_privileged_helpers():
    """Enumerate /Library/PrivilegedHelperTools/* binaries."""
    root = "/Library/PrivilegedHelperTools"
    if not os.path.isdir(root):
        return []
    results = []
    try:
        names = sorted(os.listdir(root))
    except (PermissionError, OSError):
        return []
    for name in names:
        if name.startswith("."):
            continue
        results.append(os.path.join(root, name))
    return results


def _user_crontabs():
    """Return a list of (user, crontab_body) for users with a crontab.

    Reads /var/at/tabs/* directly rather than shelling out to `crontab -l -u`
    for every user, which is both faster and less error-prone under sudo.
    """
    results = []
    cron_dir = "/var/at/tabs"
    if os.path.isdir(cron_dir):
        try:
            for name in sorted(os.listdir(cron_dir)):
                full = os.path.join(cron_dir, name)
                try:
                    with open(full) as f:
                        body = f.read()
                except (PermissionError, OSError):
                    continue
                if body.strip():
                    results.append((name, body))
        except (PermissionError, OSError):
            pass
    return results


def _sfltool_dumpbtm():
    """Snapshot `sfltool dumpbtm` output. Best-effort (empty on failure).

    Ventura+ stores login items / background-task-manager entries here.
    """
    rc, out, _ = _run_cmd_short(["sfltool", "dumpbtm"], timeout=15)
    if rc is None:
        return ""
    return out or ""


def _parse_btm_items(text):
    """Very loose parse of `sfltool dumpbtm`.

    The format is informal — we look for 'UUID:' stanzas and extract the
    'URL:' and 'Developer Name:' under each.
    """
    items = []
    current = None
    for raw in (text or "").splitlines():
        line = raw.rstrip()
        if "UUID:" in line and current is not None:
            items.append(current)
            current = None
        s = line.strip()
        if s.startswith("UUID:"):
            current = {"uuid": s.split(":", 1)[1].strip(),
                       "url": "", "dev_name": "", "team": "",
                       "bundle_id": "", "disposition": ""}
        elif current is not None:
            if s.startswith("URL:"):
                current["url"] = s.split(":", 1)[1].strip()
            elif s.startswith("Developer Name:"):
                current["dev_name"] = s.split(":", 1)[1].strip()
            elif s.startswith("Developer Team:") or s.startswith("Team ID:"):
                current["team"] = s.split(":", 1)[1].strip()
            elif s.startswith("Bundle identifier:"):
                current["bundle_id"] = s.split(":", 1)[1].strip()
            elif s.startswith("Disposition:"):
                current["disposition"] = s.split(":", 1)[1].strip()
    if current:
        items.append(current)
    return items


def _audit_persistence():
    """Comprehensive persistence audit (finding #4)."""
    findings = []

    # ---- LaunchAgents / LaunchDaemons ----
    items = _enumerate_launch_items()
    unsigned_items = 0
    for it in items:
        prog = it["program"]
        path = it["path"]
        label = it["label"]
        domain = it["domain"]
        system_signed = it["system_signed"]
        if not prog:
            # Some items are meant to run an Apple helper via reverse-DNS label
            # Label→binary mapping. Skip when there's nothing to check.
            continue
        if system_signed:
            # /System/Library entries are SSV-sealed; skip for noise reduction
            continue
        cs = _codesign_structured(prog) if prog.startswith("/") else {}
        apple = _is_apple_signed(prog, cs)
        team = cs.get("team_id", "") if cs else ""
        sig_ok = bool(cs) and cs.get("rc") == 0
        missing = prog.startswith("/") and not os.path.exists(prog)
        if missing:
            sev = "CRITICAL"
            msg_tail = "(program path MISSING)"
        elif apple or sig_ok and team:
            sev = "INFO"
            msg_tail = f"(team={team or 'Apple'})"
        else:
            sev = "HIGH"
            msg_tail = "(UNSIGNED or ad-hoc)"
            unsigned_items += 1
        evidence_parts = [
            f"plist: {path}",
            f"label: {label}",
            f"program: {prog}",
            f"domain: {domain}",
        ]
        if cs:
            evidence_parts.append(f"authority: {', '.join(cs.get('authority', []))}")
        findings.append({
            "severity": sev,
            "message": (f"Launch item: {label} → {prog} "
                        f"{msg_tail}"),
            "evidence": "\n".join(evidence_parts),
            "action": (None if apple
                       else {"type": "bootout_launchitem",
                             "plist_path": path,
                             "label": label,
                             "domain": domain}),
        })

    # ---- PrivilegedHelperTools ----
    for helper in _list_privileged_helpers():
        cs = _codesign_structured(helper) if os.path.exists(helper) else {}
        apple = _is_apple_signed(helper, cs)
        sig_ok = bool(cs) and cs.get("rc") == 0
        team = cs.get("team_id", "") if cs else ""
        if apple:
            sev = "INFO"
            tail = "(Apple)"
        elif sig_ok and team:
            sev = "MEDIUM"
            tail = f"(team={team})"
        else:
            sev = "HIGH"
            tail = "(UNSIGNED)"
        findings.append({
            "severity": sev,
            "message": f"PrivilegedHelperTool: {helper} {tail}",
            "action": None,
        })

    # ---- Crontabs ----
    for user, body in _user_crontabs():
        findings.append({
            "severity": "MEDIUM",
            "message": f"Crontab installed for user '{user}'",
            "evidence": body.strip()[:500],
            "action": None,
        })

    # ---- Background Task Manager / login items (Ventura+) ----
    btm = _parse_btm_items(_sfltool_dumpbtm())
    for item in btm:
        # Only flag entries that are disabled/awaiting-approval or unknown team
        dev = item.get("dev_name") or item.get("team") or "(unknown)"
        if item.get("url"):
            findings.append({
                "severity": "INFO",
                "message": (f"BTM login item: {item.get('bundle_id') or item.get('url')} "
                            f"by {dev}"),
                "evidence": ("\n".join(
                    f"{k}: {v}" for k, v in item.items() if v))[:400],
                "action": None,
            })

    # ---- LoginHook / LogoutHook (legacy com.apple.loginwindow) ----
    rc, out, _ = _run_cmd_short(
        ["defaults", "read", "com.apple.loginwindow"], timeout=5)
    if out and ("LoginHook" in out or "LogoutHook" in out):
        findings.append({
            "severity": "HIGH",
            "message": "Legacy LoginHook / LogoutHook configured",
            "evidence": out.strip()[:800],
            "action": None,
        })

    if not findings:
        findings.append({
            "severity": "OK",
            "message": "No unsigned or suspicious persistence items found",
            "action": None,
        })
    elif unsigned_items == 0 and not any(
            f["severity"] in ("CRITICAL", "HIGH") for f in findings):
        findings.insert(0, {
            "severity": "OK",
            "message": f"Enumerated {len(items)} launch items — no HIGH/CRITICAL signals",
            "action": None,
        })
    return findings


# ── Batch A: System hardening / Kernel+boot / OS patch posture ──────────

def _read_plist_defaults(domain):
    """Read a defaults domain as a dict via `defaults export <domain> -`.

    Works around `defaults read` variants by exporting to plist then
    parsing with plistlib. Returns {} on failure.
    """
    import plistlib
    rc, out, _ = _run_cmd_short(
        ["defaults", "export", domain, "-"], timeout=5)
    if rc != 0 or not out:
        return {}
    try:
        return plistlib.loads(out.encode("utf-8"))
    except (ValueError, TypeError, plistlib.InvalidFileException):
        return {}


def _audit_system_hardening():
    """Host trust-chain posture (finding #3).

    SIP, SSV, Gatekeeper, FileVault, Secure Boot, Secure Token, MDM
    enrollment, Lockdown Mode, XProtect/MRT versions.
    """
    findings = []

    # SIP
    rc, out, _ = _run_cmd_short(["csrutil", "status"], timeout=5)
    if out:
        if "enabled" in out.lower() and "disabled" not in out.lower():
            findings.append({"severity": "OK",
                             "message": "System Integrity Protection: enabled",
                             "action": None})
        else:
            findings.append({"severity": "CRITICAL",
                             "message": "System Integrity Protection: DISABLED",
                             "evidence": out.strip(),
                             "action": None})

    # SSV (Sealed System Volume)
    rc, out, _ = _run_cmd_short(
        ["csrutil", "authenticated-root", "status"], timeout=5)
    if out:
        if "enabled" in out.lower() and "disabled" not in out.lower():
            findings.append({"severity": "OK",
                             "message": "Authenticated Root (SSV): enabled",
                             "action": None})
        else:
            findings.append({"severity": "CRITICAL",
                             "message": "Authenticated Root (SSV): DISABLED",
                             "evidence": out.strip(),
                             "action": None})

    # Gatekeeper
    rc, out, _ = _run_cmd_short(["spctl", "--status"], timeout=5)
    if out:
        if "assessments enabled" in out.lower():
            findings.append({"severity": "OK",
                             "message": "Gatekeeper: enabled",
                             "action": None})
        else:
            findings.append({"severity": "HIGH",
                             "message": "Gatekeeper: disabled",
                             "evidence": out.strip(),
                             "action": {"type": "enable_gatekeeper"}})

    # FileVault
    rc, out, _ = _run_cmd_short(["fdesetup", "status"], timeout=5)
    if out:
        if "On" in out and "FileVault is On" in out:
            findings.append({"severity": "OK",
                             "message": "FileVault: on",
                             "action": None})
        else:
            findings.append({"severity": "HIGH",
                             "message": "FileVault: OFF (disk is not encrypted at rest)",
                             "evidence": out.strip(),
                             "action": None})

    # Secure Boot (Apple Silicon)
    rc, out, err = _run_cmd_short(["bputil", "-d"], timeout=10)
    combined = (out or "") + (err or "")
    if combined:
        if "Full Security" in combined:
            findings.append({"severity": "OK",
                             "message": "Secure Boot: Full Security",
                             "action": None})
        elif "Reduced Security" in combined:
            findings.append({"severity": "MEDIUM",
                             "message": "Secure Boot: Reduced Security",
                             "evidence": combined.strip()[:600],
                             "action": None})
        elif "Permissive" in combined or "Permissive Security" in combined:
            findings.append({"severity": "CRITICAL",
                             "message": "Secure Boot: Permissive (unsigned kexts allowed)",
                             "evidence": combined.strip()[:600],
                             "action": None})

    # MDM enrollment
    rc, out, _ = _run_cmd_short(
        ["profiles", "status", "-type", "enrollment"], timeout=5)
    if out and "Enrolled via DEP" in out:
        findings.append({"severity": "INFO",
                         "message": "Mac is DEP-enrolled (managed by org)",
                         "evidence": out.strip(),
                         "action": None})
    elif out and "MDM enrollment: Yes" in out:
        findings.append({"severity": "INFO",
                         "message": "Mac is MDM-enrolled",
                         "evidence": out.strip(),
                         "action": None})

    # Lockdown Mode
    lm = _read_plist_defaults("com.apple.security.LockdownMode")
    if lm.get("LockdownModeEnabled"):
        findings.append({"severity": "INFO",
                         "message": "Lockdown Mode is ENABLED",
                         "action": None})

    # XProtect / MRT data versions
    xp_plist = ("/Library/Apple/System/Library/CoreServices/XProtect.bundle/"
                "Contents/Info.plist")
    if os.path.exists(xp_plist):
        data = _parse_plist_file(xp_plist)
        version = data.get("CFBundleShortVersionString", "") or data.get(
            "Version", "")
        if version:
            findings.append({"severity": "INFO",
                             "message": f"XProtect data version: {version}",
                             "action": None})

    # Secure Token for current user
    rc, out, err = _run_cmd_short(
        ["sysadminctl", "-secureTokenStatus",
         os.environ.get("SUDO_USER") or os.environ.get("USER", "")],
        timeout=5)
    combined = (out or "") + (err or "")
    if "ENABLED" in combined.upper():
        findings.append({"severity": "OK",
                         "message": "Secure Token: ENABLED for current user",
                         "action": None})

    if not findings:
        findings.append({"severity": "INFO",
                         "message": "System hardening data unavailable",
                         "action": None})
    return findings


def _audit_kernel_boot():
    """Kernel / boot integrity (finding #11).

    kexts (Apple vs third-party), system extensions, SSV snapshots,
    nvram boot-args, eficheck where available.
    """
    findings = []

    # Loaded kexts. kmutil line shape:
    #   <idx> <refs> 0 0 0 com.vendor.bundle.id (version) <UUID> <deps>
    # Bundle id is the token immediately followed by "(<version>)".
    import re as _re_kmutil
    _bundle_re = _re_kmutil.compile(r"([A-Za-z0-9_.\-]+)\s+\([^)]+\)")
    rc, out, _ = _run_cmd_short(
        ["kmutil", "showloaded", "--list-only"], timeout=15)
    if rc == 0 and out:
        third_party = []
        for line in out.splitlines():
            m = _bundle_re.search(line)
            if not m:
                continue
            bundle = m.group(1)
            if (not bundle.startswith("com.apple.")
                    and not bundle.startswith("com.apple")):
                third_party.append(bundle)
        # De-dup while preserving first-seen order
        seen = set()
        unique = []
        for b in third_party:
            if b not in seen:
                unique.append(b)
                seen.add(b)
        third_party = unique
        if third_party:
            findings.append({
                "severity": "HIGH",
                "message": (f"{len(third_party)} third-party kext(s) loaded"),
                "evidence": "\n".join(third_party[:10]),
                "action": None,
            })
        else:
            findings.append({"severity": "OK",
                             "message": "No third-party kexts loaded",
                             "action": None})

    # System extensions
    sysexts = _list_system_extensions()
    waiting = [s for s in sysexts if "waiting" in (s.get("state") or "").lower()]
    if waiting:
        findings.append({
            "severity": "HIGH",
            "message": (f"{len(waiting)} system extension(s) pending "
                        f"activation"),
            "evidence": "\n".join(
                f"{s['team_id']}: {s['bundle_id']}" for s in waiting[:10]),
            "action": None,
        })
    third_party_ext = [s for s in sysexts
                       if s.get("team_id") and s["team_id"] != "Apple Inc."]
    if third_party_ext:
        findings.append({
            "severity": "INFO",
            "message": f"{len(third_party_ext)} third-party system extension(s)",
            "evidence": "\n".join(
                f"{s['team_id']}: {s['bundle_id']} [{s.get('state', '')}]"
                for s in third_party_ext[:15]),
            "action": None,
        })

    # /Library/Extensions (auxiliary kext store)
    for ext_root in ("/Library/Extensions",
                     "/Library/Apple/System/Library/Extensions"):
        if not os.path.isdir(ext_root):
            continue
        try:
            kexts = [n for n in os.listdir(ext_root) if n.endswith(".kext")]
        except (PermissionError, OSError):
            continue
        non_apple = []
        for k in kexts:
            path = os.path.join(ext_root, k)
            cs = _codesign_structured(path)
            if not _is_apple_signed(path, cs):
                non_apple.append(path)
        if non_apple:
            findings.append({
                "severity": "HIGH",
                "message": (f"{len(non_apple)} non-Apple kext(s) in "
                            f"{ext_root}"),
                "evidence": "\n".join(non_apple[:10]),
                "action": None,
            })

    # nvram boot-args
    rc, out, _ = _run_cmd_short(["nvram", "boot-args"], timeout=5)
    if rc == 0 and out and out.strip():
        if "boot-args" in out:
            val = out.split("\t", 1)[-1].strip()
            if val and val != "boot-args":
                findings.append({
                    "severity": "HIGH" if "no_compat_check" in val
                                          or "amfi_get_out_of_my_way" in val
                                          or "-v" in val.split()
                                          else "MEDIUM",
                    "message": f"nvram boot-args set: {val[:200]}",
                    "evidence": "Custom boot arguments can disable kernel "
                                "protections.",
                    "action": None,
                })

    # APFS snapshots of /
    rc, out, _ = _run_cmd_short(
        ["diskutil", "apfs", "listSnapshots", "/"], timeout=10)
    if rc == 0 and out:
        count = sum(1 for line in out.splitlines()
                    if "XID:" in line or "Snapshot UUID" in line)
        if count:
            findings.append({
                "severity": "INFO",
                "message": f"{count} APFS snapshot(s) on the System Volume",
                "action": None,
            })

    # eficheck (pre-T2 Intel Macs only)
    rc, out, _ = _run_cmd_short(
        ["/usr/libexec/firmwarecheckers/eficheck/eficheck",
         "--integrity-check"], timeout=30)
    if rc == 0 and out:
        if "No changes detected" in out:
            findings.append({"severity": "OK",
                             "message": "EFI integrity: clean",
                             "action": None})
        else:
            findings.append({
                "severity": "HIGH",
                "message": "EFI integrity check reported changes",
                "evidence": out.strip()[:600],
                "action": None,
            })

    if not findings:
        findings.append({"severity": "OK",
                         "message": "No kernel/boot anomalies detected",
                         "action": None})
    return findings


# Apple macOS supported branches (rough, updated alongside procmon releases).
# Used as a best-effort patch-posture check.
_MACOS_SUPPORTED = {
    26: "Tahoe",
    15: "Sequoia",
    14: "Sonoma",
    13: "Ventura",
    12: "Monterey",
}


def _audit_patch_posture():
    """OS patch posture (finding #15)."""
    findings = []

    rc, prod, _ = _run_cmd_short(["sw_vers", "-productVersion"], timeout=5)
    rc, build, _ = _run_cmd_short(["sw_vers", "-buildVersion"], timeout=5)
    prod = (prod or "").strip()
    build = (build or "").strip()
    if not prod:
        return [{"severity": "INFO",
                 "message": "sw_vers unavailable",
                 "action": None}]

    try:
        major = int(prod.split(".", 1)[0])
    except ValueError:
        major = 0
    branch = _MACOS_SUPPORTED.get(major, "unknown")
    findings.append({
        "severity": "INFO",
        "message": f"macOS {prod} ({build}) — {branch}",
        "action": None,
    })
    if major and major not in _MACOS_SUPPORTED:
        findings.append({
            "severity": "HIGH",
            "message": ("macOS major version is outside the supported "
                        "branches — no security updates expected"),
            "action": None,
        })

    # softwareupdate --list (missing updates)
    rc, out, err = _run_cmd_short(
        ["softwareupdate", "--list"], timeout=60)
    text = (out or "") + (err or "")
    if "No new software available" in text:
        findings.append({"severity": "OK",
                         "message": "Software Update: no pending updates",
                         "action": None})
    elif "recommended" in text.lower() or "Title:" in text:
        pending = [line for line in text.splitlines()
                   if line.strip().startswith("* Label:")
                   or "Title:" in line]
        findings.append({
            "severity": "HIGH",
            "message": f"Software Update: {len(pending)} update(s) pending",
            "evidence": "\n".join(pending[:10]),
            "action": {"type": "run_software_update"},
        })

    # Update preferences
    su = _read_plist_defaults("/Library/Preferences/com.apple.SoftwareUpdate")
    if su:
        for key, label, sev_if_off in [
            ("AutomaticCheckEnabled", "Automatic update checks", "MEDIUM"),
            ("AutomaticDownload", "Automatic download", "LOW"),
            ("AutomaticallyInstallMacOSUpdates", "Install macOS updates", "MEDIUM"),
            ("ConfigDataInstall", "Install system data files (XProtect, …)", "HIGH"),
            ("CriticalUpdateInstall", "Install critical updates", "HIGH"),
        ]:
            v = su.get(key)
            if v == 0 or v is False:
                findings.append({
                    "severity": sev_if_off,
                    "message": f"Software Update setting '{label}' is OFF",
                    "action": None,
                })

    return findings


# ── Batch B: TCC grants / Browser extensions / USB-HID / Shell dotfiles ─


_TCC_RISKY_SERVICES = {
    "kTCCServiceSystemPolicyAllFiles": "Full Disk Access",
    "kTCCServiceScreenCapture": "Screen Recording",
    "kTCCServiceCamera": "Camera",
    "kTCCServiceMicrophone": "Microphone",
    "kTCCServiceAccessibility": "Accessibility",
    "kTCCServiceListenEvent": "Input Monitoring",
    "kTCCServicePostEvent": "Post Events",
    "kTCCServiceAppleEvents": "Automation",
    "kTCCServiceLocation": "Location",
    "kTCCServiceMediaLibrary": "Media Library",
    "kTCCServiceLiverpool": "Home Data",
    "kTCCServiceMotion": "Motion",
    "kTCCServiceReminders": "Reminders",
    "kTCCServiceCalendar": "Calendar",
    "kTCCServiceAddressBook": "Contacts",
}


def _query_tcc_all_risky():
    """Read TCC.db for every service in _TCC_RISKY_SERVICES.

    Returns a list of dicts: {service, client, auth_value, db,
    last_modified}. auth_value 2 == allowed.
    """
    import sqlite3
    entries = []
    dbs = [_TCC_SYSTEM_DB,
           os.path.join(_EFFECTIVE_HOME,
                        "Library/Application Support/com.apple.TCC/TCC.db")]
    placeholders = ",".join("?" * len(_TCC_RISKY_SERVICES))
    query = (
        "SELECT service, client, client_type, auth_value, auth_reason, "
        "last_modified FROM access WHERE service IN (" + placeholders + ")")
    for db in dbs:
        if not os.path.exists(db):
            continue
        try:
            conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=2)
            cur = conn.cursor()
            cur.execute(query, tuple(_TCC_RISKY_SERVICES.keys()))
            for row in cur.fetchall():
                service, client, ctype, authv, auth_reason, lm = row
                entries.append({"service": service, "client": client,
                                "client_type": ctype, "auth_value": authv,
                                "auth_reason": auth_reason,
                                "last_modified": lm, "db": db})
            conn.close()
        except sqlite3.Error:
            continue
    return entries


def _audit_tcc_grants():
    """TCC grants audit (finding #5)."""
    findings = []
    entries = _query_tcc_all_risky()
    if not entries:
        findings.append({
            "severity": "INFO",
            "message": ("TCC.db unreadable — procmon needs Full Disk Access "
                        "to read TCC grants"),
            "evidence": ("System Settings → Privacy & Security → "
                         "Full Disk Access → add your terminal app"),
            "action": None,
        })
        return findings
    for e in entries:
        if e["auth_value"] != 2:
            continue
        client = e["client"] or ""
        svc = _TCC_RISKY_SERVICES.get(e["service"], e["service"])
        # Apple bundles get info-level only
        if client.startswith("com.apple.") or client.startswith("/System/"):
            sev = "INFO"
        elif e["service"] in ("kTCCServiceSystemPolicyAllFiles",
                              "kTCCServiceListenEvent",
                              "kTCCServiceAccessibility",
                              "kTCCServicePostEvent",
                              "kTCCServiceScreenCapture"):
            sev = "HIGH"
        else:
            sev = "MEDIUM"
        findings.append({
            "severity": sev,
            "message": f"TCC '{svc}' granted to {client}",
            "evidence": f"db: {e['db']}\nreason: {e['auth_reason']}",
            "action": {"type": "delete_tcc", "client": client,
                       "service": e["service"], "db": e["db"]},
        })
    if not findings:
        findings.append({"severity": "OK",
                         "message": "No risky TCC grants",
                         "action": None})
    return findings


def _enum_safari_extensions():
    """Safari extensions via pluginkit + containers scan."""
    results = []
    rc, out, _ = _run_cmd_short(
        ["pluginkit", "-mAvvv", "-p", "com.apple.Safari.extension"],
        timeout=10)
    if out:
        for line in out.splitlines():
            s = line.strip()
            if not s:
                continue
            results.append({"browser": "Safari", "raw": s})
    return results


def _resolve_chromium_message(vdir, msg_key, default_locale):
    """Resolve a Chrome i18n message key (e.g. "appName") into a real string.

    Chromium extensions localize strings under `_locales/<locale>/messages.json`.
    Order of preference: the manifest's `default_locale`, then `en`, then
    `en_US`, then any locale directory we find. Returns '' if nothing maps.
    """
    import json as _j
    locales_dir = os.path.join(vdir, "_locales")
    if not os.path.isdir(locales_dir):
        return ""
    try:
        available = [d for d in os.listdir(locales_dir)
                     if os.path.isdir(os.path.join(locales_dir, d))]
    except (PermissionError, OSError):
        return ""
    candidates = []
    if default_locale:
        candidates.append(default_locale)
    for fallback in ("en", "en_US", "en_GB"):
        if fallback not in candidates:
            candidates.append(fallback)
    for loc in available:
        if loc not in candidates:
            candidates.append(loc)
    for loc in candidates:
        mpath = os.path.join(locales_dir, loc, "messages.json")
        if not os.path.isfile(mpath):
            continue
        try:
            with open(mpath, encoding="utf-8") as f:
                msgs = _j.load(f)
        except (OSError, ValueError):
            continue
        # Chrome message keys are case-insensitive when referenced via
        # __MSG_<name>__, but stored case-preserved. Try both.
        for k in (msg_key, msg_key.lower()):
            entry = msgs.get(k) if isinstance(msgs, dict) else None
            if isinstance(entry, dict):
                val = entry.get("message")
                if isinstance(val, str) and val.strip():
                    return val.strip()
    return ""


def _resolve_extension_name(manifest_name, vdir, default_locale, ext_id):
    """Turn manifest.name into a display name.

    Handles the `__MSG_<key>__` pattern by reading the _locales/ files.
    Falls back to the extension ID when nothing else is available.
    """
    if not isinstance(manifest_name, str) or not manifest_name:
        return ext_id
    if manifest_name.startswith("__MSG_") and manifest_name.endswith("__"):
        key = manifest_name[len("__MSG_"):-len("__")]
        resolved = _resolve_chromium_message(vdir, key, default_locale)
        if resolved:
            return resolved
        return ext_id
    return manifest_name


def _enum_chromium_extensions(browser_name, root_rel):
    """Chrome / Brave / Edge: walk ~/Library/Application Support/<root>/.../Extensions/*/<version>/manifest.json."""
    import json as _j
    results = []
    root = os.path.join(_EFFECTIVE_HOME, root_rel)
    if not os.path.isdir(root):
        return []
    for profile in os.listdir(root):
        ext_dir = os.path.join(root, profile, "Extensions")
        if not os.path.isdir(ext_dir):
            continue
        try:
            ext_ids = os.listdir(ext_dir)
        except (PermissionError, OSError):
            continue
        for ext_id in ext_ids:
            ext_path = os.path.join(ext_dir, ext_id)
            if not os.path.isdir(ext_path):
                continue
            try:
                versions = [v for v in os.listdir(ext_path)
                            if os.path.isdir(os.path.join(ext_path, v))]
            except (PermissionError, OSError):
                continue
            if not versions:
                continue
            # Pick newest
            versions.sort()
            vdir = os.path.join(ext_path, versions[-1])
            manifest = os.path.join(vdir, "manifest.json")
            name = ext_id
            perms = []
            try:
                with open(manifest, encoding="utf-8") as f:
                    mf = _j.load(f)
                name = _resolve_extension_name(
                    mf.get("name"), vdir,
                    mf.get("default_locale", ""), ext_id)
                perms = mf.get("permissions", []) + mf.get(
                    "host_permissions", [])
            except (OSError, ValueError):
                pass
            results.append({"browser": browser_name, "id": ext_id,
                            "name": name, "permissions": perms,
                            "path": vdir})
    return results


def _enum_firefox_extensions():
    import json as _j
    results = []
    root = os.path.join(_EFFECTIVE_HOME,
                        "Library/Application Support/Firefox/Profiles")
    if not os.path.isdir(root):
        return []
    for profile in os.listdir(root):
        f = os.path.join(root, profile, "extensions.json")
        if not os.path.isfile(f):
            continue
        try:
            with open(f) as fh:
                data = _j.load(fh)
            for add in data.get("addons", []):
                if add.get("type") == "theme":
                    continue
                results.append({
                    "browser": "Firefox",
                    "id": add.get("id", ""),
                    "name": (add.get("defaultLocale") or {}).get("name", "") or add.get("id", ""),
                    "permissions": (add.get("userPermissions") or {}).get("permissions", []),
                    "path": add.get("path", ""),
                })
        except (OSError, ValueError):
            continue
    return results


def _audit_browser_extensions():
    """Browser extensions audit (finding #7)."""
    findings = []
    # Chrome-family
    families = [
        ("Chrome", "Library/Application Support/Google/Chrome"),
        ("Brave", "Library/Application Support/BraveSoftware/Brave-Browser"),
        ("Edge", "Library/Application Support/Microsoft Edge"),
        ("Arc", "Library/Application Support/Arc/User Data"),
    ]
    total = 0
    for name, relroot in families:
        exts = _enum_chromium_extensions(name, relroot)
        for e in exts:
            total += 1
            perms = [p for p in e.get("permissions", [])
                     if isinstance(p, str)]
            high_risk = any(
                p in ("<all_urls>", "webRequest", "webRequestBlocking",
                      "cookies", "debugger", "proxy", "privacy",
                      "nativeMessaging")
                or p.startswith("http")
                for p in perms)
            sev = "HIGH" if high_risk else "INFO"
            # When the name couldn't be resolved (it equals the ID), don't
            # print the ID twice — show just the ID once.
            label = (e["name"] if e["name"] and e["name"] != e["id"]
                     else f"(id={e['id']})")
            findings.append({
                "severity": sev,
                "message": f"{e['browser']} extension: {label}",
                "evidence": (
                    f"id: {e['id']}\n"
                    f"perms: {', '.join(perms[:10])}" if perms
                    else f"id: {e['id']}\nno permissions listed"),
                "action": None,
            })
    for e in _enum_firefox_extensions():
        total += 1
        label = (e["name"] if e["name"] and e["name"] != e["id"]
                 else f"(id={e['id']})")
        findings.append({
            "severity": "INFO",
            "message": f"Firefox extension: {label}",
            "evidence": f"id: {e['id']}",
            "action": None,
        })
    for e in _enum_safari_extensions():
        findings.append({
            "severity": "INFO",
            "message": f"Safari extension: {e['raw'][:120]}",
            "action": None,
        })
    if total == 0:
        findings.append({"severity": "OK",
                         "message": "No browser extensions found",
                         "action": None})
    return findings


def _audit_usb_hid():
    """USB / HID audit (finding #9). Enumerate keyboards + input devices."""
    findings = []
    rc, out, _ = _run_cmd_short(
        ["ioreg", "-p", "IOUSB", "-l", "-w", "0"], timeout=10)
    if rc != 0 or not out:
        return [{"severity": "INFO",
                 "message": "ioreg unavailable",
                 "action": None}]
    # Simple parse: count devices, flag those whose product contains "keyboard"
    devices = []
    current = {}
    for line in out.splitlines():
        s = line.strip()
        if s.startswith("+-o "):
            if current:
                devices.append(current)
            current = {"name": s[3:].split("@")[0].strip(),
                       "vendor": "", "product": "", "manufacturer": ""}
        elif current is not None and "=" in s:
            if '"idVendor"' in s:
                current["vendor"] = s.split("=", 1)[1].strip()
            elif '"idProduct"' in s:
                current["product"] = s.split("=", 1)[1].strip()
            elif '"USB Vendor Name"' in s or '"kUSBVendorString"' in s:
                current["manufacturer"] = s.split("=", 1)[1].strip().strip('"')
    if current:
        devices.append(current)
    hid_like = [d for d in devices
                if "keyboard" in d["name"].lower()
                or "mouse" in d["name"].lower()
                or "input" in d["name"].lower()]
    for d in hid_like:
        findings.append({
            "severity": "INFO",
            "message": (f"HID device: {d['name']} "
                        f"(vendor={d['vendor']}, product={d['product']}, "
                        f"mfr={d['manufacturer']})"),
            "action": None,
        })
    if not hid_like:
        findings.append({"severity": "OK",
                         "message": f"No HID USB devices attached "
                                     f"({len(devices)} total USB devices)",
                         "action": None})
    return findings


_DOTFILE_PATHS = [
    os.path.join(_EFFECTIVE_HOME, ".zshrc"),
    os.path.join(_EFFECTIVE_HOME, ".zshenv"),
    os.path.join(_EFFECTIVE_HOME, ".zprofile"),
    os.path.join(_EFFECTIVE_HOME, ".bashrc"),
    os.path.join(_EFFECTIVE_HOME, ".bash_profile"),
    os.path.join(_EFFECTIVE_HOME, ".profile"),
    os.path.join(_EFFECTIVE_HOME, ".config/fish/config.fish"),
    "/etc/zshrc",
    "/etc/zprofile",
    "/etc/zshenv",
    "/etc/profile",
    "/etc/bashrc",
    "/etc/paths",
]

_DOTFILE_PATH_DIRS = [
    "/etc/paths.d",
    "/etc/periodic/daily",
    "/etc/periodic/weekly",
    "/etc/periodic/monthly",
]

# Regexes looking for obvious backdoor-ish payloads.
_SUSPICIOUS_DOTFILE_PATTERNS = [
    (r"\b(curl|wget)\b[^|]*\|\s*(bash|sh|zsh|python3?)",
     "pipes remote script to a shell"),
    (r"\beval\s*\(?\s*\$\(", "eval $(...) of a command substitution"),
    (r"\bbase64\b.*-[dD]\b.*\|\s*(bash|sh|zsh|python3?)",
     "base64-decoded pipe to shell"),
    (r"\bnohup\b", "nohup-backgrounded process"),
    (r"\bopenssl\b.*enc.*-d", "openssl-decoded execution"),
]


def _audit_shell_dotfiles():
    """Shell dotfile persistence scanner (finding #8)."""
    import re
    findings = []
    files_to_check = list(_DOTFILE_PATHS)
    for d in _DOTFILE_PATH_DIRS:
        if os.path.isdir(d):
            try:
                for n in os.listdir(d):
                    files_to_check.append(os.path.join(d, n))
            except (PermissionError, OSError):
                pass
    for path in files_to_check:
        if not os.path.isfile(path):
            continue
        try:
            with open(path, errors="replace") as f:
                text = f.read()
        except (OSError,):
            continue
        for pat, desc in _SUSPICIOUS_DOTFILE_PATTERNS:
            for m in re.finditer(pat, text):
                # extract the offending line
                line_start = text.rfind("\n", 0, m.start()) + 1
                line_end = text.find("\n", m.end())
                if line_end == -1:
                    line_end = len(text)
                line = text[line_start:line_end].strip()
                findings.append({
                    "severity": "HIGH",
                    "message": f"{path}: {desc}",
                    "evidence": line[:240],
                    "action": None,
                })
        # PATH prepend to non-standard dirs
        for m in re.finditer(r"export\s+PATH=([^\n]+)", text):
            pv = m.group(1)
            for p in pv.split(":"):
                p_clean = p.strip().strip('"').strip("'")
                if p_clean and p_clean.startswith("/"):
                    if (p_clean not in ("/usr/local/bin", "/opt/homebrew/bin",
                                        "/usr/bin", "/bin", "/usr/sbin", "/sbin")
                            and not p_clean.startswith(_EFFECTIVE_HOME)):
                        findings.append({
                            "severity": "MEDIUM",
                            "message": (f"{path}: PATH prepends unusual "
                                        f"directory {p_clean}"),
                            "action": None,
                        })
                        break
    if not findings:
        findings.append({"severity": "OK",
                         "message": "Shell dotfiles clean",
                         "action": None})
    return findings


# ── Batch C: Installed software / Process entitlements / FS integrity / Delta ─


def _iter_app_bundles(roots):
    out = []
    for root in roots:
        if not os.path.isdir(root):
            continue
        try:
            for name in os.listdir(root):
                if name.endswith(".app"):
                    out.append(os.path.join(root, name))
        except (PermissionError, OSError):
            continue
    return out


def _audit_installed_software():
    """Installed-software trust audit (finding #6)."""
    findings = []
    apps = _iter_app_bundles([
        "/Applications",
        os.path.join(_EFFECTIVE_HOME, "Applications"),
    ])
    flagged = 0
    for app in apps:
        cs = _codesign_structured(app)
        if not cs:
            continue
        if _is_apple_signed(app, cs):
            continue
        sig_ok = cs.get("rc") == 0
        team = cs.get("team_id", "")
        ent_set = _parse_entitlements_xml(cs.get("entitlements_xml", ""))
        hr = cs.get("hardened_runtime", False)

        issues = []
        sev = "INFO"
        if not sig_ok:
            issues.append("unsigned/invalid signature")
            sev = "HIGH"
        elif not team:
            issues.append("ad-hoc signed (no Team ID)")
            sev = "HIGH"
        if sig_ok and not hr:
            issues.append("Hardened Runtime disabled")
            sev = max(sev, "MEDIUM", key=["INFO", "MEDIUM", "HIGH"].index)
        if "com.apple.security.cs.disable-library-validation" in ent_set:
            issues.append("disable-library-validation entitlement")
            sev = max(sev, "HIGH", key=["INFO", "MEDIUM", "HIGH"].index)
        # Translocation check
        if "/AppTranslocation/" in app:
            issues.append("running translocated (quarantine unresolved)")
            sev = "HIGH"
        if issues:
            flagged += 1
            findings.append({
                "severity": sev,
                "message": f"App: {os.path.basename(app)} — {'; '.join(issues)}",
                "evidence": f"path: {app}\nteam: {team or '(none)'}",
                "action": None,
            })
    if flagged == 0:
        findings.append({
            "severity": "OK",
            "message": f"All {len(apps)} application bundles look sane",
            "action": None,
        })
    return findings


def _audit_process_entitlements():
    """Per-process entitlement & runtime pass (finding #14).

    Runs against whatever processes are visible via proc_listallpids.
    Non-Apple binaries carrying dangerous entitlements are flagged with
    calibrated severity; library-validation disabled alone is HIGH, and
    escalates to CRITICAL when paired with live DYLD env vars.
    """
    findings = []
    for pid in _list_all_pids():
        if pid <= 0:
            continue
        exe = _get_proc_path(pid)
        if not exe or not exe.startswith("/"):
            continue
        if not os.path.exists(exe):
            continue
        cs = _codesign_structured(exe)
        if not cs:
            continue
        if _is_apple_signed(exe, cs):
            continue
        ent_set = _parse_entitlements_xml(cs.get("entitlements_xml", ""))
        try:
            env = _get_proc_env(pid)
        except Exception:
            env = {}
        dyld_live = any(k in env for k in (
            "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH",
            "DYLD_FRAMEWORK_PATH"))
        translocated = "/AppTranslocation/" in exe

        # Dangerous combos
        issues = []
        sev = None
        if "com.apple.security.cs.allow-dyld-environment-variables" in ent_set \
                and dyld_live:
            issues.append("dyld-env-vars entitlement + DYLD_* live in env")
            sev = "CRITICAL"
        if "com.apple.security.get-task-allow" in ent_set:
            issues.append("get-task-allow (debug) on running process")
            sev = max(sev or "HIGH", "HIGH",
                      key=["INFO", "MEDIUM", "HIGH", "CRITICAL"].index)
        if "com.apple.security.cs.disable-library-validation" in ent_set:
            if dyld_live:
                issues.append("disable-library-validation + live DYLD injection")
                sev = "CRITICAL"
            else:
                issues.append("disable-library-validation")
                if sev is None:
                    sev = "HIGH"
        if translocated:
            issues.append("running under AppTranslocation (quarantine)")
            sev = max(sev or "MEDIUM", "MEDIUM",
                      key=["INFO", "MEDIUM", "HIGH", "CRITICAL"].index)
        if not issues:
            continue
        findings.append({
            "severity": sev,
            "message": (f"PID {pid}: {os.path.basename(exe)} — "
                        f"{'; '.join(issues)}"),
            "evidence": (f"exe: {exe}\nteam: {cs.get('team_id', '(none)')}\n"
                         f"runtime: {cs.get('hardened_runtime')}"),
            "action": {"type": "kill_process", "pid": pid, "exe": exe},
        })
    if not findings:
        findings.append({"severity": "OK",
                         "message": "No non-Apple processes with dangerous entitlement combos",
                         "action": None})
    return findings


# Critical admin-configurable files. Exact-hash diffing is brittle; we check
# permission modes, ownership, ACLs, and recent modification times instead.
_FS_SENSITIVE_FILES = [
    ("/etc/hosts", 0o644, "root", "wheel"),
    ("/etc/ssh/sshd_config", 0o644, "root", "wheel"),
    ("/etc/sudoers", 0o440, "root", "wheel"),
    ("/etc/pam.d/sudo", 0o644, "root", "wheel"),
    ("/etc/pam.d/login", 0o644, "root", "wheel"),
    ("/etc/pam.d/authorization", 0o644, "root", "wheel"),
    ("/etc/pam.d/screensaver", 0o644, "root", "wheel"),
]


def _audit_filesystem_integrity():
    """Filesystem integrity pass (finding #16)."""
    import stat
    import pwd
    import grp
    findings = []

    # Sensitive config files — permission + ownership + mtime
    for path, expected_mode, expected_user, expected_group in _FS_SENSITIVE_FILES:
        if not os.path.exists(path):
            continue
        try:
            st = os.stat(path)
        except OSError:
            continue
        mode = stat.S_IMODE(st.st_mode)
        try:
            uname = pwd.getpwuid(st.st_uid).pw_name
        except (KeyError, OSError):
            uname = str(st.st_uid)
        try:
            gname = grp.getgrgid(st.st_gid).gr_name
        except (KeyError, OSError):
            gname = str(st.st_gid)
        if mode & 0o022:
            findings.append({
                "severity": "CRITICAL",
                "message": (f"{path} is world- or group-writable "
                            f"({oct(mode)})"),
                "action": None,
            })
        if uname != expected_user:
            findings.append({
                "severity": "HIGH",
                "message": f"{path} owner is {uname} (expected {expected_user})",
                "action": None,
            })
        # Recent edits (≤30 days) are worth surfacing, not necessarily bad
        age_days = (time.time() - st.st_mtime) / 86400
        if age_days < 30:
            findings.append({
                "severity": "MEDIUM",
                "message": (f"{path} modified in the last {int(age_days)}d — "
                            f"verify the change was intentional"),
                "action": None,
            })

    # AuthorizationDB key rights
    for right in ("system.login.console", "system.preferences",
                   "system.install.apple-software"):
        rc, out, _ = _run_cmd_short(
            ["security", "authorizationdb", "read", right], timeout=5)
        if rc == 0 and out:
            if "<string>allow</string>" in out and "authenticate-user" not in out:
                findings.append({
                    "severity": "HIGH",
                    "message": (f"AuthorizationDB right '{right}' is set to "
                                f"allow without authentication"),
                    "evidence": out.strip()[:400],
                    "action": None,
                })

    # World-writable files under /etc /Library /usr/local (non-SSV paths)
    world_writable_limit = 20
    found_ww = []
    try:
        rc, out, _ = _run_cmd_short(
            ["find", "/etc", "/Library", "/usr/local",
             "-xdev", "-type", "f", "-perm", "-0002"],
            timeout=60)
        if rc == 0 and out:
            for line in out.splitlines():
                s = line.strip()
                if s:
                    found_ww.append(s)
    except Exception:
        pass
    for p in found_ww[:world_writable_limit]:
        findings.append({
            "severity": "HIGH",
            "message": f"World-writable file: {p}",
            "action": None,
        })
    if len(found_ww) > world_writable_limit:
        findings.append({
            "severity": "HIGH",
            "message": (f"{len(found_ww) - world_writable_limit} more "
                        f"world-writable files omitted"),
            "action": None,
        })

    # SUID/SGID baseline — just count non-Apple hits
    rc, out, _ = _run_cmd_short(
        ["find", "/usr/local", "/opt", "/Library",
         "-xdev", "(", "-perm", "-4000", "-o", "-perm", "-2000", ")"],
        timeout=30)
    if rc == 0 and out:
        suid_hits = [l.strip() for l in out.splitlines() if l.strip()]
        if suid_hits:
            findings.append({
                "severity": "MEDIUM",
                "message": (f"{len(suid_hits)} SUID/SGID binaries outside "
                            f"/usr/bin /usr/sbin /bin /sbin"),
                "evidence": "\n".join(suid_hits[:10]),
                "action": None,
            })

    if not findings:
        findings.append({"severity": "OK",
                         "message": "Filesystem integrity clean",
                         "action": None})
    return findings


_SENSITIVE_PATH_ROOTS = [
    "/private/etc",
    "/Library/LaunchAgents",
    "/Library/LaunchDaemons",
    "/Library/Extensions",
    "/Library/Security",
    "/Library/PrivilegedHelperTools",
    "/usr/local/bin",
    "/opt/homebrew/bin",
    os.path.join(_EFFECTIVE_HOME, "Library/LaunchAgents"),
]


def _audit_sensitive_paths_delta(window_days=7):
    """Sensitive Paths Delta scanner (finding #21).

    Walks a curated watchlist, returns files modified within the window.
    Does NOT pretend to attribute the modifying process.
    """
    import pwd
    findings = []
    cutoff = time.time() - (window_days * 86400)
    recent = []
    for root in _SENSITIVE_PATH_ROOTS:
        if not os.path.isdir(root):
            continue
        for dirpath, _dirs, files in os.walk(root):
            for name in files:
                full = os.path.join(dirpath, name)
                try:
                    st = os.stat(full)
                except OSError:
                    continue
                if st.st_mtime >= cutoff:
                    try:
                        owner = pwd.getpwuid(st.st_uid).pw_name
                    except (KeyError, OSError):
                        owner = str(st.st_uid)
                    recent.append({
                        "path": full,
                        "mtime": st.st_mtime,
                        "owner": owner,
                        "size": st.st_size,
                    })
    # Sort newest first
    recent.sort(key=lambda r: r["mtime"], reverse=True)
    for r in recent[:50]:
        age_h = int((time.time() - r["mtime"]) / 3600)
        findings.append({
            "severity": "MEDIUM",
            "message": (f"{r['path']} modified ~{age_h}h ago "
                        f"(owner={r['owner']}, size={r['size']})"),
            "action": None,
        })
    if len(recent) > 50:
        findings.append({
            "severity": "MEDIUM",
            "message": f"+ {len(recent) - 50} more recent changes omitted",
            "action": None,
        })
    if not recent:
        findings.append({
            "severity": "OK",
            "message": (f"No sensitive paths modified in the last "
                        f"{window_days} days"),
            "action": None,
        })
    return findings


# ── Batch D: Keychain / Auth-stack / Package managers ────────────────────


def _audit_keychain_credentials():
    """Keychain hygiene + FileVault trust chain (finding #19)."""
    import stat
    findings = []
    # Enumerate per-domain keychain search lists
    for domain in ("user", "system", "common", "dynamic"):
        rc, out, _ = _run_cmd_short(
            ["security", "list-keychains", "-d", domain], timeout=5)
        if rc != 0 or not out:
            continue
        for line in out.splitlines():
            kc = line.strip().strip('"')
            if not kc:
                continue
            if kc.startswith("/Volumes/") and not kc.startswith("/Volumes/Macintosh"):
                findings.append({
                    "severity": "HIGH",
                    "message": (f"Keychain on removable/mounted volume: {kc} "
                                f"(domain={domain})"),
                    "action": None,
                })
                continue
            if not os.path.exists(kc):
                continue
            try:
                st = os.stat(kc)
            except OSError:
                continue
            mode = stat.S_IMODE(st.st_mode)
            if domain == "user" and (mode & 0o044):
                findings.append({
                    "severity": "CRITICAL",
                    "message": (f"User keychain is group/world readable: {kc} "
                                f"({oct(mode)})"),
                    "action": None,
                })
            if domain == "system" and (mode & 0o022) and st.st_uid != 0:
                findings.append({
                    "severity": "CRITICAL",
                    "message": (f"System keychain is writable by non-root: {kc} "
                                f"({oct(mode)}, owner uid={st.st_uid})"),
                    "action": None,
                })

    # FileVault unlock users vs Secure Token holders
    rc, out, _ = _run_cmd_short(["fdesetup", "list"], timeout=5)
    unlock_users = []
    if rc == 0 and out:
        for line in out.splitlines():
            if "," in line:
                unlock_users.append(line.split(",", 1)[0].strip())
    if not unlock_users and rc == 0:
        findings.append({
            "severity": "HIGH",
            "message": "No FileVault-unlock-capable users configured",
            "action": None,
        })

    rc, out, _ = _run_cmd_short(
        ["dscl", ".", "list", "/Users"], timeout=5)
    users = []
    if rc == 0 and out:
        for u in out.splitlines():
            u = u.strip()
            if u and not u.startswith("_") and u not in ("daemon", "nobody", "root"):
                users.append(u)
    tokened = []
    for u in users:
        rc, out2, err2 = _run_cmd_short(
            ["sysadminctl", "-secureTokenStatus", u], timeout=5)
        txt = (out2 or "") + (err2 or "")
        if "ENABLED" in txt.upper():
            tokened.append(u)
    if users and not tokened:
        findings.append({
            "severity": "HIGH",
            "message": ("No user holds a Secure Token — FileVault trust chain "
                        "broken"),
            "evidence": f"users: {', '.join(users)}",
            "action": None,
        })
    if not findings:
        findings.append({"severity": "OK",
                         "message": "Keychain + FileVault trust chain look healthy",
                         "action": None})
    return findings


_AUTH_PLUGIN_ROOTS = [
    "/Library/Security/SecurityAgentPlugins",
    "/Library/DirectoryServices/PlugIns",
]
_PAM_DIR = "/etc/pam.d"


def _audit_authentication_stack():
    """Auth-stack / PAM / SecurityAgentPlugins audit (finding #20)."""
    findings = []
    # Plugins
    for root in _AUTH_PLUGIN_ROOTS:
        if not os.path.isdir(root):
            continue
        try:
            names = os.listdir(root)
        except (PermissionError, OSError):
            continue
        for name in names:
            path = os.path.join(root, name)
            cs = _codesign_structured(path)
            if _is_apple_signed(path, cs):
                continue
            sig_ok = cs.get("rc") == 0 if cs else False
            team = cs.get("team_id", "") if cs else ""
            if not sig_ok or not team:
                findings.append({
                    "severity": "CRITICAL",
                    "message": (f"Unsigned/ad-hoc auth plugin: {path}"),
                    "evidence": (f"team: {team or '(none)'}\n"
                                 f"authority: {', '.join(cs.get('authority', []))}"
                                 if cs else "no codesign data"),
                    "action": None,
                })
            else:
                findings.append({
                    "severity": "MEDIUM",
                    "message": (f"Third-party auth plugin (team={team}): "
                                f"{path}"),
                    "action": None,
                })

    # Authorization DB for high-value rights
    for right in ("system.login.console", "authenticate",
                   "system.preferences.accounts",
                   "com.apple.uninstalld.uninstall"):
        rc, out, _ = _run_cmd_short(
            ["security", "authorizationdb", "read", right], timeout=5)
        if rc == 0 and out:
            if "<string>allow</string>" in out and "authenticate-user" not in out.lower():
                findings.append({
                    "severity": "HIGH",
                    "message": (f"AuthorizationDB right '{right}' weakened"),
                    "evidence": out.strip()[:400],
                    "action": None,
                })

    # PAM stack diffs
    if os.path.isdir(_PAM_DIR):
        try:
            names = os.listdir(_PAM_DIR)
        except (PermissionError, OSError):
            names = []
        for name in names:
            path = os.path.join(_PAM_DIR, name)
            try:
                st = os.stat(path)
            except OSError:
                continue
            age_days = (time.time() - st.st_mtime) / 86400
            if age_days < 90:
                findings.append({
                    "severity": "MEDIUM",
                    "message": (f"PAM config {name} modified {int(age_days)}d "
                                f"ago — verify the change"),
                    "action": None,
                })
    if not findings:
        findings.append({"severity": "OK",
                         "message": "Authentication stack looks stock",
                         "action": None})
    return findings


_TYPOSQUAT_PATTERNS = {
    # name → real name it mimics. Tiny starter list; real one ships via the
    # rule engine.
    "colors-js": "colors",
    "lodash.js": "lodash",
    "crossenv": "cross-env",
    "discord.js.rmm": "discord.js",
    "noblox.js-proxy": "noblox.js",
}


def _audit_package_managers():
    """Package-manager supply-chain audit (finding #17)."""
    findings = []

    # npm globals
    rc, out, _ = _run_cmd_short(["npm", "root", "-g"], timeout=10)
    if rc == 0 and out and os.path.isdir(out.strip()):
        npm_root = out.strip()
        try:
            for name in os.listdir(npm_root):
                path = os.path.join(npm_root, name)
                pkg_json = os.path.join(path, "package.json")
                if not os.path.isfile(pkg_json):
                    continue
                try:
                    import json as _j
                    with open(pkg_json) as f:
                        pj = _j.load(f)
                except (OSError, ValueError):
                    continue
                scripts = pj.get("scripts") or {}
                hooks = [k for k in scripts
                         if k in ("preinstall", "install", "postinstall")]
                # Signals: recent install + typosquat + install hooks
                signals = []
                try:
                    age = (time.time()
                           - os.stat(pkg_json).st_mtime) / 86400
                    if age < 30:
                        signals.append("recently installed (<30d)")
                except OSError:
                    pass
                if hooks:
                    signals.append("install hook: " + ",".join(hooks))
                if name in _TYPOSQUAT_PATTERNS:
                    signals.append(f"typosquats {_TYPOSQUAT_PATTERNS[name]}")
                sev = "HIGH" if len(signals) >= 2 else (
                    "MEDIUM" if hooks else "INFO")
                if signals:
                    findings.append({
                        "severity": sev,
                        "message": f"npm global '{name}' — {'; '.join(signals)}",
                        "action": None,
                    })
        except (PermissionError, OSError):
            pass

    # Homebrew formulae (informational)
    rc, out, _ = _run_cmd_short(["brew", "list", "--versions"], timeout=20)
    if rc == 0 and out:
        count = sum(1 for line in out.splitlines() if line.strip())
        findings.append({
            "severity": "INFO",
            "message": f"Homebrew: {count} formula/cask(s) installed",
            "action": None,
        })

    # Python site-packages — enumerate dist-info for installer provenance
    for py in ("python3", "python3.11", "python3.12"):
        rc, out, _ = _run_cmd_short(
            [py, "-c",
             "import site; print('\\n'.join(site.getsitepackages()+[site.getusersitepackages()]))"],
            timeout=10)
        if rc != 0 or not out:
            continue
        for line in out.splitlines():
            sp = line.strip()
            if not sp or not os.path.isdir(sp):
                continue
            try:
                dist_infos = [n for n in os.listdir(sp)
                              if n.endswith(".dist-info")]
            except (PermissionError, OSError):
                continue
            recent_installs = []
            for di in dist_infos:
                try:
                    st = os.stat(os.path.join(sp, di))
                except OSError:
                    continue
                age = (time.time() - st.st_mtime) / 86400
                if age < 30:
                    recent_installs.append(di)
            if recent_installs:
                findings.append({
                    "severity": "INFO",
                    "message": (f"{sp}: {len(recent_installs)} pip "
                                f"package(s) installed in last 30d"),
                    "evidence": "\n".join(recent_installs[:10]),
                    "action": None,
                })
            break  # one python per interpreter name is enough

    # Cargo
    cargo_bin = os.path.join(_EFFECTIVE_HOME, ".cargo/bin")
    if os.path.isdir(cargo_bin):
        try:
            bins = [n for n in os.listdir(cargo_bin)]
            findings.append({
                "severity": "INFO",
                "message": f"Cargo: {len(bins)} binaries in ~/.cargo/bin",
                "action": None,
            })
        except (PermissionError, OSError):
            pass

    if not findings:
        findings.append({"severity": "OK",
                         "message": "No package-manager red flags",
                         "action": None})
    return findings


# ── Batch E: Baseline / Rule engine / Scoring ──────────────────────────


_BASELINE_PATH = os.path.join(_EFFECTIVE_HOME, ".procmon-baseline.json")


def _collect_baseline_snapshot():
    """Snapshot of host state: launch items, listeners, kexts, sysexts,
    root CAs, profiles, sharing state. Written to ~/.procmon-baseline.json
    on demand. Future audits can diff against this to surface only deltas.
    """
    import hashlib as _h

    def _hash_file(path):
        try:
            with open(path, "rb") as f:
                return _h.sha256(f.read()).hexdigest()
        except OSError:
            return ""

    snap = {
        "version": 1,
        "captured_at": int(time.time()),
        "launch_items": [
            {
                "path": it["path"],
                "label": it["label"],
                "program": it["program"],
                "hash": _hash_file(it["path"]) if os.path.isfile(it["path"]) else "",
            }
            for it in _enumerate_launch_items()
        ],
        "system_extensions": [
            {"team_id": s["team_id"], "bundle_id": s["bundle_id"]}
            for s in _list_system_extensions()
        ],
        "listening_ports": [
            {"pid": s["pid"], "port": s["port"], "addr": s["addr"],
             "command": s["command"]}
            for s in _list_listening_sockets()
        ],
        "config_profiles": [
            {"identifier": p["identifier"],
             "display_name": p["display_name"]}
            for p in _list_config_profiles()
        ],
        "sharing": _sharing_services_state(),
    }
    return snap


def _load_baseline():
    import json as _j
    try:
        with open(_BASELINE_PATH) as f:
            return _j.load(f)
    except (FileNotFoundError, ValueError, OSError):
        return {}


def _save_baseline(snap):
    import json as _j
    try:
        with open(_BASELINE_PATH, "w") as f:
            _j.dump(snap, f, indent=2)
        return True
    except OSError:
        return False


def _audit_baseline_delta():
    """Surface deltas between current host state and a saved baseline
    (finding #13). Non-destructive: if no baseline exists, reports so.
    """
    baseline = _load_baseline()
    if not baseline:
        return [{
            "severity": "INFO",
            "message": ("No baseline captured yet. Run "
                        "procmon --capture-baseline to create one."),
            "action": {"type": "capture_baseline"},
        }]
    now = _collect_baseline_snapshot()
    findings = []

    # Launch item hash drift
    old_by_path = {li["path"]: li for li in baseline.get("launch_items", [])}
    new_by_path = {li["path"]: li for li in now["launch_items"]}
    added = set(new_by_path) - set(old_by_path)
    removed = set(old_by_path) - set(new_by_path)
    changed = []
    for p in set(old_by_path) & set(new_by_path):
        if old_by_path[p].get("hash") != new_by_path[p].get("hash"):
            changed.append(p)
    for p in sorted(added):
        findings.append({
            "severity": "HIGH",
            "message": f"NEW launch item since baseline: {p}",
            "action": None,
        })
    for p in sorted(removed):
        findings.append({
            "severity": "INFO",
            "message": f"launch item removed since baseline: {p}",
            "action": None,
        })
    for p in sorted(changed):
        findings.append({
            "severity": "HIGH",
            "message": f"launch item hash changed since baseline: {p}",
            "action": None,
        })

    # New listeners
    old_ports = {(p["pid"], p["port"]) for p in baseline.get("listening_ports", [])}
    new_ports = {(p["pid"], p["port"]) for p in now["listening_ports"]}
    for pk in sorted(new_ports - old_ports):
        findings.append({
            "severity": "MEDIUM",
            "message": f"NEW listening port since baseline: PID {pk[0]} :{pk[1]}",
            "action": None,
        })

    # New profiles
    old_profs = {p["identifier"] for p in baseline.get("config_profiles", [])}
    new_profs = {p["identifier"] for p in now["config_profiles"]}
    for pf in sorted(new_profs - old_profs):
        findings.append({
            "severity": "HIGH",
            "message": f"NEW configuration profile since baseline: {pf}",
            "action": {"type": "remove_profile", "identifier": pf},
        })

    # New system extensions
    old_sx = {(s["team_id"], s["bundle_id"])
              for s in baseline.get("system_extensions", [])}
    new_sx = {(s["team_id"], s["bundle_id"])
              for s in now["system_extensions"]}
    for sx in sorted(new_sx - old_sx):
        findings.append({
            "severity": "HIGH",
            "message": (f"NEW system extension since baseline: "
                        f"team={sx[0]} bundle={sx[1]}"),
            "action": None,
        })

    if not findings:
        age_h = int((time.time() - baseline.get("captured_at", 0)) / 3600)
        findings.append({
            "severity": "OK",
            "message": (f"No drift since baseline captured ~{age_h}h ago"),
            "action": None,
        })
    return findings


# Rule engine (finding #18). A rule is a dict:
#   {"id": "RULE-001",
#    "kind": "path_exists" | "launch_item_signer" | "file_mode" | "sysctl",
#    "severity": "HIGH",
#    "message": "...",
#    "params": {...}}
# Each kind has its own evaluator. Ships with a small default set and can
# be extended by dropping JSON files into ~/.procmon-rules.d/.

_DEFAULT_RULES = [
    {
        "id": "ODK-001",
        "kind": "path_exists",
        "severity": "HIGH",
        "message": "Objective-See DoNotDisturb installed without ReiKey — partial coverage",
        "params": {"path": "/Applications/DoNotDisturb.app"},
    },
    {
        "id": "ODK-002",
        "kind": "file_mode",
        "severity": "CRITICAL",
        "message": "/etc/sudoers is world-writable",
        "params": {"path": "/etc/sudoers", "forbid_mode_bits": 0o022},
    },
    {
        "id": "ODK-003",
        "kind": "launch_item_signer",
        "severity": "HIGH",
        "message": "LaunchDaemon/Agent signed with suspicious team",
        # Tiny denylist — real one ships as data. Keep empty by default so
        # we don't accuse legitimate devs.
        "params": {"deny_team_ids": []},
    },
    {
        "id": "ODK-004",
        "kind": "sysctl_value",
        "severity": "HIGH",
        "message": "kernel.securelevel is unlocked",
        "params": {"name": "kern.securelevel", "equals": "0"},
    },
]


def _load_custom_rules():
    """Load rules from ~/.procmon-rules.d/*.json (best-effort)."""
    import json as _j
    root = os.path.join(_EFFECTIVE_HOME, ".procmon-rules.d")
    if not os.path.isdir(root):
        return []
    out = []
    for name in os.listdir(root):
        if not name.endswith(".json"):
            continue
        try:
            with open(os.path.join(root, name)) as f:
                data = _j.load(f)
            if isinstance(data, dict):
                out.append(data)
            elif isinstance(data, list):
                out.extend(d for d in data if isinstance(d, dict))
        except (OSError, ValueError):
            continue
    return out


def _evaluate_rule(rule):
    """Evaluate a single rule. Returns a finding dict (fires) or None."""
    kind = rule.get("kind")
    params = rule.get("params") or {}
    sev = rule.get("severity", "INFO")
    msg = rule.get("message", "(unnamed rule)")
    if kind == "path_exists":
        path = params.get("path", "")
        if path and os.path.exists(path):
            return {"severity": sev, "message": f"[{rule.get('id', '')}] {msg}",
                    "evidence": f"path: {path}", "action": None}
        return None
    if kind == "file_mode":
        import stat
        path = params.get("path", "")
        forbid = params.get("forbid_mode_bits", 0)
        if path and os.path.exists(path):
            try:
                st = os.stat(path)
            except OSError:
                return None
            mode = stat.S_IMODE(st.st_mode)
            if mode & forbid:
                return {"severity": sev,
                        "message": f"[{rule.get('id', '')}] {msg}",
                        "evidence": f"{path} mode={oct(mode)}",
                        "action": None}
        return None
    if kind == "launch_item_signer":
        deny = set(params.get("deny_team_ids") or [])
        if not deny:
            return None
        hits = []
        for it in _enumerate_launch_items():
            if not it["program"] or not os.path.exists(it["program"]):
                continue
            cs = _codesign_structured(it["program"])
            team = cs.get("team_id", "") if cs else ""
            if team and team in deny:
                hits.append(f"{it['label']} ({team})")
        if hits:
            return {"severity": sev,
                    "message": f"[{rule.get('id', '')}] {msg}",
                    "evidence": "\n".join(hits[:10]),
                    "action": None}
        return None
    if kind == "sysctl_value":
        name = params.get("name", "")
        expected = str(params.get("equals", ""))
        rc, out, _ = _run_cmd_short(["sysctl", "-n", name], timeout=5)
        if rc != 0 or not out:
            return None
        actual = out.strip()
        if actual == expected:
            return {"severity": sev,
                    "message": f"[{rule.get('id', '')}] {msg}",
                    "evidence": f"{name} = {actual}",
                    "action": None}
        return None
    return None


def _audit_rule_engine():
    """Run the default + user rule set (finding #18)."""
    rules = list(_DEFAULT_RULES) + _load_custom_rules()
    findings = []
    for rule in rules:
        try:
            f = _evaluate_rule(rule)
        except Exception:
            continue
        if f:
            findings.append(f)
    if not findings:
        findings.append({"severity": "OK",
                         "message": f"No rule hits ({len(rules)} rules evaluated)",
                         "action": None})
    return findings


# Per-layer classification for the scoring pass (finding #10).
_LAYER_FOR_AUDIT = {
    "network": "Network",
    "dns": "Network",
    "persistence": "Library",
    "system_hardening": "System",
    "kernel_boot": "Kernel",
    "patch_posture": "System",
    "tcc": "Library",
    "browser_exts": "Library",
    "usb_hid": "Library",
    "shell_dotfiles": "Library",
    "installed_software": "Library",
    "process_entitlements": "Library",
    "filesystem_integrity": "System",
    "sensitive_paths_delta": "System",
    "keychain": "System",
    "auth_stack": "System",
    "packages": "Library",
    "baseline_delta": "System",
    "rule_engine": "Library",
}

_LAYER_WEIGHT = {"Network": 0.25, "System": 0.30, "Kernel": 0.25, "Library": 0.20}
_SEVERITY_PENALTY = {"CRITICAL": 30, "HIGH": 15, "MEDIUM": 6, "INFO": 0, "OK": 0}


def _score_findings(results_by_audit):
    """Compute per-layer scores + global weighted score.

    `results_by_audit`: {audit_key: [finding, ...]}
    Returns: {"layers": {name: score}, "global": int,
              "fix_first": [(audit_key, finding), ...]}
    """
    layer_penalty = {"Network": 0, "System": 0, "Kernel": 0, "Library": 0}
    fix_first = []
    for audit_key, findings in results_by_audit.items():
        layer = _LAYER_FOR_AUDIT.get(audit_key, "Library")
        for f in findings:
            pen = _SEVERITY_PENALTY.get(f.get("severity", "INFO"), 0)
            layer_penalty[layer] += pen
            if f.get("severity") in ("CRITICAL", "HIGH") and f.get("action"):
                fix_first.append((audit_key, f))
    layers = {name: max(0, 100 - layer_penalty[name]) for name in layer_penalty}
    global_score = 0.0
    for name, weight in _LAYER_WEIGHT.items():
        global_score += layers[name] * weight
    # Fix-first priority: severity × reversibility (actions are reversible)
    sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3, "OK": 4}
    fix_first.sort(key=lambda item: (
        sev_rank.get(item[1].get("severity", "INFO"), 99),
        item[1].get("message", "")))
    return {"layers": layers,
            "global": int(round(global_score)),
            "fix_first": fix_first}


def _severity_band(score):
    """Color-coded band label for a 0–100 score."""
    if score >= 85:
        return "GREEN"
    if score >= 60:
        return "YELLOW"
    if score >= 40:
        return "ORANGE"
    return "RED"


def _audit_global_score():
    """Run every audit, compute per-layer + global score, return report lines.

    This is the Fix-First view the user enters with the `A` key.
    """
    audits_to_run = [
        ("network", _audit_network_exposure),
        ("dns", _audit_dns_proxy_mdm),
        ("persistence", _audit_persistence),
        ("system_hardening", _audit_system_hardening),
        ("kernel_boot", _audit_kernel_boot),
        ("patch_posture", _audit_patch_posture),
        ("tcc", _audit_tcc_grants),
        ("browser_exts", _audit_browser_extensions),
        ("usb_hid", _audit_usb_hid),
        ("shell_dotfiles", _audit_shell_dotfiles),
        ("installed_software", _audit_installed_software),
        ("process_entitlements", _audit_process_entitlements),
        ("filesystem_integrity", _audit_filesystem_integrity),
        ("sensitive_paths_delta", _audit_sensitive_paths_delta),
        ("keychain", _audit_keychain_credentials),
        ("auth_stack", _audit_authentication_stack),
        ("packages", _audit_package_managers),
        ("baseline_delta", _audit_baseline_delta),
        ("rule_engine", _audit_rule_engine),
    ]
    results = {}
    for key, fn in audits_to_run:
        try:
            results[key] = fn()
        except Exception as e:
            results[key] = [{"severity": "INFO",
                             "message": f"[{key}] audit error: {e}",
                             "action": None}]
    score = _score_findings(results)

    # Build finding-style output so the global score plugs into the audit UI.
    findings = []
    band = _severity_band(score["global"])
    findings.append({
        "severity": {"GREEN": "OK", "YELLOW": "MEDIUM",
                     "ORANGE": "HIGH", "RED": "CRITICAL"}[band],
        "message": (f"Global security score: {score['global']}/100 [{band}]"),
        "evidence": (
            f"Network: {score['layers']['Network']}\n"
            f"System:  {score['layers']['System']}\n"
            f"Kernel:  {score['layers']['Kernel']}\n"
            f"Library: {score['layers']['Library']}"),
        "action": None,
    })
    # Fix-First list
    if score["fix_first"]:
        findings.append({
            "severity": "HIGH",
            "message": f"Fix First ({len(score['fix_first'])} items)",
            "action": None,
        })
        for audit_key, f in score["fix_first"][:20]:
            ff = dict(f)
            ff["message"] = f"[{audit_key}] {f['message']}"
            findings.append(ff)
    else:
        findings.append({"severity": "OK",
                         "message": "No HIGH/CRITICAL actionable findings",
                         "action": None})
    # Per-audit totals
    for key, findings_list in results.items():
        by_sev = {}
        for f in findings_list:
            by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
        summary = ", ".join(f"{s}:{c}" for s, c in sorted(by_sev.items()))
        findings.append({
            "severity": "INFO",
            "message": f"{key}: {summary}",
            "action": None,
        })
    return findings


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
        # Hidden process detection state
        self._hidden_pids = set()
        self._hidden_alert_count = 0
        self._hidden_scan_mode = False
        self._hidden_scan_lines = []
        self._hidden_scan_scroll = 0
        self._hidden_scan_worker = None
        self._hidden_scan_pending = None
        self._hidden_scan_loading = False
        self._last_hidden_check = 0.0
        # Bulk security scan state
        self._bulk_scan_mode = False
        self._bulk_scan_lines = []
        self._bulk_scan_scroll = 0
        self._bulk_scan_worker = None
        self._bulk_scan_pending = None
        self._bulk_scan_loading = False
        self._bulk_scan_progress = (0, 0)  # (completed, total)
        self._bulk_scan_cancel = False
        # Live findings accumulated during a bulk scan (thread-safe via
        # _bulk_scan_live_lock). Rendered underneath the progress bar so the
        # user has something to read while the scan runs.
        self._bulk_scan_live = []
        self._bulk_scan_live_lock = threading.Lock()
        self._bulk_scan_current = ""  # short label of the process being worked on
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
        self._chat_context_label = ""  # shown in the chat title
        self._chat_context_text = ""   # full context string fed into the prompt
        # Keyboard-hook / keylogger detection state
        self._keyscan_mode = False
        self._keyscan_lines = []
        self._keyscan_scroll = 0
        self._keyscan_worker = None
        self._keyscan_pending = None
        self._keyscan_loading = False
        # Structured view of the current scan; each entry is a dict with
        # keys {severity, message, action}. `action` is None when the
        # finding is informational; otherwise the UI's `D` handler
        # dispatches on its `type`.
        self._keyscan_findings_structured = []
        self._keyscan_line_for_finding = []
        self._keyscan_cursor = 0        # index into _keyscan_findings_structured
        # Structured result of the most recent action. `level` is "ok" /
        # "error" / "info"; `summary` is a short headline; `detail_lines`
        # is pre-wrapped multi-line text that gets rendered in its own
        # bordered panel above the findings list.
        self._keyscan_action_result = None  # None = no recent action
        # LLM-generated executive summaries rendered above each finding list.
        # Stored per-view so switching modes doesn't lose context. The *_pending
        # slot is written by the background worker and consumed by the poll
        # helper; *_loading drives a "thinking…" indicator in the UI.
        self._llm_summary = {
            "audit": None, "keyscan": None, "hidden": None,
            "inspect": None, "events": None,
        }
        self._llm_summary_pending = {
            "audit": None, "keyscan": None, "hidden": None,
            "inspect": None, "events": None,
        }
        self._llm_summary_loading = {
            "audit": False, "keyscan": False, "hidden": False,
            "inspect": False, "events": False,
        }
        self._llm_summary_worker = {
            "audit": None, "keyscan": None, "hidden": None,
            "inspect": None, "events": None,
        }
        # Host security audits (network / dns / persistence)
        self._audit_mode = False
        self._audit_type = None           # "network" | "dns" | "persistence"
        self._audit_lines = []
        self._audit_scroll = 0
        self._audit_worker = None
        self._audit_pending = None
        self._audit_loading = False
        self._audit_findings_structured = []
        self._audit_line_for_finding = []
        self._audit_cursor = 0
        self._audit_action_result = None
        # Live event stream state
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
        # ── Traffic Inspector (mitmproxy wrapper) ──────────────────────
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

    _CONFIG_PATH = os.path.expanduser("~/.procmon.json")

    def _load_config(self):
        """Load saved config from ~/.procmon.json if it exists."""
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
        """Save current config to ~/.procmon.json."""
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

        # Compute net rates first so they're available for tree aggregation
        net_snap = get_net_snapshot()
        now = time.monotonic()
        if self.prev_net and self.prev_time:
            dt = now - self.prev_time
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
        for p in all_procs:
            rates = self.net_rates.get(p["pid"])
            p["net_in"] = rates[0] if rates else -1
            p["net_out"] = rates[1] if rates else -1
            snap = net_snap.get(p["pid"])
            p["bytes_in"] = snap[0] if snap else 0
            p["bytes_out"] = snap[1] if snap else 0

        matched = [p for p in all_procs
                   if p["pid"] not in _PHANTOM_TREE_PARENTS
                   and (not self.patterns or any(pat in p["command"].lower() for pat in self.patterns))
                   and not any(pat in p["command"].lower() for pat in self.exclude_patterns)]

        _build = build_vendor_tree if self._vendor_grouped else build_tree
        tree = _build(matched, all_procs, self._sort_key(), self._sort_reverse())
        flat = flatten_tree(tree, self._expanded)
        all_display_pids = [r["pid"] for r in flat]

        fd_map = {} if self.skip_fd else get_fd_counts(all_display_pids)
        cwd_map = get_cwds(all_display_pids)

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
        self._put(y, x, " procmon ", curses.color_pair(1) | curses.A_BOLD)
        x = 9
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
            tc = sum(r["cpu"] for r in self.rows)
            tm = sum(r["rss_kb"] for r in self.rows)
            tf = sum(r["fds"] for r in self.rows if r["fds"] >= 0)
            tt = sum(r["threads"] for r in self.rows)
            ti = sum(r["net_in"] for r in self.rows if r["net_in"] >= 0)
            to_ = sum(r["net_out"] for r in self.rows if r["net_out"] >= 0)
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
            return

        # ── Compute detail box content and height ──
        if self._inspect_mode:
            if self._inspect_lines:
                detail_all_lines = list(self._inspect_lines)
                summary = (self._llm_summary.get("inspect")
                           or self._llm_summary_loading_banner("inspect"))
                if summary:
                    detail_all_lines = summary + detail_all_lines
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
        elif self._hidden_scan_mode:
            if self._hidden_scan_lines:
                detail_all_lines = list(self._hidden_scan_lines)
                summary = (self._llm_summary.get("hidden")
                           or self._llm_summary_loading_banner("hidden"))
                if summary:
                    detail_all_lines = summary + detail_all_lines
            elif self._hidden_scan_loading:
                detail_all_lines = [" Running deep hidden process scan\u2026"]
            else:
                detail_all_lines = [" No scan results"]
            detail_title = "Hidden Processes + Kernel Modules Scan"
            max_detail_h = max(8, (h - y) * 2 // 3)
            detail_h = min(len(detail_all_lines) + 2, max_detail_h)
        elif self._keyscan_mode:
            if self._keyscan_lines:
                # Build the panel first so we know how far it pushes the
                # findings down — the cursor arrow then lands on the
                # correct line.
                result = self._keyscan_action_result
                panel = []
                if result:
                    panel = self._format_action_panel(result, w - 6)
                detail_all_lines = list(self._keyscan_lines)
                # Overlay the cursor arrow on the selected finding's line.
                # All finding lines are shaped "    [x] [SEV]  msg" (4-space
                # indent) — replace the first 4 chars with "  \u25b6 ".
                cur_finding = None
                if self._keyscan_findings_structured and self._keyscan_line_for_finding:
                    cursor_idx = self._keyscan_cursor
                    if 0 <= cursor_idx < len(self._keyscan_line_for_finding):
                        line_idx = self._keyscan_line_for_finding[cursor_idx]
                        if line_idx < len(detail_all_lines):
                            original = detail_all_lines[line_idx]
                            if len(original) >= 4:
                                detail_all_lines[line_idx] = (
                                    "  \u25b6 " + original[4:])
                    if 0 <= cursor_idx < len(self._keyscan_findings_structured):
                        cur_finding = self._keyscan_findings_structured[cursor_idx]
                # Append the DETAIL pane for the cursored finding
                if cur_finding is not None:
                    detail_all_lines.extend(
                        self._format_finding_detail(cur_finding, w - 6))
                # Prepend AI SUMMARY panel
                summary = (self._llm_summary.get("keyscan")
                           or self._llm_summary_loading_banner("keyscan"))
                if summary:
                    detail_all_lines = summary + detail_all_lines
                detail_all_lines = panel + detail_all_lines
            elif self._keyscan_loading:
                detail_all_lines = [" Scanning event taps + TCC + Input Methods\u2026"]
            else:
                detail_all_lines = [" No scan results"]
            detail_title = "Keyboard Hook / Keylogger Scan"
            if self._keyscan_loading and self._keyscan_lines:
                detail_title = detail_title + " \u2014 rescanning\u2026"
            max_detail_h = max(8, (h - y) * 2 // 3)
            detail_h = min(len(detail_all_lines) + 2, max_detail_h)
        elif self._bulk_scan_mode:
            if self._bulk_scan_lines:
                # Final report rendered after scan completion
                detail_all_lines = list(self._bulk_scan_lines)
            elif self._bulk_scan_loading:
                done, total = self._bulk_scan_progress
                if total > 0:
                    pct = int(done * 100 / total)
                    bar_w = 40
                    filled = int(bar_w * done / total)
                    bar = "\u2588" * filled + "\u2591" * (bar_w - filled)
                    header = [
                        f" Bulk security scan \u2014 {done}/{total} ({pct}%)",
                        f" [{bar}]",
                    ]
                    if self._bulk_scan_current:
                        header.append(f" Last completed: {self._bulk_scan_current}")
                    header.append(" Press Esc or F to cancel.")
                    header.append("")
                    # Snapshot live findings so the user sees them streaming in
                    with self._bulk_scan_live_lock:
                        live_snapshot = list(self._bulk_scan_live)
                    if live_snapshot:
                        live_lines = [" Findings so far "
                                      f"({len(live_snapshot)} flagged):"]
                        # Sort worst-first so the CRITICAL items stay visible
                        live_snapshot.sort(
                            key=lambda f: (self._RISK_RANK.get(f[0], 99), f[1]))
                        for risk, pid, cmd, reasons, _ in live_snapshot[:40]:
                            path = _get_proc_path(pid) or (
                                cmd[:60] if cmd else "(no command)")
                            live_lines.append(f"  [{risk}] PID {pid}: {path}")
                            for r in reasons[:2]:
                                live_lines.append(f"      \u2022 {r}")
                        if len(live_snapshot) > 40:
                            live_lines.append(
                                f"  \u2026 ({len(live_snapshot) - 40} more)")
                    else:
                        live_lines = [" (no flagged processes yet)"]
                    detail_all_lines = header + live_lines
                else:
                    detail_all_lines = [" Starting bulk security scan\u2026"]
            else:
                detail_all_lines = [" No scan results"]
            detail_title = "Bulk Security Scan"
            # Use most of the remaining space so findings get room to breathe
            max_detail_h = max(10, (h - y) * 3 // 4)
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
                title_map = {"network": "network exposure",
                             "dns": "DNS / proxy / MDM",
                             "persistence": "persistence"}
                detail_all_lines = [f" Running {title_map.get(self._audit_type, self._audit_type or 'audit')} audit\u2026"]
            else:
                detail_all_lines = [" No audit results"]
            detail_title = self._AUDIT_SCANS.get(
                self._audit_type, (None, "Host Security Audit"))[1]
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
            detail_title = "Live Event Stream"
            if self._events_awaiting_summary:
                detail_title += " \u2014 stream stopped, Esc again to close"
            max_detail_h = max(8, (h - y) * 2 // 3)
            detail_h = min(len(detail_all_lines) + 2, max_detail_h)
        elif self._traffic_mode:
            detail_all_lines = self._format_traffic_view()
            detail_title = "Traffic Inspector (mitmproxy)"
            max_detail_h = max(8, (h - y) * 2 // 3)
            detail_h = min(len(detail_all_lines) + 2, max_detail_h)
        elif self._net_mode:
            if self._net_entries:
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
        elif self._hidden_scan_mode:
            scroll = self._hidden_scan_scroll
            sel_line = -1
        elif self._keyscan_mode:
            scroll = self._keyscan_scroll
            sel_line = -1
        elif self._bulk_scan_mode:
            scroll = self._bulk_scan_scroll
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
        elif self._net_mode:
            scroll = self._net_scroll
            sel_line = self._net_selected if self._detail_focus else -1
        else:
            scroll = 0
            sel_line = -1
        self._render_detail(detail_y, w, detail_all_lines, detail_title,
                            scroll, self._detail_focus, sel_line)

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

    def _col_header(self, w):
        sort_ind_c = "*" if self.sort_mode == SORT_CPU else " "
        sort_ind_m = "*" if self.sort_mode == SORT_MEM else " "
        sort_ind_n = "*" if self.sort_mode == SORT_NET else " "
        sort_ind_bi = "*" if self.sort_mode == SORT_BYTES_IN else " "
        sort_ind_bo = "*" if self.sort_mode == SORT_BYTES_OUT else " "
        right_parts = [f"{'PID':>7}", f"{'PPID':>7}", f"{'MEM':>8}{sort_ind_m}", f"{'CPU%':>6}{sort_ind_c}", f"{'THR':>4}"]
        if not self.skip_fd:
            right_parts.append(f"{'FDs':>5}")
        right_parts += [f"{'Forks':>6}", f"{'\u2193 In':>9}{sort_ind_n}", f"{'\u2191 Out':>10}",
                        f"{'\u2193Recv':>9}{sort_ind_bi}", f"{'\u2191Sent':>9}{sort_ind_bo}"]
        right = " ".join(right_parts)
        left_w = w - len(right) - 2
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

        net_in = r.get("net_in", -1)
        net_out = r.get("net_out", -1)
        net_line = f"Net: \u2193 {fmt_rate(net_in)}  \u2191 {fmt_rate(net_out)}"
        if has_ch:
            net_line += f"  [group: \u2193 {fmt_rate(agg_ni)}  \u2191 {fmt_rate(agg_no)}]"

        raw = [
            pid_line,
            mem_line,
            net_line,
            f"CWD: {r.get('cwd', '-')}",
            f"CMD: {r['command']}",
        ]

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
            elif self._hidden_scan_mode:
                shortcuts = [
                    ("\u2191\u2193", "Scroll"),
                    ("PgU/D", "Page"),
                    ("?", "Ask"),
                    ("H", "Close"),
                    ("Tab", "Procs"),
                    ("Esc", "Back"),
                    ("q", "Quit"),
                ]
            elif self._keyscan_mode:
                shortcuts = [
                    ("\u2191\u2193", "Select"),
                    ("D", "Remove"),
                    ("L", "Log"),
                    ("?", "Ask"),
                    ("Tab", "Procs"),
                    ("Esc", "Close"),
                    ("q", "Quit"),
                ]
            elif self._bulk_scan_mode:
                shortcuts = [
                    ("\u2191\u2193", "Scroll"),
                    ("PgU/D", "Page"),
                    ("?", "Ask"),
                    ("Esc", "Cancel/Close"),
                    ("Tab", "Procs"),
                    ("q", "Quit"),
                ]
            elif self._audit_mode:
                shortcuts = [
                    ("\u2191\u2193", "Select"),
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
            else:
                shortcuts = [
                    ("\u2191\u2193", "Select"),
                    ("k", "Kill"),
                    ("?", "Ask"),
                    ("N", "Close"),
                    ("Tab", "Procs"),
                    ("Esc", "Back"),
                    ("q", "Quit"),
                ]
        elif self._net_mode:
            shortcuts = [
                ("Tab", "Conns"),
                ("?", "Ask"),
                ("N", "Close"),
                ("Esc", "Back"),
                ("q", "Quit"),
            ]
        else:
            shortcuts = [
                ("s", "Sort"),
                ("F", "Forensic"),
                ("a", "Audits"),
                ("?", "Ask"),
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
            elif self._hidden_scan_mode:
                if key == curses.KEY_UP:
                    self._hidden_scan_scroll = max(0, self._hidden_scan_scroll - 1)
                elif key == curses.KEY_DOWN:
                    self._hidden_scan_scroll += 1
                elif key == curses.KEY_PPAGE:
                    self._hidden_scan_scroll = max(0, self._hidden_scan_scroll - self._page_size())
                elif key == curses.KEY_NPAGE:
                    self._hidden_scan_scroll += self._page_size()
                elif key == ord("H"):
                    self._toggle_hidden_scan_mode()
                elif key == ord("\t"):
                    self._detail_focus = False
                elif key == 27:
                    self._hidden_scan_mode = False
                    self._detail_focus = False
                elif key == ord("q"):
                    return False
                return True
            elif self._keyscan_mode:
                if key == curses.KEY_UP:
                    # Move the finding cursor up; fall back to scroll when
                    # we have no structured findings (older tests).
                    if self._keyscan_findings_structured:
                        self._keyscan_move_cursor(-1)
                    else:
                        self._keyscan_scroll = max(0, self._keyscan_scroll - 1)
                elif key == curses.KEY_DOWN:
                    if self._keyscan_findings_structured:
                        self._keyscan_move_cursor(1)
                    else:
                        self._keyscan_scroll += 1
                elif key == curses.KEY_PPAGE:
                    self._keyscan_scroll = max(0, self._keyscan_scroll - self._page_size())
                elif key == curses.KEY_NPAGE:
                    self._keyscan_scroll += self._page_size()
                elif key in (ord("D"), ord("d")):
                    # Remove the hook under the cursor (TCC grant, input
                    # method bundle, or CGEventTap owner process)
                    self._keyscan_remove_current()
                elif key == ord("\t"):
                    self._detail_focus = False
                elif key == 27:
                    self._keyscan_mode = False
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
            elif self._bulk_scan_mode:
                if key == curses.KEY_UP:
                    self._bulk_scan_scroll = max(0, self._bulk_scan_scroll - 1)
                elif key == curses.KEY_DOWN:
                    self._bulk_scan_scroll += 1
                elif key == curses.KEY_PPAGE:
                    self._bulk_scan_scroll = max(0, self._bulk_scan_scroll - self._page_size())
                elif key == curses.KEY_NPAGE:
                    self._bulk_scan_scroll += self._page_size()
                elif key == ord("F"):
                    self._toggle_bulk_scan_mode()
                elif key == ord("\t"):
                    self._detail_focus = False
                elif key == 27:
                    self._bulk_scan_cancel = True
                    self._bulk_scan_mode = False
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
                    self._kill_net_connection()
                elif key == ord("N"):
                    self._toggle_net_mode()
                elif key == ord("\t"):
                    self._detail_focus = False
                elif key == 27:  # Escape — close net mode
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
        elif key == ord("N"):
            self._toggle_net_mode()
        elif key == ord("I"):
            self._toggle_inspect_mode()
        elif key == ord("H"):
            self._toggle_hidden_scan_mode()
        elif key == ord("a"):
            self._prompt_audit()
        elif key == ord("\t"):
            if (self._inspect_mode or self._hidden_scan_mode or self._net_mode
                    or self._bulk_scan_mode or self._events_mode
                    or self._keyscan_mode or self._audit_mode
                    or self._traffic_mode):
                self._detail_focus = True
        elif key == ord("C"):  # Shift+C — alert config
            self._prompt_config()
        elif key == ord("f"):
            self._prompt_filter()
        elif key == ord("k"):
            self._kill_selected()
        elif key == 27:  # Escape
            if self._inspect_mode:
                self._inspect_mode = False
                self._detail_focus = False
            elif self._hidden_scan_mode:
                self._hidden_scan_mode = False
                self._detail_focus = False
            elif self._keyscan_mode:
                self._keyscan_mode = False
                self._detail_focus = False
            elif self._bulk_scan_mode:
                self._bulk_scan_cancel = True
                self._bulk_scan_mode = False
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

    def _kill_net_connection(self):
        """Kill the process owning the selected network connection."""
        if not self._net_entries or self._net_selected >= len(self._net_entries):
            return
        entry = self._net_entries[self._net_selected]
        pid = entry["pid"]
        if pid <= 0:
            return
        try:
            os.kill(pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        # Refresh connections in background
        self._start_net_fetch(self._net_pid)

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
        self._hidden_scan_mode = False
        self._bulk_scan_mode = False
        if getattr(self, "_keyscan_mode", False):
            self._keyscan_mode = False
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

    # ── Hidden Process Detection ──────────────────────────────────────────

    def _deep_hidden_scan(self):
        """Comprehensive hidden process detection. Runs in background thread."""
        findings = []
        libproc_pids = set(_list_all_pids())
        own_pid = os.getpid()

        # 1. ps cross-reference
        ps_hidden = _check_hidden_pids_quick(list(libproc_pids))
        if ps_hidden:
            findings.append("\u2500\u2500 ps vs libproc discrepancies \u2500\u2500")
            for pid in sorted(ps_hidden):
                findings.append(f"  [!] PID {pid}: visible to ps but NOT to proc_listallpids()")
            findings.append("")

        # 2. Network cross-reference
        net_pids = _check_hidden_pids_network()
        net_hidden = net_pids - libproc_pids
        net_hidden.discard(0)
        net_hidden.discard(own_pid)
        if net_hidden:
            findings.append("\u2500\u2500 Network-visible but libproc-invisible \u2500\u2500")
            for pid in sorted(net_hidden):
                findings.append(f"  [!] PID {pid}: has network connections but not in proc_listallpids()")
            findings.append("")

        # 3. PID brute-force: try proc_pidinfo on PIDs 1..max_pid
        max_pid_val = 99999
        try:
            proc = subprocess.Popen(["sysctl", "-n", "kern.maxproc"],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, _ = proc.communicate(timeout=3)
            max_pid_val = min(int(stdout.strip()), 99999)
        except Exception:
            pass

        brute_hidden = set()
        local_bsdinfo = proc_bsdinfo()
        for test_pid in range(1, max_pid_val + 1):
            if test_pid == own_pid or test_pid in libproc_pids:
                continue
            ret = _libproc.proc_pidinfo(
                test_pid, PROC_PIDTBSDINFO, 0,
                ctypes.byref(local_bsdinfo), ctypes.sizeof(local_bsdinfo))
            if ret > 0:
                brute_hidden.add(test_pid)

        if brute_hidden:
            findings.append("\u2500\u2500 PID brute-force: respond to proc_pidinfo but not listed \u2500\u2500")
            for pid in sorted(brute_hidden):
                path = _get_proc_path(pid) or "[unknown]"
                findings.append(f"  [!] PID {pid}: {path}")
            findings.append("")

        # 4. Verify binary paths exist
        findings.append("\u2500\u2500 Binary path verification \u2500\u2500")
        missing_count = 0
        for pid in sorted(libproc_pids):
            if pid <= 0 or pid == own_pid:
                continue
            path = _get_proc_path(pid)
            if path and not os.path.exists(path):
                findings.append(f"  [!] PID {pid}: binary missing at {path}")
                missing_count += 1
        if missing_count == 0:
            findings.append("  All binary paths verified OK")
        findings.append("")

        # 5. Orphaned PPID check
        findings.append("\u2500\u2500 Orphaned PPID check \u2500\u2500")
        orphan_count = 0
        local_info = proc_bsdinfo()
        for pid in sorted(libproc_pids):
            if pid <= 0 or pid == own_pid:
                continue
            ret = _libproc.proc_pidinfo(
                pid, PROC_PIDTBSDINFO, 0,
                ctypes.byref(local_info), ctypes.sizeof(local_info))
            if ret > 0:
                ppid = local_info.pbi_ppid
                if ppid > 1 and ppid not in libproc_pids:
                    path = _get_proc_path(pid) or "[unknown]"
                    findings.append(f"  [!] PID {pid} ({path}): PPID {ppid} does not exist")
                    orphan_count += 1
        if orphan_count == 0:
            findings.append("  No orphaned PPIDs found")
        findings.append("")

        # 6. Kernel-extension cross-reference (IOKit vs kmutil)
        findings.append("\u2500\u2500 Kernel module cross-reference \u2500\u2500")
        kext_findings = _find_hidden_kexts()
        if kext_findings:
            for severity, msg in kext_findings:
                findings.append(f"  [{severity}] {msg}")
        else:
            findings.append("  No kext inconsistencies detected")
        findings.append("")

        # 7. System extensions (user-space replacements for kexts)
        findings.append("\u2500\u2500 System extensions \u2500\u2500")
        sysexts = _list_system_extensions()
        if sysexts:
            for s in sysexts:
                flag = "[!]" if s.get("state") and "waiting" in s["state"] else "   "
                findings.append(
                    f"  {flag} team={s['team_id']:<12} "
                    f"bundle={s['bundle_id']} state={s['state']}")
        else:
            findings.append("  (none installed, or systemextensionsctl unavailable)")
        findings.append("")

        # 8. Live kernel hook detection limitation notice
        # Per the synthesi research, live syscall/trap-table integrity checks
        # are blocked by SIP/KTRR on modern macOS. Document it instead of
        # pretending to check.
        findings.append("\u2500\u2500 Live kernel-hook detection \u2500\u2500")
        findings.append(
            "  [skipped] /dev/kmem is gone; task_for_pid(kernel_task) needs")
        findings.append(
            "  a debug-signed entitlement. Use KDK+lldb on a captured")
        findings.append("  kernelcore for offline syscall/trap-table analysis.")
        findings.append("")

        # Summary
        total = (len(ps_hidden) + len(net_hidden) + len(brute_hidden)
                 + missing_count + orphan_count + len(kext_findings))
        findings.insert(0,
            f"Deep scan complete: {total} finding(s) "
            f"across processes + kernel modules")
        findings.insert(1, "")
        return findings

    def _toggle_hidden_scan_mode(self):
        """Toggle deep hidden process scan mode (H key)."""
        if self._hidden_scan_mode:
            self._hidden_scan_mode = False
            self._detail_focus = False
            return
        self._hidden_scan_lines = []
        self._hidden_scan_scroll = 0
        self._hidden_scan_mode = True
        self._llm_summary["hidden"] = None
        self._llm_summary_pending["hidden"] = None
        self._llm_summary_loading["hidden"] = False
        self._inspect_mode = False
        self._bulk_scan_mode = False
        if getattr(self, "_keyscan_mode", False):
            self._keyscan_mode = False
        if getattr(self, "_events_mode", False):
            self._stop_events_stream()
            self._events_mode = False
        self._net_mode = False
        self._detail_focus = True
        self._hidden_scan_loading = True
        self._start_hidden_scan()

    def _start_hidden_scan(self):
        """Launch background thread for deep hidden process scan."""
        if self._hidden_scan_worker and self._hidden_scan_worker.is_alive():
            return
        self._hidden_scan_loading = True
        self._hidden_scan_pending = None

        def _worker():
            try:
                result = self._deep_hidden_scan()
            except Exception as e:
                result = [f"[Scan error: {e}]"]
            self._hidden_scan_pending = result

        self._hidden_scan_worker = threading.Thread(target=_worker, daemon=True)
        self._hidden_scan_worker.start()

    def _poll_hidden_scan_result(self):
        """Check if background hidden scan completed."""
        if self._hidden_scan_pending is None:
            return False
        if not self._hidden_scan_mode:
            self._hidden_scan_pending = None
            self._hidden_scan_loading = False
            return False
        self._hidden_scan_lines = self._hidden_scan_pending
        self._hidden_scan_pending = None
        self._hidden_scan_loading = False
        # Kick off the AI summary. Hidden-scan output is raw text, so we wrap
        # each non-blank line as a pseudo-finding for the summarizer.
        pseudo = []
        for ln in self._hidden_scan_lines:
            s = ln.strip()
            if not s or s.startswith(("\u2500", "\u2501", "==", "--")):
                continue
            sev = ("HIGH" if ("[!]" in s or "brute-force" in s
                              or "not in proc_listallpids" in s)
                   else "INFO")
            pseudo.append({"severity": sev, "message": s[:200], "action": None})
        self._start_llm_summary(
            "hidden", "Hidden processes + kernel modules scan", pseudo)
        return True

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

    def _format_llm_summary_panel(self, text, width=120):
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
                lines.append(f"    [CRITICAL]  {body}")
            elif s.strip().startswith("SIGNAL:"):
                body = s.strip()[len("SIGNAL:"):].strip()
                lines.append(f"    [HIGH]  {body}")
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

        `scope` is one of: "audit", "keyscan", "hidden", "inspect", "events".
        """
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
                resp = self._run_llm(
                    "claude", self._LLM_SUMMARY_PROMPT, body, timeout=60)
                if resp.startswith("["):  # error-tagged string
                    self._llm_summary_pending[scope] = [
                        f"  \u2501\u2501 AI SUMMARY \u2501\u2501",
                        "",
                        f"    [INFO]  Summary unavailable: "
                        f"{resp[:120]}",
                        ""]
                else:
                    self._llm_summary_pending[scope] = (
                        self._format_llm_summary_panel(resp))
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

    def _format_keyscan_report(self, findings):
        """Format keyboard-hook scan findings, sorted worst-first.

        Delegates to `_format_structured_report` so the layout matches the
        host-audit views. Accepts the legacy `(severity, message)` tuple
        form too for backward compat with older tests.
        """
        # Normalize + stash structured view for the UI to act on
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
        self._keyscan_findings_structured = normalized
        self._keyscan_line_for_finding = []
        return self._format_structured_report(
            title="Keyboard hook / keylogger scan",
            findings=normalized,
            line_map=self._keyscan_line_for_finding,
            empty_message="No keyboard-hook signals detected.",
            subtitle=("Signal sources: CGEventTaps + TCC grants + "
                      "Input Methods + Secure Keyboard Entry"))

    def _toggle_keyscan_mode(self):
        """Toggle keyboard-hook / keylogger scan."""
        if self._keyscan_mode:
            self._keyscan_mode = False
            self._detail_focus = False
            return
        self._keyscan_lines = []
        self._keyscan_scroll = 0
        self._keyscan_mode = True
        self._llm_summary["keyscan"] = None
        self._llm_summary_pending["keyscan"] = None
        self._llm_summary_loading["keyscan"] = False
        self._inspect_mode = False
        self._hidden_scan_mode = False
        self._bulk_scan_mode = False
        self._net_mode = False
        if getattr(self, "_events_mode", False):
            self._stop_events_stream()
            self._events_mode = False
        self._detail_focus = True
        self._keyscan_loading = True
        self._start_keyscan()

    def _start_keyscan(self):
        """Launch background thread for the keyboard-hook scan."""
        if self._keyscan_worker and self._keyscan_worker.is_alive():
            return
        self._keyscan_loading = True
        self._keyscan_pending = None

        def _worker():
            try:
                findings = _scan_keyboard_hooks()
                lines = self._format_keyscan_report(findings)
            except Exception as e:
                lines = [f"[keyboard-hook scan error: {e}]"]
            self._keyscan_pending = lines

        self._keyscan_worker = threading.Thread(target=_worker, daemon=True)
        self._keyscan_worker.start()

    def _poll_keyscan_result(self):
        """Return True when a pending keyscan result has been applied."""
        if self._keyscan_pending is None:
            return False
        if not self._keyscan_mode:
            self._keyscan_pending = None
            self._keyscan_loading = False
            return False
        self._keyscan_lines = self._keyscan_pending
        self._keyscan_pending = None
        self._keyscan_loading = False
        # Reset the cursor to the first actionable finding so the user
        # doesn't have to hunt for it after a rescan.
        self._keyscan_cursor = 0
        for i, f in enumerate(self._keyscan_findings_structured):
            if f.get("action"):
                self._keyscan_cursor = i
                break
        self._keyscan_scroll = 0
        self._scroll_keyscan_to_cursor()
        # Kick off AI summary (best-effort, async)
        self._start_llm_summary(
            "keyscan", "Keyboard hook / keylogger scan",
            self._keyscan_findings_structured)
        return True

    def _keyscan_move_cursor(self, delta):
        """Move the keyscan selection cursor. No-op if no structured data."""
        n = len(self._keyscan_findings_structured)
        if n == 0:
            return
        self._keyscan_cursor = max(0, min(n - 1, self._keyscan_cursor + delta))
        self._keyscan_action_result = None  # clear any lingering action result
        self._scroll_keyscan_to_cursor()

    # ── Host Security Audits (Network / DNS / Persistence) ──────────────

    _AUDIT_SCANS = {
        "network": (_audit_network_exposure,
                    "Network Exposure Audit"),
        "dns": (_audit_dns_proxy_mdm,
                "DNS / Proxy / MDM Audit"),
        "persistence": (_audit_persistence,
                        "Persistence Audit"),
        "system_hardening": (_audit_system_hardening,
                             "System Hardening / Trust Chain"),
        "kernel_boot": (_audit_kernel_boot,
                        "Kernel / Boot Integrity"),
        "patch_posture": (_audit_patch_posture,
                          "OS Patch Posture"),
        "tcc": (_audit_tcc_grants,
                "TCC Grants Audit"),
        "browser_exts": (_audit_browser_extensions,
                         "Browser Extensions Audit"),
        "usb_hid": (_audit_usb_hid,
                    "USB / HID Audit"),
        "shell_dotfiles": (_audit_shell_dotfiles,
                           "Shell Dotfile Scanner"),
        "installed_software": (_audit_installed_software,
                               "Installed Software Trust"),
        "process_entitlements": (_audit_process_entitlements,
                                 "Per-Process Entitlements"),
        "filesystem_integrity": (_audit_filesystem_integrity,
                                 "Filesystem Integrity"),
        "sensitive_paths_delta": (_audit_sensitive_paths_delta,
                                  "Sensitive Paths Delta (7d)"),
        "keychain": (_audit_keychain_credentials,
                     "Keychain & Credential Hygiene"),
        "auth_stack": (_audit_authentication_stack,
                       "Authentication Stack"),
        "packages": (_audit_package_managers,
                     "Package Manager Supply Chain"),
        "baseline_delta": (_audit_baseline_delta,
                           "Baseline Delta"),
        "rule_engine": (_audit_rule_engine,
                        "Rule Engine (Meta-Detector)"),
        "global_score": (_audit_global_score,
                         "Global Security Score / Fix-First"),
    }

    def _toggle_audit_mode(self, audit_type):
        """Enter a host-level audit. `audit_type` in {'network','dns','persistence'}."""
        if audit_type not in self._AUDIT_SCANS:
            return
        # Re-pressing the same audit key closes it; a different key switches.
        if self._audit_mode and self._audit_type == audit_type:
            self._audit_mode = False
            self._detail_focus = False
            return
        self._audit_type = audit_type
        self._audit_mode = True
        self._audit_lines = []
        self._audit_scroll = 0
        self._audit_action_result = None
        # Wipe any stale AI summary — we'll regenerate for the new audit.
        self._llm_summary["audit"] = None
        self._llm_summary_pending["audit"] = None
        self._llm_summary_loading["audit"] = False
        # Close mutually-exclusive modes
        self._inspect_mode = False
        self._hidden_scan_mode = False
        self._bulk_scan_mode = False
        self._keyscan_mode = False
        self._net_mode = False
        if getattr(self, "_events_mode", False):
            self._stop_events_stream()
            self._events_mode = False
        self._detail_focus = True
        self._audit_loading = True
        self._start_audit()

    def _start_audit(self):
        """Launch the background scan for the current audit_type."""
        if self._audit_worker and self._audit_worker.is_alive():
            return
        if self._audit_type not in self._AUDIT_SCANS:
            return
        scan_fn, _ = self._AUDIT_SCANS[self._audit_type]
        self._audit_loading = True
        self._audit_pending = None

        def _worker():
            try:
                findings = scan_fn()
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
        title = self._AUDIT_SCANS.get(
            self._audit_type, (None, "Host Security Audit"))[1]
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
        title = self._AUDIT_SCANS.get(
            self._audit_type, (None, "Host Security Audit"))[1]
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

    def _audit_remediate_current(self):
        """Dispatch the `D` key: confirm + remediate the finding under cursor."""
        finding = self._audit_current_finding()
        if not finding:
            self._audit_action_result = self._build_action_result(
                "info", "Nothing selected.")
            return
        action = finding.get("action")
        if not action:
            self._audit_action_result = self._build_action_result(
                "info",
                "This finding is informational — no auto-remediation.")
            return
        a_type = action.get("type")
        prompt_map = {
            "enable_alf": ("Turn on the Application Firewall?\n"
                           "  Runs: socketfilterfw --setglobalstate on"),
            "enable_alf_stealth": ("Enable firewall stealth mode?\n"
                                   "  Runs: socketfilterfw --setstealthmode on"),
            "disable_remote_login": (
                "Disable Remote Login (SSH)?\n"
                "  Runs: systemsetup -setremotelogin off"),
            "disable_sharing_service": (
                f"Stop service {action.get('service','')}?\n"
                f"  Runs: launchctl disable system/{action.get('service','')}"),
            "remove_profile": (
                f"Remove configuration profile?\n"
                f"  identifier: {action.get('identifier','')}\n"
                f"  Runs: profiles remove -identifier <id>"),
            "flush_dns": (
                "Flush DNS cache?\n"
                "  Runs: dscacheutil -flushcache; killall -HUP mDNSResponder"),
            "restore_hosts": (
                "Quarantine /etc/hosts and restore a stock file?\n"
                "  Original will be saved in ~/.procmon-quarantine"),
            "bootout_launchitem": (
                f"Bootout and quarantine this launch item?\n"
                f"  plist:  {action.get('plist_path','')}\n"
                f"  label:  {action.get('label','')}\n"
                f"  domain: {action.get('domain','')}\n"
                f"Plist will be moved to ~/.procmon-quarantine/"),
            "kill_process": (
                f"SIGTERM the owning process?\n"
                f"  pid: {action.get('pid')}\n"
                f"  exe: {action.get('exe','(unknown)')}"),
            "capture_baseline": (
                f"Snapshot host state to ~/.procmon-baseline.json?\n"
                f"Subsequent baseline-delta audits will diff against it."),
            "run_software_update": (
                "Install all pending macOS updates?\n"
                "  Runs: softwareupdate --install --all\n"
                "  May take several minutes; reboot may be required."),
            "enable_gatekeeper": (
                "Enable Gatekeeper?\n  Runs: spctl --master-enable"),
        }
        prompt = prompt_map.get(a_type) or f"Run remediation '{a_type}'?"

        if not self._confirm_action(prompt):
            self._audit_action_result = self._build_action_result(
                "info", "Cancelled.")
            return

        ok, msg = self._dispatch_audit_action(action)
        if ok:
            self._audit_action_result = self._build_action_result(
                "ok", f"Remediated: {msg}")
            # Optimistically remove the remediated row from the on-screen list
            # so the user sees immediate feedback. The background rescan we
            # kick off next will replace the list with a fresh snapshot when
            # it finishes — for the global-score audit that can take 30+
            # seconds, so without this the user thinks the fix didn't stick.
            self._audit_remove_current_finding()
            self._start_audit()
            return
        detail = (f"Remediation failed.\n\nRaw error:\n  {msg}\n\n"
                  f"Press L to see the full debug log.")
        self._audit_action_result = self._build_action_result(
            "error", f"Could not remediate ({a_type})", detail)

    def _audit_remove_current_finding(self):
        """Drop the cursored finding from the visible list and re-render.

        Used for optimistic UI updates after a successful remediation. The
        background rescan replaces the list when it completes; this keeps
        the user from staring at stale data in the meantime.
        """
        if not self._audit_findings_structured:
            return
        idx = self._audit_cursor
        if not (0 <= idx < len(self._audit_findings_structured)):
            return
        del self._audit_findings_structured[idx]

        # Re-build the display lines from the remaining findings. We reuse
        # the shared formatter, which also resets `_audit_line_for_finding`.
        title = self._AUDIT_SCANS.get(
            self._audit_type, (None, "Host Security Audit"))[1]
        self._audit_line_for_finding = []
        self._audit_lines = self._format_structured_report(
            title=title,
            findings=self._audit_findings_structured,
            line_map=self._audit_line_for_finding,
            empty_message="No findings.")

        # Keep the cursor on the next finding (or the previous one if we
        # just removed the last entry).
        n = len(self._audit_findings_structured)
        if idx >= n:
            idx = max(0, n - 1)
        self._audit_cursor = idx
        self._audit_scroll = 0
        self._scroll_audit_to_cursor()

    def _dispatch_audit_action(self, action):
        """Execute one remediation action. Returns (success, message).

        Covers the audit-specific actions. Shared types (kill_process,
        delete_tcc, remove_bundle) are delegated to _dispatch_keyscan_action.
        """
        a_type = action.get("type")
        self._log("ACTION", f"dispatching audit {a_type}: {action}")
        if a_type in ("kill_process", "delete_tcc", "remove_bundle"):
            return self._dispatch_keyscan_action(action)
        if a_type == "enable_alf":
            rc, out, err = _run_cmd_short(
                ["/usr/libexec/ApplicationFirewall/socketfilterfw",
                 "--setglobalstate", "on"], timeout=10)
            ok = rc == 0
            msg = (out or err or "").strip() or "ok"
            self._log("OK" if ok else "FAIL", f"enable_alf → {msg}")
            return ok, msg
        if a_type == "enable_alf_stealth":
            rc, out, err = _run_cmd_short(
                ["/usr/libexec/ApplicationFirewall/socketfilterfw",
                 "--setstealthmode", "on"], timeout=10)
            ok = rc == 0
            msg = (out or err or "").strip() or "ok"
            self._log("OK" if ok else "FAIL", f"enable_alf_stealth → {msg}")
            return ok, msg
        if a_type == "disable_remote_login":
            rc, out, err = _run_cmd_short(
                ["systemsetup", "-setremotelogin", "off"], timeout=15)
            ok = rc == 0
            msg = (out or err or "").strip() or "ok"
            self._log("OK" if ok else "FAIL",
                      f"disable_remote_login → {msg}")
            return ok, msg
        if a_type == "disable_sharing_service":
            svc = action.get("service", "")
            if not svc:
                return False, "missing service name"
            rc, out, err = _run_cmd_short(
                ["launchctl", "disable", f"system/{svc}"], timeout=10)
            ok = rc == 0
            msg = (out or err or "").strip() or "ok"
            self._log("OK" if ok else "FAIL",
                      f"disable_sharing_service {svc} → {msg}")
            return ok, msg
        if a_type == "remove_profile":
            ident = action.get("identifier", "")
            if not ident:
                return False, "missing identifier"
            rc, out, err = _run_cmd_short(
                ["profiles", "remove", "-identifier", ident], timeout=15)
            ok = rc == 0
            msg = (out or err or "").strip() or "ok"
            self._log("OK" if ok else "FAIL",
                      f"remove_profile {ident} → {msg}")
            return ok, msg
        if a_type == "flush_dns":
            rc1, o1, e1 = _run_cmd_short(
                ["dscacheutil", "-flushcache"], timeout=5)
            rc2, o2, e2 = _run_cmd_short(
                ["killall", "-HUP", "mDNSResponder"], timeout=5)
            ok = rc1 == 0 and rc2 == 0
            msg = (f"flushcache rc={rc1} / mDNSResponder rc={rc2}")
            self._log("OK" if ok else "FAIL", f"flush_dns → {msg}")
            return ok, msg
        if a_type == "bootout_launchitem":
            plist_path = action.get("plist_path", "")
            domain = action.get("domain", "system")
            if not plist_path or not os.path.exists(plist_path):
                return False, "plist not found"
            # launchctl bootout target is `<domain>` + the plist path
            domain_arg = {
                "system": "system",
                "gui": f"gui/{os.getuid()}",
                "user": f"user/{os.getuid()}",
            }.get(domain, "system")
            rc, out, err = _run_cmd_short(
                ["launchctl", "bootout", domain_arg, plist_path],
                timeout=10)
            # bootout returns non-zero if the item wasn't loaded; still proceed
            # to quarantine the plist so it doesn't re-load on next login.
            qok, qmsg = self._quarantine_file(plist_path)
            combined_ok = qok
            parts = [f"bootout rc={rc}"]
            parts.append(f"quarantine: {qmsg}")
            msg = "; ".join(parts)
            self._log("OK" if combined_ok else "FAIL",
                      f"bootout_launchitem → {msg}")
            return combined_ok, msg
        if a_type == "quarantine_plist":
            return self._quarantine_file(action.get("plist_path", ""))
        if a_type == "capture_baseline":
            try:
                snap = _collect_baseline_snapshot()
            except Exception as e:
                self._log("FAIL", f"capture_baseline → {e}")
                return False, f"snapshot failed: {e}"
            ok = _save_baseline(snap)
            msg = (f"wrote {_BASELINE_PATH}" if ok
                   else f"could not write {_BASELINE_PATH}")
            self._log("OK" if ok else "FAIL", f"capture_baseline → {msg}")
            return ok, msg
        if a_type == "run_software_update":
            rc, out, err = _run_cmd_short(
                ["softwareupdate", "--install", "--all"], timeout=300)
            ok = rc == 0
            msg = (out or err or "").strip()[:400] or "ok"
            self._log("OK" if ok else "FAIL", f"run_software_update → {msg}")
            return ok, msg
        if a_type == "enable_gatekeeper":
            rc, out, err = _run_cmd_short(
                ["spctl", "--master-enable"], timeout=10)
            ok = rc == 0
            msg = (out or err or "").strip() or "ok"
            self._log("OK" if ok else "FAIL", f"enable_gatekeeper → {msg}")
            return ok, msg
        if a_type == "restore_hosts":
            src = "/etc/hosts"
            if not os.path.exists(src):
                return False, "/etc/hosts not found"
            qok, qmsg = self._quarantine_file(src)
            if not qok:
                return False, qmsg
            stock = ("##\n# Host Database\n#\n"
                     "# localhost is used to configure the loopback interface\n"
                     "# when the system is booting.  Do not change this entry.\n"
                     "##\n127.0.0.1\tlocalhost\n255.255.255.255\tbroadcasthost\n"
                     "::1             localhost\n")
            try:
                with open(src, "w") as f:
                    f.write(stock)
            except (PermissionError, OSError) as e:
                return False, f"restore failed: {e}"
            return True, f"/etc/hosts quarantined and reset ({qmsg})"
        self._log("FAIL", f"unknown audit action: {a_type}")
        return False, f"unknown action: {a_type}"

    def _quarantine_file(self, path):
        """Move a file to ~/.procmon-quarantine/<timestamp>-<basename>.

        Returns (ok, message). Creates the quarantine dir on first use.
        """
        if not path or not os.path.exists(path):
            return False, "file not found"
        try:
            os.makedirs(_QUARANTINE_DIR, exist_ok=True)
        except OSError as e:
            return False, f"mkdir quarantine failed: {e}"
        ts = time.strftime("%Y%m%d-%H%M%S")
        dest = os.path.join(_QUARANTINE_DIR,
                            f"{ts}-{os.path.basename(path)}")
        try:
            shutil.move(path, dest)
        except (PermissionError, OSError) as e:
            return False, f"move failed: {e}"
        return True, f"moved to {dest}"

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
                    f"`sudo procmon` — but note that sudo alone won't "
                    f"fix this: SIP protects TCC.db from writes even for "
                    f"root.")
            lines.append("")
            lines.append("To remove TCC grants you need Full Disk Access on")
            lines.append("your terminal app (not on procmon itself):")
            lines.append("  System Settings → Privacy & Security →")
            lines.append("  Full Disk Access → add your terminal app")
            lines.append("  → quit and relaunch the terminal → retry")
            lines.append("")
        lines.append("Raw error:")
        lines.append(f"  {message}")
        lines.append("")
        lines.append("Press L to see the full debug log.")
        return "\n".join(lines)

    def _scroll_keyscan_to_cursor(self):
        """Adjust `_keyscan_scroll` so the current cursor is visible.

        Without this, Up/Down just moves the (invisible) cursor index while
        the viewport stays frozen at the top of the report — so the user
        can't see anything past the first few findings. Also accounts for
        the action-result panel that may occupy the top of the box.
        """
        if not self._keyscan_line_for_finding:
            return
        idx = self._keyscan_cursor
        if not (0 <= idx < len(self._keyscan_line_for_finding)):
            return
        panel_height = 0
        if self._keyscan_action_result:
            try:
                _, w = self.stdscr.getmaxyx()
            except Exception:
                w = 120
            panel_height = len(self._format_action_panel(
                self._keyscan_action_result, w - 6))
        summary = (self._llm_summary.get("keyscan")
                   or self._llm_summary_loading_banner("keyscan"))
        if summary:
            panel_height += len(summary)
        target_line = self._keyscan_line_for_finding[idx] + panel_height
        # The detail box is about 2/3 of the remaining screen height; this
        # is only an approximation because we don't have direct access to
        # the rendered inner_h here, but the detail renderer clamps scroll
        # anyway if we overshoot.
        try:
            h, _ = self.stdscr.getmaxyx()
        except Exception:
            h = 40
        # Conservative guess: the detail pane is roughly 2/3 of the screen.
        inner_h = max(4, h * 2 // 3 - 4)
        if target_line < self._keyscan_scroll:
            # Cursor moved above the viewport — scroll up so target is on top
            self._keyscan_scroll = max(0, target_line - 1)
        elif target_line >= self._keyscan_scroll + inner_h:
            # Cursor moved below — scroll down so target sits near the bottom
            self._keyscan_scroll = max(0, target_line - inner_h + 2)

    def _keyscan_current_finding(self):
        """The finding under the cursor, or None if there's nothing selected."""
        idx = self._keyscan_cursor
        if 0 <= idx < len(self._keyscan_findings_structured):
            return self._keyscan_findings_structured[idx]
        return None

    def _keyscan_remove_current_finding(self):
        """Optimistically drop the cursored keyscan finding and re-render."""
        if not self._keyscan_findings_structured:
            return
        idx = self._keyscan_cursor
        if not (0 <= idx < len(self._keyscan_findings_structured)):
            return
        del self._keyscan_findings_structured[idx]
        self._keyscan_line_for_finding = []
        self._keyscan_lines = self._format_structured_report(
            title="Keyboard hook / keylogger scan",
            findings=self._keyscan_findings_structured,
            line_map=self._keyscan_line_for_finding,
            empty_message="No keyboard-hook signals detected.",
            subtitle=("Signal sources: CGEventTaps + TCC grants + "
                      "Input Methods + Secure Keyboard Entry"))
        n = len(self._keyscan_findings_structured)
        if idx >= n:
            idx = max(0, n - 1)
        self._keyscan_cursor = idx
        self._keyscan_scroll = 0
        self._scroll_keyscan_to_cursor()

    def _keyscan_remove_current(self):
        """Dispatch the `D` key: confirm + remove the hooked entry.

        The user confirms via a modal prompt. After removal, a fresh scan
        runs so the list reflects the new state. No-op for informational
        entries (action=None). The outcome of the attempt is stored in
        `_keyscan_action_result` so the render loop can draw a dedicated
        wrapped-text panel instead of cramming a banner into a single line.
        """
        finding = self._keyscan_current_finding()
        if not finding:
            self._keyscan_action_result = self._build_action_result(
                "info", "Nothing selected.")
            return
        action = finding.get("action")
        if not action:
            self._keyscan_action_result = self._build_action_result(
                "info",
                "This finding is informational — nothing to remove.")
            return
        a_type = action.get("type")
        if a_type == "delete_tcc":
            prompt = (
                f"Delete TCC grant?\n"
                f"  client:  {action['client']}\n"
                f"  service: {action['service']}\n"
                f"  db:      {action['db']}\n"
                f"Requires Full Disk Access on this terminal.")
        elif a_type == "kill_process":
            prompt = (
                f"Kill the process that owns this CGEventTap?\n"
                f"  pid: {action['pid']}\n"
                f"  exe: {action.get('exe', '(unknown)')}")
        elif a_type == "remove_bundle":
            prompt = (
                f"Remove this Input Method bundle?\n"
                f"  path: {action['path']}\n"
                f"This will recursively delete the bundle directory.")
        else:
            self._keyscan_action_result = self._build_action_result(
                "error", f"Unknown action type: {a_type}")
            return

        if not self._confirm_action(prompt):
            self._keyscan_action_result = self._build_action_result(
                "info", "Cancelled.")
            return

        ok, msg = self._dispatch_keyscan_action(action)
        if ok:
            # Success — short summary, optimistic UI update, rescan
            self._keyscan_action_result = self._build_action_result(
                "ok", f"Removed: {msg}")
            self._keyscan_remove_current_finding()
            self._start_keyscan()
            return

        # Failure — build a rich, multi-line explanation
        if a_type == "delete_tcc":
            detail = self._sip_explanation(os.geteuid(), msg)
            summary = (f"Could not remove TCC grant for "
                       f"{action.get('client', '')}")
        elif a_type == "kill_process":
            detail = (f"Failed to SIGTERM PID {action.get('pid')}.\n\n"
                      f"Raw error:\n  {msg}\n\n"
                      f"Press L to see the full debug log.")
            summary = f"Could not kill PID {action.get('pid')}"
        elif a_type == "remove_bundle":
            detail = (f"Failed to remove bundle at "
                      f"{action.get('path')}.\n\nRaw error:\n  {msg}\n\n"
                      f"Press L to see the full debug log.")
            summary = "Could not remove bundle"
        else:
            detail = msg
            summary = "Action failed"

        self._keyscan_action_result = self._build_action_result(
            "error", summary, detail)

    def _dispatch_keyscan_action(self, action):
        """Execute one removal action. Returns (success, message).

        Every step is logged to the debug panel so the user can hit `L`
        and see exactly what was attempted.
        """
        a_type = action.get("type")
        self._log("ACTION", f"dispatching {a_type}: {action}")
        if a_type == "delete_tcc":
            ok, msg = _delete_tcc_grant(
                action["client"], action["service"], action["db"],
                logger=self._log)
            self._log("OK" if ok else "FAIL",
                      f"delete_tcc → {msg}")
            return ok, msg
        if a_type == "kill_process":
            pid = action["pid"]
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                self._log("FAIL", f"kill PID {pid}: process not found")
                return False, f"PID {pid} not found (already gone)"
            except PermissionError:
                self._log("FAIL", f"kill PID {pid}: permission denied")
                return False, f"permission denied killing PID {pid}"
            except OSError as e:
                self._log("FAIL", f"kill PID {pid}: {e}")
                return False, f"kill failed: {e}"
            self._log("OK", f"sent SIGTERM to PID {pid}")
            return True, f"sent SIGTERM to PID {pid}"
        if a_type == "remove_bundle":
            ok, msg = _remove_bundle(action["path"])
            self._log("OK" if ok else "FAIL", f"remove_bundle → {msg}")
            return ok, msg
        self._log("FAIL", f"unknown action type: {a_type}")
        return False, f"unknown action: {a_type}"

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

    # ── Bulk Security Scan (all processes) ──────────────────────────────

    _RISK_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

    def _heuristic_scan_process(self, proc):
        """Fast local heuristic scan of a single process. No LLMs, no fork-heavy calls.

        Returns (risk_level, reasons_list). Uses short subprocess calls with
        tight timeouts so bulk scanning stays responsive.
        """
        pid = proc["pid"]
        cmd = proc.get("command", "") or ""
        # Canonical executable path — proc_pidpath is the source of truth.
        # Falling back to cmd.split()[0] is unreliable because command strings
        # often contain unescaped spaces (e.g. "/Applications/Google Chrome").
        exe_path = _get_proc_path(pid) or ""

        reasons = []

        def _quick(cmd_argv, timeout=3):
            try:
                p = subprocess.Popen(cmd_argv, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE)
                try:
                    out, err = p.communicate(timeout=timeout)
                except subprocess.TimeoutExpired:
                    p.kill()
                    p.wait()
                    return None
                combined = (out + b"\n" + err).decode("utf-8", errors="replace")
                return (p.returncode, combined)
            except (FileNotFoundError, OSError):
                return None

        # 1. Binary path exists
        if exe_path.startswith("/") and not os.path.exists(exe_path):
            reasons.append(("CRITICAL", f"binary missing: {exe_path}"))

        # 2. Suspicious install location
        if exe_path.startswith("/tmp/") or exe_path.startswith("/private/tmp/"):
            reasons.append(("HIGH", f"binary in /tmp: {exe_path}"))
        elif exe_path.startswith("/var/folders/"):
            reasons.append(("MEDIUM", f"binary in /var/folders: {exe_path}"))

        # 3. Code signature
        if exe_path.startswith("/"):
            sig = _quick(["codesign", "-v", exe_path])
            if sig is not None:
                rc, txt = sig
                lower = txt.lower()
                if rc != 0:
                    if "code object is not signed" in lower or "not signed at all" in lower:
                        reasons.append(("HIGH", "unsigned binary"))
                    elif "invalid signature" in lower or "failed" in lower:
                        reasons.append(("HIGH", "invalid code signature"))
                    elif "adhoc" in lower or "ad-hoc" in lower:
                        reasons.append(("MEDIUM", "ad-hoc signed"))

        # 4. Suspicious DYLD env vars
        try:
            env = _get_proc_env(pid)
        except Exception:
            env = {}
        for k in env:
            if k in ("DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "DYLD_FRAMEWORK_PATH"):
                val = env[k]
                # Truncate for display
                short_val = val if len(val) < 60 else val[:57] + "..."
                reasons.append(("HIGH", f"{k}={short_val}"))

        # 5. Missing from libproc but visible to us (shouldn't happen — sanity)
        if pid in getattr(self, "_hidden_pids", set()):
            reasons.append(("CRITICAL", "appears hidden from proc_listallpids()"))

        # Structured signature used by the next two checks
        cs = {}
        if exe_path.startswith("/") and os.path.exists(exe_path):
            cs = _codesign_structured(exe_path) or {}
        is_apple_signed = _is_apple_signed(exe_path, cs)

        # 6. Gatekeeper / notarization (spctl). spctl's assess type is
        #    "execute" here; it rejects anything that isn't a bundled .app
        #    with the benign reason "the code is valid but does not seem to
        #    be an app". That's a type mismatch, not a security finding, so
        #    suppress it.  Real signing failures (invalid, revoked, unnotarized)
        #    still surface.
        if exe_path.startswith("/") and os.path.exists(exe_path):
            gate = _check_gatekeeper(exe_path)
            if gate and not gate.get("accepted"):
                reason_text = gate.get("reason") or "spctl reject"
                if "does not seem to be an app" not in reason_text \
                        and "the code is valid" not in reason_text:
                    reasons.append(("HIGH",
                        f"Gatekeeper rejected: {reason_text[:100]}"))

        # 7. Dangerous entitlements. Apple system binaries legitimately carry
        #    entitlements like allow-jit / allow-dyld-environment-variables
        #    (dyld itself, debugging tooling, etc.) — flagging them produces
        #    ~100 false positives on a typical root-run scan, so we only flag
        #    these on third-party binaries.
        if cs and not is_apple_signed:
            ent_set = _parse_entitlements_xml(cs.get("entitlements_xml", ""))
            for ent, desc in _DANGEROUS_ENTITLEMENTS.items():
                if ent in ent_set:
                    reasons.append(("HIGH",
                        f"entitlement {ent.split('.')[-1]}: {desc}"))

        # 8. Dylibs loaded from user-writable paths (injection vector)
        if exe_path.startswith("/") and os.path.exists(exe_path):
            rc, otool_out, _ = _run_cmd_short(
                ["otool", "-L", exe_path], timeout=5)
            if rc is not None:
                bad_dylibs = _otool_user_writable_dylibs(otool_out)
                for dylib in bad_dylibs[:3]:  # cap noise
                    reasons.append(("HIGH", f"dylib from user-writable path: {dylib}"))

        # 9. VirusTotal hash reputation — only when VT_API_KEY is configured
        if exe_path.startswith("/") and os.path.exists(exe_path) \
                and os.environ.get("VT_API_KEY"):
            rc, sha_out, _ = _run_cmd_short(
                ["shasum", "-a", "256", exe_path], timeout=5)
            if rc == 0 and sha_out:
                sha256 = sha_out.split()[0] if sha_out.split() else ""
                if len(sha256) == 64:
                    vt = _virustotal_lookup(sha256)
                    if vt and vt.get("found"):
                        mal = vt.get("malicious", 0)
                        susp = vt.get("suspicious", 0)
                        if mal >= 3:
                            threat = vt.get("popular_threat_name") or "multiple engines"
                            reasons.append(("CRITICAL",
                                f"VirusTotal: {mal} malicious ({threat})"))
                        elif mal > 0 or susp >= 3:
                            reasons.append(("HIGH",
                                f"VirusTotal: {mal} malicious / {susp} suspicious"))

        # 10. YARA match on the on-disk binary
        if exe_path.startswith("/") and os.path.exists(exe_path):
            yara_hits = _yara_scan_file(exe_path)
            for rule in yara_hits[:3]:  # cap noise
                reasons.append(("HIGH", f"YARA match: {rule}"))

        if not reasons:
            return "LOW", []
        worst = min(reasons, key=lambda r: self._RISK_RANK.get(r[0], 99))[0]
        return worst, [r[1] for r in reasons]

    def _bulk_scan_run(self, procs, max_workers=5, llm_confirm=True):
        """Bulk scan: every process goes through heuristics + 3 LLMs + consensus.

        Each work unit covers a single process end-to-end: heuristic pre-check,
        artifact collection, parallel Claude/Codex/Gemini analysis, and
        consensus synthesis. Progress ticks exactly once per process when that
        entire pipeline completes.

        Args:
            procs: list of process dicts
            max_workers: how many processes to pipeline concurrently. Each
                process internally fans out to 3 LLM CLIs, so the effective
                concurrent subprocess count is ~3x this.
            llm_confirm: if False, skip the LLM pass (heuristic-only mode).
                Used for fast standalone testing.

        Returns a list of (risk, pid, cmd, reasons_list, llm_report) tuples
        for processes with non-LOW risk. `llm_report` is None when llm_confirm
        is False, otherwise the synthesized consensus text.
        Honors `self._bulk_scan_cancel` for early termination.
        """
        from concurrent.futures import ThreadPoolExecutor, as_completed

        total = len(procs)
        self._bulk_scan_progress = (0, total)
        findings = []
        lock = threading.Lock()

        def _analyze(proc):
            """Full pipeline for one process. Returns a finding tuple or None."""
            if self._bulk_scan_cancel:
                return None

            # Heuristic pre-check — gives quick signals and forms input context
            try:
                heur_risk, reasons = self._heuristic_scan_process(proc)
            except Exception as e:
                return (proc["pid"], proc.get("command", ""), "ERROR",
                        [f"scan error: {e}"], None)

            # When LLM confirmation is disabled, use heuristic verdict directly
            if not llm_confirm:
                return (proc["pid"], proc.get("command", ""), heur_risk,
                        reasons, None)

            # Every process goes through the 3 LLMs + synthesis
            pid = proc["pid"]
            exe_path = _get_proc_path(pid) or ""
            if not exe_path:
                # Kernel threads and similar have no exe path — keep heuristic
                return (pid, proc.get("command", ""), heur_risk, reasons, None)

            try:
                artifacts = self._collect_inspect_artifacts(pid, exe_path)
                analyses = self._run_llms_parallel(artifacts)
                synth_tool, consensus = self._synthesize_analyses(analyses)
                header = (f"(synthesized by {synth_tool})" if synth_tool
                          else "(local fallback)")
                llm_report = f"{header}\n{consensus}"

                # Parse final risk from consensus; fall back to heuristic
                final_risk = heur_risk
                for line in consensus.splitlines():
                    if line.startswith("CONSENSUS_RISK:"):
                        level = line.split(":", 1)[1].strip().upper()
                        if level in self._RISK_RANK:
                            final_risk = level
                        break
                return (pid, proc.get("command", ""), final_risk, reasons,
                        llm_report)
            except Exception as e:
                return (pid, proc.get("command", ""), heur_risk, reasons,
                        f"[LLM analysis error: {e}]")

        # Reset the live view at the start of a fresh scan
        with self._bulk_scan_live_lock:
            self._bulk_scan_live.clear()
        self._bulk_scan_current = ""

        completed = 0
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = [ex.submit(_analyze, p) for p in procs]
            for f in as_completed(futures):
                result = f.result()
                with lock:
                    completed += 1
                    self._bulk_scan_progress = (completed, total)
                if result is None:
                    continue
                pid, cmd, risk, reasons, llm_report = result
                # Update "currently working on" hint to whatever just finished
                short = (cmd or "").split()[0] if cmd else ""
                self._bulk_scan_current = f"PID {pid}: {short[:60]}"
                # Include non-LOW OR anything the LLM downgraded from a heuristic flag
                if risk != "LOW" or reasons:
                    finding = (risk, pid, cmd, reasons, llm_report)
                    findings.append(finding)
                    with self._bulk_scan_live_lock:
                        self._bulk_scan_live.append(finding)
        return findings

    def _format_bulk_report(self, findings, total_scanned):
        """Format bulk scan findings into display lines, sorted by severity.

        Accepts either legacy 4-tuples (risk, pid, cmd, reasons) or 5-tuples
        with an optional LLM report appended.
        """
        # Normalize tuples to 5 items for uniform handling
        normalized = []
        for f in findings:
            if len(f) == 5:
                normalized.append(f)
            else:
                normalized.append((*f, None))
        normalized.sort(key=lambda f: (self._RISK_RANK.get(f[0], 99), f[1]))
        lines = [
            f"Bulk security scan \u2014 {total_scanned} process(es) scanned",
            f"Flagged: {len(normalized)}  "
            f"(CRITICAL: {sum(1 for f in normalized if f[0] == 'CRITICAL')}, "
            f"HIGH: {sum(1 for f in normalized if f[0] == 'HIGH')}, "
            f"MEDIUM: {sum(1 for f in normalized if f[0] == 'MEDIUM')})",
            "",
        ]
        if not normalized:
            lines.append("  No suspicious processes detected.")
            return lines
        current_risk = None
        for risk, pid, cmd, reasons, llm_report in normalized:
            if risk != current_risk:
                lines.append(f"\u2500\u2500 [{risk}] \u2500\u2500")
                current_risk = risk
            path = _get_proc_path(pid) or (cmd[:70] if cmd else "(no command)")
            lines.append(f"  PID {pid}: {path}")
            for r in reasons:
                lines.append(f"    \u2022 {r}")
            if llm_report:
                lines.append(f"    \u251c\u2500 LLM consensus:")
                for line in llm_report.splitlines():
                    lines.append(f"    \u2502  {line}")
        return lines

    def _toggle_bulk_scan_mode(self):
        """Toggle bulk security scan mode."""
        if self._bulk_scan_mode:
            # Closing: cancel in-flight scan
            self._bulk_scan_cancel = True
            self._bulk_scan_mode = False
            self._detail_focus = False
            return
        self._bulk_scan_lines = []
        self._bulk_scan_scroll = 0
        self._bulk_scan_progress = (0, 0)
        self._bulk_scan_cancel = False
        self._bulk_scan_mode = True
        self._inspect_mode = False
        self._hidden_scan_mode = False
        self._keyscan_mode = False
        self._net_mode = False
        self._detail_focus = True
        self._bulk_scan_loading = True
        self._start_bulk_scan()

    def _start_bulk_scan(self):
        """Launch background thread to scan all processes."""
        if self._bulk_scan_worker and self._bulk_scan_worker.is_alive():
            return
        self._bulk_scan_loading = True
        self._bulk_scan_pending = None
        procs = list(getattr(self, "_all_procs", []))

        def _worker():
            try:
                findings = self._bulk_scan_run(procs)
                if self._bulk_scan_cancel:
                    self._bulk_scan_pending = ["Scan cancelled."]
                    return
                lines = self._format_bulk_report(findings, len(procs))
                self._bulk_scan_pending = lines
            except Exception as e:
                self._bulk_scan_pending = [f"[Bulk scan error: {e}]"]

        self._bulk_scan_worker = threading.Thread(target=_worker, daemon=True)
        self._bulk_scan_worker.start()

    def _poll_bulk_scan_result(self):
        """Check if bulk scan finished. Returns True if re-render is needed."""
        if self._bulk_scan_pending is None:
            return False
        if not self._bulk_scan_mode:
            self._bulk_scan_pending = None
            self._bulk_scan_loading = False
            return False
        self._bulk_scan_lines = self._bulk_scan_pending
        self._bulk_scan_pending = None
        self._bulk_scan_loading = False
        return True

    # ── Live Event Stream (eslogger / dtrace / praudit) ──────────────────

    def _pick_event_source(self):
        """Return (source_name, argv) for the best available live event tool.

        Preference: eslogger (macOS 12+) → dtrace → praudit. Returns (None, None)
        if none are available or usable without additional setup.
        """
        if shutil.which("eslogger"):
            # eslogger streams NDJSON; exec is the most relevant event.
            return ("eslogger", ["eslogger", "exec"])
        if shutil.which("dtrace"):
            # execsnoop-style one-liner: prints PID + args on each exec.
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
            event = data.get("event", {})
            exec_info = event.get("exec", {}) or {}
            target = exec_info.get("target") or {}
            exe = (target.get("executable") or {}).get("path", "")
            audit = target.get("audit_token") or {}
            pid = audit.get("pid") or target.get("pid") or 0
            ppid = target.get("parent_audit_token", {}).get("pid", 0)
            return {
                "ts": data.get("time") or "",
                "kind": "exec",
                "pid": int(pid) if pid else 0,
                "ppid": int(ppid) if ppid else 0,
                "cmd": exe,
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
                "pid": 0,
                "ppid": 0,
                "cmd": line[:200],
                "raw": line[:200],
            }
        return None

    def _toggle_events_mode(self):
        """Toggle live event stream mode."""
        if self._events_mode:
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
        self._hidden_scan_mode = False
        self._bulk_scan_mode = False
        self._keyscan_mode = False
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
        """Spawn the event source subprocess and reader threads.

        All event sources on modern macOS (eslogger, dtrace, praudit) require
        root. If we're not running as root, warn the user upfront; we still
        try to launch the subprocess because some systems may have looser
        audit/dtrace configuration.
        """
        if self._events_worker and self._events_worker.is_alive():
            return
        source, argv = self._pick_event_source()
        self._events_source = source or ""
        if not source:
            self._append_event(
                "error",
                "[no event source available — install eslogger (macOS 12+) "
                "or enable dtrace]",
            )
            return

        if os.geteuid() != 0:
            self._append_event(
                "error",
                f"[{source} typically requires root on macOS \u2014 "
                f"re-run with: sudo procmon]",
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
                f"event stream stopped]",
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

    # ── Traffic Inspector (mitmproxy wrapper) ──────────────────────────

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
        """Open/close the Traffic Inspector (mitmproxy wrapper)."""
        if self._traffic_mode:
            self._stop_traffic_stream()
            self._traffic_mode = False
            self._detail_focus = False
            return
        # Preflight — mitmdump must be on PATH
        mitm = shutil.which("mitmdump")
        if not mitm:
            self._traffic_error = (
                "mitmdump not found. Install via: brew install mitmproxy")
            self._traffic_mode = True
            self._detail_focus = True
            return
        self._traffic_error = ""
        self._traffic_flows = []
        self._traffic_scroll = 0
        self._traffic_mode = True
        self._inspect_mode = False
        self._hidden_scan_mode = False
        self._bulk_scan_mode = False
        self._keyscan_mode = False
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
        # procmon instances don't stomp on each other.
        shim_path = f"/tmp/procmon-mitm-shim-{os.getpid()}.py"
        try:
            with open(shim_path, "w") as f:
                f.write(self._MITM_SHIM)
        except OSError as e:
            self._traffic_error = f"could not write shim: {e}"
            return
        self._traffic_shim_path = shim_path

        argv = [mitm_path, "-q", "-s", shim_path,
                "--listen-port", str(self._traffic_port)]
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
            return
        self._traffic_loading = True

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
        lines = [f"Traffic Inspector \u2014 mitmdump on :"
                 f"{self._traffic_port}"]
        if self._traffic_error:
            lines.append("")
            lines.append(f"  [!]  {self._traffic_error}")
            if "not found" in self._traffic_error:
                lines.append("")
                lines.append("  After install:")
                lines.append("    1. Start procmon again and open Traffic Inspector")
                lines.append("    2. Trust mitmproxy's CA:")
                lines.append("       ~/.mitmproxy/mitmproxy-ca-cert.pem")
                lines.append("    3. Route your suspect app through "
                             "127.0.0.1:8080 (system proxy or SwitchyOmega)")
            return lines
        lines.append("")
        lines.append("  Configure your system/app to route through "
                     f"127.0.0.1:{self._traffic_port}")
        lines.append("  (System Settings → Network → Advanced → Proxies → "
                     "'Web Proxy' + 'Secure Web Proxy')")
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
        """Snapshot the captured events and feed them to Claude for a
        narrative summary: which processes look suspicious, which are
        normal background activity, any chains worth investigating."""
        with self._events_lock:
            events = list(self._events)
        if not events:
            return

        # Compact textual representation so Claude sees one line per event.
        body_lines = [f"Live exec/fork event stream from source: "
                      f"{self._events_source}",
                      f"Total events captured: {len(events)}", ""]
        for evt in events[-300:]:  # cap so we don't blow past context
            ts = (evt.get("ts") or "")[:19]
            pid = evt.get("pid", 0)
            ppid = evt.get("ppid", 0)
            kind = evt.get("kind", "")
            cmd = (evt.get("cmd") or "")[:180]
            body_lines.append(f"  {ts} pid={pid} ppid={ppid} {kind}: {cmd}")
        body = "\n".join(body_lines)

        self._llm_summary["events"] = None
        self._llm_summary_pending["events"] = None
        self._llm_summary_loading["events"] = True

        prompt = (
            "You are analyzing a stream of macOS exec/fork events. Return a "
            "3–6 bullet narrative. Each bullet ≤25 words and starts with "
            "one of: TOP_CONCERN:, SIGNAL:, NOISE:, ACTION:.\n"
            "- TOP_CONCERN: any process chain or binary that looks malicious "
            "(short-lived droppers, suspicious locations, privileged "
            "children, unusual parents).\n"
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
                    self._llm_summary_pending["events"] = (
                        self._format_llm_summary_panel(resp))
            except Exception as e:
                self._llm_summary_pending["events"] = [
                    "  \u2501\u2501 AI SUMMARY \u2501\u2501",
                    "",
                    f"    [INFO]  Summary error: {e}",
                    ""]

        t = threading.Thread(target=_worker, daemon=True)
        self._llm_summary_worker["events"] = t
        t.start()

    def _format_events_view(self):
        """Build display lines for the events detail box."""
        header = f"Live events \u2014 source: {self._events_source or '(none)'}"
        if self._events_source and os.geteuid() != 0:
            header += " \u2014 NOT ROOT (source likely inert)"
        lines = [header, ""]
        with self._events_lock:
            snapshot = list(self._events)
        f = self._events_filter.lower()
        if f:
            snapshot = [e for e in snapshot if f in e.get("cmd", "").lower()]
        if not snapshot:
            lines.append("  (no events yet — waiting for process activity)")
            if self._events_source and os.geteuid() != 0:
                lines.append("")
                lines.append("  [!] Most macOS event sources require root.")
                lines.append("      Quit procmon and re-run with: sudo procmon")
            return lines
        for evt in snapshot[-200:]:
            ts = evt.get("ts", "")[:19]
            pid = evt.get("pid", 0)
            ppid = evt.get("ppid", 0)
            cmd = evt.get("cmd", "")[:120]
            kind = evt.get("kind", "")
            mark = "[!]" if kind == "error" else "   "
            if pid:
                lines.append(f"  {mark} {ts} pid={pid} ppid={ppid} {cmd}")
            else:
                lines.append(f"  {mark} {ts} {cmd}")
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

        # 1. Code signature verification
        artifacts["codesign_verify"] = _run_cmd(
            ["codesign", "-vvv", "--deep", exe_path])

        # 2. Entitlements
        artifacts["entitlements"] = _run_cmd(
            ["codesign", "-d", "--entitlements", ":-", exe_path])

        # 3. Linked dylibs
        artifacts["dylibs"] = _run_cmd(["otool", "-L", exe_path])

        # 4. Binary hash
        artifacts["sha256"] = _run_cmd(["shasum", "-a", "256", exe_path])

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

        # 13. VirusTotal reputation (if API key configured)
        artifacts["virustotal"] = None
        sha256_line = artifacts.get("sha256", "")
        sha256 = sha256_line.split()[0] if sha256_line and not sha256_line.startswith("[") else ""
        if len(sha256) == 64 and os.environ.get("VT_API_KEY"):
            artifacts["virustotal"] = _virustotal_lookup(sha256)

        # 14. YARA scan on the on-disk binary
        artifacts["yara_file"] = _yara_scan_file(exe_path)

        # 15. YARA scan on a memory snapshot (only if root — lldb needs perms)
        if is_root:
            artifacts["yara_memory"] = _yara_scan_memory(pid)
        else:
            artifacts["yara_memory"] = {"success": False,
                                        "error": "skipped — requires root"}

        artifacts["exe_path"] = exe_path
        artifacts["pid"] = pid
        return artifacts

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
        vt = artifacts.get("virustotal") or {}
        if vt.get("found"):
            lines.append(f"  [VT] {vt.get('malicious', 0)} malicious / "
                         f"{vt.get('suspicious', 0)} suspicious")
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
        if cs:
            lines.append("\u2500\u2500 Signature Details \u2500\u2500")
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

        # VirusTotal
        vt = artifacts.get("virustotal")
        if vt:
            lines.append("\u2500\u2500 VirusTotal \u2500\u2500")
            if vt.get("error"):
                lines.append(f"  Error: {vt['error']}")
            elif not vt.get("found"):
                lines.append("  Hash not found in VT database")
            else:
                mal = vt.get("malicious", 0)
                susp = vt.get("suspicious", 0)
                tag = f"  [!] {mal} malicious" if mal else f"  {mal} malicious"
                lines.append(f"{tag}, {susp} suspicious, {vt.get('undetected', 0)} undetected")
                if vt.get("popular_threat_name"):
                    lines.append(f"  Threat label: {vt['popular_threat_name']}")
                names = vt.get("known_names") or []
                if names:
                    lines.append(f"  Known names: {', '.join(names[:5])}")
            lines.append("")
        elif os.environ.get("VT_API_KEY"):
            lines.append("\u2500\u2500 VirusTotal \u2500\u2500")
            lines.append("  [skipped — no SHA-256 available]")
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
        if cs:
            cs_summary = (
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

        vt = artifacts.get("virustotal")
        if vt and vt.get("found"):
            sections.append(
                f"\n=== VIRUSTOTAL ===\n"
                f"malicious={vt.get('malicious')} "
                f"suspicious={vt.get('suspicious')} "
                f"threat={vt.get('popular_threat_name')} "
                f"names={vt.get('known_names')}")

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
        """Run Claude, Codex, Gemini in parallel. Returns dict tool -> response."""
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
            self._inspect_phase = "collecting"
            artifacts = self._collect_inspect_artifacts(pid, exe_path)

            # Intermediate: show raw artifacts while LLMs analyze
            report_lines = self._format_inspect_report(artifacts)
            self._inspect_pending = ("artifacts", report_lines)

            # Run all three LLMs in parallel
            self._inspect_phase = "analyzing"
            analyses = self._run_llms_parallel(artifacts)

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
        self._inspect_lines = []
        self._inspect_scroll = 0
        self._inspect_mode = True
        self._llm_summary["inspect"] = None
        self._llm_summary_pending["inspect"] = None
        self._llm_summary_loading["inspect"] = False
        self._hidden_scan_mode = False
        self._bulk_scan_mode = False
        if getattr(self, "_keyscan_mode", False):
            self._keyscan_mode = False
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

    def _collect_chat_context(self):
        """Build (label, text) describing what the user is currently looking at.

        The text is fed into Claude as system context so follow-up questions
        ("what does this mean?", "is this suspicious?", etc.) stay grounded in
        what's actually on screen rather than requiring the user to re-explain.
        """
        label = "procmon"
        parts = []

        if self._inspect_mode and self._inspect_lines:
            label = f"Inspect: PID {self._inspect_pid} ({self._inspect_cmd})"
            parts.append(
                f"The user is looking at a forensic inspect report for "
                f"PID {self._inspect_pid} ({self._inspect_cmd}). Full report:")
            parts.append("\n".join(self._inspect_lines))
        elif self._hidden_scan_mode and self._hidden_scan_lines:
            label = "Hidden processes + kernel modules scan"
            parts.append(
                "The user is looking at a deep hidden-process + kernel-module "
                "scan. Full output:")
            parts.append("\n".join(self._hidden_scan_lines))
        elif self._keyscan_mode and self._keyscan_lines:
            label = "Keyboard hook / keylogger scan"
            parts.append(
                "The user is looking at a keyboard-hook / keylogger scan. "
                "Full output:")
            parts.append("\n".join(self._keyscan_lines))
            cur = self._keyscan_current_finding()
            if cur:
                parts.append("")
                parts.append(
                    "The cursor is on this finding (most likely what the "
                    "user is asking about):")
                parts.append(f"  severity: {cur.get('severity', 'INFO')}")
                parts.append(f"  message:  {cur.get('message', '')}")
                act = cur.get('action')
                if act:
                    parts.append(f"  action:   {act}")
        elif self._audit_mode and self._audit_lines:
            title = self._AUDIT_SCANS.get(
                self._audit_type, (None, "Host Security Audit"))[1]
            label = title
            parts.append(
                f"The user is looking at the '{title}' audit (audit_type="
                f"{self._audit_type!r}). This is a host-level security "
                f"posture report, not a per-process inspect — answer in that "
                f"frame. Full report:")
            parts.append("\n".join(self._audit_lines))
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
        elif self._bulk_scan_mode:
            label = "Bulk security scan"
            if self._bulk_scan_lines:
                parts.append(
                    "The user is looking at a completed bulk security scan. "
                    "Full report:")
                parts.append("\n".join(self._bulk_scan_lines))
            else:
                done, total = self._bulk_scan_progress
                parts.append(
                    f"The user is looking at a bulk security scan in progress "
                    f"({done}/{total} processes scanned so far).")
                with self._bulk_scan_live_lock:
                    live = list(self._bulk_scan_live)
                if live:
                    parts.append("Live findings so far:")
                    for risk, pid, cmd, reasons, _ in live[:30]:
                        parts.append(f"  [{risk}] PID {pid}: {cmd} — {reasons}")
        elif self._net_mode and self._net_entries:
            label = f"Network: PID {self._net_pid} ({self._net_cmd})"
            parts.append(
                f"The user is looking at network connections for "
                f"PID {self._net_pid} ({self._net_cmd}). Connections:")
            for e in self._net_entries[:80]:
                parts.append(f"  {e.get('display', '')}")
        elif self._events_mode:
            label = "Live event stream"
            with self._events_lock:
                snap = list(self._events)[-50:]
            parts.append(
                f"The user is watching a live exec/fork event stream "
                f"(source: {self._events_source}). Recent events:")
            for e in snap:
                parts.append(
                    f"  pid={e.get('pid')} ppid={e.get('ppid')} "
                    f"{e.get('cmd', '')}")
        elif self.rows and self.selected < len(self.rows):
            r = self.rows[self.selected]
            label = f"Process: PID {r['pid']} ({r['command'][:40]})"
            parts.append(
                f"The user is looking at the main process list with "
                f"PID {r['pid']} selected. Selected process details:")
            parts.append(
                f"  command: {r['command']}\n"
                f"  ppid: {r.get('ppid')}\n"
                f"  cpu: {r.get('cpu', 0):.1f}%\n"
                f"  memory: {r.get('rss_kb', 0)} KB\n"
                f"  threads: {r.get('threads', 0)}\n"
                f"  fds: {r.get('fds', '?')}")
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

    def _exit_chat_mode(self):
        """Close the chat overlay. Leaves conversation history in place so
        re-opening within the same context can resume — we explicitly reset
        it in _enter_chat_mode when the context itself changes."""
        self._chat_mode = False

    def _chat_send(self):
        """Send the current input line as a new user message."""
        question = self._chat_input.strip()
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
                system_prompt = (
                    "You are a macOS security and process-analysis assistant "
                    "embedded in procmon, a live process monitor. Answer the "
                    "user's question concisely and grounded in the context "
                    "they're looking at. Prefer bullet-point answers for "
                    "anything longer than two sentences. If the user asks "
                    "about a process / scan output / network connections, "
                    "reason specifically about what's in the context — don't "
                    "give generic advice."
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

                proc = subprocess.Popen(
                    ["claude", "-p", system_prompt],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=env,
                )
                try:
                    stdout, stderr = proc.communicate(
                        input=stdin_text.encode("utf-8"), timeout=120)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
                    self._chat_pending = "[claude timed out after 120s]"
                    return
                if proc.returncode != 0:
                    err = stderr.decode("utf-8", errors="replace").strip()
                    out = stdout.decode("utf-8", errors="replace").strip()
                    detail = err or out or "(no output)"
                    self._chat_pending = f"[claude error rc={proc.returncode}: {detail[:200]}]"
                    return
                self._chat_pending = stdout.decode("utf-8", errors="replace").strip()
            except FileNotFoundError:
                self._chat_pending = "[claude CLI not found — install: npm install -g @anthropic-ai/claude-code]"
            except OSError as e:
                self._chat_pending = f"[claude error: {e}]"
            except Exception as e:
                self._chat_pending = f"[unexpected error: {e}]"

        self._chat_worker = threading.Thread(target=_worker, daemon=True)
        self._chat_worker.start()

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
            return False
        self._chat_messages.append({"role": "assistant",
                                     "content": self._chat_pending})
        self._chat_pending = None
        self._chat_loading = False
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
        loading_marker = " [claude thinking\u2026]" if self._chat_loading else ""
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

    # Rows in the forensic / audit dialogs are (label, kind, payload):
    #   kind == "header"  → section heading, non-selectable (bold+dim)
    #   kind == "action"  → selectable; payload is the method name or audit type
    # Keep the two menus split clearly: Forensic = per-process investigation;
    # Audits = host-level posture checks.

    _FORENSIC_ROWS = [
        ("Process", "header", None),
        ("Inspect process (Claude + Codex + Gemini)", "action", "inspect"),
        ("Hidden processes + kernel modules scan (deep)", "action", "hidden"),
        ("Bulk security scan (all processes)", "action", "bulk"),
        ("Per-process entitlements (audit)", "action", "audit:process_entitlements"),
        ("Input & Peripherals", "header", None),
        ("Keyboard hook / keylogger scan", "action", "keyscan"),
        ("USB / HID devices (audit)", "action", "audit:usb_hid"),
        ("Live Activity", "header", None),
        ("Live event stream (exec/fork)", "action", "events"),
        ("Traffic Inspector (mitmproxy — pre-TLS capture)", "action", "traffic"),
        ("Network connections (for selected process)", "action", "network"),
    ]

    _AUDIT_ROWS = [
        ("Overview", "header", None),
        ("Global Security Score (Fix-First)", "action", "global_score"),
        ("Network", "header", None),
        ("Network exposure (firewall + sharing + ports)", "action", "network"),
        ("DNS / Proxy / MDM redirection", "action", "dns"),
        ("System & Kernel", "header", None),
        ("System hardening (SIP, SSV, Gatekeeper, FileVault)", "action", "system_hardening"),
        ("Kernel / boot integrity (kexts, SSV, nvram)", "action", "kernel_boot"),
        ("OS patch posture (softwareupdate)", "action", "patch_posture"),
        ("Filesystem integrity", "action", "filesystem_integrity"),
        ("Persistence & Paths", "header", None),
        ("LaunchAgents / Daemons / BTM / Helpers", "action", "persistence"),
        ("Shell dotfiles", "action", "shell_dotfiles"),
        ("Sensitive paths delta (7d)", "action", "sensitive_paths_delta"),
        ("Identity & Access", "header", None),
        ("TCC grants", "action", "tcc"),
        ("Keychain & credential hygiene", "action", "keychain"),
        ("Authentication stack", "action", "auth_stack"),
        ("Software & Supply Chain", "header", None),
        ("Installed software trust", "action", "installed_software"),
        ("Browser extensions", "action", "browser_exts"),
        ("Package manager supply chain", "action", "packages"),
        ("Meta", "header", None),
        ("Baseline delta (vs saved snapshot)", "action", "baseline_delta"),
        ("Rule engine (meta-detector)", "action", "rule_engine"),
    ]

    def _run_sectioned_menu(self, rows, title, footer, on_select):
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
        """Handle a selection from the Forensic menu."""
        if payload == "inspect":
            self._toggle_inspect_mode()
        elif payload == "hidden":
            self._toggle_hidden_scan_mode()
        elif payload == "keyscan":
            self._toggle_keyscan_mode()
        elif payload == "bulk":
            self._toggle_bulk_scan_mode()
        elif payload == "events":
            self._toggle_events_mode()
        elif payload == "network":
            self._toggle_net_mode()
        elif payload == "traffic":
            self._toggle_traffic_mode()
        elif isinstance(payload, str) and payload.startswith("audit:"):
            # Forensic entries that cross into a host-level audit (USB/HID,
            # per-process entitlements) — keep in the forensic menu because
            # they're about processes/hardware, but reuse the audit runtime.
            self._toggle_audit_mode(payload[len("audit:"):])

    def _prompt_forensic(self):
        """Show the Forensic menu (F key) — per-process investigation."""
        self._run_sectioned_menu(
            self._FORENSIC_ROWS,
            title=" Forensic \u2014 \u2191\u2193 navigate, Enter select, Esc cancel ",
            footer="Per-process investigation. Audits menu (a) is for host posture.",
            on_select=self._dispatch_forensic_action,
        )

    def _prompt_audit(self):
        """Show the Audits menu (a key) — host-level posture checks."""
        self._run_sectioned_menu(
            self._AUDIT_ROWS,
            title=" Audits \u2014 \u2191\u2193 navigate, PgUp/PgDn jump, Enter run, Esc cancel ",
            footer="Global Score runs every audit and surfaces a Fix-First list.",
            on_select=self._toggle_audit_mode,
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

        # Carry over fds and cwd from previous rows
        old = {r["pid"]: r for r in self.rows}
        for r in flat:
            prev = old.get(r["pid"], {})
            r["fds"] = prev.get("fds", -1)
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
        # Signal the bulk scanner (if running) to stop submitting new work
        self._bulk_scan_cancel = True
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
            if self._hidden_scan_pending is not None:
                if self._poll_hidden_scan_result():
                    self.render()
            if self._keyscan_pending is not None:
                if self._poll_keyscan_result():
                    self.render()
            if self._chat_pending is not None:
                if self._poll_chat_result():
                    self.render()
            if self._bulk_scan_pending is not None:
                if self._poll_bulk_scan_result():
                    self.render()
            if self._audit_pending is not None:
                if self._poll_audit_result():
                    self.render()
            # Poll per-scope LLM summaries (audits, keyscan, hidden, inspect,
            # events). Each slot is independent; rendering the finished
            # panel kicks the viewport up by its height.
            for _scope in ("audit", "keyscan", "hidden", "inspect", "events"):
                if self._llm_summary_pending.get(_scope) is not None:
                    if self._poll_llm_summary(_scope):
                        self.render()
            # Re-render to advance the bulk scan progress bar while running
            if self._bulk_scan_mode and self._bulk_scan_loading:
                self.render()
            # Re-render the events view as new events arrive
            if self._events_mode:
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
        prog="procmon",
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
    parser.add_argument("--capture-baseline", action="store_true",
                        help=("Capture a host-state snapshot to "
                              "~/.procmon-baseline.json and exit"))
    parser.add_argument("--audit", default="",
                        help=("Run a single audit headless and print results: "
                              "network|dns|persistence|system_hardening|"
                              "kernel_boot|patch_posture|tcc|browser_exts|"
                              "usb_hid|shell_dotfiles|installed_software|"
                              "process_entitlements|filesystem_integrity|"
                              "sensitive_paths_delta|keychain|auth_stack|"
                              "packages|baseline_delta|rule_engine|global_score"))
    args = parser.parse_args()

    if args.interval <= 0:
        parser.error("Interval must be positive")

    if args.capture_baseline:
        snap = _collect_baseline_snapshot()
        ok = _save_baseline(snap)
        print(f"{'wrote' if ok else 'failed to write'} {_BASELINE_PATH} "
              f"(launch_items={len(snap['launch_items'])}, "
              f"listening_ports={len(snap['listening_ports'])}, "
              f"system_extensions={len(snap['system_extensions'])}, "
              f"config_profiles={len(snap['config_profiles'])})")
        sys.exit(0 if ok else 1)

    if args.audit:
        audit_map = {
            "network": _audit_network_exposure,
            "dns": _audit_dns_proxy_mdm,
            "persistence": _audit_persistence,
            "system_hardening": _audit_system_hardening,
            "kernel_boot": _audit_kernel_boot,
            "patch_posture": _audit_patch_posture,
            "tcc": _audit_tcc_grants,
            "browser_exts": _audit_browser_extensions,
            "usb_hid": _audit_usb_hid,
            "shell_dotfiles": _audit_shell_dotfiles,
            "installed_software": _audit_installed_software,
            "process_entitlements": _audit_process_entitlements,
            "filesystem_integrity": _audit_filesystem_integrity,
            "sensitive_paths_delta": _audit_sensitive_paths_delta,
            "keychain": _audit_keychain_credentials,
            "auth_stack": _audit_authentication_stack,
            "packages": _audit_package_managers,
            "baseline_delta": _audit_baseline_delta,
            "rule_engine": _audit_rule_engine,
            "global_score": _audit_global_score,
        }
        fn = audit_map.get(args.audit)
        if not fn:
            print(f"unknown audit '{args.audit}'. Options: "
                  + ", ".join(sorted(audit_map)))
            sys.exit(2)
        findings = fn()
        rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3, "OK": 4}
        findings.sort(key=lambda f: rank.get(f.get("severity"), 99))

        # Summary header
        counts = {}
        for f in findings:
            s = f.get("severity", "INFO")
            counts[s] = counts.get(s, 0) + 1
        actionable = sum(1 for f in findings if f.get("action"))
        title = args.audit.replace("_", " ").upper()
        bar = "=" * 72

        print(bar)
        print(f"  {title}")
        print(bar)
        print()
        sev_parts = []
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "INFO", "OK"):
            if counts.get(sev, 0):
                sev_parts.append(f"[{sev} {counts[sev]}]")
        if sev_parts:
            print("  Severity:    " + "  ".join(sev_parts))
        print(f"  Actionable:  {actionable} (rows marked [*])")
        print(f"  Total:       {len(findings)}")
        print()

        # Findings overview (one line each)
        print("-" * 72)
        print("  FINDINGS")
        print("-" * 72)
        print()
        for i, f in enumerate(findings, 1):
            mark = "[*]" if f.get("action") else "   "
            print(f"  {i:3}. {mark} [{f.get('severity', 'INFO'):<8}] "
                  f"{f.get('message', '')}")
        print()

        # Per-finding details (only where there's evidence or an action)
        detailed = [(i, f) for i, f in enumerate(findings, 1)
                    if (f.get("evidence") or f.get("action"))]
        if detailed:
            print("-" * 72)
            print("  DETAILS")
            print("-" * 72)
            print()
            for i, f in detailed:
                print(f"  [{i}] [{f.get('severity')}] "
                      f"{f.get('message', '')}")
                ev = (f.get("evidence") or "").strip()
                if ev:
                    for line in ev.splitlines():
                        print(f"        {line}")
                action = f.get("action")
                if action:
                    print(f"        action: {action.get('type')}  "
                          f"({action})")
                print()
        sys.exit(0)

    # Preflight: check external CLI dependencies before entering curses
    if not _preflight(skip=args.skip_preflight):
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
