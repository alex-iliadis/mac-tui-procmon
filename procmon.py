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

_rdns_cache = {}  # ip -> hostname or None


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
        hostname = _socket.gethostbyaddr(ip)[0]
        _rdns_cache[ip] = hostname
        return hostname
    except (_socket.herror, _socket.gaierror, OSError):
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


def _group_siblings(children):
    """Group sibling nodes that share the same short command name into a single
    synthetic node. Only groups when there are 2+ siblings with the same name."""
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
        # Create a synthetic group node from the first member
        leader = members[0]
        group = {**leader}
        group["command"] = leader["command"]  # keep original command
        group["_group_name"] = name
        group["_group_count"] = len(members)
        group["pid"] = leader["pid"]  # use first PID for selection/expand
        group["_group_pids"] = [m["pid"] for m in members]
        # Merge all members' children into the group
        merged_children = []
        for m in members:
            merged_children.extend(m.get("children", []))
        group["children"] = merged_children
        # Recompute aggregates across all members
        group["rss_kb"] = sum(m["rss_kb"] for m in members)
        group["cpu"] = sum(m["cpu"] for m in members)
        group["cpu_ticks"] = sum(m["cpu_ticks"] for m in members)
        group["threads"] = sum(m["threads"] for m in members)
        group["agg_rss_kb"] = sum(m.get("agg_rss_kb", m["rss_kb"]) for m in members)
        group["agg_cpu"] = sum(m.get("agg_cpu", m["cpu"]) for m in members)
        group["agg_cpu_ticks"] = sum(m.get("agg_cpu_ticks", m["cpu_ticks"]) for m in members)
        group["agg_threads"] = sum(m.get("agg_threads", m["threads"]) for m in members)
        group["agg_forks"] = sum(m.get("agg_forks", 0) for m in members)
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


# ── Curses UI ────────────────────────────────────────────────────────────

class ProcMonUI:
    def __init__(self, stdscr, name, interval, skip_fd):
        self.stdscr = stdscr
        self.name = name
        self.patterns = [p.strip().lower() for p in name.split(",") if p.strip()] if name else []
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
        except (FileNotFoundError, ValueError, KeyError):
            pass

    def _save_config(self):
        """Save current config to ~/.procmon.json."""
        cfg = {
            "alert_thresholds": self._alert_thresholds,
            "alert_interval": self._alert_interval,
            "alert_max_count": self._alert_max_count,
        }
        try:
            with open(self._CONFIG_PATH, "w") as f:
                f.write(_json.dumps(cfg, indent=2))
        except OSError:
            pass

    def _sort_key(self):
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
                   if not self.patterns or any(pat in p["command"].lower() for pat in self.patterns)]

        tree = build_tree(matched, all_procs, self._sort_key(), self._sort_reverse())
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
        self.matched_count = len(matched)
        if self.selected >= len(self.rows):
            self.selected = max(0, len(self.rows) - 1)

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
        if self.name:
            filter_str = f" matching '{self.name}'"
        else:
            filter_str = ""
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
        self._put(y, x, f"\u2014 sort: {sort_label}{sort_arrow} ", sort_color | curses.A_BOLD)
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
        if self._net_mode:
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
        mem_red = 2 * 1024 * 1024      # 2 GB in KB
        mem_yellow = 1536 * 1024        # 1.5 GB in KB
        for i, r in enumerate(visible):
            idx = self.scroll_offset + i
            line = self._fmt_row(r, w)
            agg_mem = r.get("agg_rss_kb", r["rss_kb"])
            agg_cpu = r.get("agg_cpu", r["cpu"])
            if idx == self.selected:
                self._put(y, 0, line.ljust(w)[:w], curses.color_pair(2))
            elif (agg_mem >= mem_red or agg_cpu >= 80
                  or r.get("agg_forks", 0) > 15
                  or r.get("agg_fds", 0) > 1025
                  or r.get("agg_threads", 0) > 250):
                self._put(y, 0, line[:w], curses.color_pair(5) | curses.A_BOLD)
            elif agg_mem >= mem_yellow or agg_cpu >= 40:
                self._put(y, 0, line[:w], curses.color_pair(6) | curses.A_BOLD)
            elif r["depth"] > 0:
                self._put(y, 0, line[:w], curses.color_pair(10))
            elif agg_cpu > 5 or agg_mem > 512 * 1024:
                self._put(y, 0, line[:w], curses.color_pair(11))
            else:
                self._put(y, 0, line[:w], curses.A_NORMAL)
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
            y += 1

        # ── Scroll indicator ──
        total = len(self.rows)
        if total > list_h:
            indicator = f" [{self.scroll_offset + 1}-{min(self.scroll_offset + list_h, total)} of {total}]"
            self._put(detail_y - 1, max(0, w - len(indicator) - 1), indicator[:w], curses.A_DIM)

        # ── Detail box ──
        scroll = self._net_scroll if self._net_mode else 0
        sel_line = self._net_selected if self._net_mode and self._detail_focus else -1
        self._render_detail(detail_y, w, detail_all_lines, detail_title,
                            scroll, self._detail_focus, sel_line)

        # ── Shortcut bar (mc-style) ──
        self._render_shortcut_bar(h, w)
        self.stdscr.refresh()

    def _col_header(self, w):
        sort_ind_c = "*" if self.sort_mode == SORT_CPU else " "
        sort_ind_m = "*" if self.sort_mode == SORT_MEM else " "
        sort_ind_n = "*" if self.sort_mode == SORT_NET else " "
        sort_ind_bi = "*" if self.sort_mode == SORT_BYTES_IN else " "
        sort_ind_bo = "*" if self.sort_mode == SORT_BYTES_OUT else " "
        right_parts = [f"{'MEM':>8}{sort_ind_m}", f"{'CPU%':>6}{sort_ind_c}", f"{'THR':>4}"]
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
        right_parts = [f"{fmt_mem(mem):>8} ", f"{cpu:6.1f} ", f"{thr:4}"]
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
        name = _short_command(r["command"])
        group_count = r.get("_group_count", 0)
        if group_count > 1:
            name += f" (x{group_count})"
        left = r["prefix"] + indicator + name
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

        group_count = r.get("_group_count", 0)
        pid_line = f"PID: {r['pid']}  PPID: {r['ppid']}  Forks: {r['forks']}  Threads: {r['threads']}"
        if group_count > 1:
            pid_line += f"  Grouped: x{group_count}"
        if has_ch:
            pid_line += f" (group: {agg_thr})"

        mem_line = f"CPU: {r['cpu']:.1f}%   MEM: {fmt_mem(r['rss_kb'])} ({r['rss_kb']:,} KB)"
        if has_ch:
            mem_line += f"  [group: CPU {agg_cpu:.1f}%  MEM {fmt_mem(agg_mem)}]"
        if not self.skip_fd:
            mem_line += f"   FDs: {r.get('fds', -1) if r.get('fds', -1) >= 0 else '?'}"

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
            shortcuts = [
                ("\u2191\u2193", "Select"),
                ("k", "Kill"),
                ("N", "Close"),
                ("Tab", "Procs"),
                ("Esc", "Back"),
                ("q", "Quit"),
            ]
        elif self._net_mode:
            shortcuts = [
                ("Tab", "Conns"),
                ("N", "Close"),
                ("Esc", "Back"),
                ("q", "Quit"),
            ]
        else:
            shortcuts = [
                ("m", "Mem"),
                ("c", "CPU"),
                ("n", "Net"),
                ("A", "A-Z"),
                ("V", "Vendor"),
                ("R", "\u2193In"),
                ("O", "\u2191Out"),
                ("N", "Conns"),
                ("f", "Filter"),
                ("C", "Config"),
                ("\u2190\u2192", "Fold"),
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
        # Detail box has focus — navigate and act on connections
        if self._detail_focus:
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
        elif key == ord("N"):
            self._toggle_net_mode()
        elif key == ord("\t"):
            if self._net_mode:
                self._detail_focus = True
        elif key == ord("C"):  # Shift+C — alert config
            self._prompt_config()
        elif key == ord("f"):
            self._prompt_filter()
        elif key == ord("k"):
            self._kill_selected()
        elif key == 27:  # Escape
            if self._net_mode:
                self._net_mode = False
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
                pass

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
        # Respect max count
        if self._alert_max_count > 0 and self._alert_count >= self._alert_max_count:
            return
        # Cooldown based on configured interval
        if now - self._alert_last_sound < self._alert_interval:
            return
        # System-wide totals
        total_cpu = sum(r.get("cpu", 0) for r in self.rows)
        total_mem_mb = sum(r.get("rss_kb", 0) for r in self.rows) / 1024.0
        total_thr = sum(r.get("threads", 0) for r in self.rows)
        total_fds = sum(max(r.get("fds", 0), 0) for r in self.rows)
        total_forks = sum(r.get("forks", 0) for r in self.rows)
        total_net_in = sum(max(r.get("net_in", 0), 0) for r in self.rows) / 1024.0
        total_net_out = sum(max(r.get("net_out", 0), 0) for r in self.rows) / 1024.0
        total_recv_mb = sum(r.get("bytes_in", 0) for r in self.rows) / (1024 * 1024)
        total_sent_mb = sum(r.get("bytes_out", 0) for r in self.rows) / (1024 * 1024)

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
            # Reset count and timer when no longer triggered
            self._alert_count = 0
            self._alert_last_sound = 0.0
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
        """Show a text input at the bottom of the screen to change the filter."""
        h, w = self.stdscr.getmaxyx()
        prompt = " Filter: "
        y = h - 1
        self._put(y, 0, prompt.ljust(w)[:w], curses.color_pair(4) | curses.A_BOLD)
        self.stdscr.refresh()

        curses.curs_set(1)
        self.stdscr.timeout(-1)  # blocking input while typing

        buf = list(self.name)
        cursor = len(buf)

        while True:
            # Render input line
            text = "".join(buf)
            display = prompt + text
            self._put(y, 0, display.ljust(w)[:w], curses.color_pair(4) | curses.A_BOLD)
            cx = min(len(prompt) + cursor, w - 1)
            try:
                self.stdscr.move(y, cx)
            except curses.error:
                pass
            self.stdscr.refresh()

            ch = self.stdscr.getch()
            if ch in (curses.KEY_ENTER, 10, 13):
                break
            elif ch == 27:  # Escape — cancel
                curses.curs_set(0)
                self.stdscr.timeout(100)
                return
            elif ch in (curses.KEY_BACKSPACE, 127, 8):
                if cursor > 0:
                    buf.pop(cursor - 1)
                    cursor -= 1
            elif ch == curses.KEY_DC:  # Delete key
                if cursor < len(buf):
                    buf.pop(cursor)
            elif ch == curses.KEY_LEFT:
                if cursor > 0:
                    cursor -= 1
            elif ch == curses.KEY_RIGHT:
                if cursor < len(buf):
                    cursor += 1
            elif ch == curses.KEY_HOME or ch == 1:  # Ctrl-A
                cursor = 0
            elif ch == curses.KEY_END or ch == 5:  # Ctrl-E
                cursor = len(buf)
            elif ch == 21:  # Ctrl-U — clear line
                buf.clear()
                cursor = 0
            elif 32 <= ch <= 126:
                buf.insert(cursor, chr(ch))
                cursor += 1

        curses.curs_set(0)
        self.stdscr.timeout(100)

        new_filter = "".join(buf).strip()
        self.name = new_filter
        self.patterns = [p.strip().lower() for p in new_filter.split(",") if p.strip()] if new_filter else []
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
                   if not self.patterns or any(pat in p["command"].lower() for pat in self.patterns)]

        tree = build_tree(matched, all_procs, self._sort_key(), self._sort_reverse())
        flat = flatten_tree(tree, self._expanded)

        # Carry over fds and cwd from previous rows
        old = {r["pid"]: r for r in self.rows}
        for r in flat:
            prev = old.get(r["pid"], {})
            r["fds"] = prev.get("fds", -1)
            r["cwd"] = prev.get("cwd", "-")

        self.rows = flat
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

        while True:
            key = self.stdscr.getch()
            if key != -1:
                if not self.handle_input(key):
                    break
                self.render()

            # Poll for background net fetch results
            if self._net_pending is not None:
                if self._poll_net_result():
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
    args = parser.parse_args()

    if args.interval <= 0:
        parser.error("Interval must be positive")

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
