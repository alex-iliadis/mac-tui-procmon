#!/usr/bin/env python3
"""Reusable live-process injection / anti-debug lab for procmon tests."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path


def compile_c_binary(root: Path, name: str, source: str, extra_args=None) -> Path:
    extra_args = list(extra_args or [])
    src = root / f"{name}.c"
    out = root / name
    src.write_text(source, encoding="utf-8")
    subprocess.run(
        ["cc", "-o", str(out), str(src)] + extra_args,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    out.chmod(out.stat().st_mode | stat.S_IXUSR)
    return out


def compile_dylib(root: Path, name: str, source: str) -> Path:
    src = root / f"{name}.c"
    out = root / f"lib{name}.dylib"
    src.write_text(source, encoding="utf-8")
    subprocess.run(
        ["cc", "-dynamiclib", "-o", str(out), str(src)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    out.chmod(out.stat().st_mode | stat.S_IXUSR)
    return out


def terminate_process(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


@dataclass
class InjectionLab:
    root: Path
    hold_delay: float = 1.2
    procs: list[subprocess.Popen] = field(default_factory=list)
    metadata: list[dict] = field(default_factory=list)

    def _launch(self, name: str, path: Path, env=None, kind: str = "") -> subprocess.Popen:
        proc = subprocess.Popen([str(path)], env=env, start_new_session=True)
        self.procs.append(proc)
        self.metadata.append({
            "name": name,
            "kind": kind or name,
            "path": str(path),
            "pid": proc.pid,
        })
        return proc

    def start(self) -> list[dict]:
        self.root.mkdir(parents=True, exist_ok=True)

        dyld_host = compile_c_binary(
            self.root,
            "dyld_injected",
            "#include <unistd.h>\nint main(void){ while(1) sleep(1); return 0; }\n",
        )
        anti_ptrace = compile_c_binary(
            self.root,
            "anti_ptrace",
            (
                "#include <unistd.h>\n"
                "#include <sys/types.h>\n"
                "#include <sys/ptrace.h>\n"
                "int main(void){ ptrace(PT_DENY_ATTACH, 0, 0, 0); while(1) sleep(1); return 0; }\n"
            ),
        )
        anti_exc = compile_c_binary(
            self.root,
            "anti_exc_ports",
            (
                "#include <unistd.h>\n"
                "#include <mach/mach.h>\n"
                "int main(void){\n"
                "  task_set_exception_ports(mach_task_self(), EXC_MASK_BAD_ACCESS, MACH_PORT_NULL, EXCEPTION_DEFAULT, THREAD_STATE_NONE);\n"
                "  while(1) sleep(1);\n"
                "  return 0;\n"
                "}\n"
            ),
        )
        dylib = compile_dylib(
            self.root,
            "inject",
            (
                "#include <stdio.h>\n"
                "__attribute__((constructor)) static void init(void) {\n"
                "  FILE *f = fopen(\"/tmp/procmon_lab_inject.log\", \"a\");\n"
                "  if (f) { fputs(\"loaded\\n\", f); fclose(f); }\n"
                "}\n"
            ),
        )

        env = {**os.environ, "DYLD_INSERT_LIBRARIES": str(dylib)}
        self._launch("dyld_injected", dyld_host, env=env, kind="dyld")
        self._launch("anti_ptrace", anti_ptrace, kind="ptrace")
        self._launch("anti_exc_ports", anti_exc, kind="exception_ports")

        deleted_copy = self.root / "deleted_exec"
        shutil.copy2(dyld_host, deleted_copy)
        deleted_proc = self._launch("deleted_exec", deleted_copy, kind="deleted_binary")

        time.sleep(self.hold_delay)

        try:
            deleted_copy.unlink()
        except OSError:
            pass

        for meta in self.metadata:
            if meta["pid"] == deleted_proc.pid:
                meta["deleted_on_disk"] = True
                meta["path_deleted"] = True
                break

        return list(self.metadata)

    def pid_list(self) -> list[int]:
        return [int(meta["pid"]) for meta in self.metadata]

    def payload(self) -> dict:
        return {
            "root": str(self.root),
            "pids": self.pid_list(),
            "processes": list(self.metadata),
        }

    def stop(self) -> None:
        for proc in reversed(self.procs):
            terminate_process(proc)
        self.procs.clear()


def _main() -> int:
    parser = argparse.ArgumentParser(description="Launch the procmon injection test lab")
    parser.add_argument("--state-file", default="", help="Write lab metadata JSON here")
    parser.add_argument("--hold", action="store_true", help="Keep the lab running until terminated")
    parser.add_argument("--root", default="", help="Existing temp dir to use for lab binaries")
    args = parser.parse_args()

    if not shutil.which("cc"):
        print("cc required for injection lab", file=sys.stderr)
        return 2

    root_ctx = None
    if args.root:
        root = Path(args.root)
    else:
        root_ctx = tempfile.TemporaryDirectory(prefix="procmon-injection-lab-")
        root = Path(root_ctx.name)

    lab = InjectionLab(root)
    try:
        payload = lab.payload() if lab.metadata else None
        lab.start()
        payload = lab.payload()
        if args.state_file:
            Path(args.state_file).write_text(
                json.dumps(payload, indent=2),
                encoding="utf-8",
            )
        print(json.dumps(payload))
        sys.stdout.flush()
        if not args.hold:
            return 0

        stop = {"flag": False}

        def _stop(*_args):
            stop["flag"] = True

        signal.signal(signal.SIGTERM, _stop)
        signal.signal(signal.SIGINT, _stop)
        while not stop["flag"]:
            time.sleep(0.2)
        return 0
    finally:
        lab.stop()
        try:
            os.remove("/tmp/procmon_lab_inject.log")
        except OSError:
            pass
        if root_ctx is not None:
            root_ctx.cleanup()


if __name__ == "__main__":
    raise SystemExit(_main())
