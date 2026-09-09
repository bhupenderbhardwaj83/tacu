"""Bounded foreground execution without pipes that descendants can hold open."""

from __future__ import annotations

import os
import signal
import subprocess
import tempfile
from pathlib import Path


def stop_group(process: subprocess.Popen) -> None:
    if os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                       capture_output=True, check=False, timeout=10)
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    process.wait(timeout=10)


def run_captured(command: list[str], *, cwd: Path, timeout: int,
                 limit: int = 1_000_000) -> tuple[int, bytes, bytes, bool]:
    """Run argv, retain bounded output, and stop the process group on timeout/interrupt."""

    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        process = subprocess.Popen(command, cwd=cwd, stdin=subprocess.DEVNULL,
                                   stdout=out, stderr=err, start_new_session=os.name != "nt",
                                   creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0)
        timed_out = False
        try:
            code = process.wait(timeout=max(1, timeout))
        except subprocess.TimeoutExpired:
            timed_out = True
            stop_group(process)
            code = 124
        except BaseException:
            stop_group(process)
            raise
        out.seek(0)
        err.seek(0)
        stdout, stderr = out.read(limit + 1), err.read(limit + 1)
        truncated = len(stdout) > limit or len(stderr) > limit
        stdout, stderr = stdout[:limit], stderr[:limit]
        if timed_out:
            stderr += (f"\nTimed out after {timeout}s. For a long-running server use "
                       "service_process start with a health_url, not shell.").encode()
        return code, stdout, stderr, truncated
