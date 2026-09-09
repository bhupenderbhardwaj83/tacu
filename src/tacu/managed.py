"""A small supervisor for coding servers. It owns process handles, logs and shutdown."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

from .execution import stop_group


def workspace_key(workspace: Path) -> str:
    return hashlib.sha256(str(workspace.resolve()).encode()).hexdigest()[:24]


def atomic_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, default=str), encoding="utf-8")
    temporary.chmod(0o600)
    os.replace(temporary, path)


def supervise(path: Path) -> None:
    record = json.loads(path.read_text())
    process = None
    try:
        with (path.parent / "stdout.log").open("ab") as out, (path.parent / "stderr.log").open("ab") as err:
            process = subprocess.Popen(record["command"], cwd=record["cwd"], stdin=subprocess.DEVNULL,
                                       stdout=out, stderr=err, start_new_session=os.name != "nt",
                                       creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0)
            record.update(state="running", pid=process.pid)
            started = time.monotonic()
            while process.poll() is None:
                record["heartbeat"] = time.time()
                atomic_json(path, record)
                # Logs are files, never inherited captured pipes. Bound runaway output.
                too_large = any((path.parent / name).stat().st_size > 20_000_000
                                for name in ("stdout.log", "stderr.log"))
                if ((path.parent / "stop").exists() or too_large
                        or time.monotonic() - started > 86400):
                    record["reason"] = "stop requested" if (path.parent / "stop").exists() else "service resource limit"
                    stop_group(process)
                    break
                time.sleep(0.25)
            record.update(state="exited", exit_code=process.returncode)
    except BaseException as error:
        record.update(state="error", error=str(error))
        if process is not None and process.poll() is None:
            stop_group(process)
    finally:
        record["heartbeat"] = time.time()
        atomic_json(path, record)


if __name__ == "__main__":
    supervise(Path(sys.argv[1]))
