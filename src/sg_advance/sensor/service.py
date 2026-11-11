"""Run the sensor daemon as a per-user background service (macOS launchd LaunchAgent).

    sga-sensor service install --openclaw     # write the plist and start it
    sga-sensor service status
    sga-sensor service uninstall

The service runs ``sga-sensor --home <home> run ...`` at login and restarts it if it exits.
No secrets go into the plist: the gateway token is read from ``<home>/openclaw-token`` (0600).
Linux (systemd --user) is printed with ``--dry-run`` only for now.
"""

from __future__ import annotations

import os
import plistlib
import shutil
import subprocess
import sys
import time
from pathlib import Path

LABEL = "com.sg-advance.sensor"


def sensor_executable() -> str:
    """The sga-sensor next to the running interpreter (the venv), else the one on PATH."""
    beside = Path(sys.executable).parent / "sga-sensor"
    if beside.exists():
        return str(beside)
    found = shutil.which("sga-sensor")
    if not found:
        raise RuntimeError("sga-sensor executable not found")
    return found


def plist_path() -> Path:
    return Path.home() / "Library" / "LaunchAgents" / f"{LABEL}.plist"


def launchd_plist(home: Path, run_args: list[str], exe: str | None = None) -> bytes:
    logs = home / "logs"
    doc = {
        "Label": LABEL,
        "ProgramArguments": [exe or sensor_executable(), "--home", str(home), "run", *run_args],
        "RunAtLoad": True,
        "KeepAlive": True,
        "ThrottleInterval": 10,  # don't hot-loop if the daemon keeps failing
        "ProcessType": "Background",
        "StandardOutPath": str(logs / "sensor.log"),
        "StandardErrorPath": str(logs / "sensor.log"),
        "WorkingDirectory": str(home),
        # launchd starts jobs with a bare PATH; the integrity scan runs `openclaw` (a node script).
        # PATH is not secret; tokens still come from <home>/openclaw-token.
        "EnvironmentVariables": {"PATH": service_path()},
    }
    return plistlib.dumps(doc)


def service_path(env_path: str | None = None) -> str:
    """The installer's PATH plus the usual system dirs, so `openclaw` and `node` resolve."""
    raw = (env_path if env_path is not None else os.environ.get("PATH", "")).split(":")
    system = ["/usr/local/bin", "/opt/homebrew/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"]
    return ":".join(dict.fromkeys(p for p in [*raw, *system] if p))  # keep order, drop repeats


def systemd_unit(home: Path, run_args: list[str], exe: str | None = None) -> str:
    cmd = " ".join([exe or sensor_executable(), "--home", str(home), "run", *run_args])
    return (
        "[Unit]\nDescription=SG-Advance sensor\n\n"
        f"[Service]\nExecStart={cmd}\nRestart=always\nRestartSec=10\n\n"
        "[Install]\nWantedBy=default.target\n"
    )


def _launchctl(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["launchctl", *args], capture_output=True, text=True, check=False)


def install(home: Path, run_args: list[str], dry_run: bool = False) -> str:
    if sys.platform != "darwin":
        unit = systemd_unit(home, run_args)
        if dry_run:
            return unit
        raise RuntimeError("only macOS launchd is supported for now; use --dry-run to print a systemd unit")
    data = launchd_plist(home, run_args)
    if dry_run:
        return data.decode()
    (home / "logs").mkdir(parents=True, exist_ok=True)
    path = plist_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    domain = f"gui/{os.getuid()}"
    _launchctl("bootout", f"{domain}/{LABEL}")  # replace an older definition, ignore "not loaded"
    path.write_bytes(data)
    res = _launchctl("bootstrap", domain, str(path))
    if res.returncode != 0:  # bootout finishes asynchronously; "5: Input/output error" until it does
        time.sleep(2)
        res = _launchctl("bootstrap", domain, str(path))
    if res.returncode != 0:
        raise RuntimeError(f"launchctl bootstrap failed: {res.stderr.strip() or res.stdout.strip()}")
    return f"installed {path} and started {LABEL}"


def uninstall() -> str:
    _launchctl("bootout", f"gui/{os.getuid()}/{LABEL}")
    path = plist_path()
    if path.exists():
        path.unlink()
        return f"stopped and removed {path}"
    return "not installed"


def status() -> str:
    res = _launchctl("print", f"gui/{os.getuid()}/{LABEL}")
    if res.returncode != 0:
        return "not running (not loaded)"
    keep = ("state =", "pid =", "last exit code", "program =")
    lines = [ln.strip() for ln in res.stdout.splitlines() if ln.strip().startswith(keep)]
    return "\n".join(lines) or res.stdout.strip()
