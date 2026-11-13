"""Run the sensor daemon as a per-user background service.

    sga-sensor service install --openclaw     # write the definition and start it
    sga-sensor service status
    sga-sensor service uninstall

The service runs ``sga-sensor --home <home> run ...`` at login and restarts it if it exits.
No secrets go into the definition: the gateway token is read from ``<home>/openclaw-token`` (0600).

- macOS: a launchd LaunchAgent.
- Windows (M12): a Task Scheduler task for the signed-in user (at logon, restart on failure), run
  windowless with ``pythonw``, logging to ``<home>/logs/sensor.log``. Per user, not SYSTEM: the sensor
  watches that person's agents (``~/.openclaw``). If the task cannot be created (some managed PCs
  forbid it), a hidden launcher goes into the user's Startup folder instead.
- Linux (systemd --user) is printed with ``--dry-run`` only for now.
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


TASK_NAME = "SG-Advance Sensor"


def windows_command(home: Path, run_args: list[str], python_dir: Path | None = None) -> tuple[str, list[str]]:
    """(program, arguments): the venv's pythonw running the sensor module, no console window."""
    scripts = python_dir or Path(sys.executable).parent
    pythonw = scripts / "pythonw.exe"
    log = home / "logs" / "sensor.log"
    args = ["-m", "sg_advance.sensor.cli", "--home", str(home), "run", *run_args, "--log-file", str(log)]
    return str(pythonw), args


def _quote(arg: str) -> str:
    return f'"{arg}"' if (" " in arg or not arg) else arg


def windows_task_xml(home: Path, run_args: list[str], user: str, python_dir: Path | None = None) -> str:
    """Task Scheduler XML: at this user's logon, as this user (no elevation), restart on failure."""
    from xml.sax.saxutils import escape as e

    program, args = windows_command(home, run_args, python_dir)
    arguments = " ".join(_quote(a) for a in args)
    who = e(user)
    return "\n".join(
        [
            '<?xml version="1.0" encoding="UTF-16"?>',
            '<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">',
            "  <RegistrationInfo><Description>SG-Advance endpoint sensor"
            " (reports agent activity to security)</Description></RegistrationInfo>",
            "  <Triggers><LogonTrigger><Enabled>true</Enabled>"
            f"<UserId>{who}</UserId></LogonTrigger></Triggers>",
            f'  <Principals><Principal id="Author"><UserId>{who}</UserId>'
            "<LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>",
            "  <Settings>",
            "    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>",
            "    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>",
            "    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>",
            "    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>",
            "    <RestartOnFailure><Interval>PT1M</Interval><Count>999</Count></RestartOnFailure>",
            "  </Settings>",
            '  <Actions Context="Author"><Exec>',
            f"    <Command>{e(program)}</Command>",
            f"    <Arguments>{e(arguments)}</Arguments>",
            f"    <WorkingDirectory>{e(str(home))}</WorkingDirectory>",
            "  </Exec></Actions>",
            "</Task>",
            "",
        ]
    )


def startup_launcher(home: Path, run_args: list[str], python_dir: Path | None = None) -> str:
    """Fallback: a .vbs in the Startup folder that starts the sensor hidden at sign-in."""
    program, args = windows_command(home, run_args, python_dir)
    line = " ".join(_quote(a) for a in [program, *args]).replace('"', '""')
    return f'CreateObject("WScript.Shell").Run "{line}", 0, False\r\n'


def _startup_path() -> Path:
    appdata = Path(os.environ.get("APPDATA", str(Path.home() / "AppData" / "Roaming")))
    return appdata / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup" / "sg-advance-sensor.vbs"


def _schtasks(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["schtasks", *args], capture_output=True, text=True, errors="replace", check=False)


def _windows_user() -> str:
    domain = os.environ.get("USERDOMAIN")
    user = os.environ.get("USERNAME") or Path.home().name
    return f"{domain}\\{user}" if domain else user


def install_windows(home: Path, run_args: list[str], dry_run: bool = False) -> str:
    xml = windows_task_xml(home, run_args, _windows_user())
    if dry_run:
        return xml
    (home / "logs").mkdir(parents=True, exist_ok=True)
    path = home / "sensor-task.xml"
    path.write_text(xml, encoding="utf-16")
    res = _schtasks("/Create", "/TN", TASK_NAME, "/XML", str(path), "/F")
    if res.returncode == 0:
        _schtasks("/Run", "/TN", TASK_NAME)
        return f"registered task '{TASK_NAME}' (at logon) and started it; log: {home / 'logs' / 'sensor.log'}"
    launcher = _startup_path()
    launcher.parent.mkdir(parents=True, exist_ok=True)
    launcher.write_text(startup_launcher(home, run_args), encoding="utf-8")
    subprocess.run(["wscript.exe", str(launcher)], check=False)  # start it now too
    why = (res.stderr or res.stdout).strip()
    return f"task not allowed ({why}); started from the Startup folder instead: {launcher}"


def _launchctl(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["launchctl", *args], capture_output=True, text=True, check=False)


def install(home: Path, run_args: list[str], dry_run: bool = False) -> str:
    if sys.platform == "win32":
        return install_windows(home, run_args, dry_run)
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
    if sys.platform == "win32":
        _schtasks("/End", "/TN", TASK_NAME)
        res = _schtasks("/Delete", "/TN", TASK_NAME, "/F")
        removed = [f"task '{TASK_NAME}'"] if res.returncode == 0 else []
        if _startup_path().exists():
            _startup_path().unlink()
            removed.append("Startup launcher")
        return "removed " + " and ".join(removed) if removed else "not installed"
    _launchctl("bootout", f"gui/{os.getuid()}/{LABEL}")
    path = plist_path()
    if path.exists():
        path.unlink()
        return f"stopped and removed {path}"
    return "not installed"


def status() -> str:
    if sys.platform == "win32":
        res = _schtasks("/Query", "/TN", TASK_NAME, "/V", "/FO", "LIST")
        if res.returncode != 0:
            return "Startup launcher installed" if _startup_path().exists() else "not installed"
        keep = ("Status:", "Last Run Time:", "Last Result:", "Next Run Time:")
        return "\n".join(ln.strip() for ln in res.stdout.splitlines() if ln.strip().startswith(keep))
    res = _launchctl("print", f"gui/{os.getuid()}/{LABEL}")
    if res.returncode != 0:
        return "not running (not loaded)"
    keep = ("state =", "pid =", "last exit code", "program =")
    lines = [ln.strip() for ln in res.stdout.splitlines() if ln.strip().startswith(keep)]
    return "\n".join(lines) or res.stdout.strip()
