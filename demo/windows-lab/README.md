# Windows lab pages (docs/windows-test.md, step 2)

Served from the Mac to the Windows laptop during the live test only:

    python3 -m http.server 18896 --bind <Mac LAN IP> --directory demo/windows-lab

- `setup.html`: external page with an injection line (group 3: injection then destructive command)
- `reset.html`: external page without an injection line (group 3: external input then destructive command)
- `install.ps1`: a harmless script for `iwr | iex` (group 3: downloaded script run directly)
- `lab.txt`: PowerShell helpers for the tester (`irm http://<Mac LAN IP>:18896/lab.txt | iex`, then `lab`, `lab-reset`,
  `lab-sensor off|on`, `lab-hook off|on`, `lab-t15`). ASCII only, served as text so `irm | iex` gets a string.
- `prompts.html`: the test prompts to copy into Claude Code (open it in the laptop's browser)

All content is fake. Nothing here is imported by src/, tests/ or scripts/.
