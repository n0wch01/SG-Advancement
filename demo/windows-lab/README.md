# Windows lab pages (docs/windows-test.md, step 2)

Served from the Mac to the Windows laptop during the live test only:

    python3 -m http.server 18896 --bind <Mac LAN IP> --directory demo/windows-lab

- `setup.html`: external page with an injection line (group 3: injection then destructive command)
- `reset.html`: external page without an injection line (group 3: external input then destructive command)
- `install.ps1`: a harmless script for `iwr | iex` (group 3: downloaded script run directly)

All content is fake. Nothing here is imported by src/, tests/ or scripts/.
