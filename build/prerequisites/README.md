# NetGuard Windows prerequisites

NetGuard bundles **Npcap** into `NetGuard-Setup.exe` so customers get one installer.

## Default build (development / home)

Running `build\windows\build-installer.ps1` downloads `npcap-installer.exe` from
[npcap.com](https://npcap.com/dist/) and embeds it in the setup EXE.

During install, if Npcap is not already on the PC, the setup runs the bundled
installer (customer accepts the Npcap license once in the Npcap wizard).

## Commercial / unlimited distribution

The free Npcap license allows only **5 installs** with third-party software and
does **not** allow silent redistribution at scale.

For a product you sell or deploy widely:

1. Purchase **Npcap OEM Redistribution** from [npcap.com/oem](https://npcap.com/oem/)
2. Save your licensed installer as:

   `build/prerequisites/npcap-oem.exe`

3. Rebuild: `.\build\windows\build-installer.ps1`

NetGuard will install Npcap **silently** (`/S`) with no extra windows.

## Files in this folder (not committed to git)

| File | Purpose |
|------|---------|
| `npcap-installer.exe` | Auto-downloaded free Npcap (bundled in setup) |
| `npcap-oem.exe` | Your licensed OEM build (silent, commercial) |
