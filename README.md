# NetProbe

Passive LLDP/CDP neighbor discovery for Windows and macOS — a desktop alternative to the Netool.io probe.

![NetProbe main window](docs/netprobe_main.png)

Plug into a switch port and NetProbe shows you the network in three clean panels:

- **NIC Status** — every adapter on this machine, link state, IP, MAC
- **LAN Info** — the attached network's identity: IP, subnet, gateway, DNS, DHCP server, MAC (read from the OS, plus what DHCP traffic is observed on the wire)
- **Switch Info** — the neighbor the port is connected to: hostname, model, switch port (from the Port Description TLV), VLAN, management IPs. **Management IPs are clickable**: clicking one asks for an SSH username, then opens a terminal running `ssh user@ip`. The password is typed straight into the terminal's own ssh prompt — NetProbe never stores or logs it.

No history, no scanning, no tracking — a readout, not a collector. Capture runs automatically on launch; change the interface dropdown at any time to swap adapters live.

## Design language

K'Nex over Duplo. Professional, engineered, dense, precise. No bubble buttons,
no flat pastel candy, no toy-app chrome. Same palette and styling as WiFi Explorer.

## Quick start

```
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python app.py                    # capture starts automatically
python app.py --demo             # simulated network, no privileges needed
```

## Build

- **Windows (folder):** `python build_exe.py` → `dist/NetProbe/NetProbe.exe` (portable folder, no install; Npcap required on target)
- **Windows (single file):** `python build_portable.py` → `dist/NetProbe-Portable.exe` — one self-contained exe, no `_internal` folder. Slower to start (extracts to temp each run) but pushable to a client device by remote tooling that only moves one file.
- **macOS:** `python build_mac.py` → `dist/NetProbe.app` + zip (portable bundle; Gatekeeper note in script)

### Release via GitHub Actions (recommended)

Tag a release and CI builds both platforms and publishes a GitHub Release:

```
git tag netprobe-v1.0.0
git push origin netprobe-v1.0.0
```

The workflow (`.github/workflows/netprobe.yml`) runs the test suite, builds
Windows + macOS, zips both, and creates a release with the downloads attached.
The in-app **Update available** link points at the latest release.

> Note: `dist/` is gitignored on purpose — CI builds from source on tag, so
> release binaries never live in the repo. Tagging is the deliberate act.

## Requirements

- **Windows:** Npcap installed (from npcap.com)
- **macOS:** capture needs BPF access (admin)

## Debugging

The **Raw frames** toggle at the bottom shows the exact bytes of every captured
frame (hexdump) — copy any frame into Wireshark to verify what the switch sent.

## Structure

```
app.py                  entry point
build_exe.py            Windows portable build (PyInstaller onedir)
build_mac.py            macOS portable build (.app + zip)
netprobe.spec           PyInstaller spec (Windows)
netprobe-mac.spec       PyInstaller spec (macOS)
netprobe/
  capture/              interface discovery + sniffing (Scapy) + demo replay
  parse/                LLDP + CDP + DHCP parsers
  ui/                   PySide6 readout widgets
tests/                  pytest suite + frame fixtures
```
