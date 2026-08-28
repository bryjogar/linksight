# LinkSight

Passive LLDP/CDP neighbor discovery for Windows, macOS, and Linux — identify which switch port and VLAN your device is connected to.

![LinkSight main window](docs/linksight_main.png)

Plug into an Ethernet port and LinkSight presents the network environment in three panels:

- **NIC Status** — lists network adapters on the local machine with link status, IP address, MAC address, and hardware descriptions.
- **LAN Info** — attached network identity: IP, subnet mask, gateway, DNS servers, DHCP server, and lease details read from the operating system and passively observed DHCP traffic.
- **Switch Info** — neighbor device connected to the active switch port: system hostname, hardware model, switch port ID and port description, VLAN ID, and management IPs. **Management IPs are clickable**: clicking an IP prompts for an SSH username, then launches a system terminal session with `ssh username@ip`. Passwords are typed directly into the terminal's ssh prompt; LinkSight never captures or stores credentials.

No historical logs, no active scanning, and no background tracking — LinkSight operates as an in-memory readout. Packet capture starts automatically upon launch on the preferred adapter, and selecting a different interface from the dropdown updates the capture stream live.

## Design

Dark, engineering-focused UI designed for readability, high information density, and instant status assessment.

## Quick Start

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python app.py                    # capture starts automatically
python app.py --demo             # replay simulated network frames without capture privileges
```

## Build

- **Windows (Folder / Portable):** `python build_exe.py` → `dist/LinkSight/LinkSight.exe` (portable directory, extracts once at build time for instant startup; Npcap required on target).
- **Windows (Single File):** `python build_portable.py` → `dist/LinkSight-Portable.exe` — single self-contained executable without `_internal/` folder. Convenient for remote deployment tools that transfer a single binary, though startup takes several seconds while decompressing to a temporary directory on each run.
- **macOS:** `python build_mac.py` → `dist/LinkSight.app` and `dist/LinkSight-mac.zip` (portable application bundle).

### Release via GitHub Actions

Tag a release to trigger automated multi-platform builds and a GitHub Release:

```bash
git tag linksight-v1.0.0
git push origin linksight-v1.0.0
```

The workflow (`.github/workflows/linksight.yml`) runs the test suite, builds Windows (portable folder and single-file executable) and macOS bundles, and publishes the release with downloadable artifacts attached.

## Requirements & Privileges

- **Windows:** Npcap driver installed (available from [npcap.com](https://npcap.com/#download)). Administrator privileges are typically required for raw packet capture.
- **macOS:** Packet capture requires BPF device access permissions (admin privileges / terminal permission).
- **Linux:** Requires `CAP_NET_RAW` capability (e.g. running via `sudo` or Docker `cap_add: [NET_RAW]`).

## Debugging

The **Raw frames** toggle at the bottom expands a live hexdump feed of captured LLDP, CDP, and DHCP frames, allowing frame verification against packet analyzers like Wireshark.

## Project Structure

```
app.py                  Application entry point
build_exe.py            Windows portable build script (PyInstaller onedir)
build_portable.py       Windows single-file portable build script
build_mac.py            macOS portable build script (.app + zip)
linksight.spec          PyInstaller spec (Windows onedir)
linksight-onefile.spec  PyInstaller spec (Windows single-file with slimmed Qt dependencies)
linksight-mac.spec      PyInstaller spec (macOS bundle)
linksight/
  capture/              Packet sniffing (Scapy), interface enumeration, Npcap helper, demo replay
  parse/                LLDP, CDP, and DHCP frame parsers and data models
  ui/                   PySide6 readout widgets, styling, and controller
tests/                  pytest suite and byte-accurate frame fixtures
```

