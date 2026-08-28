# NetProbe — single-file portable build (for remote deployment tools)
#
# Produces dist/NetProbe-Portable.exe — one self-contained file with the
# entire runtime embedded. Extracts to a temp dir on each launch (5-15s
# startup), but requires NO _internal folder, no install, no dependencies.
#
# Remote-tool use case: service desk pushes this single exe to a client
# device, runs it, reads the port/switch info, done.

# -*- mode: python ; coding: utf-8 -*-

a = Analysis(
    ['app.py'],
    pathex=[],
    binaries=[],
    datas=[('netprobe.ico', '.')],
    hiddenimports=[
        'netprobe',
        'netprobe.capture',
        'netprobe.capture.interfaces',
        'netprobe.capture.sniffer',
        'netprobe.capture.demo',
        'netprobe.capture.npcap',
        'netprobe.capture.oui_lookup',
        'netprobe.capture.system_info',
        'netprobe.parse',
        'netprobe.parse.lldp',
        'netprobe.parse.cdp',
        'netprobe.parse.frames',
        'netprobe.parse.model',
        'netprobe.parse.builders',
        'netprobe.parse.dhcp',
        'netprobe.ui',
        'netprobe.ui.controller',
        'netprobe.ui.theme',
        'netprobe.ui.main_window',
        'netprobe.ui.nic_status_widget',
        'netprobe.ui.lan_info_widget',
        'netprobe.ui.switch_info_widget',
        'netprobe.ui.settings_widget',
        'netprobe.ui.feed_widget',
        'netprobe.ui.ssh_terminal',
        'netprobe.ui.update_event',
        'netprobe.updater',
        'netprobe.util',
    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='NetProbe-Portable',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    icon='netprobe.ico',
    disable_windowed_traceback=True,
)
