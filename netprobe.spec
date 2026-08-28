# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for NetProbe — onedir portable bundle.

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
    [],
    exclude_binaries=True,
    name='NetProbe',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    icon='netprobe.ico',
    disable_windowed_traceback=False,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    name='NetProbe',
)
