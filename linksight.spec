# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for LinkSight — onedir portable bundle.

a = Analysis(
    ['app.py'],
    pathex=[],
    binaries=[],
    datas=[('linksight.ico', '.')],
    hiddenimports=[
        'linksight',
        'linksight.capture',
        'linksight.capture.interfaces',
        'linksight.capture.sniffer',
        'linksight.capture.demo',
        'linksight.capture.npcap',
        'linksight.capture.oui_lookup',
        'linksight.capture.system_info',
        'linksight.parse',
        'linksight.parse.lldp',
        'linksight.parse.cdp',
        'linksight.parse.frames',
        'linksight.parse.model',
        'linksight.parse.builders',
        'linksight.parse.dhcp',
        'linksight.ui',
        'linksight.ui.controller',
        'linksight.ui.theme',
        'linksight.ui.main_window',
        'linksight.ui.nic_status_widget',
        'linksight.ui.lan_info_widget',
        'linksight.ui.switch_info_widget',
        'linksight.ui.settings_widget',
        'linksight.ui.feed_widget',
        'linksight.ui.ssh_terminal',
        'linksight.ui.update_event',
        'linksight.updater',
        'linksight.util',
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
    name='LinkSight',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    icon='linksight.ico',
    disable_windowed_traceback=False,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    name='LinkSight',
)

