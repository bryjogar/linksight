# LinkSight — single-file portable build (for remote deployment tools)
#
# Produces dist/LinkSight-Portable.exe — one self-contained file with the
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
    excludes=[
        'PySide6.QtQml',
        'PySide6.QtQuick',
        'PySide6.QtQuickWidgets',
        'PySide6.QtMultimedia',
        'PySide6.QtMultimediaWidgets',
        'PySide6.QtWebEngineCore',
        'PySide6.QtWebEngineWidgets',
        'PySide6.QtWebChannel',
        'PySide6.QtPdf',
        'PySide6.QtPdfWidgets',
        'PySide6.QtSvg',
        'PySide6.QtSvgWidgets',
        'PySide6.QtDesigner',
        'PySide6.QtOpenGL',
        'PySide6.QtOpenGLWidgets',
        'PySide6.QtNetwork',
        'PySide6.QtSql',
        'PySide6.QtTest',
    ],
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
    name='LinkSight-Portable',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    icon='linksight.ico',
    disable_windowed_traceback=True,
)

