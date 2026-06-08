# -*- mode: python ; coding: utf-8 -*-

import os

from PyInstaller.utils.hooks import collect_submodules

block_cipher = None


hiddenimports = []
hiddenimports += collect_submodules("minisiem")
# Rely on PyInstaller's built-in PySide6 hooks (collecting all submodules breaks on some installs).

project_root = os.path.abspath(os.path.join(SPECPATH, ".."))


a = Analysis(
    [os.path.join(project_root, "minisiem", "__main__.py")],
    pathex=[project_root],
    binaries=[],
    datas=[],
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    a.binaries,
    a.zipfiles,
    a.datas,
    exclude_binaries=False,
    name="miniSIEM",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    onefile=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = exe

