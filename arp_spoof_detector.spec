import os

block_cipher = None

project_root = os.path.dirname(os.path.abspath(SPEC))
daemon_path = os.path.join(project_root, "daemon")

a = Analysis(
    ["daemon/detection/arp_spoof_detector.py"],
    pathex=[project_root, daemon_path],
    binaries=[],
    datas=[],
    hiddenimports=["db_path"],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludedimports=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="arp-spoof-detector",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
