import os

block_cipher = None
project_root = os.path.dirname(os.path.abspath(SPEC))
daemon_path = os.path.join(project_root, "daemon")
data_path = os.path.join(daemon_path, "data")

a = Analysis(
    ["daemon/detection/risk_scorer.py"],
    pathex=[project_root, daemon_path],
    binaries=[],
    datas=[(data_path, os.path.join("daemon", "data"))],
    hiddenimports=["db_path", "schema_extensions"],
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
    name="risk-scorer",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
