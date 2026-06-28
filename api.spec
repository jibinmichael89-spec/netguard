import os

block_cipher = None

project_root = os.path.dirname(os.path.abspath(SPEC))
vault_path = os.path.join(project_root, "daemon", "vault")
daemon_path = os.path.join(project_root, "daemon")

a = Analysis(
    ["api/main.py"],
    pathex=[project_root, vault_path, daemon_path],
    binaries=[],
    datas=[
        ("api/static", "api/static"),
        ("daemon/data", "daemon/data"),
        ("daemon/scanner", "daemon/scanner"),
        ("daemon/detection", "daemon/detection"),
        ("daemon/enforcement", "daemon/enforcement"),
        ("daemon/notifications", "daemon/notifications"),
        ("daemon/reports", "daemon/reports"),
    ],
    hiddenimports=[
        "fastapi",
        "uvicorn",
        "uvicorn.logging",
        "uvicorn.loops",
        "uvicorn.loops.auto",
        "uvicorn.protocols",
        "uvicorn.protocols.http",
        "uvicorn.protocols.http.auto",
        "uvicorn.protocols.websockets",
        "uvicorn.protocols.websockets.auto",
        "uvicorn.lifespan",
        "uvicorn.lifespan.on",
        "scapy",
        "requests",
        "pydantic",
        "password_vault",
        "db_path",
        "database",
        "schema_extensions",
        "features",
        "msp",
        "router_manager",
        "linksys_client",
        "openwrt_client",
        "cryptography",
        "cryptography.fernet",
        "cryptography.hazmat.primitives.hashes",
        "cryptography.hazmat.primitives.kdf.pbkdf2",
    ],
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
    name="NetGuard-API",
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
