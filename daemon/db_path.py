"""Shared SQLite database path resolution for dev and PyInstaller builds."""

import os
import sqlite3
import sys


def _windows_programdata_db_path() -> str:
    program_data = os.environ.get("ProgramData", r"C:\ProgramData")
    return os.path.join(program_data, "NetGuard", "netguard.db")


def _windows_appdata_db_path() -> str:
    local_app_data = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    return os.path.join(local_app_data, "NetGuard", "netguard.db")


def _windows_writable_db_path() -> str:
    """Default writable database location for installed Windows builds."""
    return _windows_programdata_db_path()


def _is_under_program_files(path: str) -> bool:
    if sys.platform != "win32":
        return False
    normalized = os.path.abspath(path).lower()
    for root in (
        os.environ.get("ProgramFiles", r"C:\Program Files"),
        os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
    ):
        root_norm = os.path.abspath(root).lower().rstrip("\\")
        if normalized == root_norm or normalized.startswith(root_norm + os.sep):
            return True
    return False


def ensure_db_directory(db_path: str) -> None:
    directory = os.path.dirname(os.path.abspath(db_path))
    if directory:
        os.makedirs(directory, exist_ok=True)


def load_netguard_env() -> None:
    """Load NETGUARD_* variables from the platform install env file when unset."""
    env_paths: list[str] = []
    if sys.platform == "win32":
        program_data = os.environ.get("ProgramData", r"C:\ProgramData")
        env_paths.append(os.path.join(program_data, "NetGuard", "netguard.env"))
        if getattr(sys, "frozen", False):
            env_paths.append(
                os.path.join(os.path.dirname(os.path.abspath(sys.executable)), "netguard.env")
            )
    else:
        env_paths.append(
            os.environ.get("NETGUARD_ENV_FILE", "/etc/netguard/netguard.env")
        )

    for path in env_paths:
        if not path or not os.path.isfile(path):
            continue
        try:
            with open(path, encoding="utf-8") as handle:
                for line in handle:
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#") or "=" not in stripped:
                        continue
                    key, _, value = stripped.partition("=")
                    key = key.strip()
                    value = value.strip()
                    if key and key not in os.environ:
                        os.environ[key] = value
            return
        except OSError:
            continue


def resolve_db_path(project_root: str | None = None) -> str:
    """
    Locate netguard.db.

    Installed Windows builds must not use Program Files (read-only). Prefer
    NETGUARD_DB_PATH, then %ProgramData%\\NetGuard\\netguard.db.
    """
    load_netguard_env()
    env_path = os.environ.get("NETGUARD_DB_PATH", "").strip()
    if env_path:
        return os.path.abspath(env_path)

    candidates: list[str] = []

    if getattr(sys, "frozen", False):
        if sys.platform == "win32":
            candidates.extend(
                [
                    _windows_programdata_db_path(),
                    _windows_appdata_db_path(),
                ]
            )

        exe_dir = os.path.dirname(os.path.abspath(sys.executable))
        candidates.append(os.path.join(exe_dir, "netguard.db"))
        candidates.append(os.path.join(os.getcwd(), "netguard.db"))

        search_dir = exe_dir
        for _ in range(5):
            candidates.append(os.path.join(search_dir, "netguard.db"))
            parent = os.path.dirname(search_dir)
            if parent == search_dir:
                break
            search_dir = parent
    else:
        root = project_root or os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..")
        )
        candidates.append(os.path.join(root, "netguard.db"))

    seen: set[str] = set()
    for path in candidates:
        normalized = os.path.abspath(path)
        if normalized in seen:
            continue
        seen.add(normalized)
        if not os.path.exists(normalized):
            continue
        if _is_under_program_files(normalized):
            continue
        return normalized

    if getattr(sys, "frozen", False):
        if sys.platform == "win32":
            return _windows_writable_db_path()
        return os.path.join(os.path.dirname(os.path.abspath(sys.executable)), "netguard.db")

    root = project_root or os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..")
    )
    return os.path.join(root, "netguard.db")


def open_db_connection(db_path: str, timeout: float = 30.0) -> sqlite3.Connection:
    """
    Open SQLite with settings suited to multi-process NetGuard daemons.

    WAL mode and a long busy timeout reduce 'database is locked' errors when
    the API and scanners are running during maintenance scripts.
    """
    ensure_db_directory(db_path)
    conn = sqlite3.connect(db_path, timeout=timeout)
    conn.execute("PRAGMA busy_timeout = 60000")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn
