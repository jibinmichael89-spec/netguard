"""Shared SQLite database path resolution for dev and PyInstaller builds."""

import os
import sqlite3
import sys


def _windows_appdata_db_path() -> str:
    local_app_data = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    return os.path.join(local_app_data, "NetGuard", "netguard.db")


def ensure_db_directory(db_path: str) -> None:
    directory = os.path.dirname(os.path.abspath(db_path))
    if directory:
        os.makedirs(directory, exist_ok=True)


def resolve_db_path(project_root: str | None = None) -> str:
    """
    Locate netguard.db.

    When installed under Program Files, defaults to a writable path in
    %LOCALAPPDATA%\\NetGuard\\ on Windows.
    """
    env_path = os.environ.get("NETGUARD_DB_PATH", "").strip()
    if env_path:
        return env_path

    candidates: list[str] = []

    if getattr(sys, "frozen", False):
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

        if sys.platform == "win32":
            candidates.append(_windows_appdata_db_path())
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
        if os.path.exists(normalized):
            return normalized

    if getattr(sys, "frozen", False):
        if sys.platform == "win32":
            return _windows_appdata_db_path()
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
