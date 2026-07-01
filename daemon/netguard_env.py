"""Read and write NetGuard install environment file (netguard.env)."""

from __future__ import annotations

import os
import sys


def netguard_env_file_path() -> str:
    if sys.platform == "win32":
        program_data = os.environ.get("ProgramData", r"C:\ProgramData")
        return os.path.join(program_data, "NetGuard", "netguard.env")
    return os.environ.get("NETGUARD_ENV_FILE", "/etc/netguard/netguard.env")


def read_env_file_values(path: str | None = None) -> dict[str, str]:
    """Return key/value pairs from the install env file."""
    env_path = path or netguard_env_file_path()
    values: dict[str, str] = {}
    if not os.path.isfile(env_path):
        return values
    try:
        with open(env_path, encoding="utf-8") as handle:
            for line in handle:
                stripped = line.strip()
                if not stripped or stripped.startswith("#") or "=" not in stripped:
                    continue
                key, _, value = stripped.partition("=")
                key = key.strip()
                if key:
                    values[key] = value.strip()
    except OSError:
        return values
    return values


def write_env_file_values(updates: dict[str, str], path: str | None = None) -> None:
    """Upsert NETGUARD_* keys in the platform netguard.env file."""
    env_path = path or netguard_env_file_path()
    directory = os.path.dirname(env_path)
    if directory:
        os.makedirs(directory, exist_ok=True)

    lines: list[str] = []
    if os.path.isfile(env_path):
        with open(env_path, encoding="utf-8") as handle:
            lines = handle.readlines()

    remaining = dict(updates)
    updated: list[str] = []
    touched: set[str] = set()

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            updated.append(line if line.endswith("\n") else f"{line}\n")
            continue
        key, _, _ = stripped.partition("=")
        key = key.strip()
        if key in remaining:
            updated.append(f"{key}={remaining[key]}\n")
            touched.add(key)
            del remaining[key]
            continue
        updated.append(line if line.endswith("\n") else f"{line}\n")

    for key, value in remaining.items():
        if updated and not updated[-1].endswith("\n\n"):
            updated.append("\n")
        updated.append(f"{key}={value}\n")

    with open(env_path, "w", encoding="utf-8") as handle:
        handle.writelines(updated)

    for key, value in updates.items():
        os.environ[key] = value


def env_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def load_and_apply_env_file() -> None:
    from db_path import load_netguard_env

    load_netguard_env()
