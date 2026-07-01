"""NETGUARD_API_KEY lifecycle and FastAPI auth dependency."""

from __future__ import annotations

import os
import secrets
import sys

from fastapi import Header, HTTPException

_API_KEY_ENV = "NETGUARD_API_KEY"


def netguard_env_file_path() -> str:
    if sys.platform == "win32":
        program_data = os.environ.get("ProgramData", r"C:\ProgramData")
        return os.path.join(program_data, "NetGuard", "netguard.env")
    return os.environ.get("NETGUARD_ENV_FILE", "/etc/netguard/netguard.env")


def read_api_key_from_env_file(path: str) -> str:
    if not os.path.isfile(path):
        return ""
    try:
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                stripped = line.strip()
                if not stripped or stripped.startswith("#") or "=" not in stripped:
                    continue
                key, _, value = stripped.partition("=")
                if key.strip() == _API_KEY_ENV:
                    return value.strip()
    except OSError:
        return ""
    return ""


def write_api_key_to_env_file(path: str, api_key: str) -> None:
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)

    lines: list[str] = []
    if os.path.isfile(path):
        with open(path, encoding="utf-8") as handle:
            lines = handle.readlines()

    updated: list[str] = []
    found = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("#") and _API_KEY_ENV in stripped:
            updated.append(f"{_API_KEY_ENV}={api_key}\n")
            found = True
            continue
        if stripped.startswith(f"{_API_KEY_ENV}="):
            updated.append(f"{_API_KEY_ENV}={api_key}\n")
            found = True
            continue
        updated.append(line if line.endswith("\n") else f"{line}\n")

    if not found:
        if updated and not updated[-1].endswith("\n\n"):
            updated.append("\n")
        updated.append(f"{_API_KEY_ENV}={api_key}\n")

    with open(path, "w", encoding="utf-8") as handle:
        handle.writelines(updated)


def ensure_api_key_configured() -> str:
    """Load or generate NETGUARD_API_KEY; persist to the platform env file."""
    from db_path import load_netguard_env

    load_netguard_env()

    configured = os.environ.get(_API_KEY_ENV, "").strip()
    if configured:
        return configured

    env_path = netguard_env_file_path()
    file_key = read_api_key_from_env_file(env_path)
    if file_key:
        os.environ[_API_KEY_ENV] = file_key
        return file_key

    generated = secrets.token_hex(16)
    write_api_key_to_env_file(env_path, generated)
    os.environ[_API_KEY_ENV] = generated
    print(
        f"[SECURITY] No API key was configured — generated one automatically. "
        f"Find it in {env_path}",
        flush=True,
    )
    return generated


def get_api_key() -> str:
    key = os.environ.get(_API_KEY_ENV, "").strip()
    if key:
        return key
    return ensure_api_key_configured()


def require_api_key(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> None:
    verify_api_key(x_api_key)


def verify_api_key(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> str:
    """FastAPI dependency: require valid X-API-Key and return it."""
    required = get_api_key()
    if not x_api_key or x_api_key != required:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
    return x_api_key
