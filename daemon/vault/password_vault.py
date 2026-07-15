#!/usr/bin/env python3
"""
NetGuard Password Vault
Encrypted local storage for device credentials with breach checking.
"""

from __future__ import annotations

import base64
import getpass
import hashlib
import json
import os
import re
import secrets
import sqlite3
import string
import sys
import time
from datetime import datetime, timezone
from typing import Any

import requests
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

if getattr(sys, "frozen", False):
    _daemon_dir = os.path.join(sys._MEIPASS, "daemon")
else:
    _daemon_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

if os.path.isdir(_daemon_dir) and _daemon_dir not in sys.path:
    sys.path.insert(0, _daemon_dir)

from db_path import resolve_db_path

DB_PATH = resolve_db_path(
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    if not getattr(sys, "frozen", False)
    else None
)

VERIFIER_PLAINTEXT = "NETGUARD_VAULT_OK"
PBKDF2_ITERATIONS = 480_000
HIBP_API_URL = "https://api.pwnedpasswords.com/range/{prefix}"
SESSION_TTL_SECONDS = 900
PASSWORD_HISTORY_LIMIT = 5

VAULT_CATEGORIES = (
    "Router",
    "Camera",
    "IoT",
    "NAS",
    "Printer",
    "Smart Home",
    "Network",
    "Other",
)

_vault_sessions: dict[str, tuple[str, float]] = {}


# ---------------------------------------------------------------------------
# Database operations
# ---------------------------------------------------------------------------

def _ensure_column(cursor: sqlite3.Cursor, table: str, column: str, definition: str) -> None:
    cursor.execute(f"PRAGMA table_info({table})")
    existing = {row[1] for row in cursor.fetchall()}
    if column not in existing:
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def init_database(db_path: str = DB_PATH) -> None:
    """Create vault tables and apply schema migrations."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS vault_credentials (
            id                 INTEGER PRIMARY KEY AUTOINCREMENT,
            device_name        TEXT NOT NULL,
            device_ip          TEXT,
            username           TEXT NOT NULL,
            encrypted_password TEXT NOT NULL,
            strength_score     INTEGER NOT NULL,
            is_compromised     INTEGER DEFAULT 0,
            last_checked       TEXT,
            created_at         TEXT NOT NULL
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS vault_config (
            id       INTEGER PRIMARY KEY,
            salt     TEXT NOT NULL,
            verifier TEXT NOT NULL
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS vault_credential_history (
            id                 INTEGER PRIMARY KEY AUTOINCREMENT,
            credential_id      INTEGER NOT NULL,
            encrypted_password TEXT NOT NULL,
            changed_at         TEXT NOT NULL,
            FOREIGN KEY (credential_id) REFERENCES vault_credentials(id) ON DELETE CASCADE
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS vault_notes (
            id                 INTEGER PRIMARY KEY AUTOINCREMENT,
            title              TEXT NOT NULL,
            encrypted_content  TEXT NOT NULL,
            category           TEXT NOT NULL DEFAULT 'Other',
            created_at         TEXT NOT NULL,
            updated_at         TEXT NOT NULL
        )
        """
    )

    _ensure_column(cursor, "vault_credentials", "category", "TEXT NOT NULL DEFAULT 'Other'")
    _ensure_column(cursor, "vault_credentials", "breach_status", "TEXT NOT NULL DEFAULT 'unchecked'")
    _ensure_column(cursor, "vault_credentials", "breach_count", "INTEGER NOT NULL DEFAULT 0")
    _ensure_column(cursor, "vault_credentials", "last_breach_check", "TEXT")

    cursor.execute(
        """
        UPDATE vault_credentials
        SET breach_status = 'breached'
        WHERE is_compromised = 1 AND breach_status = 'unchecked'
        """
    )
    cursor.execute(
        """
        UPDATE vault_credentials
        SET breach_status = 'clean', last_breach_check = COALESCE(last_breach_check, last_checked)
        WHERE is_compromised = 0 AND last_checked IS NOT NULL AND breach_status = 'unchecked'
        """
    )

    conn.commit()
    conn.close()


def vault_exists(db_path: str = DB_PATH) -> bool:
    """Return True if the vault has been initialized with a master password."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM vault_config")
    count = cursor.fetchone()[0]
    conn.close()
    return count > 0


# ---------------------------------------------------------------------------
# Session management
# ---------------------------------------------------------------------------

def _purge_expired_sessions() -> None:
    now = time.time()
    expired = [token for token, (_, expiry) in _vault_sessions.items() if expiry <= now]
    for token in expired:
        _vault_sessions.pop(token, None)


def create_vault_session(master_password: str) -> str:
    """Create a short-lived vault session token after successful unlock."""
    _purge_expired_sessions()
    token = secrets.token_urlsafe(32)
    _vault_sessions[token] = (master_password, time.time() + SESSION_TTL_SECONDS)
    return token


def touch_vault_session(session_token: str) -> bool:
    """Extend session expiry on activity."""
    session = _vault_sessions.get(session_token)
    if session is None:
        return False
    master_password, expiry = session
    if time.time() > expiry:
        _vault_sessions.pop(session_token, None)
        return False
    _vault_sessions[session_token] = (master_password, time.time() + SESSION_TTL_SECONDS)
    return True


def resolve_master_password(
    master_password: str | None,
    session_token: str | None,
) -> str | None:
    """Resolve master password from direct input or an active session token."""
    if session_token:
        session = _vault_sessions.get(session_token)
        if session is None:
            return None
        stored_password, expiry = session
        if time.time() > expiry:
            _vault_sessions.pop(session_token, None)
            return None
        _vault_sessions[session_token] = (stored_password, time.time() + SESSION_TTL_SECONDS)
        return stored_password
    if master_password:
        return master_password
    return None


def invalidate_vault_session(session_token: str) -> None:
    _vault_sessions.pop(session_token, None)


# ---------------------------------------------------------------------------
# Key derivation and vault lifecycle
# ---------------------------------------------------------------------------

def _derive_fernet_key(master_password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))


def _load_vault_config(db_path: str) -> tuple[bytes, str] | None:
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT salt, verifier FROM vault_config WHERE id = 1")
    row = cursor.fetchone()
    conn.close()
    if row is None:
        return None
    return base64.b64decode(row[0]), row[1]


def initialize_vault(master_password: str, db_path: str = DB_PATH) -> None:
    init_database(db_path)
    salt = os.urandom(16)
    fernet = Fernet(_derive_fernet_key(master_password, salt))
    verifier = fernet.encrypt(VERIFIER_PLAINTEXT.encode()).decode()

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM vault_config")
    cursor.execute(
        """
        INSERT INTO vault_config (id, salt, verifier)
        VALUES (1, ?, ?)
        """,
        (base64.b64encode(salt).decode(), verifier),
    )
    conn.commit()
    conn.close()


def unlock_vault(master_password: str, db_path: str = DB_PATH) -> Fernet | None:
    config = _load_vault_config(db_path)
    if config is None:
        return None

    salt, verifier = config
    fernet = Fernet(_derive_fernet_key(master_password, salt))

    try:
        decrypted = fernet.decrypt(verifier.encode()).decode()
    except InvalidToken:
        return None

    if decrypted != VERIFIER_PLAINTEXT:
        return None

    return fernet


def resolve_vault_fernet(
    master_password: str | None = None,
    session_token: str | None = None,
    db_path: str = DB_PATH,
) -> Fernet | None:
    password = resolve_master_password(master_password, session_token)
    if not password:
        return None
    return unlock_vault(password, db_path)


# ---------------------------------------------------------------------------
# Password analysis
# ---------------------------------------------------------------------------

def calculate_strength(password: str) -> int:
    score = 0
    if len(password) >= 12:
        score += 25
    if len(password) >= 8:
        score += 15
    if re.search(r"[A-Z]", password):
        score += 15
    if re.search(r"[a-z]", password):
        score += 15
    if re.search(r"\d", password):
        score += 15
    if any(char in string.punctuation for char in password):
        score += 20
    return min(score, 100)


def strength_label(score: int) -> str:
    if score < 40:
        return "Weak"
    if score <= 70:
        return "Fair"
    return "Strong"


def hibp_lookup(password: str) -> tuple[bool, int]:
    """Check password against HIBP k-anonymity API. Returns (breached, count)."""
    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    try:
        response = requests.get(
            HIBP_API_URL.format(prefix=prefix),
            timeout=10,
        )
        response.raise_for_status()
        for line in response.text.splitlines():
            if ":" not in line:
                continue
            hash_suffix, count_str = line.split(":", 1)
            if hash_suffix == suffix:
                return True, int(count_str)
        return False, 0
    except (requests.RequestException, ValueError):
        return False, 0


def _password_hash(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def _credential_label(device_name: str, device_ip: str | None) -> str:
    if device_ip:
        return f"{device_name} - {device_ip}"
    return device_name


def _find_duplicate_labels(
    fernet: Fernet,
    password: str,
    db_path: str,
    exclude_credential_id: int | None = None,
) -> list[str]:
    password_digest = _password_hash(password)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        """
        SELECT id, device_name, device_ip, encrypted_password
        FROM vault_credentials
        ORDER BY id
        """
    ).fetchall()
    conn.close()

    duplicates: list[str] = []
    for row in rows:
        if exclude_credential_id is not None and row["id"] == exclude_credential_id:
            continue
        try:
            decrypted = fernet.decrypt(row["encrypted_password"].encode()).decode()
        except InvalidToken:
            continue
        if _password_hash(decrypted) == password_digest:
            duplicates.append(_credential_label(row["device_name"], row["device_ip"]))
    return duplicates


def check_password_pre_save(
    password: str,
    fernet: Fernet,
    db_path: str = DB_PATH,
    exclude_credential_id: int | None = None,
) -> dict[str, Any]:
    """Pre-save password analysis without persisting the plaintext password."""
    breached, breach_count = hibp_lookup(password)
    strength_score = calculate_strength(password)
    duplicates = _find_duplicate_labels(
        fernet,
        password,
        db_path,
        exclude_credential_id=exclude_credential_id,
    )
    return {
        "breached": breached,
        "breach_count": breach_count,
        "strength_score": strength_score,
        "strength_label": strength_label(strength_score),
        "duplicate_of": duplicates,
    }


def _wordlist_path() -> str:
    if getattr(sys, "frozen", False):
        return os.path.join(sys._MEIPASS, "daemon", "data", "wordlist.json")
    return os.path.join(_daemon_dir, "data", "wordlist.json")


def _load_wordlist() -> list[str]:
    path = _wordlist_path()
    with open(path, encoding="utf-8") as handle:
        words = json.load(handle)
    if not isinstance(words, list) or not words:
        raise ValueError("wordlist.json is empty or invalid")
    return [str(word) for word in words]


def generate_password(
    length: int = 16,
    uppercase: bool = True,
    lowercase: bool = True,
    numbers: bool = True,
    symbols: bool = True,
    memorable: bool = False,
) -> dict[str, Any]:
    if memorable:
        words = _load_wordlist()
        password = "-".join(secrets.choice(words) for _ in range(4))
    else:
        charset = ""
        if lowercase:
            charset += string.ascii_lowercase
        if uppercase:
            charset += string.ascii_uppercase
        if numbers:
            charset += string.digits
        if symbols:
            charset += string.punctuation
        if not charset:
            charset = string.ascii_letters + string.digits
        length = max(8, min(64, length))
        password = "".join(secrets.choice(charset) for _ in range(length))

    score = calculate_strength(password)
    return {
        "password": password,
        "strength_score": score,
        "strength_label": strength_label(score),
    }


# ---------------------------------------------------------------------------
# Credential operations
# ---------------------------------------------------------------------------

def _normalize_category(category: str | None) -> str:
    if not category:
        return "Other"
    normalized = category.strip()
    return normalized if normalized in VAULT_CATEGORIES else "Other"


def _append_password_history(
    cursor: sqlite3.Cursor,
    credential_id: int,
    encrypted_password: str,
    changed_at: str,
) -> None:
    cursor.execute(
        """
        INSERT INTO vault_credential_history (credential_id, encrypted_password, changed_at)
        VALUES (?, ?, ?)
        """,
        (credential_id, encrypted_password, changed_at),
    )
    cursor.execute(
        """
        DELETE FROM vault_credential_history
        WHERE id NOT IN (
            SELECT id FROM vault_credential_history
            WHERE credential_id = ?
            ORDER BY changed_at DESC, id DESC
            LIMIT ?
        ) AND credential_id = ?
        """,
        (credential_id, PASSWORD_HISTORY_LIMIT, credential_id),
    )


def add_credential(
    fernet: Fernet,
    device_name: str,
    device_ip: str,
    username: str,
    password: str,
    category: str = "Other",
    db_path: str = DB_PATH,
) -> int:
    strength_score = calculate_strength(password)
    encrypted_password = fernet.encrypt(password.encode()).decode()
    created_at = datetime.now(timezone.utc).isoformat()
    breached, breach_count = hibp_lookup(password)
    breach_status = "breached" if breached else "clean"
    checked_at = datetime.now(timezone.utc).isoformat()

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO vault_credentials
            (device_name, device_ip, username, encrypted_password,
             strength_score, created_at, category, breach_status,
             breach_count, last_breach_check, is_compromised, last_checked)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            device_name,
            device_ip,
            username,
            encrypted_password,
            strength_score,
            created_at,
            _normalize_category(category),
            breach_status,
            breach_count,
            checked_at,
            1 if breached else 0,
            checked_at,
        ),
    )
    row_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return row_id


def _row_to_credential_dict(row: sqlite3.Row, include_password: bool = False, password: str | None = None) -> dict[str, Any]:
    data: dict[str, Any] = {
        "id": row["id"],
        "device_name": row["device_name"],
        "device_ip": row["device_ip"],
        "username": row["username"],
        "strength_score": row["strength_score"],
        "is_compromised": row["is_compromised"],
        "last_checked": row["last_checked"],
        "created_at": row["created_at"],
        "category": row["category"] if "category" in row.keys() else "Other",
        "breach_status": row["breach_status"] if "breach_status" in row.keys() else "unchecked",
        "breach_count": row["breach_count"] if "breach_count" in row.keys() else 0,
        "last_breach_check": row["last_breach_check"] if "last_breach_check" in row.keys() else None,
    }
    if include_password and password is not None:
        data["password"] = password
    return data


def list_credentials(db_path: str = DB_PATH) -> list[dict[str, Any]]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        """
        SELECT id, device_name, device_ip, username, strength_score,
               is_compromised, last_checked, created_at, category,
               breach_status, breach_count, last_breach_check
        FROM vault_credentials
        ORDER BY device_name COLLATE NOCASE, id
        """
    ).fetchall()
    conn.close()
    return [_row_to_credential_dict(row) for row in rows]


def get_credential(
    fernet: Fernet,
    credential_id: int,
    db_path: str = DB_PATH,
) -> dict[str, Any] | None:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        """
        SELECT id, device_name, device_ip, username, encrypted_password,
               strength_score, is_compromised, last_checked, created_at,
               category, breach_status, breach_count, last_breach_check
        FROM vault_credentials
        WHERE id = ?
        """,
        (credential_id,),
    ).fetchone()
    if row is None:
        conn.close()
        return None

    history_count = conn.execute(
        "SELECT COUNT(*) FROM vault_credential_history WHERE credential_id = ?",
        (credential_id,),
    ).fetchone()[0]
    conn.close()

    decrypted_password = fernet.decrypt(row["encrypted_password"].encode()).decode()
    credential = _row_to_credential_dict(row, include_password=True, password=decrypted_password)
    credential["password_history_count"] = history_count
    return credential


def get_all_credentials(fernet: Fernet, db_path: str = DB_PATH) -> list[dict]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        """
        SELECT id, device_name, device_ip, username, encrypted_password,
               strength_score, is_compromised, last_checked, created_at,
               category, breach_status, breach_count, last_breach_check
        FROM vault_credentials
        ORDER BY id
        """
    ).fetchall()
    conn.close()

    credentials = []
    for row in rows:
        decrypted_password = fernet.decrypt(row["encrypted_password"].encode()).decode()
        credentials.append(
            _row_to_credential_dict(row, include_password=True, password=decrypted_password)
        )
    return credentials


def update_credential(
    fernet: Fernet,
    credential_id: int,
    device_name: str | None = None,
    device_ip: str | None = None,
    username: str | None = None,
    password: str | None = None,
    category: str | None = None,
    db_path: str = DB_PATH,
) -> bool:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT * FROM vault_credentials WHERE id = ?",
        (credential_id,),
    ).fetchone()
    if row is None:
        conn.close()
        return False

    cursor = conn.cursor()
    updates: dict[str, Any] = {}
    if device_name is not None:
        updates["device_name"] = device_name
    if device_ip is not None:
        updates["device_ip"] = device_ip
    if username is not None:
        updates["username"] = username
    if category is not None:
        updates["category"] = _normalize_category(category)

    if password is not None:
        changed_at = datetime.now(timezone.utc).isoformat()
        _append_password_history(cursor, credential_id, row["encrypted_password"], changed_at)
        breached, breach_count = hibp_lookup(password)
        updates["encrypted_password"] = fernet.encrypt(password.encode()).decode()
        updates["strength_score"] = calculate_strength(password)
        updates["breach_status"] = "breached" if breached else "clean"
        updates["breach_count"] = breach_count
        updates["last_breach_check"] = changed_at
        updates["is_compromised"] = 1 if breached else 0
        updates["last_checked"] = changed_at

    if not updates:
        conn.close()
        return True

    set_clause = ", ".join(f"{column} = ?" for column in updates)
    values = list(updates.values()) + [credential_id]
    cursor.execute(f"UPDATE vault_credentials SET {set_clause} WHERE id = ?", values)
    conn.commit()
    conn.close()
    return True


def delete_credential(credential_id: int, db_path: str = DB_PATH) -> None:
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM vault_credential_history WHERE credential_id = ?", (credential_id,))
    cursor.execute("DELETE FROM vault_credentials WHERE id = ?", (credential_id,))
    conn.commit()
    conn.close()


def check_password_breach(password: str, credential_id: int, db_path: str = DB_PATH) -> bool:
    breached, breach_count = hibp_lookup(password)
    timestamp = datetime.now(timezone.utc).isoformat()
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
        UPDATE vault_credentials
        SET is_compromised = ?, breach_status = ?, breach_count = ?,
            last_checked = ?, last_breach_check = ?
        WHERE id = ?
        """,
        (
            1 if breached else 0,
            "breached" if breached else "clean",
            breach_count,
            timestamp,
            timestamp,
            credential_id,
        ),
    )
    conn.commit()
    conn.close()
    return breached


def recheck_all_breaches(
    db_path: str,
    fernet: Fernet,
) -> list[dict[str, Any]]:
    """
    Re-check every stored credential against HIBP.

    Returns credentials that became newly breached since the last check.
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        """
        SELECT id, device_name, device_ip, username, encrypted_password, breach_status
        FROM vault_credentials
        ORDER BY id
        """
    ).fetchall()
    conn.close()

    newly_breached: list[dict[str, Any]] = []
    timestamp = datetime.now(timezone.utc).isoformat()

    for row in rows:
        try:
            password = fernet.decrypt(row["encrypted_password"].encode()).decode()
        except InvalidToken:
            continue

        breached, breach_count = hibp_lookup(password)
        previous_status = row["breach_status"] or "unchecked"
        new_status = "breached" if breached else "clean"

        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE vault_credentials
            SET is_compromised = ?, breach_status = ?, breach_count = ?,
                last_checked = ?, last_breach_check = ?
            WHERE id = ?
            """,
            (
                1 if breached else 0,
                new_status,
                breach_count,
                timestamp,
                timestamp,
                row["id"],
            ),
        )
        conn.commit()
        conn.close()

        if breached and previous_status != "breached":
            newly_breached.append(
                {
                    "id": row["id"],
                    "device_name": row["device_name"],
                    "device_ip": row["device_ip"],
                    "username": row["username"],
                    "breach_count": breach_count,
                }
            )

    return newly_breached


# ---------------------------------------------------------------------------
# Secure notes
# ---------------------------------------------------------------------------

def add_note(
    fernet: Fernet,
    title: str,
    content: str,
    category: str = "Other",
    db_path: str = DB_PATH,
) -> int:
    now = datetime.now(timezone.utc).isoformat()
    encrypted_content = fernet.encrypt(content.encode()).decode()
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO vault_notes (title, encrypted_content, category, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (title.strip(), encrypted_content, _normalize_category(category), now, now),
    )
    row_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return row_id


def list_notes(db_path: str = DB_PATH) -> list[dict[str, Any]]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        """
        SELECT id, title, category, created_at, updated_at
        FROM vault_notes
        ORDER BY updated_at DESC, id DESC
        """
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_note(fernet: Fernet, note_id: int, db_path: str = DB_PATH) -> dict[str, Any] | None:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT id, title, encrypted_content, category, created_at, updated_at FROM vault_notes WHERE id = ?",
        (note_id,),
    ).fetchone()
    conn.close()
    if row is None:
        return None
    content = fernet.decrypt(row["encrypted_content"].encode()).decode()
    return {
        "id": row["id"],
        "title": row["title"],
        "content": content,
        "category": row["category"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def update_note(
    fernet: Fernet,
    note_id: int,
    title: str | None = None,
    content: str | None = None,
    category: str | None = None,
    db_path: str = DB_PATH,
) -> bool:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT id FROM vault_notes WHERE id = ?", (note_id,)).fetchone()
    if row is None:
        conn.close()
        return False

    updates: dict[str, Any] = {"updated_at": datetime.now(timezone.utc).isoformat()}
    if title is not None:
        updates["title"] = title.strip()
    if content is not None:
        updates["encrypted_content"] = fernet.encrypt(content.encode()).decode()
    if category is not None:
        updates["category"] = _normalize_category(category)

    set_clause = ", ".join(f"{column} = ?" for column in updates)
    values = list(updates.values()) + [note_id]
    conn.execute(f"UPDATE vault_notes SET {set_clause} WHERE id = ?", values)
    conn.commit()
    conn.close()
    return True


def delete_note(note_id: int, db_path: str = DB_PATH) -> None:
    conn = sqlite3.connect(db_path)
    conn.execute("DELETE FROM vault_notes WHERE id = ?", (note_id,))
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Command-line interface
# ---------------------------------------------------------------------------

def _prompt_add_credential(fernet: Fernet) -> None:
    device_name = input("Device name: ").strip()
    device_ip = input("Device IP: ").strip()
    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")
    row_id = add_credential(fernet, device_name, device_ip, username, password)
    strength = calculate_strength(password)
    print(f"Credential saved (id={row_id}, strength_score={strength}).")


def _print_credentials(credentials: list[dict]) -> None:
    if not credentials:
        print("No credentials stored.")
        return
    print(f"\n{'ID':<5} {'Device':<20} {'IP':<16} {'User':<15} {'Strength':<10} {'Breached'}")
    print("-" * 80)
    for cred in credentials:
        breached = "Yes" if cred.get("is_compromised") else "No"
        print(
            f"{cred['id']:<5} {cred['device_name']:<20} "
            f"{cred.get('device_ip') or '':<16} {cred['username']:<15} "
            f"{cred['strength_score']:<10} {breached}"
        )
    print()


def _prompt_check_breach(fernet: Fernet) -> None:
    credentials = get_all_credentials(fernet)
    if not credentials:
        print("No credentials to check.")
        return
    _print_credentials(credentials)
    raw_id = input("Credential ID to check: ").strip()
    if not raw_id.isdigit():
        print("Invalid credential ID.")
        return
    credential_id = int(raw_id)
    match = next((c for c in credentials if c["id"] == credential_id), None)
    if match is None:
        print("Credential not found.")
        return
    breached = check_password_breach(match["password"], credential_id)
    if breached:
        print(f"[!] Password for '{match['device_name']}' found in a known breach.")
    else:
        print(f"[+] Password for '{match['device_name']}' not found in known breaches.")


def main() -> None:
    init_database()
    if not vault_exists():
        print("No vault found. Create a master password.")
        master_password = getpass.getpass("New master password: ")
        confirm = getpass.getpass("Confirm master password: ")
        if master_password != confirm:
            print("Passwords do not match.")
            sys.exit(1)
        initialize_vault(master_password)
        print("Vault initialized.\n")

    master_password = getpass.getpass("Master password: ")
    fernet = unlock_vault(master_password)
    if fernet is None:
        print("Incorrect master password")
        sys.exit(1)

    print("Vault unlocked.\n")
    while True:
        print("1) Add credential")
        print("2) List credentials")
        print("3) Check breach")
        print("4) Exit")
        choice = input("Choice: ").strip()
        if choice == "1":
            _prompt_add_credential(fernet)
        elif choice == "2":
            _print_credentials(get_all_credentials(fernet))
        elif choice == "3":
            _prompt_check_breach(fernet)
        elif choice == "4":
            print("Goodbye.")
            break
        else:
            print("Invalid choice.")


if __name__ == "__main__":
    main()
