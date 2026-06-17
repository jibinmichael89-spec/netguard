#!/usr/bin/env python3
"""
NetGuard Password Vault
Encrypted local storage for device credentials with breach checking.
"""

import base64
import getpass
import hashlib
import os
import re
import sqlite3
import string
import sys
from datetime import datetime, timezone

import requests
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DB_PATH = os.path.join(PROJECT_ROOT, "netguard.db")

VERIFIER_PLAINTEXT = "NETGUARD_VAULT_OK"
PBKDF2_ITERATIONS = 480_000
HIBP_API_URL = "https://api.pwnedpasswords.com/range/{prefix}"


# ---------------------------------------------------------------------------
# Database operations
# ---------------------------------------------------------------------------

def init_database(db_path: str = DB_PATH) -> None:
    """Create vault tables if they do not already exist."""
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
# Key derivation and vault lifecycle
# ---------------------------------------------------------------------------

def _derive_fernet_key(master_password: str, salt: bytes) -> bytes:
    """Derive a Fernet-compatible key from a master password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))


def _load_vault_config(db_path: str) -> tuple[bytes, str] | None:
    """Load stored salt and encrypted verifier from vault_config."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT salt, verifier FROM vault_config WHERE id = 1")
    row = cursor.fetchone()
    conn.close()
    if row is None:
        return None
    return base64.b64decode(row[0]), row[1]


def initialize_vault(master_password: str, db_path: str = DB_PATH) -> None:
    """
    Initialize the vault with a master password.

    Stores a random salt and an encrypted verification token — the master
    password itself is never persisted.
    """
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
    """
    Attempt to unlock the vault with the given master password.

    Returns a working Fernet instance if the password is correct, else None.
    """
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


# ---------------------------------------------------------------------------
# Credential operations
# ---------------------------------------------------------------------------

def calculate_strength(password: str) -> int:
    """
    Score password strength from 0–100 based on length and character variety.

    length >= 12 adds 25, length >= 8 adds 15, uppercase +15, lowercase +15,
    digit +15, symbol +20. Total is capped at 100.
    """
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


def add_credential(
    fernet: Fernet,
    device_name: str,
    device_ip: str,
    username: str,
    password: str,
    db_path: str = DB_PATH,
) -> int:
    """Encrypt and store a credential. Returns the new row id."""
    strength_score = calculate_strength(password)
    encrypted_password = fernet.encrypt(password.encode()).decode()
    created_at = datetime.now(timezone.utc).isoformat()

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO vault_credentials
            (device_name, device_ip, username, encrypted_password,
             strength_score, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            device_name,
            device_ip,
            username,
            encrypted_password,
            strength_score,
            created_at,
        ),
    )
    row_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return row_id


def get_all_credentials(fernet: Fernet, db_path: str = DB_PATH) -> list[dict]:
    """Fetch all credentials with decrypted passwords."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT id, device_name, device_ip, username, encrypted_password,
               strength_score, is_compromised, last_checked, created_at
        FROM vault_credentials
        ORDER BY id
        """
    )
    rows = cursor.fetchall()
    conn.close()

    credentials = []
    for row in rows:
        decrypted_password = fernet.decrypt(row["encrypted_password"].encode()).decode()
        credentials.append(
            {
                "id": row["id"],
                "device_name": row["device_name"],
                "device_ip": row["device_ip"],
                "username": row["username"],
                "password": decrypted_password,
                "strength_score": row["strength_score"],
                "is_compromised": row["is_compromised"],
                "last_checked": row["last_checked"],
                "created_at": row["created_at"],
            }
        )

    return credentials


def delete_credential(credential_id: int, db_path: str = DB_PATH) -> None:
    """Delete a credential row by id."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM vault_credentials WHERE id = ?", (credential_id,))
    conn.commit()
    conn.close()


def check_password_breach(password: str, credential_id: int, db_path: str = DB_PATH) -> bool:
    """
    Check a password against HaveIBeenPwned using k-anonymity.

    Updates is_compromised and last_checked for the given credential.
    Returns True if the password appears in a breach, False otherwise.
    """
    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    try:
        response = requests.get(
            HIBP_API_URL.format(prefix=prefix),
            timeout=10,
        )
        response.raise_for_status()
        breached = any(
            line.split(":")[0] == suffix
            for line in response.text.splitlines()
            if ":" in line
        )
    except requests.RequestException:
        breached = False

    timestamp = datetime.now(timezone.utc).isoformat()
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
        UPDATE vault_credentials
        SET is_compromised = ?, last_checked = ?
        WHERE id = ?
        """,
        (1 if breached else 0, timestamp, credential_id),
    )
    conn.commit()
    conn.close()
    return breached


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
        breached = "Yes" if cred["is_compromised"] else "No"
        print(
            f"{cred['id']:<5} {cred['device_name']:<20} "
            f"{cred['device_ip'] or '':<16} {cred['username']:<15} "
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
