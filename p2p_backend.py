import os
import json
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# === File storage ===
USERS_FILE = "users.json"
PROFILE_FILE = "profile.json"
KEY_FILE = "private_key.pem"


# === RSA Key Management ===
def load_rsa_keys():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
    else:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open(KEY_FILE, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
    public_key = private_key.public_key()
    return private_key, public_key


# === User Data ===
def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, "r") as f:
            return json.load(f)
    return {}


def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f)


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def create_local_user(username: str, password: str):
    users = load_users()
    if username in users:
        return False, "Username already exists."
    users[username] = hash_password(password)
    save_users(users)
    return True, "User registered successfully."


def validate_login(username: str, password: str):
    users = load_users()
    if username not in users:
        return False, "User does not exist."
    if users[username] != hash_password(password):
        return False, "Invalid password."
    return True, "Login successful."


# === Profile Management ===
def save_profile(profile: dict):
    with open(PROFILE_FILE, "w") as f:
        json.dump(profile, f)


def load_profile():
    if os.path.exists(PROFILE_FILE):
        with open(PROFILE_FILE, "r") as f:
            return json.load(f)
    return {}


# === Fingerprint (short ID) ===
def get_fingerprint(public_key) -> str:
    """Generate a short fingerprint (first 16 hex chars)"""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(pem).hexdigest()[:16]
