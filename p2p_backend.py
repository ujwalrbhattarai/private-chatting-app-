import os
import json
import hashlib
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


# === Paths ===
DATA_DIR = os.path.expanduser("~/.p2pchat")
os.makedirs(DATA_DIR, exist_ok=True)

USERS_FILE = os.path.join(DATA_DIR, "users.json")
PROFILE_FILE = os.path.join(DATA_DIR, "profile.json")
KEY_FILE = os.path.join(DATA_DIR, "private_key.pem")
PEERS_FILE = os.path.join(DATA_DIR, "peers.json")
HISTORY_DIR = os.path.join(DATA_DIR, "history")
os.makedirs(HISTORY_DIR, exist_ok=True)


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


# === User Accounts ===
def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, "r") as f:
            return json.load(f)
    return {}


def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)


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
        json.dump(profile, f, indent=2)


def load_profile():
    if os.path.exists(PROFILE_FILE):
        with open(PROFILE_FILE, "r") as f:
            return json.load(f)
    return {"username": None, "status": ""}


# === Fingerprint (short ID) ===
def get_fingerprint(public_key) -> str:
    """Generate a short fingerprint (first 16 hex chars)"""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(pem).hexdigest()[:16]


# === Peer Management (Persistent) ===
def load_peers():
    if os.path.exists(PEERS_FILE):
        with open(PEERS_FILE, "r") as f:
            return json.load(f)
    return {}


def save_peers(peers):
    with open(PEERS_FILE, "w") as f:
        json.dump(peers, f, indent=2)


def add_peer(peer_id, username, ip, port):
    peers = load_peers()
    peers[peer_id] = {"username": username, "ip": ip, "port": port}
    save_peers(peers)


# === Chat History ===
def history_path(peer_id):
    return os.path.join(HISTORY_DIR, f"{peer_id}.json")


def save_message(peer_id, sender, message):
    path = history_path(peer_id)
    history = []
    if os.path.exists(path):
        with open(path, "r") as f:
            history = json.load(f)

    history.append({
        "sender": sender,
        "message": message,
        "time": datetime.utcnow().isoformat(timespec="seconds") + "Z"
    })

    with open(path, "w") as f:
        json.dump(history, f, indent=2)


def load_history(peer_id, last_n=100):
    path = history_path(peer_id)
    if os.path.exists(path):
        with open(path, "r") as f:
            history = json.load(f)
        return history[-last_n:]
    return []
