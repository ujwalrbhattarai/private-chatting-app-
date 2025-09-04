# p2pchat_persistent.py
import tkinter as tk
from tkinter import simpledialog, messagebox, scrolledtext, ttk
import socket
import threading
import json
import os
import base64
import secrets
import uuid
import pyperclip
import datetime
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# === Paths & Directories ===
DATA_DIR = os.path.expanduser("~/.p2pchat")
KEYS_DIR = os.path.join(DATA_DIR, "keys")
HISTORY_DIR = os.path.join(DATA_DIR, "history")
DOWNLOADS_DIR = os.path.join(DATA_DIR, "downloads")
USERS_FILE = os.path.join(DATA_DIR, "users.json")
PROFILE_FILE = os.path.join(DATA_DIR, "profile.json")
PEERS_FILE = os.path.join(DATA_DIR, "peers.json")

for d in (DATA_DIR, KEYS_DIR, HISTORY_DIR, DOWNLOADS_DIR):
    if not os.path.exists(d):
        os.makedirs(d, exist_ok=True)

# === Utility Functions ===
def now_iso():
    return datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"

def save_json(path, obj):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)

def load_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default

# === Password Hashing ===
def hash_password(password: str, salt: bytes = None):
    if salt is None:
        salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000, dklen=32)
    return {"salt": base64.b64encode(salt).decode(), "hash": base64.b64encode(dk).decode()}

def verify_password(password: str, stored: dict):
    salt = base64.b64decode(stored["salt"].encode())
    expected = stored["hash"]
    got = hash_password(password, salt)["hash"]
    return secrets.compare_digest(got, expected)

# === Users ===
def load_users():
    return load_json(USERS_FILE, {})

def save_users(u):
    save_json(USERS_FILE, u)

def create_local_user(username, password):
    users = load_users()
    if username in users:
        return False, "Username already exists"
    hashed = hash_password(password)
    users[username] = hashed
    save_users(users)
    return True, "User created"

def authenticate_local_user(username, password):
    users = load_users()
    if username not in users:
        return False
    return verify_password(password, users[username])

# === RSA Keys ===
PRIVATE_KEY_PATH = os.path.join(KEYS_DIR, "private.pem")
PUBLIC_KEY_PATH = os.path.join(KEYS_DIR, "public.pem")

def generate_and_store_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem_priv = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(PRIVATE_KEY_PATH, "wb") as f:
        f.write(pem_priv)
    public_key = private_key.public_key()
    pem_pub = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(PUBLIC_KEY_PATH, "wb") as f:
        f.write(pem_pub)
    return private_key, public_key

def load_rsa_keys():
    if not os.path.exists(PRIVATE_KEY_PATH) or not os.path.exists(PUBLIC_KEY_PATH):
        return generate_and_store_rsa_keys()
    with open(PRIVATE_KEY_PATH, "rb") as f:
        priv = serialization.load_pem_private_key(f.read(), password=None)
    with open(PUBLIC_KEY_PATH, "rb") as f:
        pub = serialization.load_pem_public_key(f.read())
    return priv, pub

# === AES Encryption ===
def generate_aes_key():
    return secrets.token_bytes(32)

def encrypt_message(key, plaintext):
    iv = secrets.token_bytes(16)
    padder = PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode("utf-8")) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + ct).decode('utf-8')

def decrypt_message(key, b64ciphertext):
    raw = base64.b64decode(b64ciphertext.encode('utf-8'))
    iv = raw[:16]
    ct = raw[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plain = decryptor.update(ct) + decryptor.finalize()
    unpadder = PKCS7(128).unpadder()
    data = unpadder.update(padded_plain) + unpadder.finalize()
    return data.decode('utf-8')

# === Profile ===
def save_profile(profile):
    save_json(PROFILE_FILE, profile)

def load_profile():
    return load_json(PROFILE_FILE, {"username": None, "avatar": None, "status": ""})

# === Peers persistence ===
def load_peers():
    return load_json(PEERS_FILE, {})

def save_peers(peers_dict):
    save_json(PEERS_FILE, peers_dict)

# === History ===
def save_message_history(peer_id, message_obj):
    path = os.path.join(HISTORY_DIR, f"{peer_id}.json")
    arr = load_json(path, [])
    arr.append(message_obj)
    save_json(path, arr)

def load_message_history(peer_id):
    path = os.path.join(HISTORY_DIR, f"{peer_id}.json")
    return load_json(path, [])

# === Networking ===
class PeerConnection(threading.Thread):
    def __init__(self, app, sock, addr, peer_id=None, is_initiator=False):
        super().__init__(daemon=True)
        self.app = app
        self.sock = sock
        self.addr = addr
        self.peer_id = peer_id
        self.is_initiator = is_initiator
        self.session_key = None
        self.running = True
        self.remote_public_key = None

    def send_json(self, obj):
        try:
            self.sock.sendall((json.dumps(obj)+"\n").encode())
        except:
            self.running = False

    def receive_line(self):
        buf = b""
        while not buf.endswith(b"\n"):
            data = self.sock.recv(4096)
            if not data:
                return None
            buf += data
        return buf.decode("utf-8").strip()

    def run(self):
        try:
            my_pub_pem = self.app.public_pem.decode("utf-8")
            hello = {"type": "hello_pub", "user_id": self.app.username, "pub": my_pub_pem}
            if self.is_initiator:
                self.send_json(hello)
                remote = self.receive_line()
                if remote:
                    self.process_incoming(remote)
            else:
                remote = self.receive_line()
                if remote:
                    self.process_incoming(remote)
                self.send_json(hello)
            if self.is_initiator:
                if self.remote_public_key:
                    self.session_key = generate_aes_key()
                    enc_key = self.remote_public_key.encrypt(
                        self.session_key,
                        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                     algorithm=hashes.SHA256(),
                                     label=None)
                    )
                    self.send_json({"type": "key", "data": base64.b64encode(enc_key).decode("utf-8")})
            else:
                line = self.receive_line()
                if line:
                    obj = json.loads(line)
                    if obj.get("type") == "key":
                        enc = base64.b64decode(obj["data"].encode())
                        self.session_key = self.app.private_key.decrypt(
                            enc,
                            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                         algorithm=hashes.SHA256(), label=None)
                        )
            if not self.session_key:
                raise RuntimeError("Handshake failed")
            self.app.notify_connection(self.peer_id, self)
            while self.running:
                line = self.receive_line()
                if not line:
                    break
                self.process_incoming(line)
        except:
            pass
        finally:
            self.sock.close()
            self.app.disconnect(self)

    def process_incoming(self, raw_line):
        try:
            obj = json.loads(raw_line)
        except:
            return
        t = obj.get("type")
        if t == "hello_pub":
            self.peer_id = obj.get("user_id", self.peer_id)
            pem = obj.get("pub")
            if pem:
                self.remote_public_key = serialization.load_pem_public_key(pem.encode("utf-8"))
        elif t == "key":
            if self.session_key is None:
                enc = base64.b64decode(obj.get("data").encode())
                self.session_key = self.app.private_key.decrypt(
                    enc,
                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                 algorithm=hashes.SHA256(), label=None)
                )
        elif t == "chat":
            if self.session_key:
                text = decrypt_message(self.session_key, obj["data"])
                save_message_history(self.peer_id, {"from": "peer", "msg": text, "time": now_iso()})
                self.app.append_chat(self.peer_id, f"{self.peer_id}: {text}\n")

    def send_message(self, plaintext):
        if not self.session_key:
            raise RuntimeError("No session key")
        enc = encrypt_message(self.session_key, plaintext)
        self.send_json({"type": "chat", "data": enc})
        save_message_history(self.peer_id, {"from": "me", "msg": plaintext, "time": now_iso()})

    def close(self):
        self.running = False
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except:
            pass
        self.sock.close()

class ChatServer(threading.Thread):
    def __init__(self, app, host='0.0.0.0', port=5000):
        super().__init__(daemon=True)
        self.app = app
        self.host = host
        self.port = port
        self.sock = None
        self.running = True

    def run(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.sock.listen(5)
        while self.running:
            try:
                client, addr = self.sock.accept()
                peer = PeerConnection(self.app, client, addr, is_initiator=False)
                peer.start()
            except:
                pass

    def stop(self):
        self.running = False
        if self.sock:
            self.sock.close()

# === Login/Register Dialog ===
class LoginDialog(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Secure P2P Chat")
        self.geometry("350x300")
        self.configure(bg="#4a00e0")
        self.result = None

        notebook = ttk.Notebook(self)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Login Tab
        login_frame = tk.Frame(notebook, bg="white")
        tk.Label(login_frame, text="Login", font=("Arial", 14, "bold"), bg="white", fg="#4a00e0").pack(pady=10)
        tk.Label(login_frame, text="Username:", bg="white").pack(anchor="w", padx=20, pady=5)
        self.login_username = tk.Entry(login_frame, highlightbackground="#4a00e0", highlightthickness=1, relief="flat")
        self.login_username.pack(fill=tk.X, padx=20)
        tk.Label(login_frame, text="Password:", bg="white").pack(anchor="w", padx=20, pady=5)
        self.login_password = tk.Entry(login_frame, show="*", highlightbackground="#4a00e0", highlightthickness=1, relief="flat")
        self.login_password.pack(fill=tk.X, padx=20)
        tk.Button(login_frame, text="Login", bg="#4a00e0", fg="white", relief="flat",
                  command=self.try_login).pack(pady=15)

        # Register Tab
        reg_frame = tk.Frame(notebook, bg="white")
        tk.Label(reg_frame, text="Register", font=("Arial", 14, "bold"), bg="white", fg="#e00070").pack(pady=10)
        tk.Label(reg_frame, text="Username:", bg="white").pack(anchor="w", padx=20, pady=5)
        self.reg_username = tk.Entry(reg_frame, highlightbackground="#e00070", highlightthickness=1, relief="flat")
        self.reg_username.pack(fill=tk.X, padx=20)
        tk.Label(reg_frame, text="Password:", bg="white").pack(anchor="w", padx=20, pady=5)
        self.reg_password = tk.Entry(reg_frame, show="*", highlightbackground="#e00070", highlightthickness=1, relief="flat")
        self.reg_password.pack(fill=tk.X, padx=20)
        tk.Button(reg_frame, text="Register", bg="#e00070", fg="white", relief="flat",
                  command=self.try_register).pack(pady=15)

        notebook.add(login_frame, text="Login")
        notebook.add(reg_frame, text="Register")

        self.transient(parent)
        self.grab_set()
        parent.wait_window(self)

    def try_login(self):
        username = self.login_username.get().strip()
        password = self.login_password.get().strip()
        if authenticate_local_user(username, password):
            self.result = ("login", username, password)
            self.destroy()
        else:
            messagebox.showerror("Login Failed", "Invalid username or password")

    def try_register(self):
        username = self.reg_username.get().strip()
        password = self.reg_password.get().strip()
        ok, msg = create_local_user(username, password)
        if ok:
            messagebox.showinfo("Success", msg)
        else:
            messagebox.showerror("Registration Failed", msg)

# === Main App ===
class P2PChatApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure P2P Chat")
        self.geometry("860x620")
        self.private_key, self.public_key = load_rsa_keys()
        self.public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # --- Login ---
        logged = False
        self.username = None
        while not logged:
            dlg = LoginDialog(self)
            if dlg.result is None:
                self.destroy()
                raise SystemExit()
            action, username, password = dlg.result
            self.username = username
            logged = True

        # --- Profile ---
        profile = load_profile()
        if profile.get("username") != self.username:
            profile["username"] = self.username
            save_profile(profile)
        self.profile = profile

        # --- State ---
        self.connections = {}
        self.current_peer_id = None
        self.peers = load_peers()

        # --- UI ---
        self.create_widgets()

        # --- Load saved peers into UI ---
        for peer_id, info in self.peers.items():
            self.contacts_list.insert(tk.END, f"{peer_id} ({info['ip']}:{info['port']})")

        # --- Server ---
        self.server = ChatServer(self)
        self.server.start()

    def create_widgets(self):
        self.left_frame = tk.Frame(self, width=250, bg="#e0e0e0")
        self.left_frame.pack(side=tk.LEFT, fill=tk.Y)
        self.contacts_list = tk.Listbox(self.left_frame)
        self.contacts_list.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        tk.Button(self.left_frame, text="Add Peer", command=self.prompt_connect, bg="#4a00e0", fg="white").pack(fill=tk.X, padx=5, pady=5)
        self.right_frame = tk.Frame(self, bg="white")
        self.right_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.chat_box = scrolledtext.ScrolledText(self.right_frame)
        self.chat_box.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.entry = tk.Entry(self.right_frame)
        self.entry.pack(fill=tk.X, padx=5, pady=5)
        self.entry.bind("<Return>", lambda e: self.send_message())

    def prompt_connect(self):
        ip = simpledialog.askstring("Connect to Peer", "Enter IP:")
        port = simpledialog.askinteger("Connect to Peer", "Enter Port:", initialvalue=5000)
        peer_id = simpledialog.askstring("Peer ID", "Enter Peer ID:")
        if not ip or not port or not peer_id:
            return
        # Save peer persistently
        self.peers[peer_id] = {"ip": ip, "port": port}
        save_peers(self.peers)
        self.contacts_list.insert(tk.END, f"{peer_id} ({ip}:{port})")
        self.connect_to_peer(ip, port, peer_id)

    def connect_to_peer(self, ip, port, peer_id):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((ip, port))
            peer = PeerConnection(self, sock, (ip, port), peer_id=peer_id, is_initiator=True)
            peer.start()
        except Exception as e:
            messagebox.showerror("Connection Failed", str(e))

    def notify_connection(self, peer_id, peer_connection):
        self.connections[peer_id] = peer_connection
        self.load_history(peer_id)

    def disconnect(self, peer_connection):
        for k, v in list(self.connections.items()):
            if v == peer_connection:
                del self.connections[k]

    def append_chat(self, peer_id, text):
        self.chat_box.insert(tk.END, text)
        self.chat_box.see(tk.END)

    def send_message(self):
        text = self.entry.get().strip()
        if not text:
            return
        sel = self.contacts_list.curselection()
        if not sel:
            messagebox.showwarning("Select Peer", "Select a peer from left list")
            return
        peer_text = self.contacts_list.get(sel[0])
        peer_id = peer_text.split(" ")[0]
        if peer_id in self.connections:
            self.connections[peer_id].send_message(text)
            self.append_chat(peer_id, f"Me: {text}\n")
        self.entry.delete(0, tk.END)

    def load_history(self, peer_id):
        hist = load_message_history(peer_id)
        self.chat_box.delete("1.0", tk.END)
        for msg in hist:
            prefix = "Me" if msg["from"]=="me" else peer_id
            self.chat_box.insert(tk.END, f"{prefix}: {msg['msg']}\n")
        self.chat_box.see(tk.END)

if __name__ == "__main__":
    app = P2PChatApp()
    app.mainloop()
