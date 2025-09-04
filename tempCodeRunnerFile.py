# p2pchat_fast.py
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

# === Paths ===
DATA_DIR = os.path.expanduser("~/.p2pchat")
KEYS_DIR = os.path.join(DATA_DIR, "keys")
HISTORY_DIR = os.path.join(DATA_DIR, "history")
DOWNLOADS_DIR = os.path.join(DATA_DIR, "downloads")
USERS_FILE = os.path.join(DATA_DIR, "users.json")
PROFILE_FILE = os.path.join(DATA_DIR, "profile.json")
SETTINGS_FILE = os.path.join(DATA_DIR, "settings.json")

for d in (DATA_DIR, KEYS_DIR, HISTORY_DIR, DOWNLOADS_DIR):
    os.makedirs(d, exist_ok=True)

# === Utilities ===
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

# === User password helpers ===
def hash_password(password: str, salt: bytes = None):
    if salt is None:
        salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000, dklen=32)
    return {"salt": base64.b64encode(salt).decode(), "hash": base64.b64encode(dk).decode()}

def verify_password(password: str, stored: dict):
    salt = base64.b64decode(stored["salt"].encode())
    expected = stored["hash"]
    got = hash_password(password, salt)["hash"]
    return secrets.compare_digest(got, expected)

def load_users():
    return load_json(USERS_FILE, {})

def save_users(u):
    save_json(USERS_FILE, u)

def create_local_user(username, password):
    users = load_users()
    if username in users:
        return False, "Username already exists"
    users[username] = hash_password(password)
    save_users(users)
    return True, "User created"

def authenticate_local_user(username, password):
    users = load_users()
    if username not in users:
        return False
    return verify_password(password, users[username])

# === AES helpers ===
def generate_aes_key():
    return secrets.token_bytes(32)

def encrypt_message(key, plaintext):
    iv = secrets.token_bytes(16)
    padder = PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + ct).decode('utf-8')

def decrypt_message(key, b64ciphertext):
    raw = base64.b64decode(b64ciphertext.encode('utf-8'))
    iv, ct = raw[:16], raw[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plain = decryptor.update(ct) + decryptor.finalize()
    unpadder = PKCS7(128).unpadder()
    return (unpadder.update(padded_plain) + unpadder.finalize()).decode('utf-8')

# === Profile & history ===
def save_profile(profile):
    save_json(PROFILE_FILE, profile)

def load_profile():
    return load_json(PROFILE_FILE, {"username": None, "avatar": None, "status": ""})

def save_message_history(peer_id, message_obj):
    path = os.path.join(HISTORY_DIR, f"{peer_id}.json")
    arr = load_json(path, [])
    arr.append(message_obj)
    save_json(path, arr)

def load_message_history(peer_id, last_n=50):
    path = os.path.join(HISTORY_DIR, f"{peer_id}.json")
    arr = load_json(path, [])
    return arr[-last_n:]

# === RSA keypair ===
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

# === Networking ===
class PeerConnection(threading.Thread):
    def __init__(self, app, sock, addr, peer_id=None, is_initiator=False, debug=False):
        super().__init__(daemon=True)
        self.app = app
        self.sock = sock
        self.addr = addr
        self.peer_id = peer_id
        self.is_initiator = is_initiator
        self.debug = debug
        self.session_key = None
        self.running = True
        self.remote_public_key = None

    def log(self, *a):
        if self.debug:
            print("[Peer]", *a)

    def send_json(self, obj):
        try:
            self.sock.sendall((json.dumps(obj) + "\n").encode())
        except Exception as e:
            self.log("send_json error:", e)
            self.running = False

    def receive_line(self):
        buf = b""
        try:
            while not buf.endswith(b"\n"):
                data = self.sock.recv(4096)
                if not data: return None
                buf += data
            return buf.decode("utf-8").strip()
        except: return None

    def run(self):
        try:
            # handshake simplified
            my_pub = self.app.public_pem.decode()
            hello = {"type": "hello_pub", "user_id": self.app.username, "pub": my_pub}
            if self.is_initiator:
                self.send_json(hello)
                remote = self.receive_line()
                self.process_incoming(remote)
            else:
                remote = self.receive_line()
                self.process_incoming(remote)
                self.send_json(hello)
            # AES key exchange
            if self.is_initiator:
                self.session_key = generate_aes_key()
                enc_key = self.remote_public_key.encrypt(
                    self.session_key,
                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                )
                self.send_json({"type":"key","data":base64.b64encode(enc_key).decode()})
            else:
                line = self.receive_line()
                obj = json.loads(line)
                enc = base64.b64decode(obj["data"])
                self.session_key = self.app.private_key.decrypt(
                    enc,
                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                )
            self.app.notify_connection(self.peer_id, self)
            while self.running:
                line = self.receive_line()
                if not line: break
                self.process_incoming(line)
        finally:
            self.close()
            self.app.disconnect(self)

    def process_incoming(self, raw_line):
        try: obj = json.loads(raw_line)
        except: return
        t = obj.get("type")
        if t=="hello_pub":
            self.peer_id = obj.get("user_id", self.peer_id)
            pem = obj.get("pub")
            if pem: self.remote_public_key = serialization.load_pem_public_key(pem.encode())
        elif t=="key" and self.session_key is None:
            enc = base64.b64decode(obj["data"])
            self.session_key = self.app.private_key.decrypt(
                enc, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
        elif t=="chat":
            if not self.session_key: return
            text = decrypt_message(self.session_key, obj["data"])
            save_message_history(self.peer_id, {"from":"peer","msg":text,"time":now_iso()})
            self.app.append_chat(self.peer_id,f"{self.peer_id}: {text}\n")

    def send_message(self, plaintext):
        if not self.session_key: raise RuntimeError("No session key")
        enc = encrypt_message(self.session_key, plaintext)
        self.send_json({"type":"chat","data":enc})
        save_message_history(self.peer_id, {"from":"me","msg":plaintext,"time":now_iso()})

    def close(self):
        self.running = False
        try: self.sock.shutdown(socket.SHUT_RDWR)
        except: pass
        try: self.sock.close()
        except: pass

class ChatServer(threading.Thread):
    def __init__(self, app, host="0.0.0.0", port=5000, debug=False):
        super().__init__(daemon=True)
        self.app, self.host, self.port, self.debug = app, host, port, debug
        self.running = True

    def run(self):
        sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        sock.bind((self.host,self.port))
        sock.listen(5)
        while self.running:
            try:
                client, addr = sock.accept()
                peer = PeerConnection(self.app, client, addr, is_initiator=False, debug=self.debug)
                peer.start()
            except: pass

    def stop(self):
        self.running=False

# === GUI ===
class LoginDialog(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Welcome to Secure P2P Chat")
        self.geometry("350x300")
        self.configure(bg="#4a00e0")
        self.result = None
        notebook = ttk.Notebook(self)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Login
        login_frame = tk.Frame(notebook, bg="white")
        tk.Label(login_frame,text="Login",font=("Arial",14,"bold"),bg="white",fg="#4a00e0").pack(pady=10)
        tk.Label(login_frame,text="Username:",bg="white").pack(anchor="w",padx=20,pady=5)
        self.login_username = tk.Entry(login_frame)
        self.login_username.pack(fill=tk.X,padx=20)
        tk.Label(login_frame,text="Password:",bg="white").pack(anchor="w",padx=20,pady=5)
        self.login_password = tk.Entry(login_frame,show="*")
        self.login_password.pack(fill=tk.X,padx=20)
        tk.Button(login_frame,text="Login",bg="#4a00e0",fg="white",command=self.try_login).pack(pady=15)

        # Register
        reg_frame = tk.Frame(notebook, bg="white")
        tk.Label(reg_frame,text="Register",font=("Arial",14,"bold"),bg="white",fg="#e00070").pack(pady=10)
        tk.Label(reg_frame,text="Username:",bg="white").pack(anchor="w",padx=20,pady=5)
        self.reg_username = tk.Entry(reg_frame)
        self.reg_username.pack(fill=tk.X,padx=20)
        tk.Label(reg_frame,text="Password:",bg="white").pack(anchor="w",padx=20,pady=5)
        self.reg_password = tk.Entry(reg_frame,show="*")
        self.reg_password.pack(fill=tk.X,padx=20)
        tk.Button(reg_frame,text="Register",bg="#e00070",fg="white",command=self.try_register).pack(pady=15)

        notebook.add(login_frame,text="Login")
        notebook.add(reg_frame,text="Register")
        self.transient(parent)
        self.grab_set()
        parent.wait_window(self)

    def try_login(self):
        u,p = self.login_username.get().strip(), self.login_password.get().strip()
        ok,msg = validate_login(u,p)
        if ok: self.result=( "login", u,p ); self.destroy()
        else: messagebox.showerror("Login Failed", msg)

    def try_register(self):
        u,p = self.reg_username.get().strip(), self.reg_password.get().strip()
        ok,msg = create_local_user(u,p)
        if ok: messagebox.showinfo("Success", msg)
        else: messagebox.showerror("Registration Failed", msg)

# === Main App ===
class P2PChatApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure P2P Chat (Fast)")
        self.geometry("860x620")
        self.private_key, self.public_key = load_rsa_keys()
        self.public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        # login
        dlg = LoginDialog(self)
        if dlg.result is None: self.destroy(); raise SystemExit()
        _, self.username, _ = dlg.result

        profile = load_profile()
        if profile.get("username") != self.username:
            profile["username"]=self.username
            save_profile(profile)
        self.profile=profile

        self.user_id = str(uuid.uuid4())[-6:]
        self.connections={}
        self.current_peer_id=None

        self.create_widgets()
        self.after(100, self.start_server)

    def create_widgets(self):
        self.left_frame = tk.Frame(self, bg="#f0f0f0", width=260)
        self.left_frame.pack(side=tk.LEFT, fill=tk.Y)
        self.lbl_profile=tk.Label(self.left_frame,text=f"{self.profile.get('username')}",bg="#cfcfcf",font=("TkDefaultFont",12,"bold"))
        self.lbl_profile.pack(fill=tk.X,padx=5,pady=6)
        tk.Button(self.left_frame,text="Copy My ID (IP:PORT)",command=self.copy_my_id).pack(fill=tk.X,padx=5,pady=4)
        self.contacts_list=tk.Listbox(self.left_frame)
        self.contacts_list.pack(fill=tk.BOTH,expand=True,padx=5,pady=6)
        self.contacts_list.bind("<<ListboxSelect>>", self.on_contact_select)
        tk.Button(self.left_frame,text="Connect to user (IP:PORT)",command=self.prompt_connect).pack(fill=tk.X,padx=5,pady=4)
        tk.Button(self.left_frame,text="Clear Selected Chat",command=self.clear_selected_chat).pack(fill=tk.X,padx=5,pady=4)

        self.right_frame = tk.Frame(self,bg="#e0e0ff")
        self.right_frame.pack(side=tk.LEFT,fill=tk.BOTH,expand=True)
        self.chat_area = scrolledtext.ScrolledText(self.right_frame,state=tk.DISABLED)
        self.chat_area.pack(fill=tk.BOTH,expand=True,padx=6,pady=6)
        self.entry_msg = tk.Entry(self.right_frame)
        self.entry_msg.pack(fill=tk.X,padx=6,pady=4)
        self.entry_msg.bind("<Return>", lambda e: self.send_message())
        tk.Button(self.right_frame,text="Send",command=self.send_message).pack(padx=6,pady=4)

    def start_server(self):
        try:
            self.server = ChatServer(self, port=5000, debug=False)
            self.server.start()
        except Exception as e:
            messagebox.showwarning("Server error", f"Could not start server on port 5000: {e}")

    def copy_my_id(self):
        ip = socket.gethostbyname(socket.gethostname())
        pyperclip.copy(f"{ip}:5000")
        messagebox.showinfo("Copied", f"Your ID copied: {ip}:5000")

    def prompt_connect(self):
        target = simpledialog.askstring("Connect", "Enter IP:PORT")
        if not target: return
        try:
            ip, port = target.split(":")
            port=int(port)
            sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((ip,port))
            sock.settimeout(None)
            peer = PeerConnection(self, sock, (ip,port), is_initiator=True, debug=False)
            peer.start()
        except Exception as e:
            messagebox.showerror("Connect Failed", str(e))

    def notify_connection(self, peer_id, conn):
        self.connections[peer_id]=conn
        self.contacts_list.insert(tk.END, peer_id)
        self.current_peer_id = peer_id
        self.load_chat(peer_id)

    def disconnect(self, conn):
        for k,v in list(self.connections.items()):
            if v==conn: del self.connections[k]
        self.refresh_contacts()

    def refresh_contacts(self):
        self.contacts_list.delete(0,tk.END)
        for k in self.connections.keys(): self.contacts_list.insert(tk.END,k)

    def append_chat(self, peer_id, text):
        if self.current_peer_id!=peer_id: return
        self.chat_area.configure(state=tk.NORMAL)
        self.chat_area.insert(tk.END,text)
        self.chat_area.see(tk.END)
        self.chat_area.configure(state=tk.DISABLED)

    def load_chat(self, peer_id):
        self.chat_area.configure(state=tk.NORMAL)
        self.chat_area.delete("1.0",tk.END)
        for m in load_message_history(peer_id):
            sender = "Me" if m["from"]=="me" else peer_id
            self.chat_area.insert(tk.END,f"{sender}: {m['msg']}\n")
        self.chat_area.configure(state=tk.DISABLED)

    def on_contact_select(self,event):
        sel = self.contacts_list.curselection()
        if sel:
            self.current_peer_id=self.contacts_list.get(sel[0])
            self.load_chat(self.current_peer_id)

    def send_message(self):
        msg = self.entry_msg.get().strip()
        if not msg or not self.current_peer_id: return
        conn = self.connections.get(self.current_peer_id)
        if not conn: return
        conn.send_message(msg)
        self.append_chat(self.current_peer_id,f"Me: {msg}\n")
        self.entry_msg.delete(0,tk.END)

    def clear_selected_chat(self):
        if not self.current_peer_id: return
        path = os.path.join(HISTORY_DIR, f"{self.current_peer_id}.json")
        if os.path.exists(path): os.remove(path)
        self.chat_area.configure(state=tk.NORMAL)
        self.chat_area.delete("1.0",tk.END)
        self.chat_area.configure(state=tk.DISABLED)

# === Login validation ===
def validate_login(u,p):
    if authenticate_local_user(u,p): return True,"OK"
    return False,"Invalid username/password"

# === Run App ===
if __name__=="__main__":
    app = P2PChatApp()
    app.mainloop()
