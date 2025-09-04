import tkinter as tk
from tkinter import simpledialog, messagebox, scrolledtext, ttk
import socket
import threading
import json
import os
import hashlib
import base64
import secrets
import uuid
import pyperclip
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

# === Encryption Helpers ===

def generate_aes_key():
    return secrets.token_bytes(32)  # 256-bit key

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
    iv = raw[:16]
    ct = raw[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plain = decryptor.update(ct) + decryptor.finalize()
    unpadder = PKCS7(128).unpadder()
    data = unpadder.update(padded_plain) + unpadder.finalize()
    return data.decode('utf-8')

# === User data & storage ===

DATA_DIR = os.path.expanduser("~/.p2pchat")
if not os.path.exists(DATA_DIR):
    os.makedirs(DATA_DIR)

def save_chat_history(contact_id, message):
    path = os.path.join(DATA_DIR, f"{contact_id}.chat")
    with open(path, "a", encoding="utf-8") as f:
        f.write(message + "\n")

def load_chat_history(contact_id):
    path = os.path.join(DATA_DIR, f"{contact_id}.chat")
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    return ""

# === Networking & Peer Handling ===

class PeerConnection(threading.Thread):
    def __init__(self, app, sock, addr, peer_id=None, is_initiator=False):
        super().__init__(daemon=True)
        self.app = app
        self.sock = sock
        self.addr = addr
        self.peer_id = peer_id  # Remote user's ID
        self.is_initiator = is_initiator
        self.session_key = generate_aes_key()
        self.running = True

    def run(self):
        try:
            # Perform handshake: exchange user_ids and confirm connection
            if self.is_initiator:
                # Send own ID and session_key (encoded)
                hello = json.dumps({
                    "type": "hello",
                    "user_id": self.app.user_id,
                    "session_key": base64.b64encode(self.session_key).decode()
                }) + "\n"
                self.sock.sendall(hello.encode())

                # Receive remote hello
                remote_hello = self.receive_line()
                self.process_hello(remote_hello)

                # Always use the correct peer_id after handshake
                self.app.notify_connection(self.peer_id, self)
            else:
                # Receive hello first
                hello = self.receive_line()
                self.process_hello(hello)

                # Send back own hello
                hello_back = json.dumps({
                    "type": "hello",
                    "user_id": self.app.user_id,
                    "session_key": base64.b64encode(self.session_key).decode()
                }) + "\n"
                self.sock.sendall(hello_back.encode())

                # Always use the correct peer_id after handshake
                self.app.notify_connection(self.peer_id, self)

            # Listen to messages
            while self.running:
                line = self.receive_line()
                if not line:
                    break
                self.app.receive_message(self, line)
        except Exception as e:
            #print("Connection error:", e)
            pass
        finally:
            self.sock.close()
            self.app.disconnect(self)

    def receive_line(self):
        buf = b""
        while not buf.endswith(b"\n"):
            data = self.sock.recv(1024)
            if not data:
                return None
            buf += data
        return buf.decode().strip()

    def send_message(self, plaintext):
        encrypted = encrypt_message(self.session_key, plaintext)
        payload = json.dumps({"type": "chat", "data": encrypted}) + "\n"
        try:
            self.sock.sendall(payload.encode())
        except:
            self.running = False

    def process_hello(self, data):
        obj = json.loads(data)
        if obj.get("type") == "hello":
            self.peer_id = obj.get("user_id")
            remote_key_b64 = obj.get("session_key")
            if remote_key_b64:
                remote_key = base64.b64decode(remote_key_b64)
                # For simplicity, use session key generated locally.
                # In real E2E use a key agreement protocol & combine keys
            else:
                pass

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
        self.sock.bind((self.host, self.port))
        self.sock.listen()
        while self.running:
            try:
                client, addr = self.sock.accept()
                peer = PeerConnection(self.app, client, addr, is_initiator=False)
                peer.start()
            except Exception as e:
                pass

    def stop(self):
        self.running = False
        if self.sock:
            self.sock.close()

# === Main App UI ===

class P2PChatApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure P2P Chat")
        self.geometry("800x600")

        self.user_id = self.generate_user_id()
        self.connections = {}  # peer_id -> PeerConnection

        self.create_widgets()
        self.server = ChatServer(self)
        self.server.start()

    def generate_user_id(self):
        # Create a simple ID: last 6 chars of UUID4
        return str(uuid.uuid4())[-6:]

    def create_widgets(self):
        # Left frame for contacts
        self.left_frame = tk.Frame(self, bg="#f0f0f0", width=200)
        self.left_frame.pack(side=tk.LEFT, fill=tk.Y)

        self.label_user = tk.Label(self.left_frame, text=f"Your ID: {self.user_id}", bg="#d0d0d0")
        self.label_user.pack(fill=tk.X)
        btn_copy_id = tk.Button(self.left_frame, text="Copy My ID", command=self.copy_my_id)
        btn_copy_id.pack(fill=tk.X, pady=2)

        self.contacts_list = tk.Listbox(self.left_frame)
        self.contacts_list.pack(fill=tk.BOTH, expand=True)
        self.contacts_list.bind("<<ListboxSelect>>", self.on_contact_select)

        btn_connect = tk.Button(self.left_frame, text="Connect to user", command=self.prompt_connect)
        btn_connect.pack(fill=tk.X, pady=5)

        # Right frame for chat
        self.right_frame = tk.Frame(self, bg="white")
        self.right_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.chat_label = tk.Label(self.right_frame, text="Select a contact to chat with")
        self.chat_label.pack(pady=3)

        self.chat_area = scrolledtext.ScrolledText(self.right_frame, state=tk.DISABLED)
        self.chat_area.pack(fill=tk.BOTH, expand=True)

        self.entry_message = tk.Entry(self.right_frame)
        self.entry_message.pack(fill=tk.X, side=tk.LEFT, expand=True, padx=5, pady=5)
        self.entry_message.bind("<Return>", self.send_message)

        self.btn_send = tk.Button(self.right_frame, text="Send", command=self.send_message)
        self.btn_send.pack(side=tk.LEFT, padx=5, pady=5)

    def notify_connection(self, peer_id, peer_conn):
        # Add peer to contacts and prompt connect
        if peer_id not in self.connections:
            self.connections[peer_id] = peer_conn
            self.contacts_list.insert(tk.END, peer_id)
            messagebox.showinfo("Connection Request", f"User {peer_id} connected.")
            # Automatically select the new contact for chat
            self.contacts_list.selection_clear(0, tk.END)
            idxs = self.contacts_list.get(0, tk.END)
            if peer_id in idxs:
                i = idxs.index(peer_id)
                self.contacts_list.selection_set(i)
                self.current_peer_id = peer_id
                self.chat_label.config(text=f"Chatting with {peer_id}")
                self.chat_area.config(state=tk.NORMAL)
                self.chat_area.delete(1.0, tk.END)
                history = load_chat_history(peer_id)
                self.chat_area.insert(tk.END, history)
                self.chat_area.config(state=tk.DISABLED)

    def prompt_connect(self):
        # Ask for friend's ID in format IP:PORT
        friend_id = simpledialog.askstring("Connect", "Enter friend's ID (IP:PORT):")
        if not friend_id or ':' not in friend_id:
            messagebox.showerror("Error", "Invalid ID format. Use IP:PORT")
            return
        ip, port = friend_id.split(':')
        try:
            port = int(port)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((ip, port))
            peer = PeerConnection(self, sock, (ip, port), is_initiator=True)
            peer.start()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to connect: {e}")

    def copy_my_id(self):
        # Copy IP:PORT to clipboard
        ip = socket.gethostbyname(socket.gethostname())
        port = self.server.port
        my_id = f"{ip}:{port}"
        try:
            pyperclip.copy(my_id)
            messagebox.showinfo("Copied", f"Your ID '{my_id}' copied to clipboard.")
        except Exception:
            messagebox.showinfo("ID", f"Your ID: {my_id}")

    def on_contact_select(self, event):
        selection = event.widget.curselection()
        if not selection:
            return
        peer_id = event.widget.get(selection[0])
        self.current_peer_id = peer_id
        self.chat_label.config(text=f"Chatting with {peer_id}")
        self.chat_area.config(state=tk.NORMAL)
        self.chat_area.delete(1.0, tk.END)
        history = load_chat_history(peer_id)
        self.chat_area.insert(tk.END, history)
        self.chat_area.config(state=tk.DISABLED)

    def receive_message(self, peer_conn, json_data):
        data = json.loads(json_data)
        if data.get("type") == "chat":
            msg_enc = data.get("data")
            try:
                msg = decrypt_message(peer_conn.session_key, msg_enc)
                display_text = f"{peer_conn.peer_id}: {msg}\n"
                self.append_chat(peer_conn.peer_id, display_text)
            except Exception as e:
                pass

    def append_chat(self, peer_id, text):
        if self.current_peer_id != peer_id:
            # Optionally notify user about messages from other contacts
            pass
        if self.current_peer_id == peer_id:
            self.chat_area.config(state=tk.NORMAL)
            self.chat_area.insert(tk.END, text)
            self.chat_area.config(state=tk.DISABLED)
            self.chat_area.see(tk.END)
        save_chat_history(peer_id, text)

    def send_message(self, event=None):
        text = self.entry_message.get().strip()
        if not text or not hasattr(self, "current_peer_id"):
            return
        peer = self.connections.get(self.current_peer_id)
        if not peer:
            messagebox.showerror("Error", "No connection to this user.")
            return
        try:
            peer.send_message(text)
            display_text = f"You: {text}\n"
            self.append_chat(self.current_peer_id, display_text)
            self.entry_message.delete(0, tk.END)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send message: {e}")

    def disconnect(self, peer_conn):
        # Remove disconnected peer from contacts list
        peer_id = peer_conn.peer_id
        if peer_id in self.connections:
            del self.connections[peer_id]
            idxs = self.contacts_list.get(0, tk.END)
            if peer_id in idxs:
                i = idxs.index(peer_id)
                self.contacts_list.delete(i)
            if getattr(self, "current_peer_id", None) == peer_id:
                self.chat_label.config(text="Select a contact to chat with")
                self.chat_area.config(state=tk.NORMAL)
                self.chat_area.delete(1.0, tk.END)
                self.chat_area.config(state=tk.DISABLED)

    def on_closing(self):
        self.server.stop()
        self.destroy()

if __name__ == "__main__":
    app = P2PChatApp()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()
