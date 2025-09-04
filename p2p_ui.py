import tkinter as tk
from tkinter import messagebox, simpledialog, scrolledtext, ttk
import threading
import socket

# Import backend functions
from p2p_backend import (
    load_rsa_keys, save_profile, load_profile,
    create_local_user, validate_login
)

# Import serialization for RSA PEM export
from cryptography.hazmat.primitives import serialization


# === Main App ===
class P2PChatApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure P2P Chat")
        self.geometry("900x600")
        self.resizable(False, False)

        # Load keys
        self.private_key, self.public_key = load_rsa_keys()
        self.public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Vars
        self.username = None
        self.profile = None
        self.connections = {}
        self.current_peer_id = None
        self.sock = None

        # Frames
        self.login_frame = None
        self.chat_frame = None

        # Show login first
        self.show_login()

    # ---------------- LOGIN SCREEN ---------------- #
    def show_login(self):
        self.login_frame = tk.Frame(self, bg="#2d2d3f")
        self.login_frame.pack(fill=tk.BOTH, expand=True)

        # Left branding panel
        left_panel = tk.Frame(self.login_frame, bg="#4a00e0")
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tk.Label(left_panel, text="🔒 Secure P2P Chat", font=("Arial", 20, "bold"),
                 bg="#4a00e0", fg="white").pack(pady=50)
        tk.Label(left_panel, text="Private. Secure. Peer-to-Peer.",
                 font=("Arial", 12), bg="#4a00e0", fg="white").pack(pady=10)

        # Right login/register panel
        right_panel = tk.Frame(self.login_frame, bg="white", padx=40, pady=40)
        right_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        notebook = ttk.Notebook(right_panel)
        notebook.pack(fill=tk.BOTH, expand=True)

        # Login tab
        login_tab = tk.Frame(notebook, bg="white")
        tk.Label(login_tab, text="Login", font=("Arial", 16, "bold"), bg="white").pack(pady=10)
        tk.Label(login_tab, text="Username:", bg="white").pack(anchor="w")
        self.login_username = tk.Entry(login_tab)
        self.login_username.pack(fill=tk.X, pady=5)
        tk.Label(login_tab, text="Password:", bg="white").pack(anchor="w")
        self.login_password = tk.Entry(login_tab, show="*")
        self.login_password.pack(fill=tk.X, pady=5)
        tk.Button(login_tab, text="Login", bg="#4a00e0", fg="white",
                  command=self.try_login).pack(pady=15)

        # Register tab
        reg_tab = tk.Frame(notebook, bg="white")
        tk.Label(reg_tab, text="Register", font=("Arial", 16, "bold"), bg="white").pack(pady=10)
        tk.Label(reg_tab, text="Username:", bg="white").pack(anchor="w")
        self.reg_username = tk.Entry(reg_tab)
        self.reg_username.pack(fill=tk.X, pady=5)
        tk.Label(reg_tab, text="Password:", bg="white").pack(anchor="w")
        self.reg_password = tk.Entry(reg_tab, show="*")
        self.reg_password.pack(fill=tk.X, pady=5)
        tk.Button(reg_tab, text="Register", bg="#e00070", fg="white",
                  command=self.try_register).pack(pady=15)

        notebook.add(login_tab, text="Login")
        notebook.add(reg_tab, text="Register")

    def try_login(self):
        u, p = self.login_username.get().strip(), self.login_password.get().strip()
        ok, msg = validate_login(u, p)
        if ok:
            self.username = u
            profile = load_profile()
            if profile.get("username") != self.username:
                profile["username"] = self.username
                save_profile(profile)
            self.profile = profile
            self.login_frame.destroy()
            self.show_chat_ui()
        else:
            messagebox.showerror("Login Failed", msg)

    def try_register(self):
        u, p = self.reg_username.get().strip(), self.reg_password.get().strip()
        ok, msg = create_local_user(u, p)
        if ok:
            messagebox.showinfo("Success", msg)
        else:
            messagebox.showerror("Registration Failed", msg)

    # ---------------- CHAT UI ---------------- #
    def show_chat_ui(self):
        self.chat_frame = tk.Frame(self, bg="#f0f0f0")
        self.chat_frame.pack(fill=tk.BOTH, expand=True)

        # Left panel
        self.left_frame = tk.Frame(self.chat_frame, bg="#f0f0f0", width=260)
        self.left_frame.pack(side=tk.LEFT, fill=tk.Y)

        self.lbl_profile = tk.Label(
            self.left_frame,
            text=f"Signed in as: {self.username}",
            bg="#cfcfcf",
            font=("TkDefaultFont", 12, "bold")
        )
        self.lbl_profile.pack(fill=tk.X, padx=5, pady=6)

        # Fingerprint for easier sharing
        short_id = self.public_pem.hex()[:16]
        tk.Label(self.left_frame, text=f"Your ID: {short_id}...",
                 bg="#f0f0f0", fg="gray").pack(pady=3)

        tk.Button(self.left_frame, text="Copy My ID (IP:PORT)",
                  command=self.copy_my_id, bg="#4a00e0", fg="white").pack(fill=tk.X, padx=5, pady=4)

        self.contacts_list = tk.Listbox(self.left_frame)
        self.contacts_list.pack(fill=tk.BOTH, expand=True, padx=5, pady=6)
        self.contacts_list.bind("<<ListboxSelect>>", self.on_contact_select)

        tk.Button(self.left_frame, text="Connect to user (IP:PORT)",
                  command=self.prompt_connect, bg="#4a00e0", fg="white").pack(fill=tk.X, padx=5, pady=4)

        tk.Button(self.left_frame, text="Clear Selected Chat",
                  command=self.clear_selected_chat, bg="#e00070", fg="white").pack(fill=tk.X, padx=5, pady=4)

        # Right panel
        self.right_frame = tk.Frame(self.chat_frame, bg="#ffffff")
        self.right_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.chat_area = scrolledtext.ScrolledText(self.right_frame, state=tk.DISABLED)
        self.chat_area.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        self.entry_msg = tk.Entry(self.right_frame)
        self.entry_msg.pack(fill=tk.X, padx=6, pady=4)
        self.entry_msg.bind("<Return>", lambda e: self.send_message())
        tk.Button(self.right_frame, text="Send", command=self.send_message,
                  bg="#4a00e0", fg="white").pack(padx=6, pady=4)

        # Start server thread
        self.after(100, self.start_server)

    # ---------------- CHAT FUNCTIONS ---------------- #
    def copy_my_id(self):
        host = socket.gethostbyname(socket.gethostname())
        my_id = f"{host}:5000"
        self.clipboard_clear()
        self.clipboard_append(my_id)
        messagebox.showinfo("Copied", f"Your ID ({my_id}) is copied!")

    def prompt_connect(self):
        peer = simpledialog.askstring("Connect", "Enter peer ID (IP:PORT):")
        if peer:
            host, port = peer.split(":")
            port = int(port)
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((host, port))
                self.connections[peer] = s
                self.contacts_list.insert(tk.END, peer)
                threading.Thread(target=self.receive_messages, args=(s, peer), daemon=True).start()
            except Exception as e:
                messagebox.showerror("Error", f"Could not connect: {e}")

    def clear_selected_chat(self):
        self.chat_area.config(state=tk.NORMAL)
        self.chat_area.delete("1.0", tk.END)
        self.chat_area.config(state=tk.DISABLED)

    def on_contact_select(self, event):
        selection = event.widget.curselection()
        if selection:
            idx = selection[0]
            self.current_peer_id = event.widget.get(idx)

    def send_message(self):
        msg = self.entry_msg.get().strip()
        if not msg or not self.current_peer_id:
            return
        conn = self.connections.get(self.current_peer_id)
        if conn:
            try:
                conn.sendall(msg.encode())
                self.display_message(self.username, msg)
                self.entry_msg.delete(0, tk.END)
            except:
                messagebox.showerror("Error", "Failed to send message.")

    def display_message(self, sender, msg):
        self.chat_area.config(state=tk.NORMAL)
        self.chat_area.insert(tk.END, f"{sender}: {msg}\n")
        self.chat_area.config(state=tk.DISABLED)
        self.chat_area.see(tk.END)

    def start_server(self):
        def server():
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.bind(("", 5000))
            self.sock.listen(5)
            while True:
                conn, addr = self.sock.accept()
                peer = f"{addr[0]}:{addr[1]}"
                self.connections[peer] = conn
                self.contacts_list.insert(tk.END, peer)
                threading.Thread(target=self.receive_messages, args=(conn, peer), daemon=True).start()

        threading.Thread(target=server, daemon=True).start()

    def receive_messages(self, conn, peer):
        while True:
            try:
                data = conn.recv(1024)
                if not data:
                    break
                self.display_message(peer, data.decode())
            except:
                break
        conn.close()


if __name__ == "__main__":
    app = P2PChatApp()
    app.mainloop()
