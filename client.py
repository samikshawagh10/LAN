#!/usr/bin/env python3
import base64
import os
import platform
import queue
import re
import secrets
import socket
import struct
import subprocess
import sys
import threading
import time
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText
from typing import Optional, Tuple

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Default shared 32-byte urlsafe base64 Fernet key for immediate zero-config testing
DEFAULT_PREDEFINED_KEY = b"PizUtw6785WXIWW7U4W9XC4gQKqlOLPuuteSoLopWwo="

HEADER_FORMAT = "!Q"  # 8-byte big-endian unsigned 64-bit integer
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
MAX_PAYLOAD_SIZE = 100 * 1024 * 1024  # 100 MB safety limit
RECV_CHUNK_SIZE = 65536  # 64 KB read buffer
DOWNLOAD_DIR_NAME = "received_files"


def derive_fernet_key(key_input: str) -> bytes:
    raw_bytes = key_input.strip().encode("utf-8")
    try:
        # Check if already a valid Fernet key
        Fernet(raw_bytes)
        return raw_bytes
    except Exception:
        # Derive using PBKDF2HMAC
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"SECURE_LAN_FERNET_SALT_V1",
            iterations=100_000,
        )
        return base64.urlsafe_b64encode(kdf.derive(raw_bytes))


def format_bytes(num_bytes: int) -> str:
    for unit in ["B", "KB", "MB", "GB"]:
        if num_bytes < 1024.0:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} TB"


def generate_security_code() -> str:
    """Generates a cryptographically secure 6-digit numeric verification code."""
    return f"{secrets.randbelow(900000) + 100000:06d}"


def format_security_code(code: str) -> str:
    """Formats a 6-digit code with spacing for readability, e.g. '582 914'."""
    cleaned = code.strip().replace(" ", "").replace("-", "")
    if len(cleaned) == 6:
        return f"{cleaned[:3]} {cleaned[3:]}"
    return cleaned


def recv_exact(sock: socket.socket, num_bytes: int) -> bytes:
    buffer = bytearray()
    while len(buffer) < num_bytes:
        chunk = sock.recv(min(num_bytes - len(buffer), RECV_CHUNK_SIZE))
        if not chunk:
            raise ConnectionResetError("Connection closed before all bytes were received.")
        buffer.extend(chunk)
    return bytes(buffer)


# ==============================================================================
# SECURE CHAT & FILE TRANSFER CLIENT (GUI & LOGIC)
# ==============================================================================


class SecureChatClient:
    def __init__(
        self,
        root: tk.Tk,
        username: Optional[str] = None,
        host: str = "127.0.0.1",
        port: int = 5000,
        key: Optional[str] = None,
        geometry: Optional[str] = None,
        autoconnect: bool = False,
    ) -> None:
        self.root = root
        self.username = username or f"User_{int(time.time()) % 10000:04d}"
        self.initial_host = host
        self.initial_port = port
        self.initial_key = key or DEFAULT_PREDEFINED_KEY.decode("utf-8")
        self.autoconnect = autoconnect

        self.root.title(f"Secure LAN Chat - [{self.username}] (E2EE)")
        if geometry:
            self.root.geometry(geometry)
        else:
            self.root.geometry("640x660")
        self.root.minsize(520, 460)

        # Networking State
        self.sock: Optional[socket.socket] = None
        self.connected = False
        self.running = True
        self.listen_thread: Optional[threading.Thread] = None

        # Cryptography State
        self.fernet: Optional[Fernet] = None

        # Thread Safety Queue (Socket Thread -> GUI Thread)
        self.gui_queue: queue.Queue = queue.Queue()

        # Download Directory setup
        self.download_dir = os.path.abspath(DOWNLOAD_DIR_NAME)
        os.makedirs(self.download_dir, exist_ok=True)

        # Style Configuration
        self._setup_styles()

        # Build GUI Components
        self._build_ui()

        # Start periodic GUI queue processor (every 40ms)
        self.root.after(40, self._process_gui_queue)

        # Auto-connect if requested
        if self.autoconnect:
            self.root.after(250, self.connect)

        # Graceful shutdown handler
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def _setup_styles(self) -> None:
        self.colors = {
            "bg_dark": "#181825",       # Deep Charcoal
            "bg_card": "#1e1e2e",       # Dark Slate panel
            "bg_chat": "#11111b",       # Chat canvas
            "bg_input": "#313244",      # Input background
            "fg_text": "#cdd6f4",       # Off-white / light slate
            "fg_muted": "#a6adc8",      # Muted subtext
            "accent_blue": "#89b4fa",   # 'You' Accent (Soft Cyan-Blue)
            "accent_purple": "#cba6f7", # 'Peer' Accent (Lavender)
            "accent_green": "#a6e3a1",  # File / Success (Sage Green)
            "accent_red": "#f38ba8",    # Error / Alert (Soft Coral)
            "accent_amber": "#f9e2af",  # Security Warning (Warm Amber)
            "border": "#45475a",        # Subtle border
        }

        self.root.configure(bg=self.colors["bg_dark"])

    def _build_ui(self) -> None:
        # Main Container
        main_frame = tk.Frame(self.root, bg=self.colors["bg_dark"], padx=14, pady=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # ----------------------------------------------------------------------
        # Top Panel: Connection, Identity & Cryptography Configuration
        # ----------------------------------------------------------------------
        config_frame = tk.LabelFrame(
            main_frame,
            text=" Connection & E2EE Key Setup ",
            font=("Helvetica", 9, "bold"),
            bg=self.colors["bg_card"],
            fg=self.colors["accent_blue"],
            relief=tk.GROOVE,
            bd=1,
            padx=10,
            pady=8,
        )
        config_frame.pack(fill=tk.X, pady=(0, 10))

        # Row 1: Server IP, Port, Status Indicator, Connect Button
        row1 = tk.Frame(config_frame, bg=self.colors["bg_card"])
        row1.pack(fill=tk.X, pady=(0, 6))

        tk.Label(row1, text="Server IP:", bg=self.colors["bg_card"], fg=self.colors["fg_text"], font=("Helvetica", 9)).pack(side=tk.LEFT)
        self.entry_host = tk.Entry(row1, width=12, bg=self.colors["bg_input"], fg=self.colors["fg_text"], insertbackground="white", bd=1)
        self.entry_host.insert(0, self.initial_host)
        self.entry_host.pack(side=tk.LEFT, padx=(4, 10))

        tk.Label(row1, text="Port:", bg=self.colors["bg_card"], fg=self.colors["fg_text"], font=("Helvetica", 9)).pack(side=tk.LEFT)
        self.entry_port = tk.Entry(row1, width=6, bg=self.colors["bg_input"], fg=self.colors["fg_text"], insertbackground="white", bd=1)
        self.entry_port.insert(0, str(self.initial_port))
        self.entry_port.pack(side=tk.LEFT, padx=(4, 10))

        self.btn_connect = tk.Button(
            row1,
            text=" Connect ",
            width=11,
            font=("Helvetica", 9, "bold"),
            bg=self.colors["accent_blue"],
            fg="#11111b",
            activebackground=self.colors["fg_text"],
            cursor="hand2",
            relief=tk.RAISED,
            bd=1,
            command=self.toggle_connection,
        )
        self.btn_connect.pack(side=tk.RIGHT, padx=4)

        self.lbl_status_pill = tk.Label(
            row1,
            text="● Disconnected",
            bg=self.colors["bg_card"],
            fg=self.colors["accent_red"],
            font=("Helvetica", 9, "bold"),
        )
        self.lbl_status_pill.pack(side=tk.RIGHT, padx=8)

        # Row 2: Username & Symmetric Fernet Key
        row2 = tk.Frame(config_frame, bg=self.colors["bg_card"])
        row2.pack(fill=tk.X)

        tk.Label(row2, text="Username:", bg=self.colors["bg_card"], fg=self.colors["fg_text"], font=("Helvetica", 9)).pack(side=tk.LEFT)
        self.entry_user = tk.Entry(row2, width=12, bg=self.colors["bg_input"], fg=self.colors["fg_text"], insertbackground="white", bd=1)
        self.entry_user.insert(0, self.username)
        self.entry_user.pack(side=tk.LEFT, padx=(4, 10))

        tk.Label(row2, text="Secret Key:", bg=self.colors["bg_card"], fg=self.colors["fg_text"], font=("Helvetica", 9)).pack(side=tk.LEFT)
        self.entry_key = tk.Entry(
            row2,
            bg=self.colors["bg_input"],
            fg=self.colors["accent_amber"],
            insertbackground="white",
            bd=1,
            show="*",
        )
        self.entry_key.insert(0, self.initial_key)
        self.entry_key.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(4, 6))

        self.btn_toggle_key = tk.Button(
            row2,
            text="Show",
            font=("Helvetica", 8),
            bg=self.colors["bg_input"],
            fg=self.colors["fg_text"],
            bd=1,
            command=self._toggle_key_visibility,
        )
        self.btn_toggle_key.pack(side=tk.LEFT, padx=2)

        self.btn_gen_key = tk.Button(
            row2,
            text="Gen Key",
            font=("Helvetica", 8),
            bg=self.colors["bg_input"],
            fg=self.colors["accent_blue"],
            bd=1,
            command=self._generate_new_key,
        )
        self.btn_gen_key.pack(side=tk.LEFT, padx=2)

        # ----------------------------------------------------------------------
        # Middle Panel: Chat & Activity History (Read-only ScrolledText)
        # ----------------------------------------------------------------------
        chat_frame = tk.Frame(main_frame, bg=self.colors["bg_dark"])
        chat_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        self.chat_display = ScrolledText(
            chat_frame,
            wrap=tk.WORD,
            bg=self.colors["bg_chat"],
            fg=self.colors["fg_text"],
            font=("Segoe UI", 10) if platform.system() == "Windows" else ("Helvetica", 10),
            bd=1,
            relief=tk.SOLID,
            state=tk.DISABLED,
            padx=12,
            pady=10,
        )
        self.chat_display.pack(fill=tk.BOTH, expand=True)

        # Configure Custom Rich Text Tags for Clear Separation
        self.chat_display.tag_configure("tag_time", foreground=self.colors["fg_muted"], font=("Courier", 8))
        self.chat_display.tag_configure("tag_you_hdr", foreground=self.colors["accent_blue"], font=("Helvetica", 10, "bold"), spacing1=6)
        self.chat_display.tag_configure("tag_you_body", foreground="#ffffff", lmargin1=16, lmargin2=16, spacing3=4)
        self.chat_display.tag_configure("tag_peer_hdr", foreground=self.colors["accent_purple"], font=("Helvetica", 10, "bold"), spacing1=6)
        self.chat_display.tag_configure("tag_peer_body", foreground=self.colors["fg_text"], lmargin1=16, lmargin2=16, spacing3=4)
        self.chat_display.tag_configure("tag_system", foreground=self.colors["fg_muted"], font=("Helvetica", 9, "italic"), spacing1=3, spacing3=3)
        self.chat_display.tag_configure("tag_security", foreground=self.colors["accent_amber"], font=("Helvetica", 9, "bold"), spacing1=4, spacing3=4)
        self.chat_display.tag_configure("tag_file_badge", foreground="#11111b", background=self.colors["accent_green"], font=("Helvetica", 9, "bold"))
        self.chat_display.tag_configure("tag_file_details", foreground=self.colors["accent_green"], lmargin1=16, lmargin2=16, spacing3=6)

        # Welcome banner in chat
        self._append_to_chat(
            "tag_system",
            "[SYSTEM] Secure LAN Client initialized. True E2EE is active.\n"
            "[SYSTEM] Configure server details above and click 'Connect'.\n"
            f"[SYSTEM] Files received will be saved to: {self.download_dir}\n",
        )

        # ----------------------------------------------------------------------
        # Bottom Panel: Message Input, Send Button, and File Transfer Button
        # ----------------------------------------------------------------------
        bottom_frame = tk.Frame(main_frame, bg=self.colors["bg_dark"])
        bottom_frame.pack(fill=tk.X, pady=(0, 4))

        self.entry_message = tk.Entry(
            bottom_frame,
            bg=self.colors["bg_input"],
            fg="#ffffff",
            insertbackground="white",
            font=("Helvetica", 10),
            bd=1,
            relief=tk.SOLID,
        )
        self.entry_message.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8), ipady=4)
        # Bind the Enter key to the send function
        self.entry_message.bind("<Return>", lambda event: self.send_text_message())

        self.btn_send = tk.Button(
            bottom_frame,
            text=" Send ",
            font=("Helvetica", 9, "bold"),
            bg=self.colors["accent_blue"],
            fg="#11111b",
            activebackground="#b4befe",
            cursor="hand2",
            bd=1,
            command=self.send_text_message,
        )
        self.btn_send.pack(side=tk.LEFT, padx=(0, 6))

        self.btn_send_file = tk.Button(
            bottom_frame,
            text="📎 Send File ",
            font=("Helvetica", 9, "bold"),
            bg=self.colors["accent_green"],
            fg="#11111b",
            activebackground="#a6e3a1",
            cursor="hand2",
            bd=1,
            command=self.choose_and_send_file,
        )
        self.btn_send_file.pack(side=tk.LEFT, padx=(0, 6))

        self.btn_open_downloads = tk.Button(
            bottom_frame,
            text="📁 Downloads",
            font=("Helvetica", 9),
            bg=self.colors["bg_input"],
            fg=self.colors["fg_text"],
            cursor="hand2",
            bd=1,
            command=self._open_downloads_folder,
        )
        self.btn_open_downloads.pack(side=tk.RIGHT)

        # ----------------------------------------------------------------------
        # Footer Status Bar
        # ----------------------------------------------------------------------
        self.lbl_footer = tk.Label(
            main_frame,
            text="E2EE Engine: Ready | Cipher: AES-128-CBC + HMAC-SHA256 (Fernet) | Zero-Knowledge Blind Relay",
            bg=self.colors["bg_dark"],
            fg=self.colors["fg_muted"],
            font=("Helvetica", 8),
            anchor=tk.W,
        )
        self.lbl_footer.pack(fill=tk.X, pady=(4, 0))

    # ==========================================================================
    # KEY MANAGEMENT & UI TOGGLE HELPERS
    # ==========================================================================

    def _toggle_key_visibility(self) -> None:
        """Toggles between hidden ('*') and plain-text display of the secret key."""
        if self.entry_key.cget("show") == "*":
            self.entry_key.configure(show="")
            self.btn_toggle_key.configure(text="Hide")
        else:
            self.entry_key.configure(show="*")
            self.btn_toggle_key.configure(text="Show")

    def _generate_new_key(self) -> None:
        """Generates a fresh Fernet symmetric key and updates the key entry."""
        if self.connected:
            messagebox.showwarning("Connection Active", "Disconnect before changing encryption keys.")
            return
        fresh_key = Fernet.generate_key().decode("utf-8")
        self.entry_key.delete(0, tk.END)
        self.entry_key.insert(0, fresh_key)
        self._append_to_chat(
            "tag_system",
            "[SYSTEM] Generated new random 32-byte Fernet key. Share this with your peer.\n",
        )

    def _open_downloads_folder(self) -> None:
        """Opens the OS-native file explorer to view received files."""
        try:
            if platform.system() == "Darwin":
                subprocess.run(["open", self.download_dir], check=False)
            elif platform.system() == "Windows":
                os.startfile(self.download_dir)
            else:
                subprocess.run(["xdg-open", self.download_dir], check=False)
        except Exception as e:
            messagebox.showerror("Error", f"Could not open directory: {e}")

    # ==========================================================================
    # NETWORKING: CONNECTION & DISCONNECTION LIFECYCLE
    # ==========================================================================

    def toggle_connection(self) -> None:
        """Handles user clicking Connect / Disconnect button."""
        if self.connected:
            self.disconnect(user_initiated=True)
        else:
            self.connect()

    def connect(self) -> None:
        host = self.entry_host.get().strip()
        port_str = self.entry_port.get().strip()
        user = self.entry_user.get().strip()
        key_input = self.entry_key.get().strip()

        if not host or not port_str:
            messagebox.showerror("Input Error", "Please provide a valid Server IP and Port.")
            return

        if not key_input:
            messagebox.showerror("Key Error", "Please provide a symmetric encryption key or passphrase.")
            return

        try:
            port = int(port_str)
            if not (1 <= port <= 65535):
                raise ValueError()
        except ValueError:
            messagebox.showerror("Input Error", "Port must be an integer between 1 and 65535.")
            return

        # Prepare and validate Fernet E2EE Engine
        try:
            derived_key = derive_fernet_key(key_input)
            self.fernet = Fernet(derived_key)
        except Exception as e:
            messagebox.showerror("Cryptography Error", f"Failed to initialize Fernet cipher engine: {e}")
            return

        self.username = user if user else f"User_{int(time.time()) % 10000:04d}"

        # Establish TCP connection
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(5.0)  # Connection timeout
            self.sock.connect((host, port))
            self.sock.settimeout(None)  # Reset to blocking socket for threads
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            messagebox.showerror("Connection Failed", f"Could not connect to {host}:{port}\nError: {e}")
            self.sock = None
            return

        self.connected = True
        self._update_ui_connected_state(True)
        self._append_to_chat(
            "tag_system",
            f"[SYSTEM] Connected to relay server at {host}:{port} as '{self.username}'.\n"
            f"[SYSTEM] End-to-End Encryption active with symmetric Fernet cipher.\n",
        )

        # Launch background listening thread
        self.listen_thread = threading.Thread(
            target=self._listen_loop,
            name="SocketListenerThread",
            daemon=True,
        )
        self.listen_thread.start()

        # Announce presence to any peers already in the room
        try:
            announce_packet = b"SYS_PRESENCE:" + self.username.encode("utf-8") + b":joined"
            cipher_ann = self.fernet.encrypt(announce_packet)
            self.sock.sendall(struct.pack(HEADER_FORMAT, len(cipher_ann)) + cipher_ann)
        except Exception:
            pass

    def disconnect(self, user_initiated: bool = False, reason: str = "") -> None:
        """Disconnects socket cleanly and resets UI state."""
        # Notify peers that we are disconnecting before closing socket
        if self.connected and self.sock and self.fernet:
            try:
                leave_packet = b"SYS_PRESENCE:" + self.username.encode("utf-8") + b":left"
                cipher_leave = self.fernet.encrypt(leave_packet)
                self.sock.sendall(struct.pack(HEADER_FORMAT, len(cipher_leave)) + cipher_leave)
            except Exception:
                pass

        self.connected = False
        if self.sock:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            finally:
                self.sock.close()
            self.sock = None

        self._update_ui_connected_state(False)
        msg = "[SYSTEM] Disconnected from server."
        if reason:
            msg += f" Reason: {reason}"
        self._append_to_chat("tag_system", f"{msg}\n")

    def _update_ui_connected_state(self, is_connected: bool) -> None:
        """Updates control widgets based on active connection state."""
        if is_connected:
            self.btn_connect.configure(text="Disconnect", bg=self.colors["accent_red"])
            self.lbl_status_pill.configure(text="● Connected (E2EE)", fg=self.colors["accent_green"])
            self.entry_host.configure(state=tk.DISABLED)
            self.entry_port.configure(state=tk.DISABLED)
            self.entry_user.configure(state=tk.DISABLED)
            self.entry_key.configure(state=tk.DISABLED)
            self.btn_gen_key.configure(state=tk.DISABLED)
        else:
            self.btn_connect.configure(text=" Connect ", bg=self.colors["accent_blue"])
            self.lbl_status_pill.configure(text="● Disconnected", fg=self.colors["accent_red"])
            self.entry_host.configure(state=tk.NORMAL)
            self.entry_port.configure(state=tk.NORMAL)
            self.entry_user.configure(state=tk.NORMAL)
            self.entry_key.configure(state=tk.NORMAL)
            self.btn_gen_key.configure(state=tk.NORMAL)

    # ==========================================================================
    # BACKGROUND NETWORK LISTENER (THREADED & THREAD-SAFE)
    # ==========================================================================

    def _listen_loop(self) -> None:
        sock = self.sock
        while self.connected and self.running:
            try:
                if not sock:
                    break
                # Step 1: Read the 8-byte framing header
                raw_header = recv_exact(sock, HEADER_SIZE)
                payload_len = struct.unpack(HEADER_FORMAT, raw_header)[0]

                if payload_len <= 0 or payload_len > MAX_PAYLOAD_SIZE:
                    self.gui_queue.put(("error", f"Protocol error: Invalid frame length ({payload_len} bytes)."))
                    break

                # Step 2: Read exact ciphertext payload
                ciphertext = recv_exact(sock, payload_len)

                # Step 3: Decrypt using Fernet E2EE engine
                try:
                    if not self.fernet:
                        raise ValueError("Cipher not initialized.")
                    plaintext = self.fernet.decrypt(ciphertext)
                except InvalidToken:
                    # Cryptographic authentication failure: incorrect key or packet tampering
                    self.gui_queue.put((
                        "security_alert",
                        "[SECURITY ALERT] Received packet failed decryption/authentication! "
                        "Mismatched symmetric key or packet modified in transit.",
                    ))
                    continue
                except Exception as e:
                    self.gui_queue.put(("error", f"Decryption exception: {e}"))
                    continue

                # Step 4: Parse Application Protocol Packet
                self._dispatch_received_packet(plaintext)

            except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
                if self.connected:
                    self.gui_queue.put(("disconnect", "Connection lost (peer or server closed)."))
                break
            except Exception as e:
                if self.connected:
                    self.gui_queue.put(("disconnect", f"Socket listener terminated: {e}"))
                break

    def _dispatch_received_packet(self, plaintext: bytes) -> None:
        # --- Handle Peer Presence Announcements ---
        if plaintext.startswith(b"SYS_PRESENCE:"):
            parts = plaintext.split(b":", 2)
            if len(parts) == 3:
                peer = parts[1].decode("utf-8", errors="replace")
                action = parts[2].decode("utf-8", errors="replace")
                if action == "joined":
                    self.gui_queue.put(("system", f"[SYSTEM] Peer '{peer}' is online and ready for E2EE chat & file transfers."))
                    # Acknowledge presence so the newly joined peer also knows we are online
                    try:
                        if self.sock and self.fernet:
                            ack_pkt = b"SYS_PRESENCE:" + self.username.encode("utf-8") + b":online"
                            c_ack = self.fernet.encrypt(ack_pkt)
                            self.sock.sendall(struct.pack(HEADER_FORMAT, len(c_ack)) + c_ack)
                    except Exception:
                        pass
                elif action == "online":
                    self.gui_queue.put(("system", f"[SYSTEM] Peer '{peer}' is online and ready."))
                elif action == "left":
                    self.gui_queue.put(("system", f"[SYSTEM] Peer '{peer}' has disconnected."))
            return

        # --- Handle Text Messages ---
        elif plaintext.startswith(b"MSG:"):
            parts = plaintext.split(b":", 2)
            if len(parts) == 3:
                sender = parts[1].decode("utf-8", errors="replace")
                text_content = parts[2].decode("utf-8", errors="replace")
            else:
                sender = "Peer"
                text_content = parts[1].decode("utf-8", errors="replace")

            # Route to GUI queue
            self.gui_queue.put(("peer_message", sender, text_content))

        # --- Handle File Transfers ---
        elif plaintext.startswith(b"FILE:"):
            # Packet Structure:
            # Secure Transfer (with Security Code): FILE:<username>:<filename>:<code:6-digits>:<size>:<data>
            # Legacy Transfer: FILE:<username>:<filename>:<size>:<data> (or FILE:<filename>:<size>:<data>)
            parts6 = plaintext.split(b":", 5)
            is_secure_format = False
            security_code = ""

            if len(parts6) == 6:
                code_cand = parts6[3].decode("utf-8", errors="ignore")
                size_cand = parts6[4].decode("utf-8", errors="ignore")
                if code_cand.isdigit() and len(code_cand) == 6 and size_cand.isdigit():
                    try:
                        expected_size = int(size_cand)
                        if len(parts6[5]) == expected_size:
                            is_secure_format = True
                            sender = parts6[1].decode("utf-8", errors="replace")
                            filename = parts6[2].decode("utf-8", errors="replace")
                            security_code = code_cand
                            file_bytes = parts6[5]
                    except ValueError:
                        pass

            if not is_secure_format:
                parts_legacy = plaintext.split(b":", 4)
                if len(parts_legacy) == 5:
                    sender = parts_legacy[1].decode("utf-8", errors="replace")
                    filename = parts_legacy[2].decode("utf-8", errors="replace")
                    try:
                        expected_size = int(parts_legacy[3].decode("utf-8", errors="replace"))
                    except ValueError:
                        self.gui_queue.put(("error", "Invalid file size in legacy packet."))
                        return
                    file_bytes = parts_legacy[4]
                elif len(parts_legacy) == 4:
                    sender = "Peer"
                    filename = parts_legacy[1].decode("utf-8", errors="replace")
                    try:
                        expected_size = int(parts_legacy[2].decode("utf-8", errors="replace"))
                    except ValueError:
                        self.gui_queue.put(("error", "Invalid file size in legacy packet."))
                        return
                    file_bytes = parts_legacy[3]
                else:
                    self.gui_queue.put(("error", "Malformed file packet received."))
                    return

            # Integrity check
            if len(file_bytes) != expected_size:
                self.gui_queue.put((
                    "error",
                    f"File integrity violation for '{filename}': Expected {expected_size} bytes, got {len(file_bytes)} bytes.",
                ))
                return

            if not security_code:
                # Direct save for legacy transfers without security code
                saved_path, err = self._save_file_securely(filename, file_bytes)
                if err:
                    self.gui_queue.put(("error", f"Failed to save received file '{filename}': {err}"))
                else:
                    self.gui_queue.put(("file_received", sender, filename, saved_path, expected_size, ""))
            else:
                # Requires receiver security code entry to unlock and save
                self.gui_queue.put((
                    "file_incoming",
                    sender,
                    filename,
                    security_code,
                    file_bytes,
                    expected_size,
                ))

        else:
            self.gui_queue.put(("error", "Unknown packet structure received."))

    def _save_file_securely(self, raw_filename: str, file_bytes: bytes) -> Tuple[Optional[str], Optional[str]]:
        try:
            # 1. Strip directory components and dangerous characters
            safe_filename = os.path.basename(raw_filename).strip()
            # Remove null bytes or forbidden characters
            safe_filename = re.sub(r'[\0/\\:*?"<>|]', "_", safe_filename)
            if not safe_filename or safe_filename in (".", ".."):
                safe_filename = f"received_file_{int(time.time())}.bin"

            # 2. Collision resolution
            target_path = os.path.join(self.download_dir, safe_filename)
            base_name, ext = os.path.splitext(safe_filename)
            counter = 1
            while os.path.exists(target_path):
                target_path = os.path.join(self.download_dir, f"{base_name} ({counter}){ext}")
                counter += 1

            # 3. Write data to disk
            with open(target_path, "wb") as f:
                f.write(file_bytes)

            return target_path, None
        except Exception as e:
            return None, str(e)

    # ==========================================================================
    # MESSAGE & FILE TRANSMISSION METHODS
    # ==========================================================================

    def send_text_message(self) -> None:
        """Constructs, encrypts, and transmits a text message packet."""
        if not self.connected or not self.sock:
            messagebox.showinfo("Not Connected", "Please connect to the relay server first.")
            return

        text = self.entry_message.get().strip()
        if not text:
            return

        # Application packet structure: MSG:<username>:<text_content>
        packet = b"MSG:" + self.username.encode("utf-8") + b":" + text.encode("utf-8")

        # Encrypt with Fernet
        try:
            ciphertext = self.fernet.encrypt(packet)
            # Frame with 8-byte length prefix
            frame = struct.pack(HEADER_FORMAT, len(ciphertext)) + ciphertext
            self.sock.sendall(frame)
        except Exception as e:
            messagebox.showerror("Send Error", f"Failed to send message: {e}")
            return

        # Display immediately in chat as 'You'
        self._append_message_ui("You", text, is_self=True)
        self.entry_message.delete(0, tk.END)

    def choose_and_send_file(self) -> None:
        if not self.connected or not self.sock:
            messagebox.showinfo("Not Connected", "Please connect to the relay server first.")
            return

        file_path = filedialog.askopenfilename(title="Select File to Send over Secure LAN")
        if not file_path:
            return

        # Generate a cryptographically secure 6-digit security code for this transfer
        security_code = generate_security_code()

        # Spawn background worker to prevent Tkinter GUI freeze during file reading/encryption
        thread = threading.Thread(
            target=self._send_file_worker,
            args=(file_path, security_code),
            name="FileSenderWorker",
            daemon=True,
        )
        thread.start()

    def _send_file_worker(self, file_path: str, security_code: str) -> None:
        try:
            if not os.path.exists(file_path):
                self.gui_queue.put(("error", f"File not found: {file_path}"))
                return

            file_size = os.path.getsize(file_path)
            if file_size > MAX_PAYLOAD_SIZE:
                self.gui_queue.put((
                    "error",
                    f"File exceeds maximum allowed size ({format_bytes(MAX_PAYLOAD_SIZE)}): {format_bytes(file_size)}",
                ))
                return

            filename = os.path.basename(file_path)
            self.gui_queue.put((
                "system",
                f"[SYSTEM] Encrypting & transmitting file '{filename}' ({format_bytes(file_size)}) with Security Code...",
            ))

            # Step 1: Read file bytes
            with open(file_path, "rb") as f:
                file_bytes = f.read()

            # Step 2: Build Application Packet: FILE:<username>:<filename>:<security_code>:<file_size>:<file_bytes>
            packet = (
                b"FILE:"
                + self.username.encode("utf-8")
                + b":"
                + filename.encode("utf-8")
                + b":"
                + security_code.encode("utf-8")
                + b":"
                + str(file_size).encode("utf-8")
                + b":"
                + file_bytes
            )

            # Step 3: Encrypt payload with Fernet
            ciphertext = self.fernet.encrypt(packet)

            # Step 4: Frame with 8-byte big-endian length prefix
            frame = struct.pack(HEADER_FORMAT, len(ciphertext)) + ciphertext

            # Step 5: Transmit over TCP socket
            self.sock.sendall(frame)

            self.gui_queue.put(("file_sent", filename, file_size, security_code))

        except Exception as e:
            self.gui_queue.put(("error", f"Failed to send file '{os.path.basename(file_path)}': {e}"))

    # ==========================================================================
    # THREAD-SAFE GUI QUEUE DISPATCHER
    # ==========================================================================

    def _process_gui_queue(self) -> None:
        try:
            while True:
                event = self.gui_queue.get_nowait()
                event_type = event[0]

                if event_type == "peer_message":
                    _, sender, text = event
                    self._append_message_ui(sender, text, is_self=False)

                elif event_type == "file_sent":
                    _, filename, file_size, security_code = event
                    self._append_file_card_ui("You", filename, "", file_size, is_self=True, security_code=security_code)
                    self._show_sender_security_code_dialog(filename, file_size, security_code)

                elif event_type == "file_incoming":
                    _, sender, filename, security_code, file_bytes, expected_size = event
                    self._prompt_incoming_file_security_code(sender, filename, security_code, file_bytes, expected_size)

                elif event_type == "file_received":
                    _, sender, filename, saved_path, file_size, security_code = event
                    self._append_file_card_ui(sender, filename, saved_path, file_size, is_self=False, security_code=security_code)

                elif event_type == "system":
                    _, msg = event
                    self._append_to_chat("tag_system", f"{msg}\n")

                elif event_type == "security_alert":
                    _, msg = event
                    self._append_to_chat("tag_security", f"{msg}\n")

                elif event_type == "error":
                    _, err_msg = event
                    self._append_to_chat("tag_security", f"[ERROR] {err_msg}\n")

                elif event_type == "disconnect":
                    _, reason = event
                    self.disconnect(user_initiated=False, reason=reason)

                self.gui_queue.task_done()
        except queue.Empty:
            pass

        # Reschedule check every 40 ms
        if self.running:
            self.root.after(40, self._process_gui_queue)

    # ==========================================================================
    # SECURITY CODE DIALOGS & POPUPS
    # ==========================================================================

    def _center_toplevel(self, window: tk.Toplevel, width: int, height: int) -> None:
        """Centers a Toplevel modal dialog smoothly over the main client window."""
        window.update_idletasks()
        try:
            rx = self.root.winfo_rootx()
            ry = self.root.winfo_rooty()
            rw = self.root.winfo_width()
            rh = self.root.winfo_height()
            x = rx + max(0, (rw - width) // 2)
            y = ry + max(0, (rh - height) // 2)
            window.geometry(f"{width}x{height}+{x}+{y}")
        except Exception:
            window.geometry(f"{width}x{height}")

    def _show_sender_security_code_dialog(self, filename: str, file_size: int, code: str) -> None:
        """Displays a popup dialog to the sender showing the 6-digit security code for verification."""
        dialog = tk.Toplevel(self.root)
        dialog.title("🔐 File Transfer Security Code")
        dialog.configure(bg=self.colors["bg_card"])
        dialog.resizable(False, False)
        dialog.transient(self.root)

        width, height = 440, 320
        self._center_toplevel(dialog, width, height)

        content = tk.Frame(dialog, bg=self.colors["bg_card"], padx=20, pady=18)
        content.pack(fill=tk.BOTH, expand=True)

        lbl_title = tk.Label(
            content,
            text="🔐 File Transfer Security Code",
            font=("Helvetica", 12, "bold"),
            bg=self.colors["bg_card"],
            fg=self.colors["accent_blue"],
        )
        lbl_title.pack(anchor=tk.CENTER, pady=(0, 6))

        lbl_details = tk.Label(
            content,
            text=f"File: {filename} ({format_bytes(file_size)})",
            font=("Helvetica", 9),
            bg=self.colors["bg_card"],
            fg=self.colors["fg_text"],
            wraplength=390,
        )
        lbl_details.pack(anchor=tk.CENTER, pady=(0, 10))

        # Prominent Code Display Box
        code_formatted = format_security_code(code)
        code_frame = tk.Frame(
            content,
            bg=self.colors["bg_input"],
            bd=1,
            relief=tk.SOLID,
            padx=16,
            pady=10,
        )
        code_frame.pack(fill=tk.X, pady=(0, 12))

        lbl_code = tk.Label(
            code_frame,
            text=code_formatted,
            font=("Courier", 24, "bold"),
            bg=self.colors["bg_input"],
            fg=self.colors["accent_amber"],
        )
        lbl_code.pack(anchor=tk.CENTER)

        lbl_instruction = tk.Label(
            content,
            text="Share this one-time 6-digit security code with the recipient.\nThey must enter it to unlock and save the file.",
            font=("Helvetica", 9),
            bg=self.colors["bg_card"],
            fg=self.colors["fg_muted"],
            justify=tk.CENTER,
        )
        lbl_instruction.pack(anchor=tk.CENTER, pady=(0, 14))

        # Action Buttons
        btn_frame = tk.Frame(content, bg=self.colors["bg_card"])
        btn_frame.pack(fill=tk.X)

        def copy_code():
            self.root.clipboard_clear()
            self.root.clipboard_append(code)
            btn_copy.configure(text="✔ Copied!", bg=self.colors["accent_green"])
            dialog.after(1500, lambda: btn_copy.configure(text="📋 Copy Code", bg=self.colors["bg_input"]))

        btn_copy = tk.Button(
            btn_frame,
            text="📋 Copy Code",
            font=("Helvetica", 9, "bold"),
            bg=self.colors["bg_input"],
            fg=self.colors["fg_text"],
            bd=1,
            cursor="hand2",
            padx=10,
            command=copy_code,
        )
        btn_copy.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 6))

        btn_ok = tk.Button(
            btn_frame,
            text=" OK ",
            font=("Helvetica", 9, "bold"),
            bg=self.colors["accent_blue"],
            fg="#11111b",
            bd=1,
            cursor="hand2",
            padx=16,
            command=dialog.destroy,
        )
        btn_ok.pack(side=tk.RIGHT, expand=True, fill=tk.X, padx=(6, 0))

        dialog.bind("<Return>", lambda e: dialog.destroy())
        dialog.bind("<Escape>", lambda e: dialog.destroy())

        # Lift dialog above main window
        dialog.lift()
        dialog.focus_force()

    def _prompt_incoming_file_security_code(
        self,
        sender: str,
        filename: str,
        security_code: str,
        file_bytes: bytes,
        expected_size: int,
    ) -> None:
        """Prompts the receiver to enter the sender's 6-digit security code before saving."""
        try:
            self.root.bell()
        except Exception:
            pass

        dialog = tk.Toplevel(self.root)
        dialog.title("🔐 Incoming Secure File Transfer")
        dialog.configure(bg=self.colors["bg_card"])
        dialog.resizable(False, False)
        dialog.transient(self.root)

        width, height = 450, 360
        self._center_toplevel(dialog, width, height)

        attempts_left = [3]

        content = tk.Frame(dialog, bg=self.colors["bg_card"], padx=20, pady=16)
        content.pack(fill=tk.BOTH, expand=True)

        # Header
        lbl_title = tk.Label(
            content,
            text="🔐 Incoming File Transfer",
            font=("Helvetica", 13, "bold"),
            bg=self.colors["bg_card"],
            fg=self.colors["accent_green"],
        )
        lbl_title.pack(anchor=tk.CENTER, pady=(0, 6))

        # Details
        size_str = format_bytes(expected_size)
        lbl_details = tk.Label(
            content,
            text=f"Sender: {sender}\nFile: {filename} ({size_str})",
            font=("Helvetica", 9, "bold"),
            bg=self.colors["bg_card"],
            fg=self.colors["fg_text"],
            justify=tk.CENTER,
            wraplength=400,
        )
        lbl_details.pack(anchor=tk.CENTER, pady=(0, 8))

        # Instructions
        lbl_instruction = tk.Label(
            content,
            text=f"A security code is required to receive this file.\nEnter the 6-digit code provided by {sender}:",
            font=("Helvetica", 9),
            bg=self.colors["bg_card"],
            fg=self.colors["fg_muted"],
            justify=tk.CENTER,
        )
        lbl_instruction.pack(anchor=tk.CENTER, pady=(0, 8))

        # Code Entry
        entry_code = tk.Entry(
            content,
            font=("Courier", 18, "bold"),
            justify="center",
            bg=self.colors["bg_input"],
            fg=self.colors["accent_amber"],
            insertbackground="white",
            bd=1,
            relief=tk.SOLID,
            width=12,
        )
        entry_code.pack(anchor=tk.CENTER, ipady=4, pady=(0, 6))
        entry_code.focus_set()

        # Status / Feedback label
        lbl_status = tk.Label(
            content,
            text="(Ask sender for their 6-digit security code)",
            font=("Helvetica", 8),
            bg=self.colors["bg_card"],
            fg=self.colors["fg_muted"],
        )
        lbl_status.pack(anchor=tk.CENTER, pady=(0, 12))

        # Action Buttons
        btn_frame = tk.Frame(content, bg=self.colors["bg_card"])
        btn_frame.pack(fill=tk.X)

        def on_accept():
            user_code = entry_code.get().strip().replace(" ", "").replace("-", "")
            target_code = security_code.strip().replace(" ", "").replace("-", "")

            if not user_code:
                lbl_status.configure(text="Please enter the 6-digit code.", fg=self.colors["accent_amber"])
                return

            if user_code == target_code:
                # Code verified!
                dialog.destroy()
                saved_path, err = self._save_file_securely(filename, file_bytes)
                if err:
                    self._append_to_chat("tag_security", f"[ERROR] Failed to save file '{filename}': {err}\n")
                else:
                    self._append_file_card_ui(
                        sender,
                        filename,
                        saved_path,
                        expected_size,
                        is_self=False,
                        security_code=security_code,
                    )
                    self._append_to_chat(
                        "tag_system",
                        f"[SYSTEM] File '{filename}' verified with security code ({format_security_code(security_code)}) and saved to {saved_path}\n",
                    )
            else:
                attempts_left[0] -= 1
                if attempts_left[0] > 0:
                    lbl_status.configure(
                        text=f"❌ Incorrect security code! ({attempts_left[0]} attempt{'s' if attempts_left[0] > 1 else ''} remaining)",
                        fg=self.colors["accent_red"],
                    )
                    entry_code.delete(0, tk.END)
                    entry_code.focus_set()
                else:
                    dialog.destroy()
                    self._append_to_chat(
                        "tag_security",
                        f"[SECURITY ALERT] File transfer for '{filename}' from {sender} rejected: Maximum invalid code attempts reached.\n",
                    )
                    messagebox.showerror(
                        "Transfer Rejected",
                        f"Security code verification failed for '{filename}'.\nFile transfer rejected for security.",
                    )

        def on_decline():
            dialog.destroy()
            self._append_to_chat(
                "tag_system",
                f"[SYSTEM] Incoming file transfer for '{filename}' from {sender} was declined.\n",
            )

        btn_decline = tk.Button(
            btn_frame,
            text="✖ Decline",
            font=("Helvetica", 9),
            bg=self.colors["bg_input"],
            fg=self.colors["fg_text"],
            bd=1,
            cursor="hand2",
            padx=12,
            pady=4,
            command=on_decline,
        )
        btn_decline.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 6))

        btn_unlock = tk.Button(
            btn_frame,
            text="✔ Unlock & Receive",
            font=("Helvetica", 9, "bold"),
            bg=self.colors["accent_green"],
            fg="#11111b",
            bd=1,
            cursor="hand2",
            padx=12,
            pady=4,
            command=on_accept,
        )
        btn_unlock.pack(side=tk.RIGHT, expand=True, fill=tk.X, padx=(6, 0))

        dialog.bind("<Return>", lambda e: on_accept())
        dialog.bind("<Escape>", lambda e: on_decline())
        dialog.protocol("WM_DELETE_WINDOW", on_decline)

        dialog.lift()
        dialog.focus_force()

    # ==========================================================================
    # CHAT RENDERING HELPERS
    # ==========================================================================

    def _append_to_chat(self, tag: str, text: str) -> None:
        self.chat_display.configure(state=tk.NORMAL)
        self.chat_display.insert(tk.END, text, tag)
        self.chat_display.see(tk.END)
        self.chat_display.configure(state=tk.DISABLED)

    def _append_message_ui(self, sender: str, text: str, is_self: bool) -> None:
        now_str = datetime.now().strftime("%H:%M:%S")
        self.chat_display.configure(state=tk.NORMAL)

        # Timestamp
        self.chat_display.insert(tk.END, f"[{now_str}] ", "tag_time")

        # Sender Header
        if is_self:
            self.chat_display.insert(tk.END, f"You:\n", "tag_you_hdr")
            self.chat_display.insert(tk.END, f"{text}\n\n", "tag_you_body")
        else:
            self.chat_display.insert(tk.END, f"Peer ({sender}):\n", "tag_peer_hdr")
            self.chat_display.insert(tk.END, f"{text}\n\n", "tag_peer_body")

        self.chat_display.see(tk.END)
        self.chat_display.configure(state=tk.DISABLED)

    def _append_file_card_ui(
        self,
        sender: str,
        filename: str,
        saved_path: str,
        file_size: int,
        is_self: bool,
        security_code: str = "",
    ) -> None:
        now_str = datetime.now().strftime("%H:%M:%S")
        size_str = format_bytes(file_size)
        self.chat_display.configure(state=tk.NORMAL)

        self.chat_display.insert(tk.END, f"[{now_str}] ", "tag_time")
        if is_self:
            self.chat_display.insert(tk.END, " 📁 FILE SENT (SECURE) ", "tag_file_badge")
            code_line = f"\n  • Security Code: {format_security_code(security_code)} (Share with recipient)" if security_code else ""
            self.chat_display.insert(
                tk.END,
                f"\n  • Filename: {filename}\n  • Size: {size_str}{code_line}\n  • Status: Delivered to relay (Awaiting recipient code verification)\n\n",
                "tag_file_details",
            )
        else:
            self.chat_display.insert(tk.END, " 📥 FILE RECEIVED & VERIFIED ", "tag_file_badge")
            code_line = f"\n  • Security Code: Verified ({format_security_code(security_code)})" if security_code else ""
            self.chat_display.insert(
                tk.END,
                f"\n  • Sender: {sender}\n  • Filename: {filename}\n  • Size: {size_str}{code_line}\n  • Saved to: {saved_path}\n\n",
                "tag_file_details",
            )

        self.chat_display.see(tk.END)
        self.chat_display.configure(state=tk.DISABLED)

    # ==========================================================================
    # CLEAN SHUTDOWN
    # ==========================================================================

    def on_closing(self) -> None:
        self.running = False
        self.disconnect(user_initiated=True, reason="Client GUI closed.")
        self.root.destroy()


# ==============================================================================
# MAIN ENTRY POINT
# ==============================================================================


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Secure LAN Chat & File Transfer Client")
    parser.add_argument("--user", type=str, default=None, help="Initial username")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Relay server host")
    parser.add_argument("--port", type=int, default=5000, help="Relay server port")
    parser.add_argument("--key", type=str, default=None, help="Shared Fernet key or passphrase")
    parser.add_argument("--geometry", type=str, default=None, help="Window geometry, e.g. '620x660+50+50'")
    parser.add_argument("--autoconnect", action="store_true", help="Automatically connect on launch")
    args = parser.parse_args()

    root = tk.Tk()
    app = SecureChatClient(
        root,
        username=args.user,
        host=args.host,
        port=args.port,
        key=args.key,
        geometry=args.geometry,
        autoconnect=args.autoconnect,
    )
    root.mainloop()


if __name__ == "__main__":
    main()
