#!/usr/bin/env python3
"""
Secure LAN Chat & File Transfer - E2EE GUI Client
==================================================
Architecture & Security Design:
    - Transport Layer: TCP stream with 8-byte length-prefixed packet framing
      to completely eliminate stream fragmentation and packet coalescing issues.
    - Cryptographic Layer: True End-to-End Encryption (E2EE) using Fernet
      (AES-128-CBC + PKCS7 padding + HMAC-SHA256 authenticated encryption).
      The server is a blind relay with no decryption capability.
    - Application Protocol:
        * Text Message:  MSG:<username>:<text_content>
        * File Transfer: FILE:<username>:<filename>:<file_size>:<file_bytes>
    - Security Controls:
        * Path traversal defense (os.path.basename, null byte/slash stripping).
        * Collision avoidance in downloads.
        * File size verification.
        * Graceful InvalidToken handling (wrong key or tampering warning).
    - Concurrency & Thread Safety:
        * Network reader thread pushes events to a thread-safe queue.Queue.
        * Tkinter main thread periodically consumes queue events via root.after().
        * File transmission runs in background worker threads to avoid GUI freezes.

Author: Senior Network Security Engineer & Python GUI Developer
"""

import base64
import os
import platform
import queue
import re
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

# ==============================================================================
# PROTOCOL & CRYPTOGRAPHIC CONSTANTS
# ==============================================================================

# Default shared 32-byte urlsafe base64 Fernet key for immediate zero-config testing
DEFAULT_PREDEFINED_KEY = b"PizUtw6785WXIWW7U4W9XC4gQKqlOLPuuteSoLopWwo="

HEADER_FORMAT = "!Q"  # 8-byte big-endian unsigned 64-bit integer
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
MAX_PAYLOAD_SIZE = 100 * 1024 * 1024  # 100 MB safety limit
RECV_CHUNK_SIZE = 65536  # 64 KB read buffer
DOWNLOAD_DIR_NAME = "received_files"


def derive_fernet_key(key_input: str) -> bytes:
    """
    Validates or derives a valid 32-byte urlsafe base64 Fernet key.
    
    If `key_input` is already a valid 32-byte urlsafe base64 Fernet key,
    it returns it directly. If the user provided a human-readable passphrase,
    it deterministically derives a Fernet key using PBKDF2-HMAC-SHA256
    (100,000 iterations with a fixed domain-separated salt).
    """
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
    """Returns human-readable string representation of byte sizes."""
    for unit in ["B", "KB", "MB", "GB"]:
        if num_bytes < 1024.0:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} TB"


def recv_exact(sock: socket.socket, num_bytes: int) -> bytes:
    """
    Reliably reads exactly `num_bytes` from a stream socket.
    
    Handles TCP fragmentation by looping until the complete byte count
    is accumulated or peer disconnects.
    """
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
    """
    Modular, Object-Oriented Secure Chat & File Transfer GUI Client.
    
    Combines an event-driven Tkinter frontend with a multi-threaded
    network socket worker and client-side Fernet E2EE encryption engine.
    """

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Secure LAN Chat & File Transfer (E2EE)")
        self.root.geometry("860x680")
        self.root.minsize(720, 520)

        # Networking State
        self.sock: Optional[socket.socket] = None
        self.connected = False
        self.running = True
        self.listen_thread: Optional[threading.Thread] = None

        # Cryptography State
        self.fernet: Optional[Fernet] = None
        self.username = f"User_{int(time.time()) % 10000:04d}"

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

        # Graceful shutdown handler
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def _setup_styles(self) -> None:
        """Configures modern color palette and typography."""
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
        """Constructs all Tkinter widgets and layout."""
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

        # Row 1: Server IP, Port, Username, Connect Button
        row1 = tk.Frame(config_frame, bg=self.colors["bg_card"])
        row1.pack(fill=tk.X, pady=(0, 6))

        tk.Label(row1, text="Server IP:", bg=self.colors["bg_card"], fg=self.colors["fg_text"], font=("Helvetica", 9)).pack(side=tk.LEFT)
        self.entry_host = tk.Entry(row1, width=13, bg=self.colors["bg_input"], fg=self.colors["fg_text"], insertbackground="white", bd=1)
        self.entry_host.insert(0, "127.0.0.1")
        self.entry_host.pack(side=tk.LEFT, padx=(4, 12))

        tk.Label(row1, text="Port:", bg=self.colors["bg_card"], fg=self.colors["fg_text"], font=("Helvetica", 9)).pack(side=tk.LEFT)
        self.entry_port = tk.Entry(row1, width=6, bg=self.colors["bg_input"], fg=self.colors["fg_text"], insertbackground="white", bd=1)
        self.entry_port.insert(0, "5000")
        self.entry_port.pack(side=tk.LEFT, padx=(4, 12))

        tk.Label(row1, text="Username:", bg=self.colors["bg_card"], fg=self.colors["fg_text"], font=("Helvetica", 9)).pack(side=tk.LEFT)
        self.entry_user = tk.Entry(row1, width=14, bg=self.colors["bg_input"], fg=self.colors["fg_text"], insertbackground="white", bd=1)
        self.entry_user.insert(0, self.username)
        self.entry_user.pack(side=tk.LEFT, padx=(4, 12))

        self.btn_connect = tk.Button(
            row1,
            text=" Connect ",
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
        self.lbl_status_pill.pack(side=tk.RIGHT, padx=10)

        # Row 2: Symmetric Fernet Key / Shared Secret Passphrase
        row2 = tk.Frame(config_frame, bg=self.colors["bg_card"])
        row2.pack(fill=tk.X)

        tk.Label(row2, text="Secret Key:", bg=self.colors["bg_card"], fg=self.colors["fg_text"], font=("Helvetica", 9)).pack(side=tk.LEFT)
        self.entry_key = tk.Entry(
            row2,
            bg=self.colors["bg_input"],
            fg=self.colors["accent_amber"],
            insertbackground="white",
            bd=1,
            show="*",
        )
        self.entry_key.insert(0, DEFAULT_PREDEFINED_KEY.decode("utf-8"))
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
        """Establishes TCP connection to the relay server and initializes E2EE."""
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

    def disconnect(self, user_initiated: bool = False, reason: str = "") -> None:
        """Disconnects socket cleanly and resets UI state."""
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
        """
        Background listener thread. Reads 8-byte framed packets from the TCP stream.
        
        Decrypts ciphertext payloads via Fernet.
        Pushes parsed events to `self.gui_queue` for thread-safe UI updates.
        """
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
        """
        Decodes decrypted application packets and schedules GUI events.
        
        Supported Packet Types:
            MSG:<username>:<text_content>
            FILE:<username>:<filename>:<size>:<file_bytes>
            (Also supports fallback formats without username: MSG:<text> and FILE:<filename>:<size>:<file_bytes>)
        """
        # --- Handle Text Messages ---
        if plaintext.startswith(b"MSG:"):
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
            # Packet Structure: FILE:username:filename:size:data (or FILE:filename:size:data)
            parts = plaintext.split(b":", 4)
            if len(parts) == 5:
                sender = parts[1].decode("utf-8", errors="replace")
                filename = parts[2].decode("utf-8", errors="replace")
                expected_size = int(parts[3].decode("utf-8", errors="replace"))
                file_bytes = parts[4]
            elif len(parts) == 4:
                sender = "Peer"
                filename = parts[1].decode("utf-8", errors="replace")
                expected_size = int(parts[2].decode("utf-8", errors="replace"))
                file_bytes = parts[3]
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

            # Save file safely to disk
            saved_path, err = self._save_file_securely(filename, file_bytes)
            if err:
                self.gui_queue.put(("error", f"Failed to save received file '{filename}': {err}"))
            else:
                self.gui_queue.put(("file_received", sender, filename, saved_path, expected_size))

        else:
            self.gui_queue.put(("error", "Unknown packet structure received."))

    def _save_file_securely(self, raw_filename: str, file_bytes: bytes) -> Tuple[Optional[str], Optional[str]]:
        """
        Prevents Path Traversal Attacks (CWE-22) and securely saves file.
        
        Sanitizes directory separators, null bytes, and traversal tokens ('../').
        Prevents accidental file overwriting by appending an incremental index.
        """
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
        """Opens OS-native file dialog and dispatches background file sender."""
        if not self.connected or not self.sock:
            messagebox.showinfo("Not Connected", "Please connect to the relay server first.")
            return

        file_path = filedialog.askopenfilename(title="Select File to Send over Secure LAN")
        if not file_path:
            return

        # Spawn background worker to prevent Tkinter GUI freeze during file reading/encryption
        thread = threading.Thread(
            target=self._send_file_worker,
            args=(file_path,),
            name="FileSenderWorker",
            daemon=True,
        )
        thread.start()

    def _send_file_worker(self, file_path: str) -> None:
        """Background thread worker for reading, encrypting, and sending large files."""
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
            self.gui_queue.put(("system", f"[SYSTEM] Encrypting & transmitting file '{filename}' ({format_bytes(file_size)})..."))

            # Step 1: Read file bytes
            with open(file_path, "rb") as f:
                file_bytes = f.read()

            # Step 2: Build Application Packet: FILE:<username>:<filename>:<file_size>:<file_bytes>
            packet = (
                b"FILE:"
                + self.username.encode("utf-8")
                + b":"
                + filename.encode("utf-8")
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

            self.gui_queue.put(("file_sent", filename, file_size))

        except Exception as e:
            self.gui_queue.put(("error", f"Failed to send file '{os.path.basename(file_path)}': {e}"))

    # ==========================================================================
    # THREAD-SAFE GUI QUEUE DISPATCHER
    # ==========================================================================

    def _process_gui_queue(self) -> None:
        """
        Runs on the Tkinter main thread. Consumes events from `self.gui_queue`.
        
        Guarantees that widgets are only accessed from the main thread.
        """
        try:
            while True:
                event = self.gui_queue.get_nowait()
                event_type = event[0]

                if event_type == "peer_message":
                    _, sender, text = event
                    self._append_message_ui(sender, text, is_self=False)

                elif event_type == "file_received":
                    _, sender, filename, saved_path, file_size = event
                    self._append_file_card_ui(sender, filename, saved_path, file_size, is_self=False)

                elif event_type == "file_sent":
                    _, filename, file_size = event
                    self._append_file_card_ui("You", filename, "", file_size, is_self=True)

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
    # CHAT RENDERING HELPERS
    # ==========================================================================

    def _append_to_chat(self, tag: str, text: str) -> None:
        """Inserts text into the read-only ScrolledText widget with specific styling."""
        self.chat_display.configure(state=tk.NORMAL)
        self.chat_display.insert(tk.END, text, tag)
        self.chat_display.see(tk.END)
        self.chat_display.configure(state=tk.DISABLED)

    def _append_message_ui(self, sender: str, text: str, is_self: bool) -> None:
        """Formats and displays a text message bubble."""
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
        self, sender: str, filename: str, saved_path: str, file_size: int, is_self: bool
    ) -> None:
        """Displays a dedicated card badge for file transfers."""
        now_str = datetime.now().strftime("%H:%M:%S")
        size_str = format_bytes(file_size)
        self.chat_display.configure(state=tk.NORMAL)

        self.chat_display.insert(tk.END, f"[{now_str}] ", "tag_time")
        if is_self:
            self.chat_display.insert(tk.END, " 📁 FILE SENT ", "tag_file_badge")
            self.chat_display.insert(
                tk.END,
                f"\n  • Filename: {filename}\n  • Size: {size_str}\n  • Status: Delivered to blind relay\n\n",
                "tag_file_details",
            )
        else:
            self.chat_display.insert(tk.END, " 📥 FILE RECEIVED ", "tag_file_badge")
            self.chat_display.insert(
                tk.END,
                f"\n  • Sender: {sender}\n  • Filename: {filename}\n  • Size: {size_str}\n  • Saved to: {saved_path}\n\n",
                "tag_file_details",
            )

        self.chat_display.see(tk.END)
        self.chat_display.configure(state=tk.DISABLED)

    # ==========================================================================
    # CLEAN SHUTDOWN
    # ==========================================================================

    def on_closing(self) -> None:
        """Invoked when user clicks window close button. Cleanly releases sockets."""
        self.running = False
        self.disconnect(user_initiated=True, reason="Client GUI closed.")
        self.root.destroy()


# ==============================================================================
# MAIN ENTRY POINT
# ==============================================================================


def main() -> None:
    """Initializes the Tkinter GUI and SecureChatClient application."""
    root = tk.Tk()
    app = SecureChatClient(root)
    root.mainloop()


if __name__ == "__main__":
    main()
