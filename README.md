# Secure LAN Chat & File Transfer System (E2EE)

A production-grade, multi-client Secure Local Area Network (LAN) Chat and File Transfer application written in Python. Designed using modern network security engineering principles, featuring **Zero-Knowledge Blind Relaying**, **True End-to-End Encryption (E2EE)** with Fernet (AES-128-CBC + HMAC-SHA256), robust **TCP stream framing**, and a responsive, thread-safe **Tkinter GUI**.

---

## 🛡️ Security Architecture & Engineering Design

```
+-----------------------------------------------------------------------------------+
|                                  LOCAL NETWORK                                    |
|                                                                                   |
|  +--------------------+         +-----------------------+         +-------------+ |
|  | Client A (Alice)   |         | Blind Relay Server    |         | Client B    | |
|  | Key: [Predefined K]|         | (Zero-Knowledge)      |         | Key: [K]    | |
|  +---------+----------+         +-----------+-----------+         +------+------+ |
|            |                                |                            |        |
|            | 1. Encrypt Payload with Key K  |                            |        |
|            | 2. Frame [8-Byte Len][Cipher]  |                            |        |
|            |------------------------------->|                            |        |
|            |                                | Forward Raw Cipher Frame   |        |
|            |                                |--------------------------->|        |
|            |                                |                            |        |
|            |                                |                            | 3. Decrypt & Verify |
|            |                                |                            |    with Key K       |
+-----------------------------------------------------------------------------------+
```

### 1. True End-to-End Encryption (E2EE) & Zero-Knowledge Server
* **Blind Relay**: The server acts purely as an unintelligent message forwarder. It does **not** possess the encryption key and cannot decrypt or inspect message bodies, filenames, or file content.
* **Cryptographic Primitive**: Utilizes `cryptography.fernet.Fernet`, providing authenticated symmetric encryption:
  * **Confidentiality**: 128-bit AES in CBC mode with PKCS7 padding.
  * **Integrity & Authenticity**: HMAC using SHA-256 with constant-time verification.
  * **Freshness & Replay Mitigation**: High-precision 64-bit timestamps embedded in every Fernet token.
* **Key Derivation Flexibility**:
  * Direct 32-byte urlsafe base64 Fernet key support.
  * Human-readable passphrase support via **PBKDF2-HMAC-SHA256** (100,000 iterations with domain-separated salt).

### 2. Transport Layer Framing & Custom Packet Protocol
TCP is a byte-stream protocol with no intrinsic packet boundaries. To eliminate packet fragmentation and message concatenation (Nagle’s algorithm / buffering):
* **Length-Prefixed Framing**: All frames begin with an 8-byte big-endian unsigned integer (`!Q` - up to 16 Exabytes), followed by the exact ciphertext payload.
* **Stream Reassembly**: Receivers utilize a dedicated `recv_exact()` reader that accumulates chunks across stream boundaries until the frame is fully assembled.
* **Packet Layout (Plaintext before encryption)**:
  * **Text Message**: `MSG:<username>:<text_content>`
  * **Secure File Transfer (E2EE + Security Code)**: `FILE:<username>:<filename>:<security_code>:<file_size>:<file_bytes>`
  * **Legacy File Transfer**: `FILE:<username>:<filename>:<file_size>:<file_bytes>`

### 3. Network Defense & Mitigation
* **Path Traversal Defense (CWE-22)**: Filenames received from peers are sanitized via `os.path.basename()`, stripping null bytes, forward/backward slashes, and traversal sequences (`..`). Files are strictly saved to the isolated `./received_files/` directory.
* **File Overwrite Protection**: Incremental suffixes `(1)`, `(2)` prevent destructive overwrites of local files.
* **Integrity Validation**: Reconstructed payload size is strictly validated against the declared header length before saving.
* **Denial of Service (DoS) Guard**: Server enforces a maximum frame payload limit (`MAX_FRAME_SIZE = 100 MB`) to prevent memory exhaustion attacks.
* **Graceful Disconnection Handling**: Broken pipe and reset exceptions are caught cleanly on both client and server without thread leaks or crashes.

### 4. GUI Concurrency & Thread Safety
* In Tkinter, updating UI widgets from background threads causes race conditions or crashes.
* This client employs the gold-standard architecture:
  * **Background Socket Reader Thread**: Reads and decrypts packets, pushing parsed events to a thread-safe `queue.Queue`.
  * **Background Worker Threads**: Large file encryption and transmission happen asynchronously without freezing the UI.
  * **Main GUI Event Loop**: Consumes queue events every 40ms via `root.after()`, guaranteeing thread-safe widget updates.

---

## 📁 Repository Structure

```
.
├── server.py             # Multi-threaded Zero-Knowledge TCP Blind Relay Server
├── client.py             # Tkinter GUI Client with Fernet E2EE & safe file transfers
├── test_system.py        # Automated test suite (concurrency, E2EE, file checksum, etc.)
├── requirements.txt      # Project dependencies (cryptography)
└── received_files/       # Default target directory for received files (auto-created)
```

---

## 🚀 Getting Started

### 1. Installation
Ensure Python 3.8+ is installed. Install the dependencies:
```bash
pip install -r requirements.txt
```

### 2. All-in-One Local Demo (Server + 2 Connected Clients)
To quickly start the relay server and launch two connected clients side-by-side with one command:
```bash
python3 launch_lan.py
```
This automatically launches **Alice** (left window) and **Bob** (right window), both connected and ready to chat or transfer files immediately.

### 3. Manual / Separate Host Launching

#### Start the Relay Server
Run the server on the host machine (binds to all interfaces on port `5000` by default):
```bash
python3 server.py --host 0.0.0.0 --port 5000
```

### 3. Launch the GUI Clients
Open two separate terminal windows (or run on two distinct machines on the same LAN):

**Client 1:**
```bash
python3 client.py
```
* Enter Username: e.g. `Alice`
* Server IP: `127.0.0.1` (or the LAN IP of the server, e.g., `192.168.1.50`)
* Secret Key: Keep the default predefined key or enter your shared passphrase.
* Click **Connect**.

**Client 2:**
```bash
python3 client.py
```
* Enter Username: e.g. `Bob`
* Server IP: `127.0.0.1` (or the server LAN IP)
* Secret Key: Ensure the key matches Client 1!
* Click **Connect**.

---

## 💬 Usage Guide

1. **Sending Messages**: Type your message in the bottom entry field and press **Enter** (or click **Send**).
   * Messages sent by you appear with a blue `You:` header.
   * Messages from peers appear with a purple `Peer (<username>):` header.
2. **Sending Files (with Security Code)**:
   * Click the **📎 Send File** button and select any file.
   * A 6-digit **File Transfer Security Code** (e.g., `582 914`) is generated and shown in a popup dialog (with a **📋 Copy Code** button) as well as logged in your chat history.
   * Share this 6-digit code with your intended recipient so they can unlock the file.
3. **Receiving Files (Protected Verification)**:
   * When an incoming file transfer arrives, an authorization modal prompts the recipient to enter the 6-digit security code provided by the sender.
   * Once the recipient enters the matching code and clicks **✔ Unlock & Receive**, the file is decrypted, integrity-verified, and safely saved to `./received_files/`.
   * If an incorrect code is entered or the transfer is declined, the file payload is discarded from memory without saving to disk.
   * Click **📁 Downloads** in the bottom right to open the folder directly in your operating system's file manager (Finder / Explorer / Files).
4. **Changing Keys**:
   * Click **Gen Key** to generate a fresh 32-byte Fernet key.
   * Share this key securely with your peer before connecting.

---

## 🧪 Automated Testing

To run the automated verification suite:
```bash
python3 test_system.py
```

Tests performed:
* ✅ Server socket binding and concurrent multi-client connections.
* ✅ End-to-End Encryption text messaging.
* ✅ Zero-Knowledge server blind forwarding.
* ✅ 2 MB binary file transfer with **SHA-256 checksum byte-for-byte verification**.
* ✅ Cryptographic rejection (`InvalidToken`) on mismatched keys.
* ✅ Abrupt client disconnection recovery without crashing surviving clients.
