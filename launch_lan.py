#!/usr/bin/env python3
import os
import socket
import subprocess
import sys
import time

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
HOST = "127.0.0.1"
PORT = 5000


def is_server_running(host: str, port: int) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            s.connect((host, port))
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def main():
    print("=" * 65)
    print("🚀 LAUNCHING SECURE LAN CHAT & FILE TRANSFER SYSTEM")
    print("=" * 65)

    # 1. Start Server if not already listening
    server_process = None
    if not is_server_running(HOST, PORT):
        print(f"[*] Starting Blind Relay Server on {HOST}:{PORT}...")
        server_process = subprocess.Popen(
            [sys.executable, "server.py", "--host", HOST, "--port", str(PORT)],
            cwd=PROJECT_DIR,
        )
        time.sleep(0.5)
        if not is_server_running(HOST, PORT):
            print("[-] Error: Failed to start relay server.")
            sys.exit(1)
        print("[+] Relay server is running.")
    else:
        print(f"[+] Relay server is already active on {HOST}:{PORT}.")

    # 2. Launch Client 1 (Alice - Left Side of Screen)
    print("[*] Launching Client 1 (Alice)...")
    proc_alice = subprocess.Popen(
        [
            sys.executable,
            "client.py",
            "--user", "Alice",
            "--host", HOST,
            "--port", str(PORT),
            "--geometry", "600x660+40+40",
            "--autoconnect",
        ],
        cwd=PROJECT_DIR,
    )

    time.sleep(0.3)

    # 3. Launch Client 2 (Bob - Right Side of Screen)
    print("[*] Launching Client 2 (Bob)...")
    proc_bob = subprocess.Popen(
        [
            sys.executable,
            "client.py",
            "--user", "Bob",
            "--host", HOST,
            "--port", str(PORT),
            "--geometry", "600x660+670+40",
            "--autoconnect",
        ],
        cwd=PROJECT_DIR,
    )

    print("\n" + "=" * 65)
    print("✅ System successfully launched!")
    print("   • Alice: GUI window on the left")
    print("   • Bob:   GUI window on the right")
    print(f"   • Files received are saved in: {os.path.join(PROJECT_DIR, 'received_files')}")
    print("   • Test file available to send: sample_document.txt")
    print("=" * 65)
    print("\nPress Ctrl+C in this terminal when you want to stop all processes.")

    try:
        proc_alice.wait()
        proc_bob.wait()
    except KeyboardInterrupt:
        print("\n[*] Shutting down clients...")
        proc_alice.terminate()
        proc_bob.terminate()
        if server_process:
            print("[*] Stopping server...")
            server_process.terminate()
        print("[+] Goodbye!")


if __name__ == "__main__":
    main()
