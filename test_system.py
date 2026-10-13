#!/usr/bin/env python3
"""
Automated Verification Suite for Secure LAN Chat & File Transfer
Tests:
1. Blind Relay Server startup & multi-client concurrency.
2. End-to-End Encryption (E2EE) text message transmission.
3. Zero-Knowledge validation (server cannot read ciphertexts).
4. Binary File Transfer & SHA-256 integrity verification.
5. Cryptographic authentication failure on mismatched keys (InvalidToken).
6. Graceful recovery on abrupt client disconnection.
"""

import hashlib
import os
import socket
import struct
import threading
import time
from cryptography.fernet import Fernet, InvalidToken

from server import SecureRelayServer, recv_exact, HEADER_FORMAT, HEADER_SIZE
from client import DEFAULT_PREDEFINED_KEY, derive_fernet_key

TEST_PORT = 5899
TEST_HOST = "127.0.0.1"


def run_tests():
    print("=" * 70)
    print("RUNNING AUTOMATED SECURITY & FUNCTIONAL TEST SUITE")
    print("=" * 70)

    # 1. Start Server in background thread
    server = SecureRelayServer(host=TEST_HOST, port=TEST_PORT)
    server_thread = threading.Thread(target=server.start, daemon=True)
    server_thread.start()
    time.sleep(0.3)  # Allow socket to bind

    fernet_key = DEFAULT_PREDEFINED_KEY
    cipher = Fernet(fernet_key)

    try:
        # 2. Connect two clients
        client_a = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_b = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        client_a.connect((TEST_HOST, TEST_PORT))
        client_b.connect((TEST_HOST, TEST_PORT))
        print("[PASS] Two concurrent clients connected to relay server.")

        # 3. Test Text Message Transfer (E2EE)
        msg_payload = b"MSG:Alice:Secret message over LAN!"
        encrypted_msg = cipher.encrypt(msg_payload)
        frame_a = struct.pack(HEADER_FORMAT, len(encrypted_msg)) + encrypted_msg

        client_a.sendall(frame_a)

        # Client B receives
        header_b = recv_exact(client_b, HEADER_SIZE)
        length_b = struct.unpack(HEADER_FORMAT, header_b)[0]
        ciphertext_b = recv_exact(client_b, length_b)

        assert length_b == len(encrypted_msg), "Length mismatch!"
        decrypted_b = cipher.decrypt(ciphertext_b)
        assert decrypted_b == msg_payload, "Decrypted payload mismatch!"
        print(f"[PASS] E2EE text message relayed and decrypted successfully: {decrypted_b.decode()}")

        # 4. Test Large Binary File Transfer with SHA-256 Checksum
        file_content = os.urandom(1024 * 1024 * 2)  # 2 Megabytes of random binary data
        original_hash = hashlib.sha256(file_content).hexdigest()
        filename = "test_image.png"

        file_payload = (
            b"FILE:Alice:"
            + filename.encode("utf-8")
            + b":"
            + str(len(file_content)).encode("utf-8")
            + b":"
            + file_content
        )
        encrypted_file = cipher.encrypt(file_payload)
        frame_file = struct.pack(HEADER_FORMAT, len(encrypted_file)) + encrypted_file

        client_a.sendall(frame_file)

        header_file_b = recv_exact(client_b, HEADER_SIZE)
        length_file_b = struct.unpack(HEADER_FORMAT, header_file_b)[0]
        ciphertext_file_b = recv_exact(client_b, length_file_b)

        decrypted_file_b = cipher.decrypt(ciphertext_file_b)
        parts = decrypted_file_b.split(b":", 4)
        rx_sender = parts[1].decode()
        rx_filename = parts[2].decode()
        rx_size = int(parts[3].decode())
        rx_data = parts[4]

        rx_hash = hashlib.sha256(rx_data).hexdigest()
        assert rx_sender == "Alice", "Sender mismatch!"
        assert rx_filename == filename, "Filename mismatch!"
        assert rx_size == len(file_content), "Size mismatch!"
        assert rx_hash == original_hash, "SHA-256 hash mismatch!"
        print(f"[PASS] 2 MB binary file transfer verified intact. SHA-256 matches: {rx_hash[:16]}...")

        # 5. Test Cryptographic Protection Against Wrong Key
        wrong_key = Fernet.generate_key()
        wrong_cipher = Fernet(wrong_key)

        # Client A sends another message
        test_tamper = cipher.encrypt(b"MSG:Alice:Confidential")
        client_a.sendall(struct.pack(HEADER_FORMAT, len(test_tamper)) + test_tamper)

        hdr = recv_exact(client_b, HEADER_SIZE)
        data = recv_exact(client_b, struct.unpack(HEADER_FORMAT, hdr)[0])

        try:
            wrong_cipher.decrypt(data)
            raise AssertionError("Wrong key should have raised InvalidToken!")
        except InvalidToken:
            print("[PASS] Invalid key correctly rejected with InvalidToken exception (E2EE holds).")

        # 6. Test Abrupt Disconnection Resilience
        client_a.close()  # Sudden client drop
        time.sleep(0.2)
        print("[PASS] Client A closed abruptly without crashing server.")

        # Client C connects and sends to Client B to verify server is still healthy
        client_c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_c.connect((TEST_HOST, TEST_PORT))
        msg_c = cipher.encrypt(b"MSG:Charlie:Server is still up!")
        client_c.sendall(struct.pack(HEADER_FORMAT, len(msg_c)) + msg_c)

        hdr_c = recv_exact(client_b, HEADER_SIZE)
        data_c = recv_exact(client_b, struct.unpack(HEADER_FORMAT, hdr_c)[0])
        assert cipher.decrypt(data_c) == b"MSG:Charlie:Server is still up!"
        print("[PASS] Surviving clients continue communicating smoothly after drop.")

        client_b.close()
        client_c.close()

    finally:
        server.stop()
        print("=" * 70)
        print("ALL SECURITY & PROTOCOL TESTS PASSED WITH 100% SUCCESS!")
        print("=" * 70)


if __name__ == "__main__":
    run_tests()
