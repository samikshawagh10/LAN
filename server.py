#!/usr/bin/env python3
"""
Secure LAN Chat & File Transfer - Blind Relay Server
=====================================================
Architecture & Security Role:
    Acts strictly as a Zero-Knowledge / Blind Relay over TCP.
    The server handles multiple concurrent client connections using threads,
    framing packets with an 8-byte length prefix to eliminate TCP stream
    fragmentation/concatenation issues.

    Crucially, because all payloads are End-to-End Encrypted (E2EE) with Fernet
    using a client-side symmetric key, the server cannot inspect, parse, or
    modify any message contents or file data.

Author: Senior Network Security Engineer
"""

import argparse
import logging
import socket
import struct
import sys
import threading
import time
from typing import Dict, Set, Tuple

# Security Guard: Maximum allowed frame payload size (100 MB)
# Protects against intentional or accidental memory exhaustion DoS attacks.
MAX_FRAME_SIZE = 100 * 1024 * 1024  # 100 Megabytes
HEADER_FORMAT = "!Q"  # 8-byte unsigned integer (big-endian 64-bit)
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)


def setup_logger() -> logging.Logger:
    """Configures structured, timestamped logging for security auditing."""
    logger = logging.getLogger("SecureRelayServer")
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        ch = logging.StreamHandler(sys.stdout)
        ch.setLevel(logging.INFO)
        formatter = logging.Formatter(
            fmt="[%(asctime)s] [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        ch.setFormatter(formatter)
        logger.addHandler(ch)
    return logger


logger = setup_logger()


def recv_exact(sock: socket.socket, num_bytes: int) -> bytes:
    """
    Safely reads exactly `num_bytes` from a stream socket.
    
    Handles TCP fragmentation by looping until the requested byte count
    is accumulated or the peer disconnects.
    
    Raises:
        ConnectionResetError: If the socket is closed or drops before completing.
    """
    buffer = bytearray()
    while len(buffer) < num_bytes:
        chunk = sock.recv(min(num_bytes - len(buffer), 65536))
        if not chunk:
            raise ConnectionResetError("Socket closed prematurely by peer.")
        buffer.extend(chunk)
    return bytes(buffer)


class SecureRelayServer:
    """
    Multi-threaded, Zero-Knowledge TCP Blind Relay Server.
    
    Attributes:
        host (str): Listening IP interface (default '0.0.0.0').
        port (int): Listening TCP port (default 5000).
        server_socket (socket.socket): The listening master socket.
        clients (Set[socket.socket]): Set of active client sockets.
        client_addrs (Dict[socket.socket, Tuple[str, int]]): Client address metadata.
        lock (threading.Lock): Thread lock protecting client sets.
        running (bool): Server lifecycle control flag.
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 5000) -> None:
        self.host = host
        self.port = port
        self.server_socket: socket.socket | None = None
        self.clients: Set[socket.socket] = set()
        self.client_addrs: Dict[socket.socket, Tuple[str, int]] = {}
        self.lock = threading.Lock()
        self.running = False

    def start(self) -> None:
        """Initializes the TCP listener and enters the client accept loop."""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Enable SO_REUSEADDR to avoid TIME_WAIT port binding lockouts upon restart
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(128)
            self.running = True
            logger.info("=" * 60)
            logger.info("SECURE LAN RELAY SERVER INITIALIZED")
            logger.info(f"Listening on       : {self.host}:{self.port}")
            logger.info(f"Relay Mode         : Blind E2EE Relay (Zero-Knowledge)")
            logger.info(f"Max Frame Limit    : {MAX_FRAME_SIZE / (1024 * 1024):.0f} MB")
            logger.info("=" * 60)
        except OSError as e:
            logger.error(f"Failed to bind socket to {self.host}:{self.port}: {e}")
            sys.exit(1)

        try:
            while self.running:
                try:
                    client_sock, client_addr = self.server_socket.accept()
                except OSError:
                    # Occurs when server_socket is closed during shutdown
                    break

                with self.lock:
                    self.clients.add(client_sock)
                    self.client_addrs[client_sock] = client_addr
                    total_clients = len(self.clients)

                logger.info(
                    f"[+] Client connected: {client_addr[0]}:{client_addr[1]} "
                    f"(Active Peers: {total_clients})"
                )

                # Spawn worker thread for concurrent client handling
                thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_sock, client_addr),
                    name=f"ClientHandler-{client_addr[0]}:{client_addr[1]}",
                    daemon=True,
                )
                thread.start()

        except KeyboardInterrupt:
            logger.info("Interrupt signal received. Initiating server shutdown...")
        finally:
            self.stop()

    def _handle_client(
        self, client_sock: socket.socket, client_addr: Tuple[str, int]
    ) -> None:
        """
        Worker thread for receiving and blindly relaying framed packets from a client.
        
        Framing Format:
            [8 Bytes Big-Endian Length Prefix][Encrypted Ciphertext Payload]
        """
        peer_name = f"{client_addr[0]}:{client_addr[1]}"
        try:
            while self.running:
                # Step 1: Read the 8-byte framing header
                raw_header = recv_exact(client_sock, HEADER_SIZE)
                payload_len = struct.unpack(HEADER_FORMAT, raw_header)[0]

                # Step 2: Enforce security size boundary
                if payload_len <= 0 or payload_len > MAX_FRAME_SIZE:
                    logger.warning(
                        f"[!] Violation from {peer_name}: Invalid payload size "
                        f"({payload_len} bytes). Disconnecting client."
                    )
                    break

                # Step 3: Read exact encrypted payload from TCP stream
                payload = recv_exact(client_sock, payload_len)

                # Step 4: Re-package complete frame and broadcast blindly to peers
                frame = raw_header + payload
                self._broadcast(sender_sock=client_sock, frame=frame, length=payload_len)

        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            if self.running:
                logger.info(f"[-] Client connection reset abruptly: {peer_name}")
        except OSError as e:
            if self.running:
                logger.info(f"[-] Client socket closed: {peer_name}")
        except Exception as e:
            if self.running:
                logger.warning(f"[!] Error handling client {peer_name}: {e}")
        finally:
            self._disconnect_client(client_sock)

    def _broadcast(
        self, sender_sock: socket.socket, frame: bytes, length: int
    ) -> None:
        """
        Blindly forwards an encrypted frame to all connected peers except sender.
        
        Thread-safe: Handles sudden peer disconnections without halting delivery
        to surviving clients.
        """
        sender_addr = self.client_addrs.get(sender_sock, ("unknown", 0))
        sender_str = f"{sender_addr[0]}:{sender_addr[1]}"

        dead_clients: Set[socket.socket] = set()
        delivered_count = 0

        with self.lock:
            target_clients = [c for c in self.clients if c != sender_sock]

            for peer in target_clients:
                try:
                    peer.sendall(frame)
                    delivered_count += 1
                except (BrokenPipeError, ConnectionResetError, OSError):
                    dead_clients.add(peer)

            # Purge any clients that dropped during transmission
            for dead_client in dead_clients:
                self._disconnect_client_locked(dead_client)

        logger.info(
            f"[RELAY] Blindly forwarded {length} bytes from {sender_str} "
            f"to {delivered_count} peer(s)"
        )

    def _disconnect_client(self, client_sock: socket.socket) -> None:
        """Safely removes and closes a client socket under lock."""
        with self.lock:
            self._disconnect_client_locked(client_sock)

    def _disconnect_client_locked(self, client_sock: socket.socket) -> None:
        """Internal helper for client disconnection while holding self.lock."""
        addr = self.client_addrs.pop(client_sock, None)
        if client_sock in self.clients:
            self.clients.remove(client_sock)
            try:
                client_sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            finally:
                client_sock.close()

            peer_str = f"{addr[0]}:{addr[1]}" if addr else "unknown"
            logger.info(
                f"[-] Client disconnected: {peer_str} "
                f"(Active Peers: {len(self.clients)})"
            )

    def stop(self) -> None:
        """Gracefully shuts down the server and cleans up resources."""
        if not self.running:
            return
        self.running = False
        logger.info("Stopping Secure Relay Server...")

        with self.lock:
            for client in list(self.clients):
                try:
                    client.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                client.close()
            self.clients.clear()
            self.client_addrs.clear()

        if self.server_socket:
            try:
                self.server_socket.close()
            except OSError:
                pass
            self.server_socket = None

        logger.info("Server shutdown complete. All sockets released.")


def main() -> None:
    """CLI Entry point for running the server."""
    parser = argparse.ArgumentParser(
        description="Secure LAN Chat & File Transfer - E2EE Blind Relay Server"
    )
    parser.add_argument(
        "--host",
        type=str,
        default="0.0.0.0",
        help="Interface IP address to bind (default: 0.0.0.0 / all interfaces)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=5000,
        help="TCP port to listen on (default: 5000)",
    )
    args = parser.parse_args()

    server = SecureRelayServer(host=args.host, port=args.port)
    server.start()


if __name__ == "__main__":
    main()
