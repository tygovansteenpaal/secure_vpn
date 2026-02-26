#!/usr/bin/env python3
"""
PyVPN Server - Advanced Python VPN Server
Uses TUN interface, AES-256-GCM encryption, ECDH key exchange
Run as root: sudo python3 server.py
"""

import os
import sys
import socket
import struct
import threading
import logging
import time
import fcntl
import json
import hmac
import hashlib
from collections import defaultdict
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
log = logging.getLogger("PyVPN-Server")

# ─── Configuration ────────────────────────────────────────────────────────────
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 5194
TUN_NAME    = "tun0"
TUN_ADDR    = "10.8.0.1"      # Server VPN IP
TUN_MASK    = "255.255.255.0"
VPN_SUBNET  = "10.8.0.0/24"
MTU         = 1420
MAX_CLIENTS = 50
TIMEOUT_SEC = 120             # Client idle timeout

# Pre-shared auth token (change this in production!)
PSK = b"change-this-secret-preshared-key-32b"

# ─── TUN Interface ────────────────────────────────────────────────────────────
TUNSETIFF   = 0x400454ca
IFF_TUN     = 0x0001
IFF_NO_PI   = 0x1000

def create_tun(name=TUN_NAME):
    """Create and configure a TUN interface."""
    tun = open("/dev/net/tun", "r+b", buffering=0)
    ifr = struct.pack("16sH22s", name.encode(), IFF_TUN | IFF_NO_PI, b'\x00'*22)
    fcntl.ioctl(tun, TUNSETIFF, ifr)
    os.system(f"ip addr add {TUN_ADDR}/24 dev {name} 2>/dev/null || true")
    os.system(f"ip link set dev {name} mtu {MTU} up")
    os.system(f"sysctl -w net.ipv4.ip_forward=1 > /dev/null")
    os.system(f"iptables -t nat -A POSTROUTING -s {VPN_SUBNET} -j MASQUERADE 2>/dev/null || true")
    log.info(f"TUN interface {name} created: {TUN_ADDR}/24")
    return tun

# ─── Crypto Helpers ───────────────────────────────────────────────────────────

def derive_keys(shared_secret: bytes, salt: bytes) -> dict:
    """Derive encryption and MAC keys from ECDH shared secret via HKDF."""
    hkdf = HKDF(algorithm=hashes.SHA256(), length=64, salt=salt, info=b"pyvpn-session-v1")
    material = hkdf.derive(shared_secret)
    return {
        "enc": material[:32],   # AES-256-GCM key
        "mac": material[32:],   # HMAC-SHA256 key (for packet auth fallback)
    }

def encrypt_packet(key: bytes, plaintext: bytes, seq: int) -> bytes:
    """Encrypt a packet with AES-256-GCM. Returns: nonce(12) + ciphertext+tag."""
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(key)
    aad = struct.pack(">Q", seq)   # Sequence number as AAD (prevents replay)
    ct = aesgcm.encrypt(nonce, plaintext, aad)
    return struct.pack(">Q", seq) + nonce + ct

def decrypt_packet(key: bytes, data: bytes, window: "ReplayWindow") -> bytes | None:
    """Decrypt and authenticate a packet. Returns plaintext or None on failure."""
    if len(data) < 8 + 12 + 16:
        return None
    seq = struct.unpack(">Q", data[:8])[0]
    nonce = data[8:20]
    ct = data[20:]
    if not window.check_and_update(seq):
        log.warning(f"Replay attack detected or out-of-window seq={seq}")
        return None
    aesgcm = AESGCM(key)
    aad = struct.pack(">Q", seq)
    try:
        return aesgcm.decrypt(nonce, ct, aad)
    except Exception:
        return None

# ─── Replay Window ────────────────────────────────────────────────────────────

class ReplayWindow:
    """Sliding window replay protection (256-packet window)."""
    WINDOW = 256

    def __init__(self):
        self.top = -1
        self.seen = set()
        self.lock = threading.Lock()

    def check_and_update(self, seq: int) -> bool:
        with self.lock:
            if seq > self.top:
                # Advance window
                for old in list(self.seen):
                    if old <= seq - self.WINDOW:
                        self.seen.discard(old)
                self.top = seq
                self.seen.add(seq)
                return True
            elif seq >= self.top - self.WINDOW:
                if seq in self.seen:
                    return False  # Duplicate
                self.seen.add(seq)
                return True
            else:
                return False  # Too old

# ─── Client Session ───────────────────────────────────────────────────────────

class ClientSession:
    def __init__(self, addr, enc_key, vpn_ip):
        self.addr = addr
        self.enc_key = enc_key
        self.vpn_ip = vpn_ip
        self.seq_out = 0
        self.seq_lock = threading.Lock()
        self.replay = ReplayWindow()
        self.last_seen = time.time()
        self.tx_bytes = 0
        self.rx_bytes = 0

    def next_seq(self) -> int:
        with self.seq_lock:
            s = self.seq_out
            self.seq_out += 1
            return s

    def touch(self):
        self.last_seen = time.time()

    def is_expired(self) -> bool:
        return (time.time() - self.last_seen) > TIMEOUT_SEC

# ─── IP Pool ──────────────────────────────────────────────────────────────────

class IPPool:
    def __init__(self, base="10.8.0", start=2, end=254):
        self.pool = [f"{base}.{i}" for i in range(start, end+1)]
        self.assigned = {}
        self.lock = threading.Lock()

    def allocate(self) -> str | None:
        with self.lock:
            if not self.pool:
                return None
            ip = self.pool.pop(0)
            self.assigned[ip] = True
            return ip

    def release(self, ip: str):
        with self.lock:
            if ip in self.assigned:
                del self.assigned[ip]
                self.pool.insert(0, ip)

# ─── VPN Server ───────────────────────────────────────────────────────────────

class VPNServer:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4*1024*1024)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4*1024*1024)
        self.sock.bind((LISTEN_HOST, LISTEN_PORT))

        self.tun = create_tun()
        self.ip_pool = IPPool()

        # addr -> ClientSession
        self.clients: dict[tuple, ClientSession] = {}
        # vpn_ip -> addr
        self.ip_to_addr: dict[str, tuple] = {}
        self.lock = threading.RLock()

        # Server ECDH key pair (rotated periodically in production)
        self.server_private_key = X25519PrivateKey.generate()
        self.server_public_bytes = self.server_private_key.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )

        log.info(f"PyVPN Server listening on {LISTEN_HOST}:{LISTEN_PORT}")

    # ── Handshake ─────────────────────────────────────────────────────────────

    def handle_handshake(self, data: bytes, addr: tuple):
        """
        Handshake protocol:
          CLIENT → SERVER: "HELLO" + hmac(PSK, client_pub) + client_pub(32)
          SERVER → CLIENT: "HELO2" + server_pub(32) + encrypted(vpn_ip)
        """
        if len(data) < 5 + 32 + 32:
            return
        if data[:5] != b"HELLO":
            return

        client_hmac  = data[5:37]
        client_pub   = data[37:69]

        # Verify pre-shared key MAC
        expected_mac = hmac.new(PSK, client_pub, hashlib.sha256).digest()
        if not hmac.compare_digest(client_hmac, expected_mac):
            log.warning(f"Handshake auth failed from {addr}")
            return

        # ECDH key exchange
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
        peer_pub = X25519PublicKey.from_public_bytes(client_pub)
        shared   = self.server_private_key.exchange(peer_pub)
        salt     = client_pub[:16] + self.server_public_bytes[:16]
        keys     = derive_keys(shared, salt)

        # Allocate VPN IP
        with self.lock:
            if addr in self.clients:
                old = self.clients[addr]
                self.ip_pool.release(old.vpn_ip)
                if old.vpn_ip in self.ip_to_addr:
                    del self.ip_to_addr[old.vpn_ip]

        vpn_ip = self.ip_pool.allocate()
        if not vpn_ip:
            log.error("IP pool exhausted")
            return

        # Encrypt the assigned IP in the response
        aesgcm  = AESGCM(keys["enc"])
        nonce   = secrets.token_bytes(12)
        ip_enc  = aesgcm.encrypt(nonce, vpn_ip.encode(), b"vpn-ip-assign")
        payload = b"HELO2" + self.server_public_bytes + nonce + ip_enc

        self.sock.sendto(payload, addr)

        with self.lock:
            session = ClientSession(addr, keys["enc"], vpn_ip)
            self.clients[addr] = session
            self.ip_to_addr[vpn_ip] = addr

        log.info(f"Client {addr} connected, assigned {vpn_ip}")

    # ── Packet Routing ────────────────────────────────────────────────────────

    def handle_data(self, data: bytes, addr: tuple):
        with self.lock:
            session = self.clients.get(addr)
        if not session:
            return

        session.touch()
        pkt = decrypt_packet(session.enc_key, data, session.replay)
        if pkt is None:
            return

        session.rx_bytes += len(pkt)

        # Write decrypted IP packet to TUN (kernel routes it)
        try:
            os.write(self.tun.fileno(), pkt)
        except OSError as e:
            log.error(f"TUN write error: {e}")

    def tun_to_udp(self):
        """Read packets from TUN and forward to correct VPN client."""
        while True:
            try:
                pkt = os.read(self.tun.fileno(), MTU + 100)
                if len(pkt) < 20:
                    continue

                # Extract destination IP from IPv4 header
                dst_ip = socket.inet_ntoa(pkt[16:20])

                with self.lock:
                    addr = self.ip_to_addr.get(dst_ip)
                    session = self.clients.get(addr) if addr else None

                if not session:
                    continue

                seq  = session.next_seq()
                enc  = encrypt_packet(session.enc_key, pkt, seq)
                session.tx_bytes += len(pkt)
                self.sock.sendto(enc, session.addr)

            except OSError as e:
                log.error(f"TUN read error: {e}")
                time.sleep(0.1)

    def udp_listener(self):
        """Receive UDP packets from clients."""
        while True:
            try:
                data, addr = self.sock.recvfrom(MTU + 200)
                if data[:5] == b"HELLO":
                    threading.Thread(
                        target=self.handle_handshake,
                        args=(data, addr), daemon=True
                    ).start()
                elif data[:5] == b"PING\x00":
                    # Keepalive
                    with self.lock:
                        s = self.clients.get(addr)
                    if s:
                        s.touch()
                    self.sock.sendto(b"PONG\x00", addr)
                else:
                    self.handle_data(data, addr)
            except Exception as e:
                log.error(f"UDP recv error: {e}")

    def cleanup_loop(self):
        """Remove expired client sessions."""
        while True:
            time.sleep(30)
            with self.lock:
                expired = [a for a, s in self.clients.items() if s.is_expired()]
                for addr in expired:
                    session = self.clients.pop(addr)
                    self.ip_to_addr.pop(session.vpn_ip, None)
                    self.ip_pool.release(session.vpn_ip)
                    log.info(f"Session expired: {addr} ({session.vpn_ip}) "
                             f"tx={session.tx_bytes//1024}KB rx={session.rx_bytes//1024}KB")

    def run(self):
        threading.Thread(target=self.tun_to_udp,  daemon=True, name="tun→udp").start()
        threading.Thread(target=self.cleanup_loop, daemon=True, name="cleanup").start()
        log.info("Server running. Press Ctrl+C to stop.")
        try:
            self.udp_listener()
        except KeyboardInterrupt:
            log.info("Shutting down...")
            os.system(f"ip link del {TUN_NAME} 2>/dev/null || true")

# ─── Entry Point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Error: Must run as root (sudo python3 server.py)")
        sys.exit(1)
    VPNServer().run()
