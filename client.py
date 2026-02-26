#!/usr/bin/env python3
"""
PyVPN Client - Advanced Python VPN Client
Uses TUN interface, AES-256-GCM encryption, ECDH key exchange
Run as root: sudo python3 client.py --server <IP>
"""

import os
import sys
import socket
import struct
import threading
import logging
import time
import fcntl
import argparse
import hmac
import hashlib
import secrets
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
log = logging.getLogger("PyVPN-Client")

# Must match server
SERVER_PORT  = 5194
TUN_NAME     = "tun1"
MTU          = 1420
PSK          = b"change-this-secret-preshared-key-32b"
KEEPALIVE    = 15   # seconds between keepalives
RECONNECT_DELAY = 5

# ─── TUN Interface ────────────────────────────────────────────────────────────
TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_NO_PI = 0x1000

def create_tun(name=TUN_NAME, vpn_ip=None, server_vpn_ip="10.8.0.1"):
    tun = open("/dev/net/tun", "r+b", buffering=0)
    ifr = struct.pack("16sH22s", name.encode(), IFF_TUN | IFF_NO_PI, b'\x00'*22)
    fcntl.ioctl(tun, TUNSETIFF, ifr)
    if vpn_ip:
        os.system(f"ip addr flush dev {name} 2>/dev/null || true")
        os.system(f"ip addr add {vpn_ip}/24 dev {name}")
        os.system(f"ip link set dev {name} mtu {MTU} up")
        log.info(f"TUN {name} configured: {vpn_ip}/24")
    return tun

# ─── Crypto (mirrors server) ──────────────────────────────────────────────────

def derive_keys(shared_secret: bytes, salt: bytes) -> dict:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=64, salt=salt, info=b"pyvpn-session-v1")
    material = hkdf.derive(shared_secret)
    return {"enc": material[:32], "mac": material[32:]}

def encrypt_packet(key: bytes, plaintext: bytes, seq: int) -> bytes:
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(key)
    aad = struct.pack(">Q", seq)
    ct = aesgcm.encrypt(nonce, plaintext, aad)
    return struct.pack(">Q", seq) + nonce + ct

def decrypt_packet(key: bytes, data: bytes) -> bytes | None:
    if len(data) < 8 + 12 + 16:
        return None
    nonce = data[8:20]
    ct = data[20:]
    seq = struct.unpack(">Q", data[:8])[0]
    aesgcm = AESGCM(key)
    aad = struct.pack(">Q", seq)
    try:
        return aesgcm.decrypt(nonce, ct, aad)
    except Exception:
        return None

# ─── VPN Client ───────────────────────────────────────────────────────────────

class VPNClient:
    def __init__(self, server_host: str, server_port: int, route_all: bool = False):
        self.server_host  = server_host
        self.server_port  = server_port
        self.route_all    = route_all
        self.server_addr  = (server_host, server_port)

        self.sock = None
        self.tun  = None
        self.enc_key    = None
        self.seq_out    = 0
        self.seq_lock   = threading.Lock()
        self.vpn_ip     = None
        self.server_vpn = "10.8.0.1"
        self.connected  = threading.Event()
        self.running    = True
        self._original_gw = None

    def next_seq(self) -> int:
        with self.seq_lock:
            s = self.seq_out
            self.seq_out += 1
            return s

    # ── Handshake ─────────────────────────────────────────────────────────────

    def handshake(self) -> bool:
        """Perform ECDH handshake with server. Returns True on success."""
        priv_key   = X25519PrivateKey.generate()
        client_pub = priv_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        mac        = hmac.new(PSK, client_pub, hashlib.sha256).digest()
        msg        = b"HELLO" + mac + client_pub

        self.sock.sendto(msg, self.server_addr)
        self.sock.settimeout(10)

        try:
            data, _ = self.sock.recvfrom(2048)
        except socket.timeout:
            log.error("Handshake timed out")
            return False
        finally:
            self.sock.settimeout(None)

        if data[:5] != b"HELO2" or len(data) < 5 + 32 + 12:
            log.error("Bad handshake response")
            return False

        server_pub_bytes = data[5:37]
        nonce            = data[37:49]
        ip_enc           = data[49:]

        # Derive shared key
        server_pub = X25519PublicKey.from_public_bytes(server_pub_bytes)
        shared     = priv_key.exchange(server_pub)
        salt       = client_pub[:16] + server_pub_bytes[:16]
        keys       = derive_keys(shared, salt)
        self.enc_key = keys["enc"]

        # Decrypt assigned IP
        aesgcm = AESGCM(self.enc_key)
        try:
            self.vpn_ip = aesgcm.decrypt(nonce, ip_enc, b"vpn-ip-assign").decode()
        except Exception:
            log.error("Failed to decrypt assigned IP")
            return False

        log.info(f"Handshake complete. VPN IP: {self.vpn_ip}, Server: {self.server_vpn}")
        return True

    # ── Routing ───────────────────────────────────────────────────────────────

    def setup_routing(self):
        """Optionally route all traffic through VPN."""
        if not self.route_all:
            return

        # Save original default gateway
        result = os.popen("ip route show default").read().strip()
        if result:
            self._original_gw = result.split()[2] if len(result.split()) > 2 else None
            orig_iface = result.split()[4] if len(result.split()) > 4 else None

        if self._original_gw:
            # Route VPN server traffic via original gateway
            os.system(f"ip route add {self.server_host}/32 via {self._original_gw} 2>/dev/null || true")
            # Default route through VPN
            os.system(f"ip route del default 2>/dev/null || true")
            os.system(f"ip route add default via {self.server_vpn} dev {TUN_NAME}")
            log.info("All traffic routed through VPN")

    def teardown_routing(self):
        if not self.route_all or not self._original_gw:
            return
        os.system(f"ip route del default 2>/dev/null || true")
        os.system(f"ip route add default via {self._original_gw} 2>/dev/null || true")
        os.system(f"ip route del {self.server_host}/32 2>/dev/null || true")
        log.info("Original routing restored")

    # ── I/O Loops ─────────────────────────────────────────────────────────────

    def tun_to_udp(self):
        """Read from TUN, encrypt, send to server."""
        while self.running:
            if not self.connected.wait(timeout=1):
                continue
            try:
                pkt = os.read(self.tun.fileno(), MTU + 100)
                seq = self.next_seq()
                enc = encrypt_packet(self.enc_key, pkt, seq)
                self.sock.sendto(enc, self.server_addr)
            except OSError as e:
                if self.running:
                    log.error(f"TUN read error: {e}")
                    time.sleep(0.1)

    def udp_to_tun(self):
        """Receive from server, decrypt, write to TUN."""
        while self.running:
            if not self.connected.wait(timeout=1):
                continue
            try:
                self.sock.settimeout(KEEPALIVE * 2)
                data, _ = self.sock.recvfrom(MTU + 200)
                self.sock.settimeout(None)

                if data == b"PONG\x00":
                    log.debug("Keepalive pong received")
                    continue

                pkt = decrypt_packet(self.enc_key, data)
                if pkt and self.tun:
                    os.write(self.tun.fileno(), pkt)

            except socket.timeout:
                log.warning("Server timeout, triggering reconnect...")
                self.connected.clear()
                self._reconnect()
            except OSError as e:
                if self.running:
                    log.error(f"UDP recv error: {e}")
                    time.sleep(0.1)

    def keepalive_loop(self):
        """Send periodic keepalives to maintain the session."""
        while self.running:
            if self.connected.is_set():
                try:
                    self.sock.sendto(b"PING\x00", self.server_addr)
                    log.debug("Keepalive ping sent")
                except Exception:
                    pass
            time.sleep(KEEPALIVE)

    # ── Connection Management ─────────────────────────────────────────────────

    def _connect(self) -> bool:
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2*1024*1024)
        self.seq_out = 0

        log.info(f"Connecting to {self.server_host}:{self.server_port}...")
        if not self.handshake():
            return False

        if self.tun is None:
            self.tun = create_tun(TUN_NAME, self.vpn_ip)
        else:
            # Reconfigure TUN with new IP
            os.system(f"ip addr flush dev {TUN_NAME} 2>/dev/null || true")
            os.system(f"ip addr add {self.vpn_ip}/24 dev {TUN_NAME}")

        self.setup_routing()
        self.connected.set()
        return True

    def _reconnect(self):
        log.info(f"Reconnecting in {RECONNECT_DELAY}s...")
        time.sleep(RECONNECT_DELAY)
        while self.running and not self._connect():
            log.warning(f"Reconnect failed, retrying in {RECONNECT_DELAY}s...")
            time.sleep(RECONNECT_DELAY)

    def run(self):
        if not self._connect():
            log.error("Initial connection failed.")
            sys.exit(1)

        threads = [
            threading.Thread(target=self.tun_to_udp,    daemon=True, name="tun→udp"),
            threading.Thread(target=self.udp_to_tun,    daemon=True, name="udp→tun"),
            threading.Thread(target=self.keepalive_loop, daemon=True, name="keepalive"),
        ]
        for t in threads:
            t.start()

        log.info(f"VPN connected. Your VPN IP: {self.vpn_ip}")
        log.info("Press Ctrl+C to disconnect.")

        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            log.info("Disconnecting...")
            self.running = False
            self.teardown_routing()
            os.system(f"ip link del {TUN_NAME} 2>/dev/null || true")
            log.info("Disconnected.")

# ─── Entry Point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Error: Must run as root (sudo python3 client.py)")
        sys.exit(1)

    parser = argparse.ArgumentParser(description="PyVPN Client")
    parser.add_argument("--server", required=True, help="VPN server IP or hostname")
    parser.add_argument("--port",   type=int, default=SERVER_PORT, help="Server port")
    parser.add_argument("--route-all", action="store_true",
                        help="Route ALL traffic through VPN (default: VPN subnet only)")
    args = parser.parse_args()

    VPNClient(args.server, args.port, args.route_all).run()
