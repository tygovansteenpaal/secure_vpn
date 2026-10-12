# PyVPN — Advanced Python VPN

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/platform-Linux-FCC624?logo=linux&logoColor=black)
![Encryption](https://img.shields.io/badge/encryption-AES--256--GCM-success)
![License](https://img.shields.io/badge/license-MIT-green)

A fully functional VPN built in Python using TUN interfaces and modern cryptography.

## Features

| Feature | Detail |
|---|---|
| **Encryption** | AES-256-GCM (authenticated encryption) |
| **Key Exchange** | X25519 ECDH (Elliptic Curve Diffie-Hellman) |
| **Key Derivation** | HKDF-SHA256 (64 bytes → enc + mac keys) |
| **Auth** | HMAC-SHA256 pre-shared key for handshake |
| **Replay Protection** | 256-packet sliding window |
| **Transport** | UDP (low latency) |
| **NAT** | iptables MASQUERADE (server-side) |
| **Keepalive** | PING/PONG every 15s, auto-reconnect |
| **IP Pool** | Dynamic IP assignment (10.8.0.2 – 10.8.0.254) |
| **Multi-client** | Up to 50 simultaneous clients |

---

## Requirements

- Linux (TUN/TAP support required — works on Ubuntu, Debian, CentOS, etc.)
- Python 3.10+
- Root privileges
- `iptables` installed (for NAT on server)

```bash
pip install -r requirements.txt
```

---

## Quick Start

### 1. On your SERVER machine

```bash
# Install dependencies
pip install cryptography

# (Optional but recommended) Change the PSK in server.py:
# PSK = b"your-secret-32-byte-key-here!!!!"

# Run the server
sudo python3 server.py
```

The server will:
- Create a `tun0` interface at `10.8.0.1`
- Enable IP forwarding
- Set up iptables NAT masquerade
- Listen for clients on UDP port 5194

### 2. On your CLIENT machine

```bash
# Install dependencies
pip install cryptography

# Change PSK in client.py to match server
# PSK = b"your-secret-32-byte-key-here!!!!"

# Connect (VPN subnet traffic only)
sudo python3 client.py --server YOUR_SERVER_IP

# OR: Route ALL traffic through VPN
sudo python3 client.py --server YOUR_SERVER_IP --route-all
```

---

## Security Architecture

```
CLIENT                          SERVER
  │                               │
  │  HELLO + HMAC(PSK, pub_key)   │
  │  + X25519 public key          │
  │──────────────────────────────►│
  │                               │  Verify HMAC
  │                               │  ECDH key exchange
  │                               │  Derive session key (HKDF)
  │                               │  Assign VPN IP
  │                               │
  │  HELO2 + server pub key       │
  │  + AES-GCM(assigned_ip)       │
  │◄──────────────────────────────│
  │                               │
  │  [Encrypted data packets]     │
  │  seq(8) + nonce(12) + ct+tag  │
  │◄─────────────────────────────►│
```

### Key Security Properties

- **Perfect Forward Secrecy**: New X25519 key pair generated per session
- **Authenticated Encryption**: AES-256-GCM provides both confidentiality and integrity
- **Replay Protection**: Sliding window rejects duplicate/old packets
- **Mutual Authentication**: PSK-HMAC prevents unauthorized clients
- **Session Isolation**: Each client gets unique derived keys

---

## Configuration

Edit the top of each file to adjust:

| Variable | server.py | client.py | Description |
|---|---|---|---|
| `PSK` | ✓ | ✓ | Pre-shared key (must match!) |
| `LISTEN_PORT` / `SERVER_PORT` | ✓ | ✓ | UDP port (default: 5194) |
| `TUN_ADDR` | ✓ | — | Server TUN IP (10.8.0.1) |
| `MTU` | ✓ | ✓ | Max packet size (1420) |
| `TIMEOUT_SEC` | ✓ | — | Client idle timeout (120s) |
| `KEEPALIVE` | — | ✓ | Ping interval (15s) |

---

## Firewall / Port Forwarding

On your server, allow UDP port 5194:

```bash
# ufw
sudo ufw allow 5194/udp

# iptables
sudo iptables -A INPUT -p udp --dport 5194 -j ACCEPT
```

If behind a NAT router, forward UDP 5194 to your server's local IP.

---

## Limitations & Notes

- **Linux only** — TUN/TAP is Linux-specific (macOS/Windows require different approaches)
- **No DNS leak protection** — configure `/etc/resolv.conf` or use `--route-all` with a DNS server on your VPN subnet
- **PSK must be kept secret** — this is your authentication layer
- **For production use**, consider certificate-based auth and key rotation

---

## Troubleshooting

**"No such file or directory: /dev/net/tun"**
```bash
sudo modprobe tun
```

**Packets not forwarding through server**
```bash
# Verify IP forwarding is enabled
cat /proc/sys/net/ipv4/ip_forward  # Should be 1

# Check iptables NAT rule
sudo iptables -t nat -L POSTROUTING -n -v
```

**Client can't reach internet through VPN**
```bash
# Check server has internet access
# Verify NAT rule is applied for VPN subnet (10.8.0.0/24)
```

---

## License

This project is [MIT](LICENSE) licensed.

## Author

**Tygo van Steenpaal** — [GitHub](https://github.com/tygovansteenpaal) · [LinkedIn](https://www.linkedin.com/in/tygo-van-steen-37715a3a9)
