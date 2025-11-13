# 🔧 Troubleshooting Guide

## Problem: Still seeing "Unknown" or "Ethernet" packets

### Solution 1: Restart Backend
The backend must be restarted after code changes:

```bash
# Stop current backend (Ctrl+C)
# Then restart:
cd backend
sudo python run.py
```

### Solution 2: Select the Right Interface
- **en0** - Usually your main WiFi/Ethernet (try this first!)
- **lo0** - Loopback (only shows local traffic)
- **awdl0** - Apple Wireless Direct Link
- **bridge0** - Virtual bridge

**Recommendation**: Try **en0** first, it's your main network interface.

### Solution 3: Generate Traffic
The analyzer only shows packets when there's traffic:

```bash
# In a new terminal, generate traffic:
ping 8.8.8.8                    # ICMP packets
curl http://example.com         # HTTP + DNS
curl http://httpbin.org/get     # HTTP
```

## Problem: No packets appearing

### Check 1: Backend Running?
You should see:
```
INFO:     Uvicorn running on http://0.0.0.0:8000
```

### Check 2: Using sudo?
Packet capture REQUIRES sudo:
```bash
sudo python run.py  # ✓ Correct
python run.py       # ✗ Won't work
```

### Check 3: Frontend connected?
Open browser console (F12) and check for errors.

## Problem: Only seeing TCP, not HTTP

### This is NORMAL for HTTPS!
- **HTTPS (port 443)** = Encrypted, shows as "HTTPS" or "TLS"
- **HTTP (port 80)** = Unencrypted, shows as "HTTP" with request details

Most modern websites use HTTPS, so you'll see:
- ✓ DNS queries (resolving domain names)
- ✓ TCP handshakes (SYN, SYN-ACK, ACK)
- ✓ TLS/HTTPS (encrypted data)

To see actual HTTP:
```bash
curl http://example.com      # HTTP (port 80)
curl http://httpbin.org/get  # HTTP API
```

## Protocols You Should See

### Common Protocols:
- **DNS** (port 53) - Every website visit starts with DNS
- **HTTP** (port 80) - Unencrypted web traffic
- **HTTPS** (port 443) - Encrypted web traffic
- **TCP** - Generic TCP connections
- **ICMP** - Ping responses
- **ARP** - Address resolution

### When Browsing Websites:
1. **DNS Query** - "What's the IP of google.com?"
2. **DNS Response** - "It's 142.250.185.46"
3. **TCP SYN** - Start connection
4. **TCP SYN-ACK** - Server responds
5. **TCP ACK** - Connection established
6. **TLS/HTTPS** - Encrypted data transfer

### Generate Specific Traffic:

```bash
# HTTP traffic
curl http://example.com
curl http://neverssl.com

# DNS queries
nslookup google.com
dig example.com

# ICMP (ping)
ping 8.8.8.8

# HTTPS (will show as TLS/HTTPS)
curl https://google.com
```

## Supported Protocols (100+)

### Web:
HTTP, HTTPS, WebSocket, HTTP-Alt (8080, 8000, 8888)

### Email:
SMTP, SMTPS, POP3, POP3S, IMAP, IMAPS

### Databases:
MySQL, PostgreSQL, MongoDB, Redis, MSSQL, Oracle, Cassandra, Elasticsearch, CouchDB

### File Transfer:
FTP, FTPS, SFTP, TFTP

### Remote Access:
SSH, Telnet, RDP, VNC

### Message Queues:
AMQP, Kafka, ActiveMQ, NATS, Pulsar

### Network:
DNS, DHCP, NTP, SNMP, Syslog, mDNS, LLMNR, SSDP

### Security:
TLS, IPSec, IKE, Kerberos, LDAP, LDAPS

### VPN:
OpenVPN, IPSec-NAT

### And many more...

## Still Having Issues?

1. **Check backend logs** - Look for errors in the terminal
2. **Check browser console** - Press F12 and look for errors
3. **Verify parser works** - Run `python backend/test_parser.py`
4. **Try different interface** - Some interfaces don't capture all traffic
5. **Check permissions** - Make sure you're using `sudo`

## Quick Verification

Run this to verify everything works:

```bash
# Terminal 1: Start backend
cd backend
sudo python run.py

# Terminal 2: Generate traffic
ping -c 5 8.8.8.8
curl http://example.com

# You should see ICMP and HTTP/DNS packets!
```
