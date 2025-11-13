# Mini Wireshark - Network Packet Analyzer

A modern, real-time network packet analyzer built with React and FastAPI. Capture, analyze, and inspect network traffic with a clean, Wireshark-inspired interface.

## Features

### Core Functionality
- **Real-time Packet Capture**: Live network traffic monitoring with WebSocket streaming
- **Protocol Analysis**: Deep inspection of TCP, UDP, HTTP, DNS, ICMP, ARP, and more
- **Multi-layer Parsing**: Ethernet, IP, Transport, and Application layer analysis

### Advanced Features
- **TCP Stream Reassembly**: Follow and reconstruct complete TCP conversations
- **Advanced Filtering**: Multi-criteria filtering (protocol, IP, port, packet size)
- **BPF Filtering**: Berkeley Packet Filter syntax for precise packet filtering
- **Connection Flow Analysis**: Visualize active connections and data flows
- **Traffic Timeline**: Real-time visualization of packet rates over time
- **Statistics Dashboard**: Protocol distribution, bandwidth usage, and metrics

### User Experience
- **Search & Filter**: Quick search across all packet fields
- **Detailed Inspection**: View packet details including headers and raw hex data
- **Export Capability**: Save as JSON or PCAP format for Wireshark compatibility
- **Interface Selection**: Choose from available network interfaces
- **Color-coded Protocols**: Easy visual identification of different protocols
- **Auto-scroll Control**: Toggle automatic scrolling for live captures
- **Packet Limit**: Configurable buffer to prevent memory issues

## Prerequisites

- Python 3.8+
- Node.js 18+
- Administrator/root privileges (required for packet capture)

## Installation

### Backend Setup

```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Frontend Setup

```bash
cd frontend
npm install
```

## Running the Application

### Start Backend (requires sudo/admin)

**Important**: Root/admin privileges are required for packet capture.

```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt

# Run with sudo (required for packet capture)
sudo venv/bin/python main.py

# Or with uvicorn:
sudo venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000
```

### Start Frontend

```bash
cd frontend
npm install
npm run dev
```

The application will be available at `http://localhost:3000`

### Quick Test

**Test the parser first:**
```bash
cd backend
python test_parser.py
```

**Then test live capture:**
1. Start the backend with sudo: `sudo venv/bin/python main.py`
2. Start the frontend: `cd frontend && npm run dev`
3. Open `http://localhost:3000` in your browser
4. Select a network interface (e.g., en0, eth0, wlan0)
5. Click "Start" to begin capturing
6. Generate traffic:
   - Open `http://example.com` to see HTTP/DNS traffic
   - Run `ping 8.8.8.8` to see ICMP packets
   - Run `curl http://httpbin.org/get` to see HTTP requests
7. You should see protocols like TCP, HTTP, DNS, ICMP, ARP

**Troubleshooting:**
- If you see only "Ethernet" or "Unknown": Check that you're running with sudo
- If no packets appear: Try a different network interface
- If HTTP not detected: Make sure you're visiting HTTP (not HTTPS) sites

## Usage

1. **Select Interface**: Choose your network interface from the dropdown (e.g., en0, eth0, wlan0)
2. **Set Filter** (optional): Use BPF syntax like `tcp port 80` or `udp`
3. **Start Capture**: Click the Play button to begin capturing packets
4. **View Packets**: Click any packet to see detailed information
5. **Advanced Filters**: Click "Advanced" to filter by protocol, IP, port, or packet size
6. **Follow TCP Stream**: Click "Follow" on TCP packets to see the full conversation
7. **View Statistics**: Toggle stats panel to see protocol distribution and traffic timeline
8. **Search**: Use the search box to filter displayed packets
9. **Export**: Save as JSON or PCAP format
10. **Stop Capture**: Click the Stop button when done

### Protocols Detected

The analyzer automatically detects and displays:
- **TCP/UDP**: Transport layer protocols
- **HTTP/HTTPS**: Web traffic (HTTP detected by payload inspection)
- **DNS**: Domain name queries and responses
- **SSH, FTP, SMTP**: Common services
- **MySQL, PostgreSQL, Redis, MongoDB**: Database protocols
- **ICMP**: Ping and network diagnostics
- **ARP**: Address resolution
- **And many more...**

## BPF Filter Examples

- `tcp port 80` - HTTP traffic
- `tcp port 443` - HTTPS traffic
- `udp port 53` - DNS queries
- `host 192.168.1.1` - Traffic to/from specific IP
- `net 192.168.0.0/24` - Traffic in subnet
- `icmp` - ICMP packets only

## Architecture

### Backend (FastAPI + Scapy)
- FastAPI for REST API and WebSocket support
- Scapy for packet capture and analysis
- Threading for non-blocking packet capture
- Queue-based packet processing

### Frontend (React + TypeScript)
- React 18 with TypeScript
- WebSocket for real-time updates
- Lucide React for icons
- Vite for fast development

## Security Notes

- This tool requires elevated privileges to capture packets
- Only use on networks you own or have permission to monitor
- Be aware of privacy and legal implications of packet capture
- Captured data may contain sensitive information

## Troubleshooting

**Permission Denied**: Run backend with sudo/administrator privileges

**No Interfaces Found**: Check that you have network interfaces available:
```bash
python -c "from scapy.arch import get_if_list; print(get_if_list())"
```

**WebSocket Connection Failed**: Ensure backend is running on port 8000

**Packets Not Appearing**: Try a different interface or check your filter syntax

## License

MIT License - Feel free to use and modify as needed.
# snipher
