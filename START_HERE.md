# 🚀 Quick Start Guide - Mini Wireshark

## Step 1: Start Backend (Terminal 1)

**Option A - Using Python directly:**
```bash
cd backend
sudo python run.py
```

**Option B - Using the shell script (Mac/Linux):**
```bash
cd backend
chmod +x start.sh
sudo ./start.sh
```

**Important**: You MUST use `sudo` for packet capture to work!

Wait until you see:
```
✅ Parser tests passed!
🌐 Starting FastAPI server...
INFO:     Uvicorn running on http://0.0.0.0:8000
```

## Step 2: Start Frontend (Terminal 2)

```bash
cd frontend
npm install  # Only needed first time
npm run dev
```

## Step 3: Open Browser

Open http://localhost:3000

## Step 4: Start Capturing

1. Select your network interface (e.g., `en0` for WiFi on Mac, `eth0` for Ethernet on Linux)
2. Click the **Play** button to start capturing
3. Generate some traffic:
   - Visit http://example.com (HTTP traffic)
   - Run `ping 8.8.8.8` (ICMP traffic)
   - Run `curl http://httpbin.org/get` (HTTP traffic)

## What You Should See

- **DNS** - Domain name lookups (port 53)
- **HTTP** - Web traffic on port 80
- **HTTPS** - Encrypted web traffic on port 443
- **TCP** - Generic TCP connections
- **ICMP** - Ping packets
- **ARP** - Address resolution

## Troubleshooting

### Backend shows "Unknown" packets
**Solution**: Restart the backend with `sudo ./start.sh`

### No packets appearing
**Solution**: 
1. Make sure you selected the correct network interface
2. Try a different interface from the dropdown
3. Check that backend is running with sudo

### Permission denied
**Solution**: Run backend with `sudo ./start.sh`

### Port already in use
**Solution**: 
```bash
# Kill existing process
sudo lsof -ti:8000 | xargs kill -9
# Then restart
sudo ./start.sh
```

## Features to Try

1. **Advanced Filters**: Click "Advanced" button to filter by protocol, IP, port, or size
2. **Follow TCP Stream**: Click "Follow" on any TCP packet to see the full conversation
3. **Statistics**: Toggle the stats panel to see protocol distribution and timeline
4. **Export**: Save packets as JSON or PCAP format
5. **Search**: Use the search box to find specific packets

## Need Help?

Check the full README.md for detailed documentation.
