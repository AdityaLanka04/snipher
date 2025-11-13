from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS, Raw, Ether, wrpcap
from scapy.layers.http import HTTPRequest, HTTPResponse
import asyncio
import json
from datetime import datetime
from typing import List, Dict, Optional
import threading
import queue
import logging
import tempfile
import os
from packet_parser import parse_packet

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Mini Wireshark API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

packet_queue = queue.Queue()
capture_active = False
capture_thread = None
captured_packets_raw = []  # Store raw scapy packets for PCAP export

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except:
                pass

manager = ConnectionManager()

def parse_packet_old(packet) -> Dict:
    """Parse packet into JSON-serializable format with comprehensive protocol detection"""
    try:
        from scapy.layers.inet6 import IPv6, ICMPv6ND_NS, ICMPv6ND_NA
        from scapy.layers.l2 import LLC, SNAP, STP
        from scapy.layers.dhcp import DHCP, BOOTP
        from scapy.layers.ntp import NTP
    except ImportError:
        pass
    
    packet_info = {
        "timestamp": datetime.now().isoformat(),
        "length": len(packet),
        "protocol": "Ethernet",
        "src": "N/A",
        "dst": "N/A",
        "src_port": None,
        "dst_port": None,
        "info": "",
        "raw": "",
        "layers": []
    }
    
    # Get MAC addresses from Ethernet layer
    if packet.haslayer(Ether):
        packet_info["src_mac"] = packet[Ether].src
        packet_info["dst_mac"] = packet[Ether].dst
        packet_info["src"] = packet[Ether].src
        packet_info["dst"] = packet[Ether].dst
        packet_info["layers"].append("Ethernet")
        packet_info["info"] = f"Ethernet frame"
    
    # Layer 2 - ARP
    if packet.haslayer(ARP):
        packet_info["protocol"] = "ARP"
        packet_info["src"] = packet[ARP].psrc if packet[ARP].psrc else packet[ARP].hwsrc
        packet_info["dst"] = packet[ARP].pdst if packet[ARP].pdst else packet[ARP].hwdst
        op = packet[ARP].op
        if op == 1:
            packet_info["info"] = f"Who has {packet[ARP].pdst}? Tell {packet[ARP].psrc}"
        elif op == 2:
            packet_info["info"] = f"{packet[ARP].psrc} is at {packet[ARP].hwsrc}"
        else:
            packet_info["info"] = f"ARP operation {op}"
        packet_info["layers"].append("ARP")
        return packet_info
    
    # Layer 2 - LLC/SNAP
    if packet.haslayer(LLC):
        packet_info["protocol"] = "LLC"
        packet_info["info"] = "Logical Link Control"
        packet_info["layers"].append("LLC")
    
    if packet.haslayer(SNAP):
        packet_info["protocol"] = "SNAP"
        packet_info["info"] = "Subnetwork Access Protocol"
        packet_info["layers"].append("SNAP")
    
    # Layer 2 - STP
    if packet.haslayer(STP):
        packet_info["protocol"] = "STP"
        packet_info["info"] = "Spanning Tree Protocol"
        packet_info["layers"].append("STP")
        return packet_info
    
    # Layer 3 - IPv6
    if packet.haslayer(IPv6):
        packet_info["src"] = packet[IPv6].src
        packet_info["dst"] = packet[IPv6].dst
        packet_info["protocol"] = "IPv6"
        packet_info["layers"].append("IPv6")
        packet_info["info"] = f"IPv6 {packet[IPv6].src} → {packet[IPv6].dst}"
        
        # ICMPv6
        if packet.haslayer(ICMPv6ND_NS):
            packet_info["protocol"] = "ICMPv6"
            packet_info["info"] = "Neighbor Solicitation"
            packet_info["layers"].append("ICMPv6")
        elif packet.haslayer(ICMPv6ND_NA):
            packet_info["protocol"] = "ICMPv6"
            packet_info["info"] = "Neighbor Advertisement"
            packet_info["layers"].append("ICMPv6")
        
        # Check for TCP/UDP over IPv6
        if packet.haslayer(TCP):
            packet_info["protocol"] = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            packet_info["src_port"] = src_port
            packet_info["dst_port"] = dst_port
            packet_info["src"] = f"[{packet[IPv6].src}]:{src_port}"
            packet_info["dst"] = f"[{packet[IPv6].dst}]:{dst_port}"
            
            flags = packet[TCP].flags
            flag_str = ""
            if flags & 0x02: flag_str += "SYN "
            if flags & 0x10: flag_str += "ACK "
            if flags & 0x01: flag_str += "FIN "
            if flags & 0x04: flag_str += "RST "
            if flags & 0x08: flag_str += "PSH "
            
            packet_info["tcp_flags"] = flag_str.strip()
            packet_info["seq"] = packet[TCP].seq
            packet_info["ack"] = packet[TCP].ack
            packet_info["info"] = f"{src_port} → {dst_port} [{flag_str.strip()}]"
            packet_info["layers"].append("TCP")
        
        elif packet.haslayer(UDP):
            packet_info["protocol"] = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            packet_info["src_port"] = src_port
            packet_info["dst_port"] = dst_port
            packet_info["src"] = f"[{packet[IPv6].src}]:{src_port}"
            packet_info["dst"] = f"[{packet[IPv6].dst}]:{dst_port}"
            packet_info["info"] = f"{src_port} → {dst_port}"
            packet_info["layers"].append("UDP")
        
        return packet_info
    
    # Layer 3 - IPv4
    if packet.haslayer(IP):
        packet_info["src"] = packet[IP].src
        packet_info["dst"] = packet[IP].dst
        packet_info["ttl"] = packet[IP].ttl
        packet_info["layers"].append("IPv4")
        
        # Layer 4 - TCP
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            packet_info["src_port"] = src_port
            packet_info["dst_port"] = dst_port
            packet_info["src"] = f"{packet[IP].src}:{src_port}"
            packet_info["dst"] = f"{packet[IP].dst}:{dst_port}"
            
            flags = packet[TCP].flags
            flag_str = ""
            if flags & 0x02: flag_str += "SYN "
            if flags & 0x10: flag_str += "ACK "
            if flags & 0x01: flag_str += "FIN "
            if flags & 0x04: flag_str += "RST "
            if flags & 0x08: flag_str += "PSH "
            if flags & 0x20: flag_str += "URG "
            
            packet_info["tcp_flags"] = flag_str.strip()
            packet_info["seq"] = packet[TCP].seq
            packet_info["ack"] = packet[TCP].ack
            
            # Default to TCP
            packet_info["protocol"] = "TCP"
            packet_info["info"] = f"{src_port} → {dst_port} [{flag_str.strip()}] Seq={packet[TCP].seq} Ack={packet[TCP].ack}"
            packet_info["layers"].append("TCP")
            
            # Detect application layer protocol
            app_protocol = None
            
            # First, check for HTTP in payload (most accurate)
            if packet.haslayer(Raw):
                try:
                    payload = bytes(packet[Raw].load)
                    payload_str = payload[:200].decode('utf-8', errors='ignore')
                    
                    # Check for HTTP methods
                    http_methods = ['GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ', 'PATCH ', 'CONNECT ', 'TRACE ']
                    if any(payload_str.startswith(method) for method in http_methods):
                        app_protocol = "HTTP"
                        # Extract request line
                        lines = payload_str.split('\r\n')
                        if lines:
                            packet_info["info"] = f"HTTP Request: {lines[0][:80]}"
                            # Try to extract host
                            for line in lines[1:]:
                                if line.lower().startswith('host:'):
                                    host = line.split(':', 1)[1].strip()
                                    packet_info["http_host"] = host
                                    break
                    
                    # Check for HTTP response
                    elif payload_str.startswith('HTTP/'):
                        app_protocol = "HTTP"
                        lines = payload_str.split('\r\n')
                        if lines:
                            packet_info["info"] = f"HTTP Response: {lines[0][:80]}"
                except:
                    pass
            
            # If not detected by payload, check by port
            if not app_protocol:
                if dst_port == 80 or src_port == 80:
                    app_protocol = "HTTP"
                    packet_info["info"] = f"HTTP {src_port} → {dst_port} [{flag_str.strip()}]"
                elif dst_port == 443 or src_port == 443:
                    app_protocol = "HTTPS"
                    packet_info["info"] = f"HTTPS {src_port} → {dst_port} [{flag_str.strip()}]"
                elif dst_port == 8080 or src_port == 8080 or dst_port == 8000 or src_port == 8000 or dst_port == 8888 or src_port == 8888:
                    app_protocol = "HTTP"
                    packet_info["info"] = f"HTTP-Alt {src_port} → {dst_port} [{flag_str.strip()}]"
                elif dst_port == 22 or src_port == 22:
                    app_protocol = "SSH"
                    packet_info["info"] = f"SSH {src_port} → {dst_port} [{flag_str.strip()}]"
                elif dst_port == 21 or src_port == 21 or dst_port == 20 or src_port == 20:
                    app_protocol = "FTP"
                    packet_info["info"] = f"FTP {src_port} → {dst_port} [{flag_str.strip()}]"
                elif dst_port == 25 or src_port == 25:
                    app_protocol = "SMTP"
                    packet_info["info"] = f"SMTP {src_port} → {dst_port} [{flag_str.strip()}]"
                elif dst_port == 110 or src_port == 110:
                    app_protocol = "POP3"
                    packet_info["info"] = f"POP3 {src_port} → {dst_port} [{flag_str.strip()}]"
                elif dst_port == 143 or src_port == 143:
                    app_protocol = "IMAP"
                    packet_info["info"] = f"IMAP {src_port} → {dst_port} [{flag_str.strip()}]"
                elif dst_port == 3306 or src_port == 3306:
                    app_protocol = "MySQL"
                    packet_info["info"] = f"MySQL {src_port} → {dst_port} [{flag_str.strip()}]"
                elif dst_port == 5432 or src_port == 5432:
                    app_protocol = "PostgreSQL"
                    packet_info["info"] = f"PostgreSQL {src_port} → {dst_port} [{flag_str.strip()}]"
                elif dst_port == 6379 or src_port == 6379:
                    app_protocol = "Redis"
                    packet_info["info"] = f"Redis {src_port} → {dst_port} [{flag_str.strip()}]"
                elif dst_port == 27017 or src_port == 27017:
                    app_protocol = "MongoDB"
                    packet_info["info"] = f"MongoDB {src_port} → {dst_port} [{flag_str.strip()}]"
                elif dst_port == 5672 or src_port == 5672:
                    app_protocol = "AMQP"
                    packet_info["info"] = f"AMQP {src_port} → {dst_port} [{flag_str.strip()}]"
                elif dst_port == 9200 or src_port == 9200:
                    app_protocol = "Elasticsearch"
                    packet_info["info"] = f"Elasticsearch {src_port} → {dst_port} [{flag_str.strip()}]"
            
            # Set the protocol and add to layers
            if app_protocol:
                packet_info["protocol"] = app_protocol
                packet_info["layers"].append(app_protocol)
        
        # Layer 4 - UDP
        elif packet.haslayer(UDP):
            packet_info["protocol"] = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            packet_info["src_port"] = src_port
            packet_info["dst_port"] = dst_port
            packet_info["src"] = f"{packet[IP].src}:{src_port}"
            packet_info["dst"] = f"{packet[IP].dst}:{dst_port}"
            packet_info["info"] = f"{src_port} → {dst_port} Len={len(packet[UDP])}"
            packet_info["layers"].append("UDP")
            
            # DNS
            if packet.haslayer(DNS):
                packet_info["protocol"] = "DNS"
                dns_layer = packet[DNS]
                if dns_layer.qr == 0:  # Query
                    qname = dns_layer.qd.qname.decode() if dns_layer.qd else ""
                    packet_info["info"] = f"Query: {qname}"
                    packet_info["dns_query"] = qname
                else:  # Response
                    answers = []
                    if dns_layer.an:
                        for i in range(dns_layer.ancount):
                            if hasattr(dns_layer.an[i], 'rdata'):
                                answers.append(str(dns_layer.an[i].rdata))
                    packet_info["info"] = f"Response: {', '.join(answers) if answers else 'No answers'}"
                    packet_info["dns_answers"] = answers
                packet_info["layers"].append("DNS")
            
            # DHCP
            elif packet.haslayer(DHCP):
                packet_info["protocol"] = "DHCP"
                packet_info["info"] = "DHCP"
                packet_info["layers"].append("DHCP")
            
            elif packet.haslayer(BOOTP):
                packet_info["protocol"] = "BOOTP"
                packet_info["info"] = "Bootstrap Protocol"
                packet_info["layers"].append("BOOTP")
            
            # NTP
            elif packet.haslayer(NTP):
                packet_info["protocol"] = "NTP"
                packet_info["info"] = "Network Time Protocol"
                packet_info["layers"].append("NTP")
            
            # Detect by port if not already detected
            if packet_info["protocol"] == "UDP":
                if dst_port == 123 or src_port == 123:
                    packet_info["protocol"] = "NTP"
                    packet_info["info"] = f"NTP {src_port} → {dst_port}"
                    packet_info["layers"].append("NTP")
                elif dst_port == 161 or src_port == 161 or dst_port == 162 or src_port == 162:
                    packet_info["protocol"] = "SNMP"
                    packet_info["info"] = f"SNMP {src_port} → {dst_port}"
                    packet_info["layers"].append("SNMP")
                elif dst_port == 514 or src_port == 514:
                    packet_info["protocol"] = "Syslog"
                    packet_info["info"] = f"Syslog {src_port} → {dst_port}"
                    packet_info["layers"].append("Syslog")
                elif dst_port == 67 or dst_port == 68 or src_port == 67 or src_port == 68:
                    packet_info["protocol"] = "DHCP"
                    packet_info["info"] = f"DHCP {src_port} → {dst_port}"
                    packet_info["layers"].append("DHCP")
                elif dst_port == 5353 or src_port == 5353:
                    packet_info["protocol"] = "mDNS"
                    packet_info["info"] = f"mDNS {src_port} → {dst_port}"
                    packet_info["layers"].append("mDNS")
                elif dst_port == 1900 or src_port == 1900:
                    packet_info["protocol"] = "SSDP"
                    packet_info["info"] = f"SSDP {src_port} → {dst_port}"
                    packet_info["layers"].append("SSDP")
        
        # ICMP
        elif packet.haslayer(ICMP):
            packet_info["protocol"] = "ICMP"
            icmp_type = packet[ICMP].type
            icmp_code = packet[ICMP].code
            
            type_names = {
                0: "Echo Reply",
                3: "Destination Unreachable",
                4: "Source Quench",
                5: "Redirect",
                8: "Echo Request",
                11: "Time Exceeded",
                12: "Parameter Problem",
                13: "Timestamp Request",
                14: "Timestamp Reply"
            }
            type_name = type_names.get(icmp_type, f"Type {icmp_type}")
            packet_info["info"] = f"{type_name} (Code {icmp_code})"
            packet_info["icmp_type"] = icmp_type
            packet_info["icmp_code"] = icmp_code
            packet_info["layers"].append("ICMP")
        
        # Other IP protocols
        else:
            proto_num = packet[IP].proto
            proto_names = {
                1: "ICMP",
                2: "IGMP",
                6: "TCP",
                17: "UDP",
                41: "IPv6",
                47: "GRE",
                50: "ESP",
                51: "AH",
                89: "OSPF",
                132: "SCTP"
            }
            packet_info["protocol"] = proto_names.get(proto_num, f"IP Protocol {proto_num}")
            packet_info["info"] = f"{packet_info['protocol']} packet"
            packet_info["layers"].append(packet_info["protocol"])
    
    # Raw data preview (hex dump)
    if packet.haslayer(Raw):
        raw_data = bytes(packet[Raw].load)
        hex_str = raw_data[:256].hex()
        # Format as hex dump
        formatted_hex = ' '.join([hex_str[i:i+2] for i in range(0, len(hex_str), 2)])
        packet_info["raw"] = formatted_hex
    
    return packet_info

def packet_callback(packet):
    """Callback for each captured packet"""
    try:
        packet_info = parse_packet(packet)
        logger.debug(f"Parsed packet: {packet_info['protocol']} - {packet_info['info']}")
        packet_queue.put(packet_info)
        
        # Store raw packet for PCAP export (limit to last 1000)
        global captured_packets_raw
        captured_packets_raw.append(packet)
        if len(captured_packets_raw) > 1000:
            captured_packets_raw.pop(0)
    except Exception as e:
        logger.error(f"Error parsing packet: {e}", exc_info=True)

def capture_packets(interface=None, packet_filter=None):
    """Capture packets in a separate thread"""
    global capture_active
    try:
        sniff(
            iface=interface,
            prn=packet_callback,
            filter=packet_filter,
            store=False,
            stop_filter=lambda x: not capture_active
        )
    except Exception as e:
        print(f"Capture error: {e}")
        capture_active = False

@app.get("/")
async def root():
    return {"message": "Mini Wireshark API", "status": "running"}

@app.get("/interfaces")
async def get_interfaces():
    """Get available network interfaces"""
    from scapy.arch import get_if_list
    interfaces = get_if_list()
    return {"interfaces": interfaces}

@app.post("/capture/start")
async def start_capture(interface: Optional[str] = None, filter: Optional[str] = None):
    """Start packet capture"""
    global capture_active, capture_thread
    
    if capture_active:
        return {"status": "error", "message": "Capture already running"}
    
    try:
        capture_active = True
        capture_thread = threading.Thread(
            target=capture_packets,
            args=(interface, filter),
            daemon=True
        )
        capture_thread.start()
        logger.info(f"Capture started on interface: {interface or 'default'}")
        return {"status": "success", "message": "Capture started", "interface": interface}
    except Exception as e:
        capture_active = False
        logger.error(f"Failed to start capture: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/capture/stop")
async def stop_capture():
    """Stop packet capture"""
    global capture_active
    capture_active = False
    logger.info("Capture stopped")
    return {"status": "success", "message": "Capture stopped", "packets_captured": packet_queue.qsize()}

@app.get("/capture/status")
async def capture_status():
    """Get capture status"""
    return {
        "active": capture_active,
        "queue_size": packet_queue.qsize()
    }

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time packet streaming"""
    await manager.connect(websocket)
    try:
        # Send packets from queue
        while True:
            try:
                # Non-blocking queue check
                packet = packet_queue.get_nowait()
                await manager.broadcast(packet)
            except queue.Empty:
                await asyncio.sleep(0.1)
            
            # Keep connection alive
            try:
                await asyncio.wait_for(websocket.receive_text(), timeout=0.1)
            except asyncio.TimeoutError:
                pass
                
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        print(f"WebSocket error: {e}")
        manager.disconnect(websocket)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

@app.post("/export/pcap")
async def export_pcap():
    """Export captured packets as PCAP file"""
    global captured_packets_raw
    
    if not captured_packets_raw:
        raise HTTPException(status_code=400, detail="No packets to export")
    
    try:
        # Create temporary file
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pcap')
        temp_path = temp_file.name
        temp_file.close()
        
        # Write packets to PCAP
        wrpcap(temp_path, captured_packets_raw)
        
        # Return file
        return FileResponse(
            temp_path,
            media_type='application/vnd.tcpdump.pcap',
            filename=f'capture_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pcap',
            background=lambda: os.unlink(temp_path)
        )
    except Exception as e:
        logger.error(f"Failed to export PCAP: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/statistics")
async def get_statistics():
    """Get capture statistics"""
    global captured_packets_raw
    
    protocol_counts = {}
    total_bytes = 0
    
    for packet in captured_packets_raw:
        if packet.haslayer(IP):
            if packet.haslayer(TCP):
                protocol = "TCP"
            elif packet.haslayer(UDP):
                protocol = "UDP"
            elif packet.haslayer(ICMP):
                protocol = "ICMP"
            else:
                protocol = "Other"
        elif packet.haslayer(ARP):
            protocol = "ARP"
        else:
            protocol = "Other"
        
        protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1
        total_bytes += len(packet)
    
    return {
        "total_packets": len(captured_packets_raw),
        "total_bytes": total_bytes,
        "protocol_distribution": protocol_counts,
        "capture_active": capture_active
    }

# TCP Stream reassembly
tcp_streams = {}

@app.get("/stream/{stream_id}")
async def get_tcp_stream(stream_id: str):
    """Get reassembled TCP stream data"""
    try:
        # Parse stream_id (format: src_ip:port-dst_ip:port)
        parts = stream_id.split('-')
        if len(parts) != 2:
            raise HTTPException(status_code=400, detail="Invalid stream ID")
        
        src = parts[0]
        dst = parts[1]
        
        # Find matching packets
        client_data = []
        server_data = []
        packet_count = 0
        total_bytes = 0
        
        for packet in captured_packets_raw:
            if packet.haslayer(TCP) and packet.haslayer(IP):
                pkt_src = f"{packet[IP].src}:{packet[TCP].sport}"
                pkt_dst = f"{packet[IP].dst}:{packet[TCP].dport}"
                
                if pkt_src == src and pkt_dst == dst:
                    if packet.haslayer(Raw):
                        data = bytes(packet[Raw].load)
                        client_data.append(data)
                        total_bytes += len(data)
                    packet_count += 1
                elif pkt_src == dst and pkt_dst == src:
                    if packet.haslayer(Raw):
                        data = bytes(packet[Raw].load)
                        server_data.append(data)
                        total_bytes += len(data)
                    packet_count += 1
        
        # Combine data
        client_combined = b''.join(client_data)
        server_combined = b''.join(server_data)
        
        # Try to decode as ASCII, fallback to hex
        try:
            client_str = client_combined.decode('utf-8', errors='replace')
        except:
            client_str = client_combined.hex()
        
        try:
            server_str = server_combined.decode('utf-8', errors='replace')
        except:
            server_str = server_combined.hex()
        
        return {
            "stream_id": stream_id,
            "client_to_server": client_str,
            "server_to_client": server_str,
            "packets": packet_count,
            "bytes": total_bytes
        }
    except Exception as e:
        logger.error(f"Failed to get stream: {e}")
        raise HTTPException(status_code=500, detail=str(e))
