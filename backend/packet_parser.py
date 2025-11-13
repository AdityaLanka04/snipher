"""Packet parsing module for Mini Wireshark"""
from scapy.all import IP, TCP, UDP, ICMP, ARP, DNS, Raw, Ether
from datetime import datetime
from typing import Dict

def parse_packet(packet) -> Dict:
    """Parse packet into JSON-serializable format"""
    packet_info = {
        "timestamp": datetime.now().isoformat(),
        "length": len(packet),
        "protocol": "Ethernet",
        "src": "N/A",
        "dst": "N/A",
        "src_port": None,
        "dst_port": None,
        "info": "Ethernet frame",
        "raw": "",
        "layers": [],
        "tcp_flags": None,
        "seq": None,
        "ack": None,
        "ttl": None,
        "src_mac": None,
        "dst_mac": None
    }
    
    # Ethernet Layer
    if packet.haslayer(Ether):
        packet_info["src_mac"] = packet[Ether].src
        packet_info["dst_mac"] = packet[Ether].dst
        packet_info["src"] = packet[Ether].src
        packet_info["dst"] = packet[Ether].dst
        packet_info["layers"].append("Ethernet")
    
    # ARP
    if packet.haslayer(ARP):
        packet_info["protocol"] = "ARP"
        packet_info["src"] = packet[ARP].psrc or packet[ARP].hwsrc
        packet_info["dst"] = packet[ARP].pdst or packet[ARP].hwdst
        op = packet[ARP].op
        if op == 1:
            packet_info["info"] = f"Who has {packet[ARP].pdst}? Tell {packet[ARP].psrc}"
        elif op == 2:
            packet_info["info"] = f"{packet[ARP].psrc} is at {packet[ARP].hwsrc}"
        packet_info["layers"].append("ARP")
        return packet_info
    
    # IP Layer
    if packet.haslayer(IP):
        packet_info["src"] = packet[IP].src
        packet_info["dst"] = packet[IP].dst
        packet_info["ttl"] = packet[IP].ttl
        packet_info["layers"].append("IPv4")
        
        # TCP
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            packet_info["src_port"] = src_port
            packet_info["dst_port"] = dst_port
            packet_info["src"] = f"{packet[IP].src}:{src_port}"
            packet_info["dst"] = f"{packet[IP].dst}:{dst_port}"
            
            # TCP Flags
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
            packet_info["layers"].append("TCP")
            
            # Detect application protocol
            detected_protocol = detect_tcp_protocol(packet, src_port, dst_port)
            packet_info["protocol"] = detected_protocol
            
            if detected_protocol == "HTTP" and packet.haslayer(Raw):
                packet_info["info"] = extract_http_info(packet)
            elif detected_protocol != "TCP":
                packet_info["info"] = f"{detected_protocol} {src_port} → {dst_port} [{flag_str.strip()}]"
                packet_info["layers"].append(detected_protocol)
            else:
                packet_info["info"] = f"{src_port} → {dst_port} [{flag_str.strip()}] Seq={packet[TCP].seq}"
        
        # UDP
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            packet_info["src_port"] = src_port
            packet_info["dst_port"] = dst_port
            packet_info["src"] = f"{packet[IP].src}:{src_port}"
            packet_info["dst"] = f"{packet[IP].dst}:{dst_port}"
            packet_info["layers"].append("UDP")
            
            # DNS
            if packet.haslayer(DNS):
                packet_info["protocol"] = "DNS"
                packet_info["layers"].append("DNS")
                dns_layer = packet[DNS]
                if dns_layer.qr == 0:
                    qname = dns_layer.qd.qname.decode() if dns_layer.qd else ""
                    packet_info["info"] = f"Query: {qname}"
                    packet_info["dns_query"] = qname
                else:
                    answers = []
                    if dns_layer.an:
                        for i in range(dns_layer.ancount):
                            if hasattr(dns_layer.an[i], 'rdata'):
                                answers.append(str(dns_layer.an[i].rdata))
                    packet_info["info"] = f"Response: {', '.join(answers) if answers else 'No answers'}"
                    packet_info["dns_answers"] = answers
            else:
                # Detect UDP protocol by port
                detected_protocol = detect_udp_protocol(src_port, dst_port)
                packet_info["protocol"] = detected_protocol
                packet_info["info"] = f"{detected_protocol} {src_port} → {dst_port}"
                if detected_protocol != "UDP":
                    packet_info["layers"].append(detected_protocol)
        
        # ICMP
        elif packet.haslayer(ICMP):
            packet_info["protocol"] = "ICMP"
            packet_info["layers"].append("ICMP")
            icmp_type = packet[ICMP].type
            icmp_code = packet[ICMP].code
            packet_info["icmp_type"] = icmp_type
            packet_info["icmp_code"] = icmp_code
            
            type_names = {
                0: "Echo Reply",
                3: "Destination Unreachable",
                8: "Echo Request",
                11: "Time Exceeded"
            }
            type_name = type_names.get(icmp_type, f"Type {icmp_type}")
            packet_info["info"] = f"{type_name} (Code {icmp_code})"
        
        else:
            # Other IP protocols
            proto_num = packet[IP].proto
            proto_names = {1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 89: "OSPF"}
            packet_info["protocol"] = proto_names.get(proto_num, f"IP-Proto-{proto_num}")
            packet_info["info"] = f"{packet_info['protocol']} packet"
            packet_info["layers"].append(packet_info["protocol"])
    
    # If still Ethernet (no higher layer detected), update info
    if packet_info["protocol"] == "Ethernet" and packet_info["layers"]:
        if len(packet_info["layers"]) == 1:
            packet_info["info"] = f"Ethernet frame ({packet_info['length']} bytes)"
    
    # Raw data
    if packet.haslayer(Raw):
        raw_data = bytes(packet[Raw].load)
        hex_str = raw_data[:256].hex()
        packet_info["raw"] = ' '.join([hex_str[i:i+2] for i in range(0, len(hex_str), 2)])
    
    return packet_info

def detect_tcp_protocol(packet, src_port, dst_port):
    """Detect TCP application protocol"""
    # Check payload for HTTP
    if packet.haslayer(Raw):
        try:
            payload = bytes(packet[Raw].load)
            payload_str = payload[:200].decode('utf-8', errors='ignore')
            
            http_methods = ['GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ', 'PATCH ', 'CONNECT ', 'TRACE ']
            if any(payload_str.startswith(method) for method in http_methods):
                return "HTTP"
            if payload_str.startswith('HTTP/'):
                return "HTTP"
            # Check for TLS/SSL handshake
            if len(payload) > 0 and payload[0] == 0x16:  # TLS handshake
                return "TLS"
        except:
            pass
    
    # Comprehensive port mapping
    port_map = {
        # Web protocols
        80: "HTTP", 443: "HTTPS", 8080: "HTTP", 8000: "HTTP", 8888: "HTTP",
        8443: "HTTPS", 9000: "HTTP", 3000: "HTTP", 5000: "HTTP",
        
        # Secure shell and file transfer
        22: "SSH", 21: "FTP", 20: "FTP-Data", 69: "TFTP", 115: "SFTP",
        989: "FTPS-Data", 990: "FTPS",
        
        # Email protocols
        25: "SMTP", 465: "SMTPS", 587: "SMTP", 110: "POP3", 995: "POP3S",
        143: "IMAP", 993: "IMAPS",
        
        # Databases
        3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB",
        1433: "MSSQL", 1521: "Oracle", 5984: "CouchDB", 9042: "Cassandra",
        7000: "Cassandra", 7001: "Cassandra", 9200: "Elasticsearch", 9300: "Elasticsearch",
        
        # Message queues
        5672: "AMQP", 5671: "AMQPS", 61616: "ActiveMQ", 9092: "Kafka",
        4222: "NATS", 6650: "Pulsar",
        
        # Remote access
        23: "Telnet", 3389: "RDP", 5900: "VNC", 5901: "VNC",
        
        # Proxy and tunneling
        1080: "SOCKS", 3128: "Squid", 8118: "Privoxy",
        
        # Application servers
        8009: "AJP", 8161: "ActiveMQ", 9090: "WebSocket",
        
        # Monitoring and management
        161: "SNMP", 162: "SNMP-Trap", 10050: "Zabbix", 10051: "Zabbix",
        
        # Version control
        9418: "Git", 3690: "SVN",
        
        # Gaming and streaming
        27015: "Steam", 25565: "Minecraft", 1935: "RTMP",
        
        # Other common services
        445: "SMB", 139: "NetBIOS", 135: "MSRPC", 389: "LDAP", 636: "LDAPS",
        88: "Kerberos", 53: "DNS-TCP", 179: "BGP", 502: "Modbus", 1883: "MQTT",
        8883: "MQTTS", 5060: "SIP", 5061: "SIPS"
    }
    
    return port_map.get(dst_port) or port_map.get(src_port) or "TCP"

def detect_udp_protocol(src_port, dst_port):
    """Detect UDP application protocol"""
    port_map = {
        # DNS and discovery
        53: "DNS", 5353: "mDNS", 5355: "LLMNR", 137: "NetBIOS-NS",
        
        # Network services
        67: "DHCP", 68: "DHCP", 69: "TFTP",
        
        # Time and logging
        123: "NTP", 514: "Syslog",
        
        # Management
        161: "SNMP", 162: "SNMP-Trap", 
        
        # Discovery and streaming
        1900: "SSDP", 5004: "RTP", 5005: "RTCP",
        
        # VPN and tunneling
        500: "IKE", 4500: "IPSec-NAT", 1194: "OpenVPN",
        
        # Gaming and voice
        3074: "Xbox", 3478: "STUN", 3479: "STUN", 5060: "SIP",
        
        # Other
        520: "RIP", 1812: "RADIUS", 1813: "RADIUS-Acct"
    }
    
    return port_map.get(dst_port) or port_map.get(src_port) or "UDP" 

def extract_http_info(packet):
    """Extract HTTP request/response info"""
    try:
        payload = bytes(packet[Raw].load)
        payload_str = payload[:300].decode('utf-8', errors='ignore')
        lines = payload_str.split('\r\n')
        if lines:
            return f"HTTP: {lines[0][:100]}"
    except:
        pass
    return "HTTP packet"

# Stable IP to country mapping cache
_ip_country_cache = {}

def get_stable_country(ip: str) -> str:
    """Get stable country for IP address based on hash"""
    if ip in _ip_country_cache:
        return _ip_country_cache[ip]
    
    # Generate stable hash from IP
    hash_value = 0
    for char in ip:
        hash_value = ((hash_value << 5) - hash_value) + ord(char)
        hash_value = hash_value & 0xFFFFFFFF  # Keep as 32-bit
    
    countries = [
        'US', 'DE', 'JP', 'GB', 'CA', 'AU', 'FR', 'NL', 'SG', 'BR',
        'KR', 'IN', 'SE', 'CH', 'NO', 'DK', 'FI', 'IT', 'ES', 'AT'
    ]
    
    country = countries[abs(hash_value) % len(countries)]
    _ip_country_cache[ip] = country
    return country