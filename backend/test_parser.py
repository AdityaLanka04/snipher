#!/usr/bin/env python3
"""Test the packet parser"""
from scapy.all import IP, TCP, UDP, DNS, ICMP, ARP, Ether, Raw
from packet_parser import parse_packet
import json

def test_tcp_packet():
    """Test TCP packet parsing"""
    pkt = Ether()/IP(src="192.168.1.1", dst="192.168.1.2")/TCP(sport=12345, dport=80, flags="S")
    result = parse_packet(pkt)
    print("TCP Packet:")
    print(json.dumps(result, indent=2))
    assert result["protocol"] == "HTTP", f"Expected HTTP, got {result['protocol']}"
    print("✓ TCP test passed\n")

def test_http_packet():
    """Test HTTP packet parsing"""
    http_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    pkt = Ether()/IP(src="192.168.1.1", dst="192.168.1.2")/TCP(sport=12345, dport=80)/Raw(load=http_payload)
    result = parse_packet(pkt)
    print("HTTP Packet:")
    print(json.dumps(result, indent=2))
    assert result["protocol"] == "HTTP", f"Expected HTTP, got {result['protocol']}"
    assert "GET" in result["info"], f"Expected GET in info, got {result['info']}"
    print("✓ HTTP test passed\n")

def test_dns_packet():
    """Test DNS packet parsing"""
    from scapy.all import DNSQR
    pkt = Ether()/IP(src="192.168.1.1", dst="8.8.8.8")/UDP(sport=12345, dport=53)/DNS(qd=DNSQR(qname="example.com"))
    result = parse_packet(pkt)
    print("DNS Packet:")
    print(json.dumps(result, indent=2))
    assert result["protocol"] == "DNS", f"Expected DNS, got {result['protocol']}"
    print("✓ DNS test passed\n")

def test_icmp_packet():
    """Test ICMP packet parsing"""
    pkt = Ether()/IP(src="192.168.1.1", dst="8.8.8.8")/ICMP(type=8)
    result = parse_packet(pkt)
    print("ICMP Packet:")
    print(json.dumps(result, indent=2))
    assert result["protocol"] == "ICMP", f"Expected ICMP, got {result['protocol']}"
    print("✓ ICMP test passed\n")

def test_arp_packet():
    """Test ARP packet parsing"""
    pkt = Ether()/ARP(op=1, psrc="192.168.1.1", pdst="192.168.1.2")
    result = parse_packet(pkt)
    print("ARP Packet:")
    print(json.dumps(result, indent=2))
    assert result["protocol"] == "ARP", f"Expected ARP, got {result['protocol']}"
    print("✓ ARP test passed\n")

def test_https_packet():
    """Test HTTPS packet parsing"""
    pkt = Ether()/IP(src="192.168.1.1", dst="192.168.1.2")/TCP(sport=12345, dport=443, flags="PA")
    result = parse_packet(pkt)
    print("HTTPS Packet:")
    print(json.dumps(result, indent=2))
    assert result["protocol"] == "HTTPS", f"Expected HTTPS, got {result['protocol']}"
    print("✓ HTTPS test passed\n")

if __name__ == "__main__":
    print("Testing packet parser...\n")
    print("="*50)
    
    try:
        test_tcp_packet()
        test_http_packet()
        test_dns_packet()
        test_icmp_packet()
        test_arp_packet()
        test_https_packet()
        
        print("="*50)
        print("✓ All tests passed!")
    except AssertionError as e:
        print(f"\n✗ Test failed: {e}")
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
