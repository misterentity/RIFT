# Port Flooding Test Tool

A GUI-based network testing tool designed to help game developers evaluate their DDoS prevention mechanisms by generating controlled network traffic to specific ports.

## ⚠️ Important Notice

This tool is for **EDUCATIONAL PURPOSES ONLY**. Use it only on systems you own or have explicit permission to test. Unauthorized testing can be illegal and may result in serious consequences.

## Prerequisites

- Windows 10 or later
- Python 3.6 or later
- Administrator privileges (for SYN flooding)

## Quick Start (Windows)

1. Download or clone this repository
2. Double-click `start.bat`
3. Wait for setup to complete
4. The GUI will launch automatically

## Manual Installation

If you prefer to set up manually or are using a different operating system:

1. Install Python 3.6 or later from [python.org](https://python.org)

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   
   # Windows
   venv\Scripts\activate
   
   # Linux/Mac
   source venv/bin/activate
   ```

3. Install requirements:
   ```bash
   pip install -r requirements.txt
   ```

4. Start the GUI:
   ```bash
   python port_flood_test_gui.py
   ```

## Features

- Multiple flooding protocols:
  - UDP flooding
  - TCP flooding
  - SYN flooding (requires administrator privileges)
  - Combined mode

- User-friendly interface:
  - Easy configuration
  - Real-time monitoring
  - Start/Stop control
  - Clear logging

- Configuration options:
  - Target IP
  - Port range
  - Packet size
  - Thread count
  - Delay between packets

## Usage Guidelines

1. **Basic Testing**:
   - Use UDP/TCP modes for basic testing
   - Start with local testing (127.0.0.1)
   - Monitor system resources

2. **Advanced Testing (Administrator)**:
   - Right-click -> Run as Administrator for SYN flooding
   - Select network interface if prompted
   - Use appropriate thread count for your system

3. **Safety Measures**:
   - Start with minimal settings
   - Increase gradually as needed
   - Monitor target system response
   - Stop immediately if issues occur

## Troubleshooting

1. **SYN Flooding Issues**:
   - Ensure running as Administrator
   - Check Scapy installation
   - Verify network interface availability
   - Use UDP/TCP modes as fallback

2. **Performance Issues**:
   - Reduce thread count
   - Increase packet delay
   - Monitor system resources
   - Close unnecessary applications

3. **Installation Issues**:
   - Verify Python installation
   - Check error messages in console
   - Ensure all requirements are installed
   - Try manual installation steps

## Support

For issues, questions, or contributions:
1. Check the troubleshooting guide
2. Review error messages
3. Verify your setup matches requirements
4. Create detailed issue reports

## License

This project is for educational purposes only. Use responsibly and legally. 