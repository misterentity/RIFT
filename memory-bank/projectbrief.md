# Port Flooding Test Tool Project Brief

## Project Overview
A GUI-based network testing tool designed to help game developers evaluate their DDoS prevention mechanisms by generating controlled network traffic to specific ports.

## Core Requirements

### Functional Requirements
1. Generate controlled network traffic using multiple protocols:
   - UDP flooding
   - TCP flooding
   - SYN flooding (with Scapy)
   - Combined mode (all protocols)

2. User Interface
   - Graphical interface for all settings
   - Real-time test monitoring
   - Start/Stop functionality
   - Clear log capability

3. Configuration Options
   - Target IP address
   - Port range selection
   - Packet size control
   - Thread count management
   - Delay between packets
   - Protocol selection

### Technical Requirements
1. Cross-platform compatibility (Windows focus)
2. Real-time logging and monitoring
3. Thread-safe operations
4. Graceful error handling
5. Resource management
6. Network interface detection (for SYN flooding)

### Safety Requirements
1. Educational/testing purposes only
2. Input validation
3. Warning messages
4. User confirmation
5. Controlled traffic generation
6. System resource protection

## Project Goals
1. Provide a user-friendly interface for network testing
2. Enable controlled testing of game server DDoS prevention
3. Support multiple flooding protocols
4. Maintain safe and responsible testing practices
5. Offer real-time monitoring and control

## Success Criteria
1. Successfully generate traffic using all supported protocols
2. Maintain stable operation during extended tests
3. Provide clear feedback and logging
4. Handle errors gracefully
5. Support Windows network interfaces effectively

## Constraints
1. Educational use only
2. Local/authorized testing only
3. Resource usage limitations
4. Network interface dependencies (for SYN flooding)
5. Windows-specific considerations 