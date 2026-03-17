# Network Packet Analyzer

A GUI-based network packet analyzer built using Python. This project captures and analyzes network packets in real-time and displays them in a structured format.

## Features
- Live packet capture using Scapy
- GUI interface using Tkinter
- Packet table (Source IP, Destination IP, Protocol, Length)
- Protocol counters (TCP, UDP, ICMP)
- Total packet count
- Packets per second (Packets/sec)
- Top Talker detection (most active IP)
- Clear screen functionality

## Technologies Used
- Python
- Scapy
- Tkinter

## How to Run

1. Install dependencies:
```
pip install scapy
```

2. Run the program:
```
python packet_analyzer_gui.py
```

3. Click **Start Capture** to begin monitoring packets.

## Project Structure

```
network-packet-analysis
│
├── packet_analyzer.py
├── packet_analyzer_gui.py
└── README.md
```

## Output (GUI)

The application displays:
- Real-time packet data
- Protocol statistics
- Packet rate
- Most active IP

## Author
Jolisha B



