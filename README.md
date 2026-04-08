# 🌐 Network Traffic Analyzer

A Python-based network traffic analyzer that captures
and analyzes live network traffic or existing Wireshark
.pcap files.

## Features
- Live packet capture on any network interface
- Protocol breakdown (TCP, UDP, ICMP)
- Top source IP tracking
- Saves report as JSON file
- Analyze existing Wireshark .pcap files

## Installation
pip install scapy

## How to Run

### Live Capture (requires sudo):
sudo python3 traffic_analyzer.py

### Analyze Wireshark .pcap file:
python3 analyze_pcap.py yourfile.pcap

## Example Output
![alt text](image.png)
<img width="753" height="348" alt="image" src="https://github.com/user-attachments/assets/ac1ad2bc-92f2-4532-a900-670a5c7527bc" />
For this example we tracking the packets of our local host, but obtaining many entries from local host is difficult so we run the command "ping 127.0.0.1 -c 10" as "ping" sends small data packets to an IP address to test connectivity. 
