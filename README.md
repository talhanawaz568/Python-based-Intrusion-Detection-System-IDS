# Python-Based Intrusion Detection System (IDS)

This project is a simple packet sniffer and log collector built using Python and Scapy.

## Features
- Captures raw packets using Scapy
- Logs source/destination IP, ports, protocol
- Saves logs in JSON (`network_log.txt`) and CSV (`network_log.csv`)
- Detects and separates suspicious packets (ICMP, TCP SYN)

## How to Run
```bash
sudo python3 packet_sniffer.py
