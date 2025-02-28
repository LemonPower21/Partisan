# Scapy Packet Sniffer

This Python script captures and analyzes network packets using the Scapy library. It provides detailed information about IP, TCP, and UDP packets, including source and destination addresses, ports, MAC addresses, and packet content.

## Features

* **Real-time Packet Capture:** Sniffs network packets and displays information immediately.
* **Protocol Analysis:** Extracts and displays details for IP, TCP, and UDP protocols.
* **Address and Port Display:** Shows source and destination IP addresses and ports.
* **MAC Address Display:** Retrieves and displays source and destination MAC addresses.
* **TCP Details:** Provides TCP flags, sequence numbers, and acknowledgment numbers.
* **Payload Length:** Displays the length of TCP and UDP payloads.
* **Packet Metadata:** Shows TTL (Time To Live) and IP packet length.
* **Sequential Packet Count:** Numbers each captured packet for easy tracking.
* **Terminal Clearing:** Clears the terminal screen before starting the capture for a clean display.
* **Cross-Platform Compatibility:** Works on Windows, Linux, and macOS.

## Prerequisites

* Python 3.x
* Scapy library (`pip install scapy`)

## Usage

1.  **Clone or Download:**
    * Clone the repository or download the script.

2.  **Install Scapy:**
    ```bash
    pip install scapy
    ```

3.  **Run the Script:**
    * On Linux/macOS, run with `sudo`:
        ```bash
        sudo python Partisan.py
        ```
    * On Windows, run from an administrator command prompt:
        ```bash
        python Partisan.py
        ```

## Code 

```python
from scapy.all import sniff, IP, TCP, UDP, Ether
import os
import platform

count = 0

def clean():
    os.system('cls' if platform.system() == 'Windows' else 'clear')

def packets(packet):
    global count
    count += 1
    if IP in packet:
        ipsource = packet[IP].src
        ipdestination = packet[IP].dst
        protocol = packet[IP].proto
        ttl = packet[IP].ttl
        iplength = packet[IP].len
        if Ether in packet:
            macsource = packet[Ether].src
            macdestination = packet[Ether].dst

        if TCP in packet:
            tcpsource = packet[TCP].sport
            tcpdestination = packet[TCP].dport
            tcpflags = packet[TCP].flags
            tcpsequence = packet[TCP].seq
            tcpacknowledgment = packet[TCP].ack
            tcppayload = packet[TCP].payload.original if packet[TCP].payload else "No Payload"
            tcppayloadlength = len(packet[TCP].payload.original) if packet[TCP].payload else 0

            print(f"Packet Number: {count}")
            print(f"Source MAC: {macsource}\nDestination MAC: {macdestination}")
            print(f"Source SOCKET: {ipsource}:{tcpsource}\nDestination SOCKET: {ipdestination}:{tcpdestination}")
            print(f"Protocol: TCP\nFlags: {tcpflags}\nSequence: {tcpsequence}\nACK: {tcpacknowledgment}\nPayload Length: {tcppayloadlength}\nTTL: {ttl}\nIP Length: {iplength}\n")

        elif UDP in packet:
            udpsource = packet[UDP].sport
            udpdestination = packet[UDP].dport
            udppayload = packet[UDP].payload.original if packet[UDP].payload else "No Payload"
            udppayloadlength = len(packet[UDP].payload.original) if packet[UDP].payload else 0
            print(f"Packet Number: {count}")
            print(f"Source MAC: {macsource}\nDestination MAC: {macdestination}")
            print(f"Source SOCKET: {ipsource}:{udpsource}\nDestination SOCKET: {ipdestination}:{udpdestination}")
            print(f"Protocol: UDP\nPayload Length: {udppayloadlength}\nTTL: {ttl}\nIP Length: {iplength}\n")

def main():
    clean()
    print("Sniffing...\n\n")
    sniff(prn=packets, store=0)

main()
