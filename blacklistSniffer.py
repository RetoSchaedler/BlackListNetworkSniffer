import time
import threading
import requests
import argparse
from scapy.all import *
from datetime import datetime

# URL of the blacklist
blacklist_url = "https://lists.blocklist.de/lists/all.txt"

# Initially empty blacklist
blacklist = []

# Function to download the blacklist
def download_blacklist():
    global blacklist
    while True:
        try:
            response = requests.get(blacklist_url)
            response.raise_for_status()
            blacklist = response.text.split('\n')
            print(f"Downloaded blacklist with {len(blacklist)} entries")
        except Exception as e:
            print(f"Error downloading blacklist: {e}")
        # Wait for 35 minutes
        time.sleep(35 * 60)

# Start the blacklist download thread
blacklist_thread = threading.Thread(target=download_blacklist)
blacklist_thread.start()

# Function to handle each packet
def handle_packet(packet):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if packet.haslayer(IP) and (packet[IP].src in blacklist or packet[IP].dst in blacklist):
        if packet.haslayer(TCP) and packet[TCP].flags == 'S':
            print(f"{timestamp} - Detected TCP SYN communication with blacklisted IP: {packet[IP].src} -> {packet[IP].dst}")
        elif packet.haslayer(UDP):
            print(f"{timestamp} - Detected UDP communication with blacklisted IP: {packet[IP].src} -> {packet[IP].dst}")
        elif packet.haslayer(ICMP):
            print(f"{timestamp} - Detected ICMP communication with blacklisted IP: {packet[IP].src} -> {packet[IP].dst}")
    elif packet.haslayer(IPv6) and (packet[IPv6].src in blacklist or packet[IPv6].dst in blacklist):
        if packet.haslayer(TCP) and packet[TCP].flags == 'S':
            print(f"{timestamp} - Detected TCP SYN communication with blacklisted IPv6: {packet[IPv6].src} -> {packet[IPv6].dst}")
        elif packet.haslayer(UDP):
            print(f"{timestamp} - Detected UDP communication with blacklisted IPv6: {packet[IPv6].src} -> {packet[IPv6].dst}")
        elif packet.haslayer(ICMP):
            print(f"{timestamp} - Detected ICMP communication with blacklisted IPv6: {packet[IPv6].src} -> {packet[IPv6].dst}")


# Create argument parser
parser = argparse.ArgumentParser(description="Network sniffer that alerts on communication with blacklisted IPs. Run with root rights.")
parser.add_argument("--interface", default="Ethernet 5", help="The network interface to sniff on")

# Parse command line arguments
args = parser.parse_args()

# Sniff on interface eth0
sniff(iface=args.interface, prn=handle_packet)
