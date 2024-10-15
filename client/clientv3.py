from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from scapy.all import *
import base64
import sys
import socket

# Configuration
DNS_SERVER_IP = '8.8.8.8'  # Replace with your DNS server IP
DNS_PORT = 53
DOMAIN = 'sub.brightbuys.me'  # Replace with your target domain

# Pre-shared key (PSK) for exchanging the AES key securely
psk = b"thisisaverysecurekey123456789012"  # Must be 16, 24, or 32 bytes long


# Encrypt AES key using PSK
def encrypt_with_psk(aes_key, psk, iv):
    cipher = AES.new(psk, AES.MODE_CBC, iv)
    encrypted_aes_key = cipher.encrypt(pad(aes_key, AES.block_size))
    # return base64.b64encode(iv + encrypted_aes_key).decode('utf-8')
    return "hi"


# AES encryption
def encrypt_aes(data, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
    encrypted_message = base64.b64encode(iv + encrypted_data).decode('utf-8')
    print(f"[CLIENT] Original message: {data}")
    print(f"[CLIENT] Encrypted message (base64): {encrypted_message}")
    return encrypted_message


# AES decryption
def decrypt_aes(data, key):
    try:
        print(f"[CLIENT] Encrypted data (base64) for decryption: {data}")
        data = base64.b64decode(data)
        iv = data[:16]
        encrypted_message = data[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(encrypted_message), AES.block_size)
        print(f"[CLIENT] Decrypted message: {decrypted_data.decode('utf-8')}")
        return decrypted_data.decode('utf-8')
    except Exception as e:
        print(f"[CLIENT] Decryption error: {e}")
        return None


# Fragment message to fit within DNS label size limits
def fragment_message(message, max_label_length=63):
    # Ensure the message is properly padded for base64
    missing_padding = len(message) % 4
    if missing_padding:
        message += '=' * (4 - missing_padding)  # Add padding if necessary

    fragments = []
    while message:
        fragments.append(message[:max_label_length])
        message = message[max_label_length:]

    # Logging each fragment
    print(f"[CLIENT] Total fragments created: {len(fragments)}")
    for i, fragment in enumerate(fragments):
        print(f"[CLIENT] Fragment {i + 1}: {fragment}")

    return fragments


# Send DNS query based on the query type
def send_dns_query(server_ip, query_pkt, timeout=10):  # Increase timeout to 10 seconds
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        send(query_pkt)
        response, _ = sock.recvfrom(1024)
        print(f"[CLIENT] Received response: {response}")
        return response
    except socket.timeout:
        pass
    finally:
        sock.close()


# AES decryption for the encrypted AES key
def decrypt_with_psk(encrypted_data, psk):
    try:
        print(f"[CLIENT] Encrypted data (base64) for AES key decryption: {encrypted_data}")
        data = base64.b64decode(encrypted_data)
        iv = data[:16]  # Extract the IV (first 16 bytes)
        encrypted_aes_key = data[16:]  # The rest is the encrypted AES key
        cipher = AES.new(psk, AES.MODE_CBC, iv)
        decrypted_aes_key = unpad(cipher.decrypt(encrypted_aes_key), AES.block_size)
        print(f"[CLIENT] Decrypted AES Key: {decrypted_aes_key}")
        return decrypted_aes_key
    except Exception as e:
        print(f"[CLIENT] AES key decryption error: {e}")
        return None


# Craft DNS query for the specified full domain
def craft_dns_query(domain, query_type='TXT'):
    print(f"Sending DNS Query: {domain}")
    qtype_mapping = {'TXT': 16, 'CNAME': 5, 'A': 1}
    qtype_value = qtype_mapping.get(query_type, 16)
    dns_query = (
            IP(dst=DNS_SERVER_IP) /
            UDP(sport=RandShort(), dport=53) /
            DNS(rd=1, qd=DNSQR(qname=domain, qtype=qtype_value))
    )
    return dns_query

if __name__ == "__main__":
    # ...

    # Construct the full domain name to send
    full_domain_name = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz.sub.brightbuys.me"

    # Craft and send the DNS query
    query_pkt = craft_dns_query(full_domain_name, 'TXT')
    print(f"[CLIENT] Sending DNS query for: {full_domain_name}")
    response = send_dns_query(DNS_SERVER_IP, query_pkt)

    print("Query sent")
