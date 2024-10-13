from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from scapy.all import *

# Configuration
DNS_SERVER_IP = '13.228.229.230'  # Replace with our DNS IP
DNS_PORT = 53
DOMAIN = 'sub.brightbuys.me'
aes_key = get_random_bytes(32)  # Shared AES key
aes_iv = get_random_bytes(16)  # IV for AES encryption


# AES encryption
def encrypt_aes(data, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
    return base64.b64encode(iv + encrypted_data).decode('utf-8')


# AES decryption
def decrypt_aes(data, key):
    data = base64.b64decode(data)
    iv = data[:16]
    encrypted_message = data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_message), AES.block_size)
    return decrypted_data.decode('utf-8')


# Send DNS query based on the query type
def send_dns_query(server_ip, query_pkt):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)

        # Send the DNS query packet
        sock.sendto(bytes(query_pkt), (server_ip, DNS_PORT))

        # Receive the DNS response
        response, _ = sock.recvfrom(1024)
        return response

    except socket.timeout:
        print("Request timed out")
    finally:
        sock.close()


# Craft DNS query based on the query type (TXT, CNAME, or A)
def craft_dns_query(encrypted_message, domain, query_type='TXT'):
    message = encrypted_message.replace('=', '')  # Avoid invalid base64 chars

    if query_type == 'TXT':
        # TXT record
        dns_query = IP(dst=DNS_SERVER_IP) / UDP(dport=DNS_PORT) / DNS(rd=1, qd=DNSQR(qname=f"{message}.{domain}.",
                                                                                     qtype='TXT'))
    elif query_type == 'CNAME':
        # CNAME record
        dns_query = IP(dst=DNS_SERVER_IP) / UDP(dport=DNS_PORT) / DNS(rd=1, qd=DNSQR(qname=f"{message}.{domain}.",
                                                                                     qtype='CNAME'))
    elif query_type == 'A':
        # A record
        dns_query = IP(dst=DNS_SERVER_IP) / UDP(dport=DNS_PORT) / DNS(rd=1,
                                                                      qd=DNSQR(qname=f"{message}.{domain}.", qtype='A'))
    else:
        raise ValueError("Unsupported DNS query type")

    return dns_query


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 client.py <message> <query_type>")
        print("query_type: 'TXT', 'CNAME', or 'A'")
        sys.exit(1)

    # Extract message and query type from the cmd args
    message_to_send = sys.argv[1]
    query_type = sys.argv[2].upper()  # Ensure the query type is uppercase (TXT, CNAME, A)

    if query_type not in ['TXT', 'CNAME', 'A']:
        print("Error: query_type must be one of 'TXT', 'CNAME', or 'A'")
        sys.exit(1)

    # Encrypt the message using AES
    encrypted_message = encrypt_aes(message_to_send, aes_key, aes_iv)
    print(f"Encrypted Message: {encrypted_message}")

    # Craft the DNS query based on the selected query type
    query_pkt = craft_dns_query(encrypted_message, DOMAIN, query_type)

    # Send the DNS query to the server and get the response
    response = send_dns_query(DNS_SERVER_IP, query_pkt)

    if response:
        try:
            # For now we assume that the response contains an encrypted message in the DNS answer
            dns_response = DNS(response)
            if dns_response.an and dns_response.an.rdata:
                encrypted_response = dns_response.an.rdata.decode()  # Decode the DNS answer depend on the record type
                decrypted_response = decrypt_aes(encrypted_response, aes_key)
                print(f"Decrypted Response: {decrypted_response}")
            else:
                print("No valid response in DNS answer section")
        except Exception as e:
            print(f"Failed to decrypt response: {e}")
