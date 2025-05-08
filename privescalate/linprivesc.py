#!/bin/python3

import subprocess
from time import sleep

def sudo():
    # Test for sudo privileges for current user
    command = ["sudo", '-n', 'true']
    
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=5)
        
        if result.returncode == 0:
            print("User has passwordless sudo privileges!")
        else:
            if result.stderr:
                print(f"Sudo stderr: {result.stderr.strip()}")
                return False
            
            print("Sudo command requires password... Attempting to run it. Please enter the password!")
            command = ["sudo", '-l']
            
            result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=5)
            output = result.stdout.strip()
            
            if result.returncode != 0:
                print("Command resulted in an error code...")
                return

    except Exception as e:
        print(f"Error: {e}")
        return

def suid():
    pass

def cron():
    pass

def main():
    print(50 * "#")
    print("LINUX PRIVILEGE ESCALATION - By: CyberPanther232")
    print(50 * "#")

    sleep(3)
    print("\n\nFOR LEGAL AND ETHICAL USE ONLY!")
    sleep(3)
    
    print("\nAttempting to detect privilege escalation vectors...")
    
    print("\nTesting for sudo permissions...")
    sudo()


if __name__ == "__main__":
    main()