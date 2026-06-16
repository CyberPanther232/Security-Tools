"""
------------------------------------------------------------------------------------------------------------
DISCLAIMER: For Legal and Ethical Uses only!
Program: c2-control.py
Developer: CyberPanther232
Purpose: To demonstrate a proof-of-concept command and control server log monitoring script
Date Created: 05-11-2025
------------------------------------------------------------------------------------------------------------
"""

import time

def main():
    with open('./c2-log.txt') as logfile:
        logfile.seek(0, 2)
        
        while True:
            line = logfile.readline()
            if not line:
                time.sleep(0.5)
                continue
            print(line.strip())

if __name__ == "__main__":
    main()