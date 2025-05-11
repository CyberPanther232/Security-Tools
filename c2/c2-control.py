
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