#!/bin/python3

import subprocess
import os
from time import sleep

def sudo():
    # Test for sudo privileges for current user
    command = ["sudo", '-n', 'true'] # Check for passwordless sudo
    
    try:
        # First 'sudo -n true' call:
        # NO 'check=True', so it won't raise an error if 'sudo -n true' fails.
        result = subprocess.run(command, capture_output=True, text=True, timeout=5)
        
        if result.returncode == 0:
            print("User has passwordless sudo privileges!")
            # The function ends here if passwordless sudo is available.
            
        else: # This block executes if 'sudo -n true' failed (e.g., password required)
            if result.stderr: # 'sudo -n true' usually puts "sudo: a password is required" on stderr
                print("Sudo command requires password... Attempting to run it. Please enter the password!")
        
        command_interactive = ["sudo", '-l'] # Command to list sudo privileges, will prompt for password
        
        print("\nDisplaying privilege test results...")
        # Second 'sudo -l' call:
        # CRITICAL POINT: `capture_output=True` is used here.
        result_interactive = subprocess.run(
            command_interactive, 
            capture_output=True, # This is the main issue for interactivity
            text=True, 
            timeout=5
        )
        # output_interactive = result_interactive.stdout.strip() # You capture stdout but don't print `output_interactive`
        
        print(result_interactive.stdout.strip())
        
        if "(ALL : ALL) ALL" in result_interactive.stdout:
            print("Detected (ALL : ALL) ALL!!!")
            print("\nAttempting to privilege escalate using 'su!'")
            os.system("sudo su")
            print("sudo privilege escalation complete!")
            return True
        
        else:
            return False

    except subprocess.TimeoutExpired as e_timeout:
        print(f"Error: A command timed out: {e_timeout.cmd}")
        if e_timeout.stdout: # stdout might be bytes
            print(f"Stdout before timeout: {e_timeout.stdout.decode(errors='ignore') if isinstance(e_timeout.stdout, bytes) else e_timeout.stdout}")
        if e_timeout.stderr: # stderr might be bytes
            print(f"Stderr before timeout: {e_timeout.stderr.decode(errors='ignore') if isinstance(e_timeout.stderr, bytes) else e_timeout.stderr}")
        return False
    
    except FileNotFoundError:
        print("Error: 'sudo' command not found. Is it installed and in PATH?")
        return False
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return False

def suid():
    
    gtfobins = [
        "aa-exec", "ab", "agetty", "alpine",
        "ar", "arj", "arp", "as", "ascii",
        "ash", "aspell", "atobm", "awk",
        "base32", "base64", "basenc", "basez",
        "bash", "bc", "bridge", "busctl",
        "busybox", "bzip2", "cabal", "capsh",
        "cat", "chmod", "choom", "chown",
        "chroot", "clamscan", "cmp", "column",
        "comm", "cp", "cpio", "cpulimit", "csh",
        "csplit", "csvtool", "csvtool", "cupsfilter",
        "curl", "cut", "dash", "date", "dd", "debugfs",
        "dialog", "diff", "dig", "distcc", "dmsetup",
        "docker", "dosbox", "ed", "efax", "elvish",
        "emacs", "env", "eqn", "espeak", "expand",
        "expect", "file", "find", "fish", "flock",
        "fmt", "fold", "gawk", "gcore", "gdb",
        "genie", "genisoimage", "gimp", "grep",
        "gtester", "gzip", "hd", "head", "hexdump",
        "highlight", "hping3", "iconv", "install",
        "ionice", "ip", "ispell", "jjs", "join",
        "join", "jq", "jrunscript", "julia",
        "ksh", "ksshell", "kubectl", "ld.so", "less",
        "logsave", "look", "lua", "make", "mawk",
        "minicom", "more", "mosquitto", "msgattrib",
        "msgcat", "msgconv", "msgfilter", "msgmerge",
        "msguniq", "multitime", "mv", "nasm", "nawk",
        "ncftp", "nft", "nice", "nl", "nm", "nmap",
        "node", "nohup", "ntpdate", "od", "openssl",
        "openvpn", "pandoc", "paste", "perf", "perl",
        "pexec", "pg", "php", "pidstat", "pr", "python",
        "python3", "rc", "readelf", "restic", "rev",
        "rlwrap", "rsync", "rtorrent", "run-parts",
        "rview", "rvim", "sash", "scanmem", "sed",
        "setarch", "setfacl", "setlock", "shuf",
        "soelim", "softlimit", "sort", "sqlite3",
        "ss", "ssh-agent", "ssh-keygen", "ssh-keyscan",
        "sshpass", "start-stop-daemon", "stdbuf", "strace",
        "strings", "sysctl", "systemctl", "tac", "tail",
        "taskset", "tbl", "tclsh", "tee", "terraform",
        "tftp", "tic", "time", "timeout", "troff", "ul",
        "unexpand", "uniq", "unshare", "unsquashfs",
        "unzip", "update-alteratives", "undecode",
        "uuencode", "vagrant", "varnishncsa", "view",
        "vigr", "vim", "vimdiff", "vipw", "w3m",
        "watch", "wc", "wget", "whiptail", "xargs",
        "xdotool", "xmodmap", "xmore", "xxd", "xz",
        "yash", "zsh", "zsoelim"
    ]

    command_args = ["find", "/", "-type", "f", "-perm", "/4000"]

    try:
        result = subprocess.run(
            command_args,
            stdout=subprocess.PIPE,    # Explicitly capture stdout
            stderr=subprocess.DEVNULL, # Redirect stderr to /dev/null
            text=True,                 # Decode output as text
            check=True                 # Raise an exception if 'find' returns non-zero
        )
        print("SUID files found:")
        print(result.stdout.strip())

    except subprocess.CalledProcessError as e:
        print(f"Error executing find: {e}")
        if e.stdout: # stdout might still have been captured before the error
            print(f"Stdout from failed command:\n{e.stdout.strip()}")
        # e.stderr will be None because we redirected it to DEVNULL
        print(f"Stderr was redirected to null, error likely due to return code: {e.returncode}")
    except FileNotFoundError:
        print("Error: 'find' command not found. Is it installed and in PATH?")
    except Exception as e: # Catch any other unexpected errors
        print(f"An unexpected error occurred: {e}")

def cron():
    pass

def main():
    print(50 * "#")
    print("LINUX PRIVILEGE ESCALATION - By: CyberPanther232")
    print(50 * "#")

    sleep(3)
    print("\nFOR LEGAL AND ETHICAL USE ONLY!")
    sleep(3)
    
    print("\nAttempting to detect privilege escalation vectors...")
    
    print("\nTesting for sudo permissions...")
    # if sudo():
    #     exit()

    print("\nTesting for suid bit binaries...")
    if suid():
        exit()

if __name__ == "__main__":
    main()