```
   ___      _                            
  / __\   _| |__  _ __ ___  ___ ___  _ __  
 / / | | | | '_ \| '__/ _ \/ __/ _ \| '_ \ 
/ /__| |_| | |_) | | |  __/ (_| (_) | | | |
\____/\__, |_.__/|_|  \___|\___\___/|_| |_|
        |___/                           
```

# Cyber Recon Security Toolkit v1.1

## Developed by - Hunter Kinney

---

## **Toolkit Guide Ver. 1**

Cybrecon (Cyber Recon) is a toolkit created to assist with enumeration, scanning, and detection procedures. It serves as a wrapper for underlying tools such as Nmap and also utilizes custom-built functions to enhance its operations. Below are some use cases and information to assist users with its functionality and usage.

---

## **Section 1: Host Enumeration**

### **Available Tools:**

- `pingsw`
- `qscan`

### **pingsw (Ping Sweep)**

`pingsw` is a simple Bash script that performs a ping sweep on any provided subnet. It also interprets CIDR notation to determine the range to scan.

#### **Example Usage:**

```bash
cybrecon pingsw 192.168.1.1/25
```

This command runs:

```bash
nmap -sn 192.168.1.1/25
```

- `-sn` tells Nmap to execute host detection (ping sweep).
- The output will list active hosts responding to the scan.

#### **Example Output:**

```
192.168.1.1
192.168.1.105
192.168.1.112
```

> **Note:** This scan may not always be 100% accurate. A host might not respond in one scan but may respond in another.

### **qscan (Quick Scan) - WIP**

`qscan` is a custom-built script that leverages `Netcat` to quickly enumerate ports and extract important details from specific services such as HTTP and FTP.

#### **Example Usage**

```bash
cybrecon qscan 192.168.1.1/25 80-1024 2>/dev/null
```

##### How this works

`qscan` uses the `subcalc` function mentioned later in this guide in the general purpose section to determine the range of host needed to be scanned. It then performs the following tasks:

- Runs `nc` scans on each host within the subnet
- Wgets ftp and http ports if detected (quietly unless verbose mode is on)
- Formats the output and then displays each port open on each host
- The main purpose of this tool is to enumerate ports, however, it can also work great at host enumeration

#### **Example Output**

```
IP Addr - PortNum:(Protocol)
192.168.1.1 - 22:(ssh)
192.168.1.105 - 22:(ssh)
192.168.1.105 - 80:(http)
192.168.1.112 - 21:(ftp)
192.168.1.112 - 80:(http)
```

> **Note:** In this tools current state the protocol detection located in the (Protocol) section of the output above can sometimes make errors or not properly display. This is currently being worked on.

---

## **Section 2: Service / Port Enumeration**

*(Details to be added)*

## **Section 3: Web App Scanning / Enumeration**

*(Details to be added)*

## **Section 4: Operating System Detection**

*(Details to be added)*

## **Section 5: General-Purpose**

*(Details to be added)*

---

This document will be updated as new features are added to Cyber Recon. Stay tuned for further updates!
