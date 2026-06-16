![Alt text](https://github.com/CyberPanther232/Security-Tools/blob/main/Sec_Tools_logo_mini.png)

# 🔍 Cybersecurity Tools & Toolkits

Welcome to the **Cybersecurity Tools & Toolkits** – a powerful set of Bash and Python scripts designed for ethical hackers, penetration testers, and security researchers. This repository contains scripts and utilities for network reconnaissance, vulnerability scanning, and various security assessments.

## ⚡ Features

- **Network Scanning**: Tools to gather information regarding ports, services, and ips.
- **Reconnaissance Tools**: Gather detailed information about targets.
- **Vulnerability Assessment**: Identify weaknesses in networked systems.
- **Automation**: Easily integrate with existing workflows using modular scripts.
- **Customizable**: Modify and extend functionality based on your needs.
- **Reverse Shells**: Create and manage multiple reverse shell sessions.
- **Command and Control**: Scripts to conduct remote exploitation of machines

## 🚀 Getting Started

### Prerequisites

Ensure you have the following installed:

- `nmap`
- `netcat`
- `curl`
- `python3.11`
- `php`

## 📁 Directory Structure

```
.
├── c2/
│   ├── templates # templates directory for the advanced keylogger script
│   │   ├── index.html # main webpage for advanced key logger server GUI
│   ├── c2-command.py # python script to assist with managing multiple remote shell sessions
│   ├── c2-control.py # python script that displays log information from remote shell sessions and c2-command.py
│   ├── data-recv-server.py # python server that listens for advanced keylogger data
│   ├── encryping-client.py # python client that receives encrypted commands through icmp packets
│   ├── encryping.py # python server that sends encrypted commands through icmp packets to client
│   ├── necro.py # necromancer python script that provides a terminal that can also control machines infected with zombie.py
│   ├── zombie.py # zombie python script that when ran on a machine reaches out periodically to the necro server to receive commands
├── ctf/
│   ├── packet_captures
│   │   ├── pyshark_scripts
│   │   │    ├── get_dns.py # PyShark script to gather all dns queries and domain names from a packet capture
│   │   │    ├── get_export_objects.py # PyShark script to gather all export objects from a packet capture
│   │   │    ├── pcap_stats.py # PyShark script to gather the conversations, protocols, and endpoints from a packet capture
│   │   ├── tshark_scripts
│   │   │    ├── getHTTP.sh # Bash script that uses TShark to parse HTTP traffic and data from packet captures
│   │   │    ├── installTshark.sh # Bash script designed to automatically install tshark for linux machines
│   │   ├── tcpdump_cheatsheet.md # Markdown document containing commands and a guide to using tcpdump
├── exploits/
│   ├── exp.py # buffer overflow exploit template
│   ├── vuln-serv-exp.py # vulnerable Server executable buffer overflow python script
│   ├── simple-keylogger.py # simple python3 keylogger software for ethical and legal uses only
├── general/ 
│   ├── subcalc # performs subnet calculations
├── guides/
│   ├── cybrecon-guide.md # WIP: markdown document with information / guides for using the cybrecon toolkit
│   ├── sql-syringe-guide.md # WIP: markdown document with information / guides for using the sql-syringe.py toolkit
├── privescalate/
│   ├── linprivesc.py # python script that attempts to detect and exploit privilege escalation vectors within a linux OS machine
├── revshells/
│   ├── adv-rev-shell.py # advanced reverse shell script to work in combination with c2-listener.py
│   ├── rev-shell.c # simple C reverse shell code
│   ├── rev-shell.py # simple python reverse shell script
│   ├── rev-shells.json # WIP: reverse shell template storage for rev-generator.py
├── scanning/
│   ├── cybrecon # scanning toolkit designed for many reconnaissance tasks (network, http, banners) - Bash
│   ├── cybrecon.ps1 # scanning toolkit designed for many reconnaissance tasks (network, http, banners) - PowerShell
│   ├── pingsw # ping sweep command in script form (does subnet calculations automatically)
│   ├── qscan # custom built netcat scanning tool that is also included in cybrecon
├── ssh/ 
│   ├── clssh # known_hosts clearing
│   ├── socks # detects and kills dynamic SOCKS5 ssh tunnels
├── web/ 
│   ├── cookie-cruncher.py # XSS scripting assistance tool
│   ├── requirements.txt # dependencies to install for python scripts (python3 -m pip install -r ./cyber-tools/web/requirements.txt)
│   ├── fuzzylist # default wordlist for fuzzing scripts (built off of Bo0oM's fuzz.txt)
│   ├── sql-syringe.py # python sql injection toolkit
│   ├── web_scrape.py # general python web scraping script
├── LICENSE
├── README.md # project documentation
├── toolkit-setup.sh # Bash setup script to setup tools in binaries folder (/bin)
```

## Future Additions

- Firewall Rules Tester
- Advanced C2 scripts
- Exploit/File injection script
- More granular scanning options
- PowerShell scripts to perform tool functions on Windows machines
- Improvements in UI to make tools User Friendly

## ⚠️ Legal Disclaimer

These tools and toolkit are intended **strictly for ethical hacking** and **security research**. Unauthorized use against networks you do not own or have explicit permission to test is illegal. The developers are **not responsible for any misuse** of this software.

## In-Class Disclaimer

This toolkit is not intended to replace learning. If you do not understand what the tools are accomplishing / doing then you should not use them.
The point of these tools are to assist with mundane and repitious tasks without fully replacing the need of understanding core concepts and fundamentals of cybersecurity and ethical hacking.

## 🎯 Roadmap

- [ ] Improve scan speed & efficiency
- [ ] Add more recon techniques
- [ ] Integrate OSINT data sources
- [ ] Enhance reporting & visualization
- [ ] Improve effectiveness of learning and task completion

## 🤝 Contributing

Please feel free to contribute. If you don't understand the code, don't touch it please :)

## 📜 License

This project is licensed under the [GNU General Public License v3.0](LICENSE).

## 📬 Contact

For questions or suggestions, open an issue or reach out via GitHub discussions or Email

Email: summit.betel3421@eagereverest.com

---

💻 Happy Hacking & Stay Secure!
