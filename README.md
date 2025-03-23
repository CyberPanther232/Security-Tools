# 🔍 Cybersecurity Tools & Toolkits

Welcome to the **Cybersecurity Tools & Toolkits** – a powerful set of Bash and Python scripts designed for ethical hackers, penetration testers, and security researchers. This repository contains scripts and utilities for network reconnaissance, vulnerability scanning, and various security assessments.

## ⚡ Features
- **Network Scanning**: Tools to gather information regarding ports, services, and ips.
- **Reconnaissance Tools**: Gather detailed information about targets.
- **Vulnerability Assessment**: Identify weaknesses in networked systems.
- **Automation**: Easily integrate with existing workflows using modular scripts.
- **Customizable**: Modify and extend functionality based on your needs.
- **Reverse Shells**: Create and manage multiple reverse shell sessions

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
├── exploits/
│   ├── exp.py # Buffer overflow exploit template
│   ├── vuln-serv-exp.py # Vulnerable Server executable buffer overflow python script
├── general/ 
│   ├── subcalc # performs subnet calculations
├── guides/
│   ├── cybrecon-guide.md # WIP: markdown document with information / guides for using the cybrecon toolkit
│   ├── sql-syringe-guide.md # WIP: markdown document with information / guides for using the sql-syringe.py toolkit
├── revshells/
│   ├── adv-rev-shell.py # Advanced reverse shell script to work in combination with c2-listener.py
│   ├── c2-command.py # python script to assist with managing multiple remote shell sessions
│   ├── c2-control.py # python script that displays log information from remote shell sessions and c2-command.py
│   ├── rev-shell.c # Simple C reverse shell code
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
- LFI/RFI Scanner
- Firewall Rules Tester
- Payload Encoder/Decoder
- More granular scanning options
- PowerShell scripts to perform tool functions on Windows machines
- Improvements in UI to make tools User Friendly

## ⚠️ Legal Disclaimer
These tools and toolkit are intended **strictly for ethical hacking** and security research. Unauthorized use against networks you do not own or have explicit permission to test is illegal. The developers are **not responsible for any misuse** of this software.

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
Email: kinneyh27@gmail.com

---
💻 Happy Hacking & Stay Secure!

