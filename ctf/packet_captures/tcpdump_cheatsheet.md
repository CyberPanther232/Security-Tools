# TCPDump Cheatsheets and Commands

### Author: CyberPanther232

This document aims to provide ethical hackers, aspiring penetration testers, and security professionals with a cheatsheet to assist with running tcpdump commands that might help with Capture-The-Flag (CTF) competitions.



### TCPDump Basic Synopsis

Source: https://www.tcpdump.org/manpages/tcpdump.1.html

```bash
tcpdump [ -AbdDefghHIJKlLnNOpqStuUvxX# ] [ -B buffer_size ]
         [ -c count ] [ --count ] [ -C file_size ]
         [ -E spi@ipaddr algo:secret,... ]
         [ -F file ] [ -G rotate_seconds ] [ -i interface ]
         [ --immediate-mode ] [ -j tstamp_type ] [ --lengths ]
         [ -m module ] ... [ -M secret ] [ --number ] [ --print ]
         [ --print-sampling nth ] [ -Q in|out|inout ] [ -r file ]
         [ -s snaplen ] [ --skip count ] [ -T type ] [ --version ]
         [ -V file ] [ -w file ] [ -W filecount ] [ -y datalinktype ]
         [ -z postrotate-command ] [ -Z user ]
         [ --time-stamp-precision=tstamp_precision ]
         [ --micro ] [ --nano ]
         [ -- ] [ expression ]
```



### Useful Commands


#### Reading Pcap Files

```bash
tcpdump -r <pcap, pcapng>
```

* This command will read any packet capture file and allow you to perform filtering without capturing live traffic


#### Writing Pcap Files

```bash
tcpdump -w <pcap, pcapng>
```

* This command writes a live capture to a pcap file. By default, TCPDump will start sniffing or listening for traffic. This command takes that standard behavior and instead of just displaying the output on your console, it writes it to a pcap file for future processing and analysis
