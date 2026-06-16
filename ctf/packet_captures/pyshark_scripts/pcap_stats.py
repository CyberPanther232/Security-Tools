"""
------------------------------------------------------------------------------------------------------------
DISCLAIMER: For Legal and Ethical Uses only!
Program: pcap_stats.py
Developer: CyberPanther232
Purpose: To help with analyzing packet captures for CTFs, research, and other legal and legitimate purposes
Date Created: 07-16-2026
------------------------------------------------------------------------------------------------------------
"""

import os
import argparse
import pyshark

def parse_pcap(pcap_file):
    
    # Input validation and verification
    if os.path.exists(pcap_file):
        print(f"File '{pcap_file}' found. Proceeding with analysis...")
    else:
        print(f"Error: File '{pcap_file}' not found. Please provide a valid pcap file.")
        return
    
    if pcap_file.endswith('.pcap') or pcap_file.endswith('.pcapng'):
        print(f"File '{pcap_file}' is a valid pcap file.")
    else:
        print(f"Error: File '{pcap_file}' is not a valid pcap file. Please provide a .pcap or .pcapng file.")
        return
    
    # Initialize data structures for analysis
    conversations = {}
    endpoints = set()
    protocols = set()
    packet_count = 0
    macs = set()
    ips = set()
    oui = set()
    dns_queries = set()
    
    try:
        capture = pyshark.FileCapture(pcap_file)
        print(f"Analyzing pcap file: {pcap_file}")
        print(f"Total packets in capture: {len(capture)}")
        
    except Exception as e:
        print(f"Error analyzing pcap file: {e}")

def main():
    parser = argparse.ArgumentParser(description="Analyze a pcap file and provide statistics.")
    parser.add_argument("pcap_file", help="Path to the pcap file to analyze")
    args = parser.parse_args()
    parse_pcap(args.pcap_file)

if __name__ == "__main__":
    main()
