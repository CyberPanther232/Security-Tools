#!/usr/bin/env bash

# ---------------------------------------------------------------------------------------------
# Developer: CyberPanther232
# Program: getHTTP.sh
# Description: This script uses tshark to extract HTTP requests and responses from a pcap file.
# Usage: ./getHTTP.sh <input.pcap> <output.txt>
# Date Created: 07-16-2026
# ---------------------------------------------------------------------------------------------

# Argument validation
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <input.pcap> <output.txt>"
    exit 1
fi

# Validate if tshark is installed
if ! command -v tshark &> /dev/null; then
    echo "Error: tshark may not be installed. Please install it and try again."
    exit 1
fi

# Assign input arguments to variables
input_pcap="$1"
output_file="$2"

# Use tshark to extract HTTP requests and responses
tshark -r "$input_pcap" -Y "http.request or http.response" -T fields -e frame.number -e ip.src -e ip.dst -e http.request.method -e http.request.uri -e http.response.code -e http.response.phrase > "$output_file"