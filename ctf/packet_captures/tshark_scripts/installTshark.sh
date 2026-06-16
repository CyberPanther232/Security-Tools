#!/usr/bin/env bash

# ---------------------------------------------------------------------------------------------
# Developer: CyberPanther232
# Program: installTshark.sh
# Description: This script installs tshark, a powerful network protocol analyzer, on various operating systems.
# Usage: ./installTshark.sh
# Date Created: 07-16-2026
# ---------------------------------------------------------------------------------------------

echo "Attempting to install tshark..."

echo "Checking to see if tshark is already installed..."
# Validate if tshark is installed
if command -v tshark &> /dev/null; then
    echo "tshark is already installed."
    exit 0
fi

# Determine the correct linux package manager and install tshark
if [ -x "$(command -v apt-get)" ]; then
    echo "Using apt-get to install tshark..."
    sudo apt-get update
    sudo apt-get install -y tshark
elif [ -x "$(command -v yum)" ]; then
    echo "Using yum to install tshark..."
    sudo yum update -y
    sudo yum install -y tshark
elif [ -x "$(command -v dnf)" ]; then
    echo "Using dnf to install tshark..."
    sudo dnf update -y
    sudo dnf install -y tshark
else
    echo "Error: No supported package manager found. Please install tshark manually."
    exit 1
fi

echo "tshark installation completed successfully."
