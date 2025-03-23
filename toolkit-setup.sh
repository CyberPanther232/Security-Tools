#!/bin/bash

# Requires SUDO or Root privileges in most cases

echo "Running toolkit-setup script!"

echo ""
echo "Adding scanning tools!"
cp ./scanning/cybrecon /bin/cybrecon && chmod +x /bin/cybrecon
cp ./scanning/pingsw /bin/pingsw && chmod +x /bin/pingsw
cp ./scanning/qscan /bin/qscan && chmod +x /bin/qscan

echo ""
echo "Done!"
sleep 1

echo ""
echo "Adding general tools!"
cp ./general/subcalc /bin/subcalc && chmod +x /bin/subcalc

echo ""
echo "Done!"
sleep 1

echo ""
echo "Adding reverse shell tools!"
cp ./revshells/c2-command.py /bin/c2-command && chmod +x /bin/c2-command
cp ./revshells/c2-control.py /bin/c2-control && chmod +x /bin/c2-control

echo ""
echo "Done!"
sleep 1

echo ""
echo "Adding SSH tools!"
cp ./ssh/clssh /bin/clssh && chmod +x /bin/clssh
cp ./ssh/socks /bin/socks && chmod +x /bin/socks

echo ""
echo "Done!"
sleep 1

echo ""
echo "Adding web tools!"
cp ./web/cookie-cruncher.py /bin/cookie-cruncher && chmod +x /bin/cookie-cruncher
cp ./web/sql-syringe.py /bin/sql-syringe && chmod +x /bin/sql-syringe

echo ""
echo "Done!"
sleep 1

echo ""
echo "Toolkit binary setup process completed!"
sleep 3
clear
