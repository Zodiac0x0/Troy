#!/usr/bin/env python
# WebPwn3r is a Web Applications Security Scanner
# By Ebrahim Hegazy - twitter.com/zigoo0
# Develped by Omar islam x.com/Zodiac_
import re
import urllib.request
import sys
import logging
from headers import *  # Assumes corrected headers.py with ga and headers_reader

# Import specific functions from your modules
from path_traversal import traversal  # From path_traversal.py
from XSS import xss_scan  # From xss_scanner.py (requires payloads file)
# Placeholder imports (assuming these exist or will be added later)
import RCE  # Replace with actual function import if available
import SQLi  # Replace with actual function import if available

# Logging Configuration
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] - [%(levelname)s] - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('web_scan.log')  # Changed to a more general name
    ]
)

# Vulnerability scanning functions
def rce_func(url):
    logging.info(ga.yellow + f" [!] Checking {url} for RCE..." + ga.end)
    # Placeholder: Add actual RCE scanning logic or import from RCE.py
    print("RCE scan not implemented yet.")

def xss_func(url, payloads_file="xss_payloads.txt"):
    logging.info(ga.yellow + f" [!] Checking {url} for XSS..." + ga.end)
    xss_scan(url, payloads_file)  # Call the imported xss_scan function

def error_based_sqli_func(url):
    logging.info(ga.yellow + f" [!] Checking {url} for SQLi..." + ga.end)
    # Placeholder: Add actual SQLi scanning logic or import from SQLi.py
    print("SQLi scan not implemented yet.")

def path_traversal_func(url,payload_file):
    logging.info(ga.yellow + f" [!] Checking {url} for Path Traversal..." + ga.end)
    traversal(url,payload_file)  # Call the imported test_path_traversal function

# Banner
print(ga.green + '''
      
                    
                $$$$$$$$\                            
                \__$$  __|                           
                   $$ | $$$$$$\   $$$$$$\  $$\   $$\ 
                   $$ |$$  __$$\ $$  __$$\ $$ |  $$ |
                   $$ |$$ |  \__|$$ /  $$ |$$ |  $$ |
                   $$ |$$ |      $$ |  $$ |$$ |  $$ |
                   $$ |$$ |      \$$$$$$  |\$$$$$$$ |
                   \__|\__|       \______/  \____$$ |
                                           $$\   $$ |
                                           \$$$$$$  |
                                            \______/ 
                                                                                                              
        ##############################################################
        #| "Troy" Web Applications Security Scanner                #
        #   by Omar Islam   - X Zodiac_0x0                           #
        ##############################################################
        ''' + ga.end)

def urls_or_list():
    url = input(" [!] Enter the URL: ")
    if not url.startswith("http://") and not url.startswith("https://"):
        print(ga.red + '''\n Invalid URL, Please Make Sure That The URL Starts With "http://" or "https://" \n''' + ga.end)
        sys.exit(1)
    if "?" in url:
        headers_reader(url)  # Fingerprint server headers
        print("Choose a scan type:")
        print("1: XSS")
        print("2: Path Traversal")
        print("3: SQLi")
        print("4: RCE")
        i = int(input("Enter choice (1-4): "))
        if i == 1:
            xss_func(url)  # Execute XSS scan
        elif i == 2:
            path_traversal_func(url)  # Execute Path Traversal scan
        elif i == 3:
            error_based_sqli_func(url)  # Execute SQLi scan
        elif i == 4:
            rce_func(url)  # Execute RCE scan
        else:
            print(ga.red + " [!] Invalid choice! Enter 1-4." + ga.end)
            sys.exit(1)
    else:
        print(ga.red + "\n [Warning] " + ga.end + ga.bold + f"{url}" + ga.end + ga.red + " is not a valid URL" + ga.end)
        print(ga.red + " [Warning] You should write a Full URL .e.g http://site.com/page.php?id=value \n" + ga.end)
        sys.exit(1)

if __name__ == "__main__":
    urls_or_list()