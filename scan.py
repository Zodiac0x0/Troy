#!/usr/bin/env python
# Troy - Web Applications Security Scanner
# by Omar Islam x.com/Zodiac_0x0
import re
import sys
import logging
import argparse
from vulnz import main_function
from headers import *  # Assumes corrected headers.py with ga and headers_reader
from path_traversal import traversal
from XSS import xss_scan

# Logging Configuration
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] - [%(levelname)s] - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('web_scan.log')
    ]
)

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
        #| "Troy" Web Applications Security Scanner                  #
        #|  by Omar Islam   - X Zodiac_0x0                           #
        ##############################################################
        ''' + ga.end)
print(ga.blue + "Version: 1.1" + ga.end)

def parse_arguments():
    parser = argparse.ArgumentParser(description="Troy - Web Applications Security Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target URL to scan")
    parser.add_argument("-t", "--type", choices=["xss", "path", "all"], default="all",
                        help="Type of scan: 'xss', 'path', or 'all' (default: all)")
    parser.add_argument("-p", "--payloads",
                        help="Path to payloads file",required=True)
    return parser.parse_args()

def validate_url(url):
    if not (url.startswith("http://") or url.startswith("https://")):
        print(ga.red + "[!] Invalid URL: Must start with http:// or https://" + ga.end)
        sys.exit(1)
    if "?" not in url:
        print(ga.red + "[!] Invalid URL: Must contain parameters (e.g., ?id=1)" + ga.end)
        sys.exit(1)

def scan_url(url, scan_type, payloads_file):
    validate_url(url)
    logging.info(f"Starting scan on {url} with payloads from {payloads_file}")

    if scan_type in ["xss", "all"]:
        logging.info(ga.yellow + "[!] Checking for XSS..." + ga.end)
        xss_scan(url, payloads_file)

    if scan_type in ["path", "all"]:
        logging.info(ga.yellow + "[!] Checking for Path Traversal..." + ga.end)
        traversal(url, payloads_file)

def main():
    args = parse_arguments()
    url = args.url
    scan_type = args.type
    payloads_file = args.payloads

    try:
        with open(payloads_file, 'r') as f:
            pass
    except FileNotFoundError:
        print(ga.red + f"[!] Payloads file '{payloads_file}' not found!" + ga.end)
        sys.exit(1)

    scan_url(url, scan_type, payloads_file)

if __name__ == "__main__":
    main()