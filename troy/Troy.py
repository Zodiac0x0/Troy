#!/usr/bin/env python
# Troy - Web Applications Security Scanner
# by Omar Islam x.com/Zodiac_0x0
import sys
import logging
import argparse
import os
from importlib import resources
from .headers import *  # Relative import within troy package
from .path_traversal import traversal
from .XSS import xss_scan

# Banner
print(ga.green + r'''
      
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

# Logging Configuration
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] - [%(levelname)s] - %(message)s',
    handlers=[logging.StreamHandler(), logging.FileHandler('web_scan.log')]
)

def parse_arguments():
    parser = argparse.ArgumentParser(description="Troy - XSS and Path Traversal Scanner")
    parser.add_argument("--url", required=True, help="Target URL (e.g., http://example.com/?id=1)")
    parser.add_argument("--type", choices=["xss", "path", "all"], default="all", help="Scan type: xss, path, or all")
    parser.add_argument("--xss-payloads", default=None, help="File with XSS payloads (default: built-in xss_payloads.txt)")
    parser.add_argument("--path-payloads", default=None, help="File with Path Traversal payloads (default: built-in path_payloads.txt)")
    parser.add_argument("--method", choices=["GET", "POST"], default="GET", help="HTTP method for Path Traversal")
    parser.add_argument("--threads", type=int, default=10, help="Number of threads for scanning")
    return parser.parse_args()

def validate_url(url):
    try:
        if not (url.startswith("http://") or url.startswith("https://")):
            raise ValueError("URL must start with http:// or https://")
        if "?" not in url:
            raise ValueError("URL must contain parameters (e.g., ?id=1)")
        return True
    except ValueError as e:
        logging.error(ga.red + f"[!] {str(e)}" + ga.end)
        return False

def get_default_payload_file(filename):
    try:
        with resources.path("troy.payloads", filename) as file_path:
            return str(file_path)
    except Exception as e:
        logging.error(ga.red + f"[!] Could not load default {filename}: {e}" + ga.end)
        sys.exit(1)

def scan_url(url, scan_type, xss_payloads_file, path_payloads_file, method, threads):
    if not validate_url(url):
        sys.exit(1)
    logging.info(ga.yellow + f"[+] Starting scan on {url}" + ga.end)

    # Use default payloads if not specified
    xss_payloads_file = xss_payloads_file or get_default_payload_file("xss_payloads.txt")
    path_payloads_file = path_payloads_file or get_default_payload_file("path_payloads.txt")

    if scan_type in ["xss", "all"]:
        logging.info(ga.yellow + "[!] Checking for XSS..." + ga.end)
        xss_scan(url, xss_payloads_file, threads)

    if scan_type in ["path", "all"]:
        logging.info(ga.yellow + "[!] Checking for Path Traversal..." + ga.end)
        traversal(url, path_payloads_file, method, threads)

def main():
    args = parse_arguments()
    scan_url(args.url, args.type, args.xss_payloads, args.path_payloads, args.method, args.threads)
    logging.info(ga.green + "[+] Scan complete. Check logs for details." + ga.end)

if __name__ == "__main__":
    main()