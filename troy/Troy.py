#!/usr/bin/env python
# Troy - Web Applications Security Scanner
# by Omar Islam x.com/Zodiac_0x0
import sys
import logging
import argparse
from filetool.Troy.troy.headers import *  # Assumes ga for colored output
from path_traversal import traversal
from filetool.Troy.troy.XSS import xss_scan

# Logging Configuration
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] - [%(levelname)s] - %(message)s',
    handlers=[logging.StreamHandler(), logging.FileHandler('web_scan.log')]
)
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


def parse_arguments():
    parser = argparse.ArgumentParser(description="Troy - XSS and Path Traversal Scanner")
    parser.add_argument("--url", required=True, help="Target URL (e.g., http://example.com/?id=1)")
    parser.add_argument("--type", choices=["xss", "path", "all"], default="all", help="Scan type: xss, path, or all")
    parser.add_argument("--xss-payloads", default="xss_payloads.txt", help="File with XSS payloads")
    parser.add_argument("--path-payloads", default="path_payloads.txt", help="File with Path Traversal payloads")
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

def scan_url(url, scan_type, xss_payloads_file, path_payloads_file, method, threads):
    if not validate_url(url):
        sys.exit(1)
    logging.info(ga.yellow + f"[+] Starting scan on {url}" + ga.end)

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

