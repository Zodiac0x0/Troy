# troy/path_traversal.py
import logging
import requests
from .headers import *  # Relative import
from concurrent.futures import ThreadPoolExecutor, as_completed

# Logging Configuration
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] - [%(levelname)s] - %(message)s',
    handlers=[logging.StreamHandler(), logging.FileHandler('path_traversal_test.log')]
)

def test_payload(url, payload, method="GET"):
    print(ga.bold + "\n [!] Now Scanning for Path Traversal " + ga.end)
    print(ga.blue + " [!] Please wait ...." + ga.end)
    full_url = url + payload
    try:
        if method == "POST":
            response = requests.post(url, data={"file": payload}, timeout=5)
        else:
            response = requests.get(full_url, timeout=5)

        if response.status_code == 200:
            content = response.text
            content_size = len(content)
            if ("root:x:" in content or "[fonts]" in content or content_size > 1000):
                logging.info(ga.red + f"[*] Vulnerable! Payload: {payload}" + ga.end)
                logging.info(ga.blue + f"[*] POC: {full_url}" + ga.end)
                with open("vulnerable_urls.txt", "a") as vuln_file:
                    vuln_file.write(full_url + "\n")
                return True
        logging.info(ga.red + f"[-] Not Vulnerable: {payload}" + ga.end)
        return False
    except requests.RequestException as e:
        logging.error(ga.red + f"[!] HTTP Request Error: {e}" + ga.end)
        return False

def traversal(url, payload_file, method="GET", threads=10):
    try:
        with open(payload_file, 'r') as f:
            payloads = [line.strip() for line in f.readlines()]
        if not payloads:
            logging.warning(ga.red + "[!] No payloads found in the file." + ga.end)
            return

        logging.info(ga.yellow + f"[+] Loaded {len(payloads)} payloads for testing." + ga.end)

        vuln_count = 0
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(test_payload, url, payload, method) for payload in payloads]
            for future in as_completed(futures):
                if future.result():
                    vuln_count += 1

        logging.info(ga.green + f"[!] Path Traversal scan complete. Found {vuln_count} potential vulnerabilities." + ga.end)
    except FileNotFoundError:
        logging.error(ga.red + f"[!] Error: File '{payload_file}' not found." + ga.end)
    except Exception as e:
        logging.error(ga.red + f"[!] Unexpected Error: {e}" + ga.end)