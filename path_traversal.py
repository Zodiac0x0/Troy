from headers import *
import logging
import requests
import argparse
import concurrent.futures

# Logging Configuration
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] - [%(levelname)s] - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('path_traversal_test.log')
    ]
)

def test_payload(url, payload, method="GET"):
    print(ga.bold + "\n [!] Now Scanning for XSS " + ga.end)
    print(ga.blue + " [!] Please wait ...." + ga.end)
    full_url = url + payload
    try:
        if method == "POST":
            response = requests.post(url, data={"file": payload}, timeout=5)
        else:
            response = requests.get(full_url, timeout=5)

        if response.status_code == 200 and ("root:x:" in response.text or "[fonts]" in response.text):
            logging.info(f"[*] Vulnerable! Payload: {payload}")
            with open("vulnerable_urls.txt", "a") as vuln_file:
                vuln_file.write(full_url + "\n")  # Save to file
        else:
            logging.info(ga.red + f"[-] Not Vulnerable: {payload}" + ga.end)

    except requests.exceptions.RequestException as e:
        logging.error(ga.red + f"[!] HTTP Request Error: {e}" + ga.end)

def traversal(url, payload_file, method="GET", threads=10):
    try:
        with open(payload_file, 'r') as f:
            payloads = [line.strip() for line in f.readlines()]

        if not payloads:
            logging.warning(ga.red + "[!] No payloads found in the file."+ ga.end)
            return

        logging.info(ga.yellow + f"[+] Loaded {len(payloads)} payloads for testing." + ga.end)

        # Multithreading for faster execution
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(test_payload, url, payload, method) for payload in payloads]
            concurrent.futures.wait(futures)

    except FileNotFoundError:
        logging.error(ga.red + f"[!] Error: File '{payload_file}' not found."+ ga.end)
    except Exception as e:
        logging.error(ga.red + f"[!] Unexpected Error: {e}" + ga.end)


parser = argparse.ArgumentParser(description="Path Traversal Scanner")
parser.add_argument("url", help="Target URL (e.g., http://example.com/?file=)")
parser.add_argument("payload_file", help="File containing payloads")
parser.add_argument("--method", choices=["GET", "POST"], default="GET", help="HTTP request method (default: GET)")
parser.add_argument("--threads", type=int, default=10, help="Number of threads (default: 10)")

args = parser.parse_args()
traversal(args.url, args.payload_file, args.method, args.threads)