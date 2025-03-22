# troy/XSS.py
import re
import logging
import requests
import urllib.parse
from .headers import *  # Relative import
from concurrent.futures import ThreadPoolExecutor, as_completed

# Logging Configuration
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] - [%(levelname)s] - %(message)s',
    handlers=[logging.StreamHandler(), logging.FileHandler('xss_scan.log')]
)

def load_payloads(payloads_file):
    try:
        with open(payloads_file, 'r') as f:
            payloads = [line.strip() for line in f if line.strip()]
        if not payloads:
            raise ValueError("Payload file is empty")
        return payloads
    except FileNotFoundError:
        logging.error(ga.red + f"[!] Payloads file '{payloads_file}' not found!" + ga.end)
        return []
    except ValueError as e:
        logging.error(ga.red + f"[!] {str(e)}" + ga.end)
        return []

def test_url(test_url, payload):
    try:
        response = requests.get(test_url, timeout=5)
        if response.status_code == 200:
            content = response.text.lower()
            payload_lower = payload.lower()
            if payload_lower in content or re.search(r"(alert|onerror|script)", content, re.I):
                logging.warning(ga.red + "[*] Possible XSS Vulnerability Found!" + ga.end)
                logging.warning(ga.blue + f"[*] Payload: {payload}" + ga.end)
                logging.warning(ga.blue + f"[*] POC: {test_url}" + ga.end)
                return True
        return False
    except requests.RequestException as e:
        logging.error(ga.red + f"[!] Request failed for {test_url}: {e}" + ga.end)
        return False

def xss_scan(url, payloads_file, threads=10):
    logging.info(ga.yellow + "[!] Starting XSS scan..." + ga.end)

    payloads = load_payloads(payloads_file)
    if not payloads:
        return

    parsed_url = urllib.parse.urlparse(url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
    params = urllib.parse.parse_qs(parsed_url.query)

    if not params:
        logging.warning(ga.red + "[!] No query parameters found in URL." + ga.end)
        return

    vuln_count = 0
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        for param_name in params.keys():
            for payload in payloads:
                test_params = {k: v for k, v in params.items()}
                test_params[param_name] = payload
                test_url = base_url + "?" + urllib.parse.urlencode(test_params, doseq=True)
                futures.append(executor.submit(test_url, test_url, payload))

        for future in as_completed(futures):
            if future.result():
                vuln_count += 1

    logging.info(ga.green + f"[!] XSS scan complete. Found {vuln_count} potential vulnerabilities." + ga.end)