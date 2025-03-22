import re
import logging
from filetool.Troy.troy.headers import *
import requests
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configure logging 
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] - [%(levelname)s] - %(message)s',
    handlers=[logging.StreamHandler(), logging.FileHandler('xss_scan.log')]
)

# Precompile regex patterns once for all payloads
def load_payloads(payloads_file):
    with open(payloads_file, 'r') as f:
        payloads = [line.strip() for line in f if line.strip()]
    return payloads, [re.compile(re.escape(payload), re.I) for payload in payloads]

# Check for XSS in response
def check_xss(response, payload_patterns):
    content = response.text
    for pattern in payload_patterns:
        if pattern.search(content):
            return True
    return False

# Test a single URL for XSS
def test_url(test_url, payload_patterns):
    try:
        response = requests.get(test_url, timeout=5)
        if response.status_code == 200 and check_xss(response, payload_patterns):
            logging.warning(ga.red + "[*] Possible XSS Vulnerability Found!" + ga.end)
            logging.warning(ga.blue + f"[*] POC: {test_url}" + ga.end)
    except requests.RequestException as e:
        logging.error(ga.red + f"[!] Request failed for {test_url}: {e}" + ga.end)

# Main XSS scanning function
def xss_scan(url, payloads_file):
    logging.info(ga.yellow + "[!] Starting XSS scan..."+ ga.end)

    try:
        # Load and cache payloads once
        payloads, payload_patterns = load_payloads(payloads_file)

        # Parse URL once
        parsed_url = urllib.parse.urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        params = urllib.parse.parse_qs(parsed_url.query)

        if not params:
            logging.warning(ga.red+ "[!] No query parameters found in URL."+ ga.end)
            return

        # Test URLs concurrently
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for param_name in params.keys():
                for payload in payloads:
                    test_params = {k: v for k, v in params.items()}
                    test_params[param_name] = payload
                    test_url = base_url + "?" + urllib.parse.urlencode(test_params, doseq=True)
                    futures.append(executor.submit(test_url, test_url, payload_patterns))

            # Process results as they complete
            for future in as_completed(futures):
                future.result()  # Exceptions are raised here if any

        logging.info(ga.yellow + "[!] Scan complete. Check log for results." + ga.end)

    except FileNotFoundError:
        logging.error(ga.red + f"[!] Payloads file '{payloads_file}' not found!"+ ga.end)
    except Exception as e:
        logging.error(ga.red + f"[!] Unexpected error: {e}"+ ga.end)