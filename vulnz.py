import requests
import re
from headers import *

def main_function(url, payloads, check):
    print(ga.blue + " [!] Sending requests with payloads..." + ga.end)
    vuln = 0
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:22.0) Gecko/20100101 Firefox/22.0'
    }
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            print(ga.green + " [!] Initial connection successful" + ga.end)
        else:
            print(ga.red + f" [!] HTTP Error: {response.status_code}" + ga.end)
            return
    except requests.RequestException as e:
        print(ga.red + f" [!] Connection Error: {e}" + ga.end)
        return
    
    if "?" not in url:
        print(ga.red + " [!] No parameters found in the URL!" + ga.end)
        return

    for params in url.split("?")[1].split("&"):
        for payload in payloads:
            bugs = url.replace(params, params + str(payload).strip())
            try:
                res = requests.get(bugs, headers=headers)
                html = res.text  
                
                if re.search(check, html):  
                    print(ga.red + " [*] Payload Found . . ." + ga.end)
                    print(ga.red + f" [*] Payload: {payload}" + ga.end)
                    print(ga.green + " [!] Code Snippet: " + ga.end + re.findall(check, html)[0])
                    print(ga.blue + " [*] POC: " + ga.end + bugs)
                    print(ga.green + " [*] Happy Exploitation :D" + ga.end)
                    vuln += 1

            except requests.RequestException:
                continue  

    if vuln == 0:
        print(ga.green + " [!] Target is not vulnerable!" + ga.end)
    else:
        print(ga.blue + f" [!] Congratulations, you've found {vuln} bugs :-)" + ga.end)