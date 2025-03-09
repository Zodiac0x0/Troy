#!/usr/bin/env python
# WebPwn3r is a Web Applications Security Scanner
# By Ebrahim Hegazy - twitter.com/zigoo0
# First demo conducted 12Apr-2014 @OWASP Chapter Egypt
# https://www.owasp.org/index.php/Cairo
import urllib.request
import sys
class colors:
    def __init__(self):
        # Red: Warnings or critical findings (e.g., XSS detected)
        self.red = "\033[91m"
        # Yellow: Ongoing actions or progress (e.g., trying a payload)
        self.yellow = "\033[93m"
        # Blue: Informational messages (e.g., instructions, POCs)
        self.blue = "\033[94m"
        # Green: Success or safe results (e.g., no vulnerabilities)
        self.green = "\033[92m"
        # Bold: Emphasis for key messages (e.g., headers)
        self.bold = "\033[1m"
        # End: Reset color to default
        self.end = "\033[0m"
ga = colors()

class HTTP_HEADER:
    HOST = "Host"
    SERVER = "Server"

def headers_reader(url):
    print(ga.bold + " \n [!] Fingerprinting the backend Technologies." + ga.end)
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:22.0) Gecko/20100101 Firefox/22.0'
    }
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req) as opener:
            print(ga.green + " [!] Status code: 200 OK" + ga.end)
            server = opener.headers.get(HTTP_HEADER.SERVER, "Not disclosed")
            host = url.split("/")[2]
            print(ga.green + " [!] Host: " + str(host) + ga.end)
            print(ga.green + " [!] WebServer: " + str(server) + ga.end)
            for header, value in opener.headers.items():
                if header.lower() == "x-powered-by":
                    print(ga.green + " [!] " + str(value).strip() + ga.end)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            print(ga.red + " [!] Page was not found! Please check the URL \n" + ga.end)
            sys.exit(1)
    except Exception as e:
        print(ga.red + f" [!] Error: {str(e)}" + ga.end)
        sys.exit(1)
