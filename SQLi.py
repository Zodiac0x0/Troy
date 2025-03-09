from vulnz import main_function
import re
from headers import *

def error_based_sqli_func(url):
    print(ga.bold + "\n [!] Now Scanning for Error Based SQL Injection " + ga.end)
    print(ga.blue + " [!] Covering MySQL, Oracle, MSSQL, MSACCESS & PostGreSQL Databases " + ga.end)
    print(ga.blue + " [!] Please wait ...." + ga.end)

    payloads = ["3'", "3%5c", "3%27%22%28%29", "3'><", "3%22%5C%27%5C%22%29%3B%7C%5D%2A%7B%250d%250a%3C%2500%3E%25bf%2527%27"]

    check = re.compile("Incorrect syntax|Syntax error|Unclosed.+mark|unterminated.+qoute|SQL.+Server|Microsoft.+Database|Fatal.+error", re.I)
    main_function(url, payloads, check)
