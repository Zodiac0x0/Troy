# 🌐 Troy - Simple Web Applications Security Scanner  
### by **Omar Islam** - X [@Zodiac_0x0](https://x.com/Zodiac_0x0) - Github [Zodiac0x0](https://github.com/Zodiac0x0)  

## 🚀 About Troy  
Troy is a web security scanner focused on detecting:  
✔️ **Cross-Site Scripting (XSS)**  
✔️ **Path Traversal Attacks**  

## 🛠 Installation  
### Option 1: Install via pip from GitHub  
```bash
pip install git+https://github.com/Zodiac0x0/Troy.git
```
### Option 2: Install via Clone
```bash
git clone https://github.com/Zodiac0x0/Troy.git
cd Troy
pip install .
```

## Usage
Once installed, run Troy from the command line using the troy command:


```bash
troy --url "http://example.com/?id=1" --type all
Command-Line Options
--url: Target URL to scan (required). Example: http://example.com/?id=1
--type: Scan type: xss, path, or all (default: all)
--xss-payloads: File containing XSS payloads (default: xss.txt)
--path-payloads: File containing Path Traversal payloads (default: paths.txt)
--method: HTTP method for Path Traversal: GET or POST (default: GET)
--threads: Number of concurrent threads (default: 10)
```
## Example Usage

### Scanning For Xss
```bash
troy --url "http://localhost/dvwa/vulnerabilities/xss_r/?name=test" --type xss --xss-payloads xss.txt
```
### Scanning For Path Traversal
```bash
troy --url "http://localhost/dvwa/vulnerabilities/fi/?page=test" --type path --path-payloads paths.txt --method GET
```

### Output:
         Results are logged to web_scan.log (general), xss_scan.log (XSS), and path_traversal_test.log(PathTraversal) 
         Vulnerable URLs are saved to vulnerable_urls.txt for Path Traversal
## Notes 
    Legal Use: Test only on systems you own or have permission to scan (e.g., DVWA).
    Limitations: Basic detection only; no advanced exploitation or crawling.
# Contact
### **Follow me on - X [@Zodiac_0x0](https://x.com/Zodiac_0x0) For Any Questions**