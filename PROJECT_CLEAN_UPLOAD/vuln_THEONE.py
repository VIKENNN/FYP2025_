import time

#import requests
from requests.exceptions import SSLError
import reading_cve_valid

#Misconfiguration Function
#=======================================================================================================================
import requests
from requests.exceptions import RequestException
import certifi


def check_misconfigurations(url):
    try:
        response = requests.get(url, verify=certifi.where(), timeout=10)  # Single request with timeout
        response_text = response.text  # Store response text to avoid repeated fetching
        headers = response.headers  # Store headers
        
        # ✅ Check for directory listing (only append paths if the base URL works)
        directories = ["/admin", "/backup", "/logs"]
        for directory in directories:
            test_url = f"{url.rstrip('/')}{directory}"  # Normalize URL
            dir_response = requests.get(test_url, timeout=10)
            if dir_response.status_code == 200 and "Index of" in dir_response.text:
                print(f"[!] Directory listing enabled at: {test_url}")
            else:
                print(f"[+] Directory listing is not enabled at: {test_url}")
        
        # ✅ Check for missing security headers
        security_headers = {
            "Content-Security-Policy": "Mitigates XSS and other injection attacks.",
            "X-Frame-Options": "Prevents clickjacking attacks.",
            "X-Content-Type-Options": "Blocks MIME-type sniffing.",
            "Strict-Transport-Security": "Enforces HTTPS.",
            "Referrer-Policy": "Controls referrer information sent with requests.",
            "Permissions-Policy": "Limits browser feature access (e.g., camera, microphone).",
            "Cache-Control": "Prevents sensitive data from being cached.",
            "Pragma": "Legacy header for cache control.",
            "Expect-CT": "Helps detect and enforce certificate transparency.",
            "Cross-Origin-Embedder-Policy": "Enhances security for embedding resources.",
            "Cross-Origin-Opener-Policy": "Prevents cross-origin attacks.",
            "Cross-Origin-Resource-Policy": "Restricts resource sharing.",
            "X-Permitted-Cross-Domain-Policies": "Controls Flash/Silverlight cross-domain requests.",
            "Access-Control-Allow-Origin": "Manages cross-origin resource sharing (CORS)."
        }
        
        for header, description in security_headers.items():
            if header not in headers:
                print(f"[!] Missing security header: {header} - {description}")
            else:
                print(f"[+] Security header {header} is present.")
        
        # ✅ Check for verbose error messages
        if "error" in response_text.lower() or "exception" in response_text.lower():
            print(f"[!] Verbose error messages detected at: {url}")
        else:
            print(f"[+] No verbose error messages detected at: {url}")
        
        # ✅ Check for unnecessary HTTP methods
        options_response = requests.options(url, timeout=5)
        if "Allow" in options_response.headers:
            allowed_methods = options_response.headers["Allow"]
            found_insecure_method = False
            for method in ["PUT", "DELETE", "TRACE"]:
                if method in allowed_methods:
                    print(f"[!] HTTP method {method} is enabled at: {url}")
                    found_insecure_method = True
            if not found_insecure_method:
                print(f"[+] No insecure HTTP methods enabled at: {url}")
    
    except RequestException as e:
        print(f"[!] Failed to connect to {url}: {e}")
    except SSLError as ssl_err:
        print("[!] SSL certificate verification failed:", ssl_err)
#=======================================================================================================================


def run_scan():
    # nvd_feeds_dir = "nvd_feeds"
    url = input("Enter URL to scan (include http:// or https://): ").strip()
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url  # Default to HTTP if no scheme provided
    print("Checking for Misconfigurations...")
    # Misconfiguration Function
    check_misconfigurations(url)
    time.sleep(1)
    print("Checking for Known Vulnerabilities on the server...")
    # Checking Vulnerability Local Database:
    reading_cve_valid.get_cve_details(url)
    time.sleep(2)
    
#vuln function
run_scan()