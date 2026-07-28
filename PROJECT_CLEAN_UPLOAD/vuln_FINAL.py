import time

# import requests
import READING_CVE_DATABASE_LOOKUP
from misc_modules import my_ruler
import Session

# Misconfiguration Function
# =======================================================================================================================


import requests
import certifi
from requests.exceptions import RequestException, SSLError

def check_misconfigurations(url):
    findings = {
        "directory_listing": [],
        "missing_headers": [],
        "verbose_errors": False,
        "insecure_methods": []
    }

    try:
        response = requests.get(url, verify=certifi.where(), timeout=10)
        response_text = response.text
        headers = response.headers

        # ✅ Directory listing
        directories = ["/admin", "/backup", "/logs"]
        for directory in directories:
            test_url = f"{url.rstrip('/')}{directory}"
            dir_response = requests.get(test_url, timeout=10)
            if dir_response.status_code == 200 and "Index of" in dir_response.text:
                print(f"[!] Directory listing enabled at: {test_url}")
                findings["directory_listing"].append(test_url)
            else:
                print(f"[+] Directory listing is not enabled at: {test_url}")

        # ✅ Missing headers
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
                findings["missing_headers"].append({header: description})
            else:
                print(f"[+] Security header {header} is present.")

        # ✅ Verbose errors
        if "error" in response_text.lower() or "exception" in response_text.lower():
            print(f"[!] Verbose error messages detected at: {url}")
            findings["verbose_errors"] = True
        else:
            print(f"[+] No verbose error messages detected at: {url}")

        # ✅ Insecure HTTP methods
        options_response = requests.options(url, timeout=5)
        if "Allow" in options_response.headers:
            allowed_methods = options_response.headers["Allow"]
            for method in ["PUT", "DELETE", "TRACE"]:
                if method in allowed_methods:
                    print(f"[!] HTTP method {method} is enabled at: {url}")
                    findings["insecure_methods"].append(method)

            if not findings["insecure_methods"]:
                print(f"[+] No insecure HTTP methods enabled at: {url}")

    except RequestException as e:
        print(f"[!] Failed to connect to {url}: {e}")
    except SSLError as ssl_err:
        print("[!] SSL certificate verification failed:", ssl_err)

    return findings


# =======================================================================================================================


def run_scan(url):
    # raw_url = input("Enter URL to scan (include http:// or https://): ").strip()
    # url = raw_url if raw_url.startswith(('http://', 'https://')) else 'http://' + raw_url

    print(
        '''
        VULNERABILITY SCAN Module:

        1. Misconfigurations Check
        2. CVE LOOKUPS
        3. quit

        '''
    )
    choice = input("\nWhat would you like to do? (1-3): ").strip()
    my_ruler()
    
    if choice == "1":
        my_ruler()
        print("Checking for Misconfigurations...")
        # Misconfiguration Function
        misconfiguration = check_misconfigurations(url)
        Session.session.append({"type": "vuln_MISCONFIGCHECKS", "data": misconfiguration})
        time.sleep(1)
        my_ruler()
    elif choice == "2":
        my_ruler()
        print("Checking for Known Vulnerabilities on the server...")
        # Checking Vulnerability Local Database:
        cve_lookup = READING_CVE_DATABASE_LOOKUP.start(url)
        Session.session.append({"type": "vuln_CVELOOKUP", "data": cve_lookup})
        time.sleep(2)
        my_ruler()
    elif choice == "3":
        pass
    else:
        print("\n[!] Invalid choice. Please try again.")
        time.sleep(1)

# vuln function
#run_scan()
