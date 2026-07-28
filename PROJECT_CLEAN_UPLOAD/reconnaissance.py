import json
import os
import whois
import re
import subprocess
from prettytable import PrettyTable
#import nmap
import time
import urllib
import urllib.request
from urllib.error import URLError
import nmap
from misc_modules import my_ruler
from misc_modules import resolve_url_to_ip
import Session


#WHOIS Function
#=======================================================================================================================
def perform_combined_whois_lookup(target):
    """
    Perform a WHOIS lookup combining the whois module and raw terminal output for reliability.
    """
    combined_data = {}

    # Step 1: Query with whois module
    try:
        print("[INFO] Querying WHOIS module...")
        domain = target
        domain_whois = whois.whois(domain)
        combined_data["Creation Date"] = domain_whois.creation_date
        combined_data["Expiration Date"] = domain_whois.expiration_date
        combined_data["Last Updated"] = domain_whois.updated_date
        combined_data["Registrar"] = domain_whois.registrar
        combined_data["Domain Status"] = domain_whois.status
        combined_data["Name Servers"] = ", ".join(domain_whois.name_servers or [])
    except Exception as e:
        print(f"[WARNING] WHOIS module failed: {e}")

    # Step 2: Query with raw terminal output
    try:
        print("[INFO] Querying raw WHOIS output...")
        raw_output = run_terminal_whois(target)
        if raw_output:
            parsed_raw_data = parse_raw_whois_output(raw_output)
            combined_data.update({k: v for k, v in parsed_raw_data.items() if v != "Not Available"})
    except Exception as e:
        print(f"[ERROR] Failed to query raw WHOIS: {e}")

    return combined_data


def run_terminal_whois(target):
    """
    Execute the WHOIS command in the terminal and return raw output.
    """
    ip = resolve_url_to_ip(target)
    try:
        result = subprocess.run(["whois", ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
            return result.stdout
        else:
            print("[ERROR] WHOIS command failed.")
            return None
    except Exception as e:
        print(f"[ERROR] Exception during terminal WHOIS lookup: {e}")
        return None


def parse_raw_whois_output(raw_output):
    """
    Parse raw WHOIS output to extract additional fields not covered by the whois module.
    """
    parsed_data = {}

    # Regex patterns for parsing specific fields
    patterns = {
        "IP Range": r"inetnum:\s*(.+)",
        "Net Name": r"netname:\s*(.+)",
        "Description": r"descr:\s*(.+)",
        "Country": r"country:\s*(.+)",
        "Organization": r"org-name:\s*(.+)",
        "Maintainers": r"mnt-by:\s*(.+)",
    }

    for key, pattern in patterns.items():
        match = re.search(pattern, raw_output, re.IGNORECASE)
        parsed_data[key] = match.group(1).strip() if match else "Not Available"

    # Extract contact details
    contacts = []
    for contact_match in re.finditer(
        r"person:\s*(.+?)\n.*?address:\s*((?:.+\n)+?)phone:\s*((?:tel:.+\n)+)",
        raw_output,
        re.IGNORECASE,
    ):
        contact = {
            "Name": contact_match.group(1).strip(),
            "Address": ", ".join([line.strip() for line in contact_match.group(2).strip().split("\n")]),
            "Phone": ", ".join([line.strip() for line in contact_match.group(3).strip().split("\n")]),
        }
        contacts.append(contact)
    parsed_data["Contacts"] = contacts

    return parsed_data


def display_combined_whois_data(data):
    """
    Display the combined WHOIS data in a structured format.
    """
    if not data:
        print("[INFO] No data available.")
        return {"whois": "No data available"}
    
    
    print("\n[WHOIS Lookup Results]")
    print(f"Creation Date: {data.get('Creation Date', 'Not Available')}")
    print(f"Expiration Date: {data.get('Expiration Date', 'Not Available')}")
    print(f"Last Updated: {data.get('Last Updated', 'Not Available')}")
    print(f"Registrar: {data.get('Registrar', 'Not Available')}")
    print(f"Domain Status: {data.get('Domain Status', 'Not Available')}")
    print(f"Name Servers: {data.get('Name Servers', 'Not Available')}")

    print("\n--- Network Information ---")
    print(f"IP Range: {data.get('IP Range', 'Not Available')}")
    print(f"Net Name: {data.get('Net Name', 'Not Available')}")
    print(f"Description: {data.get('Description', 'Not Available')}")
    print(f"Country: {data.get('Country', 'Not Available')}")
    print(f"Organization: {data.get('Organization', 'Not Available')}")
    print(f"Maintainers: {data.get('Maintainers', 'Not Available')}")

    print("\n--- Contact Details ---")
    if data.get("Contacts"):
        for contact in data["Contacts"]:
            print(f"Name: {contact['Name']}")
            print(f"Address: {contact['Address']}")
            print(f"Phone: {contact['Phone']}")
            print("---")
    else:
        print("No contact details found.")
        
        # --- returning structured values ---
    return {
        "whois": {
            "Creation Date": data.get("Creation Date", "Not Available"),
            "Expiration Date": data.get("Expiration Date", "Not Available"),
            "Last Updated": data.get("Last Updated", "Not Available"),
            "Registrar": data.get("Registrar", "Not Available"),
            "Domain Status": data.get("Domain Status", "Not Available"),
            "Name Servers": data.get("Name Servers", "Not Available"),
            "IP Range": data.get("IP Range", "Not Available"),
            "Net Name": data.get("Net Name", "Not Available"),
            "Description": data.get("Description", "Not Available"),
            "Country": data.get("Country", "Not Available"),
            "Organization": data.get("Organization", "Not Available"),
            "Maintainers": data.get("Maintainers", "Not Available"),
            "Contacts": data.get("Contacts", []),
        }
    }
    
#=======================================================================================================================

def dns_lookup(target):
    try:
#        target = input("\033[1;91m[+] Enter Domain or IP Address: \033[1;m").lower()
        os.system("reset")
        print("\033[34m[~] Searching for DNS Lookup: \033[0m".format(target) + target)
        time.sleep(1.5)
        command = ("dig " + target + " +trace ANY")
        proces = os.popen(command)
        results = str(proces.read())
        print(results + command)

    except Exception:
        pass

#PortScans
#=======================================================================================================================
#Version Scan
def nmap_scan1(host):
    scanner = nmap.PortScanner()
    try:
        scanner.scan(hosts=host, arguments="-sV -O -F")
        if host not in scanner.all_hosts():
            return {"error": f"No scan results for {host}"}

        results = []
        for proto in scanner[host].all_protocols():
            for port in scanner[host][proto].keys():
                state = scanner[host][proto][port]['state']
                service = scanner[host][proto][port].get('name', 'N/A')
                version = scanner[host][proto][port].get('version', 'N/A')
                results.append({
                    "Protocol": proto,
                    "Port": port,
                    "Service": service,
                    "Version": version,
                    "State": state
                })

        os_fingerprint = scanner[host].get("osmatch", [])
        os_info = os_fingerprint[0].get("name", "Unknown OS") if os_fingerprint else "N/A"
        cpe_info = os_fingerprint[0].get("cpe", "N/A") if os_fingerprint else "N/A"

        return {
            "scan_type": "Version Scan",
            "results": results,
            "os_info": os_info,
            "cpe_info": cpe_info
        }

    except Exception as e:
        return {"error": str(e)}
#========================================================================================================================
#Quick Scan
def nmap_scan2(host, nmap_arguments='-sS -p 1-1000'):
    scanner = nmap.PortScanner()
    try:
        scanner.scan(hosts=host, arguments=nmap_arguments)

        results = []
        for proto in scanner[host].all_protocols():
            for port in scanner[host][proto].keys():
                state = scanner[host][proto][port]['state']
                service = scanner[host][proto][port].get('name', 'N/A')
                results.append({
                    "Protocol": proto,
                    "Port": port,
                    "Service": service,
                    "State": state
                })

        return {
            "scan_type": "Quick Scan",
            "results": results
        }

    except Exception as e:
        return {"error": str(e)}



def nmap_scans(target):
    case = input(
        """What type of scan would you like?
        [+]1. Quick Scan
        [+]2. Version Scan
        [+]3. Known Ports Scan
        Enter choice: """
    ).strip()

    os.system("clear" if os.name == "posix" else "cls")

    print(f"\033[34m[~] Scanning with Nmap: \033[0m{target}")
    print("This will take a moment... Get some coffee 😃\n")

    # Run the appropriate scan
    if case == '1':
        result = nmap_scan2(target)   # Quick Scan
    elif case == '2':
        result = nmap_scan1(target)   # Version Scan
    elif case == '3':
        print("[INFO] Known Ports Scan not yet implemented.")
        return None
    else:
        print("\033[31m[!] Invalid entry. Please choose a valid option.\033[0m")
        return None

    # If there was an error
    if "error" in result:
        print(f"\033[31m[!] {result['error']}\033[0m")
        return result

    # Prepare PrettyTable for terminal output
    if "results" in result and result["results"]:
        table = PrettyTable()
        headers = list(result["results"][0].keys())
        table.field_names = headers
        for row in result["results"]:
            table.add_row([row[h] for h in headers])
        print(f"[INFO] Nmap Scan Results: {result.get('scan_type', '')}\n")
        print(table)

        # Optional OS / CPE info
        if "os_info" in result:
            print(f"[INFO] OS Detection: {result['os_info']}")
        if "cpe_info" in result:
            print(f"[INFO] CPE Info: {result['cpe_info']}")

    return result

#IP address Tracker
#========================================================================================================================
def ip_finder(target):
    try:
        url = "http://ip-api.com/json/"
        response = urllib.request.urlopen(url + target)
        data = response.read()
        jso = json.loads(data)
        
        result = {
            "URL": target,
            "IP": jso.get("query", "N/A"),
            "Status": jso.get("status", "N/A"),
            "Region": jso.get("regionName", "N/A"),
            "Country": jso.get("country", "N/A"),
            "City": jso.get("city", "N/A"),
            "ISP": jso.get("isp", "N/A"),
            "Latitude": jso.get("lat", "N/A"),
            "Longitude": jso.get("lon", "N/A"),
            "Zipcode": jso.get("zip", "N/A"),
            "Timezone": jso.get("timezone", "N/A"),
            "AS": jso.get("as", "N/A"),
            "Google Maps": f"https://maps.google.com/?q={jso.get('lat')},{jso.get('lon')}"
        }
        
        # --- Optional: pretty print for CLI ---
        os.system("reset")
        print("\033[34m[~] Searching IP Location Finder: \033[0m" + target)
        time.sleep(1.5)
        
        for key, val in result.items():
            print(f" [+] \033[34m{key}: {val}\033[0m")
        print()
        my_ruler()
        
        return result
    
    except URLError:
        print("\033[1;31m[-] Please provide a valid IP address!\033[1;m")
        return None

def run_recon_module(url, host):
    target = resolve_url_to_ip(url)
    print(
        '''
        Reconnaissance Module:

        1. Whois
        2. PortScans
        3. Ip Locator
        4. quit

        '''
    )
    choice = input("\nWhat would you like to do? (1-4): ").strip()
    my_ruler()

    if choice == "1":
        combined_whois_data = perform_combined_whois_lookup(target)
        whois_data = display_combined_whois_data(combined_whois_data)
        if whois_data:  # append only if valid
            Session.session.append({"type": "reconnaissance_WHOSIS", "data": whois_data})

    elif choice == "2":
        scan_values = nmap_scans(target)
        if scan_values:  # append only if valid
            Session.session.append({"type": "reconnaissance_PORTSCAN", "data": scan_values})

    elif choice == "3":
        ip_info = ip_finder(target)
        if ip_info:  # append only if valid
            Session.session.append({"type": "reconnaissance_IPLOCATE", "data": ip_info})

    elif choice == "4":
        pass
    else:
        print("\n[!] Invalid choice. Please try again.")
        time.sleep(1)



#run_recon_module(url, host)