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
#from urllib.request import urlopen
from urllib.error import URLError
import nmap
from misc_modules import my_ruler
from misc_modules import resolve_url_to_ip

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
        domain_whois = whois.whois(target)
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
        return

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
    # Create a PortScanner object which will interface with Nmap
    scanner = nmap.PortScanner()

    try:
        # Run the Nmap scan on the host with the user-provided arguments (default: -sV -O)
        print(f"Running Nmap scan on {host}")
        scanner.scan(hosts=host, arguments="-sV -O -F")

        # Check if scan results are available
        if host not in scanner.all_hosts():
            return f"[ERROR] No scan results for {host}. Please check if the host is reachable."

        # Create a table to display results for open ports and their service versions
        table = PrettyTable()
        table.field_names = ["Protocol", "Port", "Service", "Version", "State"]

        # Iterate over all protocols (e.g., TCP, UDP) found by the scan
        for proto in scanner[host].all_protocols():
            # For each protocol, get the list of open ports, services, and their version
            for port in scanner[host][proto].keys():
                state = scanner[host][proto][port]['state']
                service = scanner[host][proto][port].get('name', 'N/A')
                version = scanner[host][proto][port].get('version', 'N/A')
                table.add_row([proto, port, service, version, state])

        # Get the OS detection result if available
        os_fingerprint = scanner[host].get("osmatch", [])
        os_info = "N/A"
        if os_fingerprint:
            os_info = os_fingerprint[0].get("name", "Unknown OS")

            # Filter out device-specific results by checking for common device keywords
            if "VoIP phone" in os_info or "router" in os_info or "camera" in os_info:
                os_info = "Device detected, OS not detected"  # Customize as needed

        # Capture Service Info (e.g., CPE info about the OS)
        service_info = scanner[host].get('hostnames', [])
        if 'osmatch' in scanner[host]:
            service_info = scanner[host].get('osmatch', [])

        cpe_info = "N/A"
        if 'osmatch' in scanner[host] and len(scanner[host]['osmatch']) > 0:
            cpe_info = scanner[host]['osmatch'][0].get('cpe', 'N/A')

        # Return the formatted table as a string, OS info, and Service Info
        return f"[INFO] Nmap Scan Results:\n{table}\n\n[INFO] OS Detection: {os_info}\n[INFO] CPE Info: {cpe_info}"

    except Exception as e:
        # If an error occurs (e.g., no connection, invalid host), handle it here
        return f"[ERROR] Nmap scan failed: {e}"
#========================================================================================================================
#Quick Scan
def nmap_scan2(host, nmap_arguments='-sS -p 1-1000'):
    # Create a PortScanner object which will interface with Nmap
    scanner = nmap.PortScanner()

    try:
        # Run the Nmap scan on the host with the user-provided arguments
        scanner.scan(hosts=host, arguments=nmap_arguments)

        # Create a table to display results
        table = PrettyTable()
        table.field_names = ["Protocol", "Port", "Service", "State"]  # Include the "Service" column

        # Iterate over all protocols (e.g., TCP, UDP) found by the scan
        for proto in scanner[host].all_protocols():
            # For each protocol, get the list of open ports and their state
            for port in scanner[host][proto].keys():
                state = scanner[host][proto][port]['state']
                service = scanner[host][proto][port].get('name', 'N/A')  # Get the service name for each port
                table.add_row([proto, port, service, state])  # Add service to the table row

        # Return the formatted table as a string
        return f"[INFO] Nmap Scan Results:\n{table}"

    except Exception as e:
        # If an error occurs (e.g., no connection, invalid host), handle it here
        return f"[ERROR] Nmap scan failed: {e}"



def nmap_scans(target):

#        target = input("\033[1;91m[+] Enter Domain or IP Address: \033[1;m").lower()
    case = input(
        """What type of scan would you like?
        [+]1. Quick Scan
        [+]2. Version Scan
        [+]3. Known Ports Scan
        Enter choice: """
    ).strip()  # Strip any accidental spaces

    os.system("clear" if os.name == "posix" else "cls")  # Clears terminal screen (Linux/Mac = clear, Windows = cls)

    print(f"\033[34m[~] Scanning with Nmap: \033[0m{target}")
    print("This will take a moment... Get some coffee 😃\n")

    if case == '1':
        nmap_scan1(target)
    elif case == '2':
        nmap_scan2(target)
    elif case == '3':
        pass  # Placeholder if you have a function for known ports scan
    else:
        print("\033[31m[!] Invalid entry. Please choose a valid option.\033[0m")

#IP address Tracker
#========================================================================================================================
def ip_finder(target):
    try:
        # target = input("\033[1;91m[+] Enter Domain or IP Address: \033[1;m").lower()
        url = ("http://ip-api.com/json/")
        response = urllib.request.urlopen(url + target)
        data = response.read()
        jso = json.loads(data)
        os.system("reset")
        print("\033[34m[~] Searching IP Location Finder: \033[0m".format(url) + target)
        time.sleep(1.5)

        print("\n [+] \033[34mUrl: " + target + "\033[0m")
        print(" [+] " + "\033[34m" + "IP: " + jso["query"] + "\033[0m")
        print(" [+] " + "\033[34m" + "Status: " + jso["status"] + "\033[0m")
        print(" [+] " + "\033[34m" + "Region: " + jso["regionName"] + "\033[0m")
        print(" [+] " + "\033[34m" + "Country: " + jso["country"] + "\033[0m")
        print(" [+] " + "\033[34m" + "City: " + jso["city"] + "\033[0m")
        print(" [+] " + "\033[34m" + "ISP: " + jso["isp"] + "\033[0m")
        print(" [+] " + "\033[34m" + "Lat & Lon: " + str(jso['lat']) + " & " + str(jso['lon']) + "\033[0m")
        print(" [+] " + "\033[34m" + "Zipcode: " + jso["zip"] + "\033[0m")
        print(" [+] " + "\033[34m" + "TimeZone: " + jso["timezone"] + "\033[0m")
        print(" [+] " + "\033[34m" + "AS: " + jso["as"] + "\033[0m" + "\n")
        my_ruler()
        print(" [+] " + "\033[34m" + "GOOGLE MAPS: " + "https://maps.google.com/?q=" + str(jso['lat']) + "," + str(jso['lon']) + "\033[0m")
    except URLError:
        print("\033[1;31m[-] Please provide a valid IP address!\033[1;m")



def run_recon_module():
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


    if choice == "1":
        host = input("Enter domain or IP to perform WHOIS lookup: ").strip()
        combined_whois_data = perform_combined_whois_lookup(host)
        display_combined_whois_data(combined_whois_data)
    elif choice == "2":
        url = input("Enter Target url:")
        target = resolve_url_to_ip(url)
        nmap_scans(target)
    elif choice == "3":
        url = input("Enter Target url:")
        target = resolve_url_to_ip(url)
        ip_finder(target)
    elif choice == "4":
        pass
    else:
        print("\n[!] Invalid choice. Please try again.")
        time.sleep(1)
