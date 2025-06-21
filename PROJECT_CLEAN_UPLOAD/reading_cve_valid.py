import os
import json
import re
import requests
import certifi
from packaging import version
from packaging.version import parse as parse_version
from tabulate import tabulate
from textwrap import fill
from requests.exceptions import SSLError, RequestException, Timeout


def normalize_version(version_str):
	"""Normalize version strings, stripping suffixes and invalid chars."""
	if not version_str:
		return ""
	version_str = str(version_str).lower()
	version_str = re.sub(r'^v', '', version_str)  # Remove leading 'v'
	version_str = re.sub(r'[^a-z0-9.+]+.*$', '', version_str)  # Strip suffixes
	version_str = re.sub(r'(\.0+)+$', '', version_str)  # Remove trailing .0's
	return version_str


def get_affected_versions_string(cpe_version, start_inc, end_inc, start_exc, end_exc):
	"""Generate human-readable string of affected version range"""
	if cpe_version and cpe_version != "*":
		return f"Version {cpe_version}"
	
	parts = []
	if start_inc:
		parts.append(f">= {start_inc}")
	elif start_exc:
		parts.append(f"> {start_exc}")
	
	if end_inc:
		parts.append(f"<= {end_inc}")
	elif end_exc:
		parts.append(f"< {end_exc}")
	
	return " ".join(parts) if parts else "Unknown"


def is_strictly_vulnerable(current_version, cpe_version, version_start, version_end, version_start_ex, version_end_ex):
	"""
	Strict version comparison that only returns True when:
	- Exact version matches (when specified)
	- Version falls within ALL specified boundaries
	- Not excluded by any exclusion boundaries
	"""
	try:
		current = parse_version(current_version)
		vulnerable = False
		has_boundaries = False
		
		# Case 1: Exact version match (when specified and not wildcard)
		if cpe_version and cpe_version != "*":
			return current == parse_version(cpe_version)
		
		# Case 2: Version range check
		# Check if version is above minimum (inclusive)
		if version_start:
			has_boundaries = True
			if current >= parse_version(version_start):
				vulnerable = True
			else:
				return False
		
		# Check if version is above minimum (exclusive)
		if version_start_ex:
			has_boundaries = True
			if current > parse_version(version_start_ex):
				vulnerable = True
			else:
				return False
		
		# Check if version is below maximum (inclusive)
		if version_end:
			has_boundaries = True
			if current <= parse_version(version_end):
				vulnerable = True
			else:
				return False
		
		# Check if version is below maximum (exclusive)
		if version_end_ex:
			has_boundaries = True
			if current < parse_version(version_end_ex):
				vulnerable = True
			else:
				return False
		
		# If no boundaries specified, assume not vulnerable
		return vulnerable if has_boundaries else False
	
	except version.InvalidVersion:
		# Fallback to string comparison if version parsing fails
		current_norm = normalize_version(current_version)
		vulnerable = False
		has_boundaries = False
		
		if cpe_version and cpe_version != "*":
			return current_norm == normalize_version(cpe_version)
		
		if version_start:
			has_boundaries = True
			if current_norm >= normalize_version(version_start):
				vulnerable = True
			else:
				return False
		
		if version_start_ex:
			has_boundaries = True
			if current_norm > normalize_version(version_start_ex):
				vulnerable = True
			else:
				return False
		
		if version_end:
			has_boundaries = True
			if current_norm <= normalize_version(version_end):
				vulnerable = True
			else:
				return False
		
		if version_end_ex:
			has_boundaries = True
			if current_norm < normalize_version(version_end_ex):
				vulnerable = True
			else:
				return False
		
		return vulnerable if has_boundaries else False


def load_cve_database(directory="nvd_feeds"):
	"""Stream through CVE JSON files one by one to prevent memory overload"""
	for filename in os.listdir(directory):
		if filename.endswith(".json"):
			file_path = os.path.join(directory, filename)
			try:
				with open(file_path, "r", encoding='utf-8') as f:
					data = json.load(f)
					yield from data.get("CVE_Items", [])
			except (FileNotFoundError, json.JSONDecodeError) as e:
				print(f"[!] Skipping {file_path}: {e}")


def search_cves(directory, software, current_version):
	"""Search CVE data for matching software and vulnerable versions"""
	# Expanded CPE mapping with common web technologies
	cpe_mapping = {
		"Apache HTTP Server": ["apache:http_server", "httpd"],
		"Apache Tomcat": ["apache:tomcat"],
		"Nginx": ["nginx:nginx", "f5:nginx"],
		"Microsoft-IIS": ["microsoft:iis"],
		"PHP": ["php:php"],
		"Node.js": ["nodejs:node"],
		"WordPress": ["wordpress:wordpress"],
		"Drupal": ["drupal:drupal"],
		"MySQL": ["mysql:mysql"],
		"PostgreSQL": ["postgresql:postgresql"]
	}
	
	# Get all possible CPE patterns for this software
	cpe_patterns = cpe_mapping.get(software, [software.lower().replace(" ", "_")])
	
	results = []
	
	for cve in load_cve_database(directory):
		for node in cve.get("configurations", {}).get("nodes", []):
			for cpe_match in node.get("cpe_match", []):
				cpe_uri = cpe_match.get("cpe23Uri", "").lower()
				
				# Check against all possible CPE patterns
				if any(pattern in cpe_uri for pattern in cpe_patterns):
					version_start = cpe_match.get("versionStartIncluding")
					version_end = cpe_match.get("versionEndIncluding")
					version_start_ex = cpe_match.get("versionStartExcluding")
					version_end_ex = cpe_match.get("versionEndExcluding")
					cpe_version = cpe_match.get("version", "")
					
					if is_strictly_vulnerable(current_version, cpe_version,
					                          version_start, version_end,
					                          version_start_ex, version_end_ex):
						# Get severity from CVSS v3 if available, fallback to v2
						impact = cve.get("impact", {})
						severity = "UNKNOWN"
						
						if "baseMetricV3" in impact:
							severity = impact["baseMetricV3"].get("cvssV3", {}).get("baseSeverity", "UNKNOWN")
						elif "baseMetricV2" in impact:
							severity = impact["baseMetricV2"].get("severity", "UNKNOWN")
						
						results.append({
							"ID": cve["cve"]["CVE_data_meta"]["ID"],
							"Description": fill(cve["cve"]["description"]["description_data"][0]["value"], width=75),
							"Severity": severity,
							"Affected Versions": get_affected_versions_string(
								cpe_version, version_start, version_end,
								version_start_ex, version_end_ex)
						})
	return results


def get_server_info(url):
	"""Retrieve server headers from the given URL with timeout and retry"""
	try:
		response = requests.get(
			url,
			verify=certifi.where(),
			timeout=(3.05, 10),
			headers={
				'User-Agent': 'Security Scanner/1.0',
				'Accept': 'text/html,application/xhtml+xml'
			},
			allow_redirects=True
		)
		server_header = response.headers.get("Server", "").strip()
		powered_by = response.headers.get("X-Powered-By", "").strip()
		via_header = response.headers.get("Via", "").strip()
		
		# Combine all relevant headers for detection
		combined_headers = f"{server_header} {powered_by} {via_header}"
		return combined_headers
	
	except Timeout:
		print("[!] Request timed out after 10 seconds")
	except SSLError:
		print("[!] SSL certificate verification failed")
	except RequestException as e:
		print(f"[!] Request failed: {str(e)}")
	return ""


def extract_software_and_version(headers):
	"""Extract software name and version from server headers with improved detection"""
	if not headers:
		return None, None
	
	# Ordered list of detection patterns (most specific first)
	detection_patterns = [
		# Apache variants
		(r'Apache/(\d+\.\d+(?:\.\d+)?)', 'Apache HTTP Server'),
		(r'httpd/(\d+\.\d+(?:\.\d+)?)', 'Apache HTTP Server'),
		(r'Apache-Coyote/(\d+\.\d+(?:\.\d+)?)', 'Apache Tomcat'),
		(r'Tomcat/(\d+\.\d+(?:\.\d+)?)', 'Apache Tomcat'),
		
		# Nginx variants
		(r'nginx/(\d+\.\d+(?:\.\d+)?)', 'Nginx'),
		(r'openresty/(\d+\.\d+(?:\.\d+)?)', 'Nginx'),
		
		# Microsoft IIS
		(r'IIS/(\d+\.\d+)', 'Microsoft-IIS'),
		
		# PHP
		(r'PHP/(\d+\.\d+(?:\.\d+)?)', 'PHP'),
		(r'X-Powered-By: PHP/(\d+\.\d+(?:\.\d+)?)', 'PHP'),
		
		# Other common web technologies
		(r'WordPress/(\d+\.\d+(?:\.\d+)?)', 'WordPress'),
		(r'Drupal/(\d+\.\d+(?:\.\d+)?)', 'Drupal'),
		(r'Node\.js/(\d+\.\d+(?:\.\d+)?)', 'Node.js'),
		
		# Generic fallback patterns
		(r'([A-Za-z]+)[/\s](\d+\.\d+(?:\.\d+)?)', None),
		(r'(\w+)/(\d+\.\d+(?:\.\d+)?)', None)
	]
	
	for pattern, software in detection_patterns:
		match = re.search(pattern, headers, re.IGNORECASE)
		if match:
			if software:  # Predefined software name
				return software, match.group(1)
			else:  # Extract from generic pattern
				return match.group(1).title(), match.group(2)
	
	return None, None


def get_cve_details(url, directory="nvd_feeds"):
	"""Main function to get CVE details for a given URL"""
	print(f"\n[+] Scanning {url} for vulnerabilities...")
	
	headers = get_server_info(url)
	if not headers:
		print("[!] Could not retrieve server headers")
		return
	
	software, version = extract_software_and_version(headers)
	if not software or not version:
		print("[!] Could not detect software/version from headers")
		print(f"[*] Headers received: {headers[:200]}...")  # Show first 200 chars for debugging
		return
	
	print(f"[+] Detected: {software} {version}")
	
	cves = search_cves(directory, software, version)
	if cves:
		print(f"\n[!] Found {len(cves)} potential vulnerabilities:")
		print(tabulate(
			sorted(cves, key=lambda x: x['Severity'], reverse=True),
			headers="keys",
			tablefmt="grid",
			showindex=True
		))
		
		# Show most critical vulnerabilities first
		critical = [cve for cve in cves if cve['Severity'].upper() in ['CRITICAL', 'HIGH']]
		if critical:
			print(f"\n[!] {len(critical)} CRITICAL/HIGH vulnerabilities found!")
	else:
		print("[+] No known vulnerabilities found for this version")


if __name__ == "__main__":
	print("Vulnerability Scanner CVE LOOKUP")
	print("--------------------------")

	url = input("Enter URL to scan (include http:// or https://): ").strip()
	if not url.startswith(('http://', 'https://')):
		url = 'http://' + url  # Default to HTTP if no scheme provided

	get_cve_details(url)