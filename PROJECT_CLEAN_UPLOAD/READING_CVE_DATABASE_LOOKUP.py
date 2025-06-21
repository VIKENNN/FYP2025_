import requests
import re
import certifi
import os
import json
from packaging import version
from functools import lru_cache
from tabulate import tabulate
import logging
from urllib.parse import urlparse
from requests.exceptions import Timeout, SSLError, RequestException

# Configure logging
logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)


class HeaderAnalyzer:
	@staticmethod
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
			
			combined_headers = f"{server_header} {powered_by} {via_header}"
			return combined_headers
		
		except Timeout:
			logger.warning("[!] Request timed out after 10 seconds")
		except SSLError:
			logger.warning("[!] SSL certificate verification failed")
		except RequestException as e:
			logger.warning(f"[!] Request failed: {str(e)}")
		return ""
	
	@staticmethod
	def extract_software(combined_headers):
		"""Improved server software detection from combined headers"""
		patterns = [
			(r'Apache/([\d.]+)', 'apache', 'http_server'),
			(r'nginx/([\d.]+)', 'nginx', 'nginx'),
			(r'Microsoft-IIS/([\d.]+)', 'microsoft', 'iis'),
			(r'OpenSSL/([\d.]+)', 'openssl', 'openssl'),
			(r'PHP/([\d.]+)', 'php', 'php'),
			(r'WordPress/([\d.]+)', 'wordpress', 'wordpress'),
			(r'Tomcat/([\d.]+)', 'apache', 'tomcat')
		]
		
		for pattern, vendor, product in patterns:
			match = re.search(pattern, combined_headers, re.I)
			if match:
				return vendor, product, match.group(1)
		
		if combined_headers.strip():
			return 'unknown', combined_headers.split()[0], ''
		
		return None


class VulnerabilityScanner:
	def __init__(self, index_path='reverse_index.json', cve_data_dir='cve_data'):
		self.index_path = index_path
		self.cve_data_dir = cve_data_dir
		self.index = self._load_index()
	
	def _load_index(self):
		with open(self.index_path) as f:
			return json.load(f)
	
	@lru_cache(maxsize=1000)
	def get_cves(self, vendor, product, version):
		"""Get CVEs for a software version with range checking"""
		base_key = f"{vendor.lower()}:{product.lower()}"
		results = []
		
		# Check exact matches
		exact_key = f"{base_key}:{version}"
		if exact_key in self.index:
			for cve_id in self.index[exact_key]:
				results.append(cve_id)
		
		# Check version ranges
		range_key = f"{base_key}:__RANGE__"
		if range_key in self.index:
			for entry in self.index[range_key]:
				if self._is_version_in_range(version, *entry[1:]):
					results.append(entry[0])
		
		return sorted(results)
	
	def _is_version_in_range(self, target_ver, start_ver, start_op, end_ver, end_op):
		"""Check if version falls within a vulnerability range"""
		try:
			target = version.parse(target_ver)
			
			if start_ver:
				start = version.parse(start_ver)
				if start_op == ">=" and target < start:
					return False
				if start_op == ">" and target <= start:
					return False
			
			if end_ver:
				end = version.parse(end_ver)
				if end_op == "<=" and target > end:
					return False
				if end_op == "<" and target >= end:
					return False
			
			return True
		except version.InvalidVersion:
			return False
	
	def get_cve_details(self, cve_id):
		"""Fetch CVE details from the structured NVD database"""
		try:
			# Parse CVE ID (format: CVE-YYYY-NNNN or CVE-YYYY-NNNNN)
			_, year, num = cve_id.split('-')
			num_int = int(num)
			
			# Try both possible folder structures
			folder_candidates = []
			
			# For 4-digit CVEs (standard case)
			if num_int < 10000:
				folder_candidates.append(f"{num_int:04d}"[:2] + 'xx')
			# For 5-digit CVEs
			else:
				# Try 5-digit format first (200xx)
				folder_candidates.append(f"{num_int:05d}"[:3] + 'xx')
				# Also try 4-digit format (20xx) as fallback
				folder_candidates.append(f"{num_int:05d}"[1:3] + 'xx')
			
			# Check all possible folder locations
			for folder_num in folder_candidates:
				cve_path = os.path.join(
					self.cve_data_dir,
					f'CVE-{year}',
					f'CVE-{year}-{folder_num}',
					f'{cve_id}.json'
				)
				
				if os.path.exists(cve_path):
					with open(cve_path, 'r', encoding='utf-8') as f:
						data = json.load(f)
						
						# Extract English description
						description = next(
							(desc['value'] for desc in data.get('descriptions', [])
							 if desc.get('lang') == 'en'),
							"No description available"
						)
						
						# Get the most authoritative severity (CVSS v3.0)
						severity = "UNKNOWN"
						metrics = data.get('metrics', {})
						if 'cvssMetricV30' in metrics:
							severity = metrics['cvssMetricV30'][0]['cvssData']['baseSeverity']
						elif 'cvssMetricV2' in metrics:
							# Fallback to CVSS v2 if v3 not available
							severity = metrics['cvssMetricV2'][0].get('baseSeverity', 'UNKNOWN')
						
						# Extract published date
						published = data.get('published', '').split('T')[0]
						
						return {
							'description': description,
							'severity': severity,
							'published': published
						}
				return None
		except Exception as e:
			logger.warning(f"Failed to load {cve_id}: {str(e)}")
			return None


class CVEAnalyzer:
	def __init__(self, scanner):
		self.scanner = scanner
	
	def analyze_url(self, url):
		"""Full analysis workflow for a URL with vulnerability counting"""
		try:
			# Step 1: Get server info
			combined_headers = HeaderAnalyzer.get_server_info(url)
			if not combined_headers:
				return None, "Failed to retrieve server headers", ""
			
			# Step 2: Detect software
			software = HeaderAnalyzer.extract_software(combined_headers)
			if not software:
				return None, "No identifiable server software found", ""
			
			vendor, product, ver = software
			
			# Step 3: Lookup CVEs
			cve_ids = self.scanner.get_cves(vendor, product, ver)
			if not cve_ids:
				return None, f"No known vulnerabilities for {vendor} {product} {ver}", ""
			
			# Step 4: Format results with full details
			results = []
			for idx, cve_id in enumerate(cve_ids, start=1):
				cve_details = self.scanner.get_cve_details(cve_id)
				
				if cve_details:
					results.append({
						'#': idx,
						'CVE ID': cve_id,
						'Description': cve_details['description'],
						'Severity': cve_details['severity'],
						'Affected Versions': self._get_affected_versions(vendor, product, cve_id),
						'Vendor': vendor.capitalize(),
						'Published': cve_details['published']
					})
				else:
					results.append({
						'#': idx,
						'CVE ID': cve_id,
						'Description': 'Details not available in database',
						'Severity': 'UNKNOWN',
						'Affected Versions': self._get_affected_versions(vendor, product, cve_id),
						'Vendor': vendor.capitalize(),
						'Published': 'Unknown'
					})
			
			# Step 5: Generate vulnerability counts
			severity_counts = {
				'CRITICAL': 0,
				'HIGH': 0,
				'MEDIUM': 0,
				'LOW': 0,
				'UNKNOWN': 0
			}
			
			for item in results:
				severity = item['Severity'].upper()
				severity_counts[severity] = severity_counts.get(severity, 0) + 1
			
			count_message = (
				f"Found {len(results)} vulnerabilities - "
				f"Critical: {severity_counts['CRITICAL']}, "
				f"High: {severity_counts['HIGH']}, "
				f"Medium: {severity_counts['MEDIUM']}, "
				f"Low: {severity_counts['LOW']}"
			)
			
			return results, f"{vendor} {product} {ver}", count_message
		
		except Exception as e:
			return None, f"Error analyzing {url}: {str(e)}", ""
	
	def _get_affected_versions(self, vendor, product, cve_id):
		"""Get affected version ranges for a CVE"""
		base_key = f"{vendor.lower()}:{product.lower()}"
		versions = []
		
		# Check exact matches
		for key in self.scanner.index:
			if key.startswith(base_key) and cve_id in self.scanner.index[key]:
				versions.append(key.split(':')[-1])
		
		# Check ranges
		range_key = f"{base_key}:__RANGE__"
		if range_key in self.scanner.index:
			for entry in self.scanner.index[range_key]:
				if entry[0] == cve_id:
					start = f"{entry[2]}{entry[1]}" if entry[1] else ""
					end = f"{entry[4]}{entry[3]}" if entry[3] else ""
					versions.append(f"{start} to {end}".strip())
		
		return ", ".join(versions) if versions else "All versions"
	
	def _count_severities(self, results):
		"""Count vulnerabilities by severity level"""
		counts = {
			'TOTAL': len(results),
			'CRITICAL': 0,
			'HIGH': 0,
			'MEDIUM': 0,
			'LOW': 0,
			'UNKNOWN': 0
		}
		
		for item in results:
			severity = item['Severity'].upper()
			if severity in counts:
				counts[severity] += 1
			else:
				counts['UNKNOWN'] += 1
		
		return counts


def main():
	print("CVE LOOKUP VERS.")
	print("--------------------------")
	
	url = input("Enter URL to scan (include http:// or https://): ").strip()
	if not url.startswith(('http://', 'https://')):
		url = 'http://' + url
	
	print(f"\nScanning {url} for software version...\n")
	
	scanner = VulnerabilityScanner(cve_data_dir='cve_data')
	analyzer = CVEAnalyzer(scanner)
	
	results, software_info, count_message = analyzer.analyze_url(url)
	
	if not results:
		print(f"{software_info}")
		return
	
	print(f"Detected: {software_info}")
	print(count_message + "\n")  # Display the counts here
	
	print(tabulate(
		results,
		headers='keys',
		tablefmt='grid',
		maxcolwidths=[5, None, 50, None, 30, None, None],
		stralign='left',
		showindex=False
	))


if __name__ == "__main__":
	main()