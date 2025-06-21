import os
import json
import logging
from tqdm import tqdm
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

# Configuration
CVE_DB_ROOT = "/home/ikenn/PyCharmMiscProject/cve_data"
OUTPUT_INDEX_FILE = "reverse_index.json"
LOG_FILE = "indexer.log"

# Setup logging (file-only, no console)
logging.basicConfig(
	filename=LOG_FILE,
	level=logging.INFO,
	format="%(asctime)s - %(levelname)s - %(message)s",
	filemode='w'
)
# Disable propagation to root logger to prevent console output
logging.getLogger().propagate = False


def extract_cpe_info(cpe_uri):
	"""Extract vendor, product, version from CPE string with validation."""
	if not cpe_uri or not cpe_uri.startswith("cpe:2.3:"):
		return None
	parts = cpe_uri.split(':')
	if len(parts) < 6:
		return None
	return parts[3].lower(), parts[4].lower(), parts[5].lower()


def process_cpe_match(cpe, cve_id):
	"""Process a single CPE match and return standardized entries."""
	entries = []
	cpe_uri = cpe.get("criteria") or cpe.get("cpe23Uri")
	if not cpe_uri or not cpe.get("vulnerable", False):
		return entries
	
	cpe_info = extract_cpe_info(cpe_uri)
	if not cpe_info:
		return entries
	
	vendor, product, ver = cpe_info
	base_key = f"{vendor}:{product}"
	
	# Always add exact version entry
	entries.append((f"{base_key}:{ver}", cve_id))
	logging.info(f"[INDEX] {cve_id} → {base_key}:{ver}")
	
	# Handle ranges separately
	start_inc = cpe.get("versionStartIncluding")
	start_exc = cpe.get("versionStartExcluding")
	end_inc = cpe.get("versionEndIncluding")
	end_exc = cpe.get("versionEndExcluding")
	
	if start_inc or start_exc or end_inc or end_exc:
		range_str = f"{'>=' if start_inc else '>' if start_exc else ''}{start_inc or start_exc or ''}"
		range_str += f" to {'<=' if end_inc else '<' if end_exc else ''}{end_inc or end_exc or ''}"
		range_entry = (
			cve_id,
			start_inc or start_exc or "",
			">=" if start_inc else ">" if start_exc else "",
			end_inc or end_exc or "",
			"<=" if end_inc else "<" if end_exc else ""
		)
		entries.append((f"{base_key}:__RANGE__", range_entry))
		logging.info(f"[RANGE] {cve_id} → {base_key}: {range_str}")
	
	return entries

def process_cve_file(cve_path):
	"""Process a single CVE file and return indexed entries."""
	try:
		with open(cve_path) as f:
			cve_data = json.load(f)
	except Exception as e:
		logging.error(f"Failed to load {cve_path}: {str(e)}")
		return []
	
	cve_id = cve_data.get("id", "UNKNOWN")
	entries = []
	
	for config in cve_data.get("configurations", []):
		if not isinstance(config, dict):
			continue
		for node in config.get("nodes", []):
			for cpe in node.get("cpeMatch", []) or node.get("cpe_match", []):
				entries.extend(process_cpe_match(cpe, cve_id))
	
	return entries


def build_index():
	"""Build a reverse index from CVE files using parallel processing."""
	reverse_index = defaultdict(set)
	
	# Collect all CVE JSON files
	logging.info("🔧 Building reverse index from CVE tree...")
	cve_files = [
		os.path.join(root, f)
		for root, _, files in os.walk(CVE_DB_ROOT)
		for f in files if f.endswith(".json")
	]
	logging.info(f"Found {len(cve_files)} CVE files to process")
	
	# Parallel processing (console progress only)
	with ThreadPoolExecutor(max_workers=min(4, os.cpu_count())) as executor:
		results = list(tqdm(
			executor.map(process_cve_file, cve_files),
			total=len(cve_files),
			desc="Processing CVEs",
			unit="file"
		))
	
	# Merge results
	logging.info("Merging entries into index...")
	for entries in results:
		for key, value in entries:
			if key.endswith(":__RANGE__"):
				if value not in reverse_index[key]:
					reverse_index[key].add(value)
			else:
				reverse_index[key].add(value)
	
	# Final stats
	logging.info(f"Index contains {len(reverse_index)} unique keys")
	if len(reverse_index) < 1000:
		logging.warning("Suspiciously small index size")
	
	# Save to JSON
	final_index = {k: sorted(list(v)) for k, v in reverse_index.items()}
	with open(OUTPUT_INDEX_FILE, "w") as f:
		json.dump(final_index, f, indent=2)
	
	logging.info(f"✅ Reverse index saved to {OUTPUT_INDEX_FILE}")
	print(f"\n✅ Reverse index saved to {OUTPUT_INDEX_FILE}")  # Only console output


if __name__ == "__main__":
	build_index()