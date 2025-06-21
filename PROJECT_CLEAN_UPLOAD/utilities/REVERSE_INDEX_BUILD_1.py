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

# Setup logging (file-only)
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    filemode='w'
)

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
    
    # Always add exact version entry (NEW)
    entries.append((f"{base_key}:{ver}", cve_id))
    logging.debug(f"Added exact match: {base_key}:{ver} -> {cve_id}")
    
    # Handle ranges separately
    start_inc = cpe.get("versionStartIncluding")
    start_exc = cpe.get("versionStartExcluding")
    end_inc = cpe.get("versionEndIncluding")
    end_exc = cpe.get("versionEndExcluding")
    
    if start_inc or start_exc or end_inc or end_exc:
        range_entry = (
            cve_id,
            start_inc or start_exc or "",
            ">=" if start_inc else ">" if start_exc else "",
            end_inc or end_exc or "",
            "<=" if end_inc else "<" if end_exc else ""
        )
        entries.append((f"{base_key}:__RANGE__", range_entry))
        logging.debug(f"Added range: {base_key} -> {range_entry}")
    
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
    logging.info("Starting index build process")
    cve_files = [
        os.path.join(root, f)
        for root, _, files in os.walk(CVE_DB_ROOT)
        for f in files if f.endswith(".json")
    ]
    logging.info(f"Found {len(cve_files)} CVE files to process")

    # Parallel processing
    logging.info("Beginning CVE processing")
    with ThreadPoolExecutor(max_workers=min(4, os.cpu_count())) as executor:
        results = list(tqdm(
            executor.map(process_cve_file, cve_files),
            total=len(cve_files),
            desc="Processing CVEs",
            unit="file"
        ))

    # Merge results with duplicate prevention
    logging.info("Merging results into index")
    # for entries in results:
    #     for key, value in entries:
    #         if value not in reverse_index[key]:
    #             reverse_index[key].add(value)
    for entries in results:
        for key, value in entries:
            if key.endswith(":__RANGE__"):
                # For ranges, check if identical entry exists
                if value not in reverse_index[key]:
                    reverse_index[key].add(value)
            else:
                # For exact versions, just add (allows same CVE for different versions)
                reverse_index[key].add(value)

    # Validate index size
    if len(reverse_index) < 1000:
        logging.warning(f"Suspiciously small index: {len(reverse_index)} entries")

    # Convert sets to lists
    final_index = {
        k: sorted(list(v))
        for k, v in reverse_index.items()
    }

    # Save to JSON
    with open(OUTPUT_INDEX_FILE, "w") as f:
        json.dump(final_index, f, indent=2, sort_keys=True)

    logging.info(f"Index saved to {OUTPUT_INDEX_FILE} with {len(reverse_index)} keys")
    print(f"\n✅ Reverse index saved to {OUTPUT_INDEX_FILE}")

if __name__ == "__main__":
    build_index()