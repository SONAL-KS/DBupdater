import base64
import csv
import io
import json
import logging
import os
import time
import zipfile
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import requests
from pymongo import MongoClient, UpdateOne
from pymongo.collection import Collection
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
from tqdm import tqdm

# === Configuration Constants ===

# --- General ---
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
CVEDB_NAME = "CVEDATA"
RETRY_ATTEMPTS = 5
RETRY_DELAY_SECONDS = 5  # seconds delay between retries

# --- GitHub Advisory Database ---
# The token is now hardcoded here for demonstration purposes.
GITHUB_TOKEN = "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"
if not GITHUB_TOKEN:
    raise ValueError("CRITICAL: GITHUB_TOKEN is not set. Please set your token.")
GH_REPO_OWNER = "github"
GH_REPO_NAME = "advisory-database"
GH_API_URL = f"https://api.github.com/repos/{GH_REPO_OWNER}/{GH_REPO_NAME}"
GH_CHECK_WINDOW = timedelta(hours=26)
GH_COLLECTION = "Git"

# --- ExploitDB ---
EXDB_COLLECTION = "EDB"
EXDB_CSV_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"

# --- CISA KEV ---
CISA_COLLECTION = "CISADATA"
CISA_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# --- NVD CVE Feeds ---
NVD_COLLECTION = "DATA"
MODIFIED_FEED_URL = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.zip"
RECENT_FEED_URL = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.zip"

# === Logging Setup ===
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# === MongoDB Connection Helper ===
def get_mongo_client(uri: str = MONGO_URI, attempts: int = RETRY_ATTEMPTS, delay: int = RETRY_DELAY_SECONDS) -> MongoClient:
    for attempt in range(1, attempts + 1):
        try:
            client: MongoClient = MongoClient(uri, serverSelectionTimeoutMS=5000)
            client.admin.command('ping')
            logging.info(f"MongoDB connection established on attempt {attempt}.")
            return client
        except (ConnectionFailure, ServerSelectionTimeoutError) as e:
            logging.warning(f"MongoDB connection attempt {attempt} failed: {e}")
            if attempt < attempts:
                logging.info(f"Retrying in {delay} seconds...")
                time.sleep(delay)
            else:
                logging.error("All MongoDB connection attempts failed.")
                raise
    raise ConnectionFailure("Failed to connect to MongoDB after multiple retries.")

# === GitHub Advisory Functions ===
def get_gh_api_headers() -> Dict[str, str]:
    return {
        "Accept": "application/vnd.github.v3+json",
        "Authorization": f"Bearer {GITHUB_TOKEN}",
    }

def get_recently_modified_advisories(since_dt: datetime) -> List[str]:
    logging.info("Fetching commits to find recently modified advisory files...")
    modified_files = set()
    commits_url = f"{GH_API_URL}/commits"
    params = {'since': since_dt.isoformat(), 'per_page': 100}

    resp = requests.get(commits_url, headers=get_gh_api_headers(), params=params)
    resp.raise_for_status()
    commits = resp.json()

    if not commits:
        logging.info("No new commits found in the time window.")
        return []

    for commit_info in tqdm(commits, desc="Analyzing Commits", unit="commit"):
        commit_url = commit_info['url']
        try:
            resp_commit = requests.get(commit_url, headers=get_gh_api_headers())
            resp_commit.raise_for_status()
            commit_details = resp_commit.json()
            for file_info in commit_details.get('files', []):
                filename = file_info.get('filename')
                if (filename and filename.startswith('advisories/') and
                        filename.endswith('.json') and file_info['status'] != 'removed'):
                    modified_files.add(filename)
        except requests.exceptions.RequestException as e:
            logging.warning(f"Could not fetch details for commit {commit_info.get('sha')}. Error: {e}")

    logging.info(f"Found {len(modified_files)} unique advisory files modified recently.")
    return list(modified_files)

def download_json_file_from_gh(file_path: str) -> Dict[str, Any]:
    file_api_url = f"{GH_API_URL}/contents/{file_path}"
    resp = requests.get(file_api_url, headers=get_gh_api_headers())
    resp.raise_for_status()
    file_data = resp.json()
    content = base64.b64decode(file_data['content']).decode('utf-8')
    return json.loads(content)

def extract_advisory_data(advisory_json: Dict[str, Any]) -> Dict[str, Any]:
    aliases = advisory_json.get('aliases', [])
    references = advisory_json.get('references', [])
    db_spec = advisory_json.get('database_specific', {})
    sev_list = advisory_json.get('severity', [])

    severity = db_spec.get('severity')
    if not severity and sev_list and isinstance(sev_list, list) and 'score' in sev_list[0]:
        severity = sev_list[0]['score']

    return {
        'ghsa_id': advisory_json.get('id'),
        'cve_id': next((alias for alias in aliases if alias.startswith("CVE-")), None),
        'aliases': aliases,
        'description': advisory_json.get('details'),
        'references': [ref.get('url') for ref in references if ref.get('url')],
        'reviewed': "Github Reviewed" if db_spec.get('github_reviewed', False) else "Not Reviewed",
        'severity': severity,
        'weaknesses': db_spec.get('cwe_ids', [])
    }

def upsert_advisory(collection: Collection, advisory: Dict[str, Any]) -> str:
    ghsa_id = advisory.get('ghsa_id')
    cve_id = advisory.get('cve_id')

    if cve_id:
        existing_doc = collection.find_one({"cve_id": cve_id})
        if existing_doc and existing_doc.get("ghsa_id") != ghsa_id:
            logging.warning(f"Skipping {ghsa_id}: its CVE ID ({cve_id}) is already used by {existing_doc.get('ghsa_id')}.")
            return "skipped_duplicate_cve"

    query = {"ghsa_id": ghsa_id}
    update = {"$set": advisory}
    result = collection.update_one(query, update, upsert=True)

    if result.upserted_id:
        return "inserted"
    elif result.modified_count > 0:
        return "updated"
    else:
        return "no_change"

def main_github_advisories(client: MongoClient) -> None:
    since_dt = datetime.now(timezone.utc) - GH_CHECK_WINDOW
    logging.info(f"Scanning for advisories modified since {since_dt.isoformat()}...")
    db = client[CVEDB_NAME]
    collection = db[GH_COLLECTION]
    counters = {"inserted": 0, "updated": 0, "skipped_duplicate_cve": 0, "skipped_no_id": 0, "no_change": 0, "failed": 0}

    try:
        advisory_files = get_recently_modified_advisories(since_dt)
        if not advisory_files:
            logging.info("GitHub Advisory scan complete. No new files to process.")
            return

        pbar = tqdm(advisory_files, desc="Processing Advisories", unit="file")
        for file_path in pbar:
            try:
                advisory_json = download_json_file_from_gh(file_path)
                advisory_data = extract_advisory_data(advisory_json)

                if not advisory_data.get('ghsa_id'):
                    logging.warning(f"Skipping file {file_path} due to missing GHSA ID.")
                    counters["skipped_no_id"] += 1
                    continue
                status = upsert_advisory(collection, advisory_data)
                counters[status] += 1
            except requests.exceptions.HTTPError as e:
                logging.error(f"HTTP error processing file {file_path}: {e}")
                counters["failed"] += 1
            except Exception as e:
                logging.error(f"Unexpected error processing {file_path}: {e}", exc_info=False)
                counters["failed"] += 1

        logging.info("\n--- GitHub Advisory Scan Summary ---")
        logging.info(f"Total Files Analyzed: {len(advisory_files)}")
        logging.info(f"  New Advisories Inserted:   {counters['inserted']}")
        logging.info(f"  Existing Advisories Updated: {counters['updated']}")
        logging.info(f"  Processed (No Change):     {counters['no_change']}")
        logging.info(f"  Skipped (Duplicate CVE):   {counters['skipped_duplicate_cve']}")
        logging.info(f"  Skipped (Missing GHSA ID): {counters['skipped_no_id']}")
        logging.info(f"  Failed to Process:         {counters['failed']}")
        logging.info("------------------------------------\n")

    except requests.exceptions.RequestException as e:
        logging.error(f"A critical GitHub API error occurred: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred during GitHub processing: {e}", exc_info=True)

# === ExploitDB Functions ===
def fetch_exploitdb_csv() -> str:
    logging.info("Downloading ExploitDB CSV data...")
    response = requests.get(EXDB_CSV_URL, timeout=30)
    response.raise_for_status()
    return response.text

def update_exploitdb_mongo(client: MongoClient, csv_text: str) -> None:
    logging.info("Updating ExploitDB data to MongoDB...")
    db = client[CVEDB_NAME]
    collection = db[EXDB_COLLECTION]
    collection.create_index("EDB_ID", unique=True)
    operations: List[UpdateOne] = []
    for row in csv.DictReader(io.StringIO(csv_text)):
        doc = {
            "EDB_ID": row['id'],
            "description": row.get('description', '').strip(),
            "cve_id": row.get('codes') or None,
            "type": row.get('type'), "platform": row.get('platform'),
            "source_url": row.get('source_url') or None,
            "verified": row.get('verified') == '1'
        }
        operations.append(UpdateOne({'EDB_ID': doc['EDB_ID']}, {'$set': doc}, upsert=True))
    if operations:
        result = collection.bulk_write(operations)
        logging.info(f"ExploitDB Upsert done. Inserted: {result.upserted_count}, Modified: {result.modified_count}")

def clean_exploitdb_cve_ids(client: MongoClient) -> None:
    logging.info("Cleaning ExploitDB cve_id fields with multiple CVEs...")
    db = client[CVEDB_NAME]
    collection = db[EXDB_COLLECTION]
    operations: List[UpdateOne] = []
    for doc in collection.find({"cve_id": {"$regex": ";"}}, {"cve_id": 1}):
        if cve_field := doc.get("cve_id"):
            first_cve = cve_field.split(";")[0].strip()
            operations.append(UpdateOne({"_id": doc["_id"]}, {"$set": {"cve_id": first_cve}}))
    if operations:
        result = collection.bulk_write(operations)
        logging.info(f"ExploitDB CVE cleanup updated {result.modified_count} documents.")

def main_exploitdb(client: MongoClient) -> None:
    try:
        csv_text = fetch_exploitdb_csv()
        update_exploitdb_mongo(client, csv_text)
        clean_exploitdb_cve_ids(client)
    except Exception as e:
        logging.error(f"An error occurred during ExploitDB processing: {e}", exc_info=True)

# === CISA KEV Functions ===
def fetch_kev_data(url: str) -> Optional[Dict[str, Any]]:
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logging.error(f"Error fetching CISA KEV data: {e}")
        return None

def main_cisa_kev(client: MongoClient) -> None:
    kev_data = fetch_kev_data(CISA_URL)
    if not (kev_data and (vulnerabilities := kev_data.get("vulnerabilities", []))):
        logging.warning("No CISA KEV data fetched or no vulnerabilities found, skipping update.")
        return
    logging.info(f"Total CISA KEV vulnerabilities fetched: {len(vulnerabilities)}")
    db = client[CVEDB_NAME]
    collection = db[CISA_COLLECTION]
    collection.create_index("cve_id", unique=True)
    operations: List[UpdateOne] = []
    for raw_vuln in vulnerabilities:
        if cve_id := raw_vuln.get("cveID"):
            doc = {
                "cve_id": cve_id, "vendor_project": raw_vuln.get("vendorProject"),
                "product": raw_vuln.get("product"), "vulnerability_name": raw_vuln.get("vulnerabilityName"),
                "date_added": raw_vuln.get("dateAdded"), "description": raw_vuln.get("shortDescription"),
                "required_action": raw_vuln.get("requiredAction"), "due_date": raw_vuln.get("dueDate"),
                "known_ransomware_campaign_use": raw_vuln.get("knownRansomwareCampaignUse"),
                "notes": raw_vuln.get("notes"),
                "weakness": raw_vuln.get("cwes")[0] if raw_vuln.get("cwes") else None
            }
            operations.append(UpdateOne({"cve_id": cve_id}, {"$set": doc}, upsert=True))
    if operations:
        result = collection.bulk_write(operations)
        logging.info(f"CISA KEV Upsert complete. Upserted: {result.upserted_count}, Modified: {result.modified_count}")

# === NVD CVE Feed Functions ===
def download_and_extract_json(url: str) -> Dict[str, Any]:
    logging.info(f"Downloading NVD feed: {url}")
    response = requests.get(url, timeout=60)
    response.raise_for_status()
    with zipfile.ZipFile(io.BytesIO(response.content)) as z:
        json_filename = next((n for n in z.namelist() if n.endswith(".json")), None)
        if not json_filename: raise FileNotFoundError("No JSON file in ZIP")
        with z.open(json_filename) as f: return json.load(f)

def process_nvd_feed(client: MongoClient, url: str) -> None:
    try:
        data = download_and_extract_json(url)
        vulns = data.get("vulnerabilities", [])
        cve_list = [v.get("cve") for v in vulns if v.get("cve")]
        logging.info(f"Transformed {len(cve_list)} CVEs from feed: {url}")
        if not cve_list: return

        db = client[CVEDB_NAME]
        collection = db[NVD_COLLECTION]
        collection.create_index("cve_id", unique=True)
        operations: List[UpdateOne] = []

        for cve_obj in cve_list:
            cpe_list: List[str] = []
            for config in cve_obj.get("configurations", []):
                for node in config.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        if criteria := cpe_match.get("criteria"): cpe_list.append(criteria)
            en_desc = next((d['value'] for d in cve_obj.get("descriptions", []) if d['lang'] == 'en'), "")
            en_weak = [d['value'] for w in cve_obj.get("weaknesses", []) for d in w.get("description", []) if d['lang'] == 'en']

            doc = {"cve_id": cve_obj.get("id"), "cpe": cpe_list, "weakness": en_weak, "description": en_desc}
            if doc["cve_id"]:
                operations.append(UpdateOne({"cve_id": doc["cve_id"]}, {"$set": doc}, upsert=True))

        logging.info(f"Preparing to upsert {len(operations)} NVD CVEs...")
        for i in tqdm(range(0, len(operations), 1000), desc="Upserting NVD CVEs", unit="batch"):
            collection.bulk_write(operations[i:i + 1000], ordered=False)
        logging.info("NVD MongoDB upsert process completed.")

    except Exception as e:
        logging.error(f"Failed to process NVD feed {url}: {e}", exc_info=True)

def main_nvd(client: MongoClient) -> None:
    logging.info("Processing Modified NVD feed...")
    process_nvd_feed(client, MODIFIED_FEED_URL)
    logging.info("Processing Recent NVD feed...")
    process_nvd_feed(client, RECENT_FEED_URL)

# === Main Orchestrator ===
def main() -> None:
    client: Optional[MongoClient] = None
    try:
        client = get_mongo_client()

        logging.info("\n" + "="*20 + " Starting GitHub Advisory Update " + "="*20)
        main_github_advisories(client)

        logging.info("\n" + "="*20 + " Starting ExploitDB Update " + "="*20)
        main_exploitdb(client)

        logging.info("\n" + "="*10 + " Starting CISA Known Exploited Vulnerabilities Update " + "="*10)
        main_cisa_kev(client)

        logging.info("\n" + "="*20 + " Starting NVD CVE Feeds Update " + "="*20)
        main_nvd(client)

        logging.info("\n" + "="*25 + " All updates completed " + "="*25)

    except (ConnectionFailure, ServerSelectionTimeoutError):
        logging.critical("Could not establish a connection to MongoDB. Aborting script.")
    except Exception as e:
        logging.critical(f"A critical error occurred in the main execution block: {e}", exc_info=True)
    finally:
        if client:
            client.close()
            logging.info("MongoDB connection closed.")

if __name__ == "__main__":
    main()
