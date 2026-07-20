import os
import json

# Setup core paths relative to repo root
NODES_DIR = "nodes"
MASTER_FILE = "output/master_blacklist.txt"

def load_existing_master():
    existing_ips = set()
    if os.path.exists(MASTER_FILE):
        with open(MASTER_FILE, "r") as f:
            for line in f:
                ip = line.strip()
                if ip:
                    existing_ips.add(ip)
    return existing_ips

def main():
    print("[1/3] Loading existing historical vectors from master repository...")
    master_set = load_existing_master()
    initial_count = len(master_set)
    print(f"[INFO] Current master database contains {initial_count} unique threats.")

    # Gather incoming intelligence from all node JSON files
    incoming_ips = set()
    if os.path.exists(NODES_DIR):
        for filename in os.listdir(NODES_DIR):
            if filename.endswith(".json"):
                file_path = os.path.join(NODES_DIR, filename)
                try:
                    with open(file_path, "r") as f:
                        data = json.load(f)
                        # Extract from deduplicated key structure
                        intel = data.get("intelligence", {})
                        ips = intel.get("combined_unique_members", [])
                        for ip in ips:
                            incoming_ips.add(ip.strip())
                except Exception as e:
                    print(f"[WARN] Failed to parse node telemetry {filename}: {e}")

    print(f"[2/3] Processed incoming telemetry. Found {len(incoming_ips)} total incoming vectors.")

    # Filter out historical IPs to find only brand new threats
    new_threats = incoming_ips - master_set
    new_count = len(new_threats)
    print(f"[SUCCESS] Validation Complete: Filtered out {len(incoming_ips) - new_count} duplicates. Found {new_count} brand new unique vectors.")

    if new_count == 0:
        print("[INFO] No new intelligence detected. Master manifest is already up to date.")
        return

    # Combine existing and new threats, then sort for structural uniformity
    updated_master_list = sorted(list(master_set | new_threats))

    # Ensure output directory exists cleanly
    os.makedirs(os.path.dirname(MASTER_FILE), exist_ok=True)

    with open(MASTER_FILE, "w") as f:
        for ip in updated_master_list:
            f.write(f"{ip}\n")

    print(f"[3/3] Centralized catalog rewritten successfully. Total global size: {len(updated_master_list)} IPs.")

if __name__ == "__main__":
    main()
