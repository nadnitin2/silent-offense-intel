import os
import json
from datetime import datetime

NODES_DIR = "nodes"
MASTER_FILE = "output/master_blacklist.txt"
DASHBOARD_FILE = "output/dashboard_metrics.json"

def load_existing_master():
    """Reads existing historical IPs from the master blacklist file."""
    existing_ips = set()
    if os.path.exists(MASTER_FILE):
        with open(MASTER_FILE, "r") as f:
            for line in f:
                ip = line.strip()
                if ip and not ip.startswith("#"):
                    existing_ips.add(ip)
    return existing_ips

def main():
    print("[1/3] Loading existing historical vectors from master repository...")
    master_set = load_existing_master()

    incoming_ips = set()
    node_dashboards = {}
    total_global_dropped_packets = 0

    if os.path.exists(NODES_DIR):
        for filename in os.listdir(NODES_DIR):
            if filename.endswith(".json"):
                file_path = os.path.join(NODES_DIR, filename)
                try:
                    with open(file_path, "r") as f:
                        data = json.load(f)
                        
                        node_id = filename.replace("_threats.json", "")
                        
                        # Handle both dictionary payload and direct array payload gracefully
                        if isinstance(data, dict):
                            node_id = data.get("node_name", node_id)
                            metrics = data.get("node_metrics", {"dropped_packets": 0, "dropped_bytes": 0})
                            
                            intel = data.get("intelligence", {})
                            ips = intel.get("combined_unique_members", [])
                            if not ips:
                                ips = data.get("ips", [])
                        elif isinstance(data, list):
                            metrics = {"dropped_packets": 0, "dropped_bytes": 0}
                            ips = data
                        else:
                            ips = []
                            metrics = {"dropped_packets": 0, "dropped_bytes": 0}

                        # Extract IPs cleanly
                        for ip in ips:
                            if isinstance(ip, str) and ip.strip():
                                incoming_ips.add(ip.strip())

                        # Compile telemetry per node
                        node_dashboards[node_id] = {
                            "packets_blocked": metrics.get("dropped_packets", 0),
                            "bytes_saved": metrics.get("dropped_bytes", 0),
                            "local_pool_size": len(ips) if ips else metrics.get("local_pool_size", 0),
                            "last_sync_utc": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
                        }
                        
                        total_global_dropped_packets += metrics.get("dropped_packets", 0)

                except Exception as e:
                    print(f"[WARN] Error parsing telemetry stream {filename}: {e}")

    print("[2/3] Merging multi-node threat vectors into unique master pool...")
    updated_master_list = sorted(list(master_set | incoming_ips))

    os.makedirs(os.path.dirname(MASTER_FILE), exist_ok=True)
    
    # Save unified unique IP list strictly to output/master_blacklist.txt
    with open(MASTER_FILE, "w") as f:
        for ip in updated_master_list:
            f.write(f"{ip}\n")

    # Generate Dashboard JSON Telemetry
    unified_dashboard = {
        "cluster_status": "OPERATIONAL",
        "last_updated_utc": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "global_summary": {
            "total_blacklisted_ips": len(updated_master_list),
            "total_attacks_neutralized": total_global_dropped_packets
        },
        "per_node_telemetry": node_dashboards
    }

    os.makedirs(os.path.dirname(DASHBOARD_FILE), exist_ok=True)
    with open(DASHBOARD_FILE, "w") as f:
        json.dump(unified_dashboard, f, indent=4)

    print(f"[3/3] Centralized metrics catalog synchronized. Global Blacklist Size: {len(updated_master_list)}")

if __name__ == "__main__":
    main()
