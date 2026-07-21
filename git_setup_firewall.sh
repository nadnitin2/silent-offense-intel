#!/bin/bash
# =================================================================
# SilentOffense Threat Intelligence - One-Click Protection Script
# =================================================================

RAW_URL="https://nadnitin2.github.io/silent-offense-intel/output/master_blacklist.txt"
SET_NAME="master_blacklist"

echo "=== [1/3] Preparing Firewall Environment ==="

# Check if ipset is installed
if ! command -v ipset &> /dev/null; then
    echo "[INFO] Installing ipset..."
    if command -v apt-get &> /dev/null; then
        apt-get update && apt-get install -y ipset
    elif command -v yum &> /dev/null; then
        yum install -y ipset
    fi
fi

# Create ipset if it doesn't exist (supports up to 200k entries)
ipset create $SET_NAME hash:ip hashsize 65536 maxelem 200000 2>/dev/null || true

echo "=== [2/3] Downloading Master Threat Intelligence Feed ==="
TMP_FILE="/tmp/master_ips.txt"
curl -sSL "$RAW_URL" -o "$TMP_FILE"

if [ ! -s "$TMP_FILE" ]; then
    echo "[ERROR] Failed to fetch IP feed. Aborting."
    exit 1
fi

echo "=== [3/3] Applying Master Blacklist to Local Firewall ==="

# Fast bulk restore into ipset
awk -v set_name="$SET_NAME" '{print "add " set_name " " $1 " -exist"}' "$TMP_FILE" | ipset restore

rm -f "$TMP_FILE"

# Bind master_blacklist ipset to Firewalld or IPTables
if command -v firewall-cmd &> /dev/null && systemctl is-active --quiet firewalld; then
    firewall-cmd --permanent --zone=drop --add-source=ipset:$SET_NAME 2>/dev/null || true
    firewall-cmd --reload 2>/dev/null || true
    echo "[SUCCESS] Successfully bound $SET_NAME to Firewalld DROP zone!"
else
    iptables -C INPUT -m set --match-set $SET_NAME src -j DROP 2>/dev/null || \
    iptables -I INPUT -m set --match-set $SET_NAME src -j DROP
    echo "[SUCCESS] Successfully bound $SET_NAME to IPTables DROP chain!"
fi

echo "=== Protection Activated! All Master Threat Vectors Blocked Successfully ==="
