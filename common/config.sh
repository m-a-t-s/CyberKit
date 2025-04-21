#!/bin/bash
# config.sh - Configuration settings for CyberKit
# ===============================================
# This script contains shared configuration settings used across
# both offensive and defensive tools in the CyberKit toolkit.

# Determine script directory and base path
CONFIG_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
CYBERKIT_BASE="$(dirname "$CONFIG_DIR")"

###############################################################
# Base Directories
###############################################################

# Directory structure for the toolkit
OFFENSIVE_DIR="$CYBERKIT_BASE/offensive"
DEFENSIVE_DIR="$CYBERKIT_BASE/defensive"
COMMON_DIR="$CYBERKIT_BASE/common"
TEMPLATES_DIR="$CYBERKIT_BASE/templates"

# Default directories for output
DEFAULT_ENGAGEMENTS_DIR="$HOME/engagements"
DEFAULT_REPORTS_DIR="$HOME/reports"
DEFAULT_EVIDENCE_DIR="$HOME/evidence"
DEFAULT_LOGS_DIR="$HOME/logs"

# Create base directories if they don't exist
mkdir -p "$DEFAULT_ENGAGEMENTS_DIR" 2>/dev/null
mkdir -p "$DEFAULT_REPORTS_DIR" 2>/dev/null
mkdir -p "$DEFAULT_EVIDENCE_DIR" 2>/dev/null
mkdir -p "$DEFAULT_LOGS_DIR" 2>/dev/null

###############################################################
# Tool Configuration and Paths
###############################################################

# Try to find the path to various tools
NMAP_PATH=$(which nmap 2>/dev/null || echo "/usr/bin/nmap")
MASSCAN_PATH=$(which masscan 2>/dev/null || echo "/usr/bin/masscan")
METASPLOIT_PATH=$(which msfconsole 2>/dev/null || echo "/usr/bin/msfconsole")
BURPSUITE_PATH=$(ls /usr/local/bin/burpsuite* 2>/dev/null || ls $HOME/BurpSuitePro/burpsuite* 2>/dev/null || echo "")
OPENVAS_PATH=$(which openvas 2>/dev/null || echo "/usr/bin/openvas")
WIRESHARK_PATH=$(which wireshark 2>/dev/null || echo "/usr/bin/wireshark")
TCPDUMP_PATH=$(which tcpdump 2>/dev/null || echo "/usr/sbin/tcpdump")

# Common web scanning tools
GOBUSTER_PATH=$(which gobuster 2>/dev/null || echo "/usr/bin/gobuster")
FFUF_PATH=$(which ffuf 2>/dev/null || echo "/usr/bin/ffuf")
NIKTO_PATH=$(which nikto 2>/dev/null || echo "/usr/bin/nikto")
SQLMAP_PATH=$(which sqlmap 2>/dev/null || echo "/usr/bin/sqlmap")
WPSCAN_PATH=$(which wpscan 2>/dev/null || echo "/usr/bin/wpscan")

# Reconnaissance tools
SUBFINDER_PATH=$(which subfinder 2>/dev/null || echo "$HOME/go/bin/subfinder")
AMASS_PATH=$(which amass 2>/dev/null || echo "$HOME/go/bin/amass")
HTTPX_PATH=$(which httpx 2>/dev/null || echo "$HOME/go/bin/httpx")
NUCLEI_PATH=$(which nuclei 2>/dev/null || echo "$HOME/go/bin/nuclei")
WHATWEB_PATH=$(which whatweb 2>/dev/null || echo "/usr/bin/whatweb")

# Password cracking tools
HASHCAT_PATH=$(which hashcat 2>/dev/null || echo "/usr/bin/hashcat")
JOHN_PATH=$(which john 2>/dev/null || echo "/usr/bin/john")
HYDRA_PATH=$(which hydra 2>/dev/null || echo "/usr/bin/hydra")

# Exploitation tools
MSFVENOM_PATH=$(which msfvenom 2>/dev/null || echo "/usr/bin/msfvenom")
SEARCHSPLOIT_PATH=$(which searchsploit 2>/dev/null || echo "/usr/bin/searchsploit")

# Defensive tools
SURICATA_PATH=$(which suricata 2>/dev/null || echo "/usr/bin/suricata")
ZEEK_PATH=$(which zeek 2>/dev/null || echo "/usr/bin/zeek")
WAZUH_PATH=$(which wazuh-agent 2>/dev/null || echo "/usr/bin/wazuh-agent")
TOR_PATH=$(which tor 2>/dev/null || echo "/usr/bin/tor")
PROXYCHAINS_PATH=$(which proxychains 2>/dev/null || echo "/usr/bin/proxychains")

###############################################################
# Wordlist Paths
###############################################################

# Common wordlists
if [ -d "/usr/share/wordlists" ]; then
    WORDLISTS_DIR="/usr/share/wordlists"
elif [ -d "/usr/share/seclists" ]; then
    WORDLISTS_DIR="/usr/share/seclists"
else
    WORDLISTS_DIR="$CYBERKIT_BASE/wordlists"
    mkdir -p "$WORDLISTS_DIR" 2>/dev/null
fi

# Common wordlists
ROCKYOU_PATH="$WORDLISTS_DIR/rockyou.txt"
if [ ! -f "$ROCKYOU_PATH" ] && [ -f "/usr/share/wordlists/rockyou.txt.gz" ]; then
    gunzip -c "/usr/share/wordlists/rockyou.txt.gz" > "$WORDLISTS_DIR/rockyou.txt" 2>/dev/null
fi

# Directory wordlists
DIRB_COMMON_PATH="$WORDLISTS_DIR/dirb/common.txt"
if [ ! -f "$DIRB_COMMON_PATH" ] && [ -f "/usr/share/dirb/wordlists/common.txt" ]; then
    mkdir -p "$WORDLISTS_DIR/dirb" 2>/dev/null
    cp "/usr/share/dirb/wordlists/common.txt" "$DIRB_COMMON_PATH" 2>/dev/null
fi

# SecLists paths
SECLISTS_DIR="/usr/share/seclists"
if [ ! -d "$SECLISTS_DIR" ]; then
    SECLISTS_DIR="$WORDLISTS_DIR/seclists"
    mkdir -p "$SECLISTS_DIR" 2>/dev/null
fi

###############################################################
# Default Tool Options
###############################################################

# Default scan settings
DEFAULT_NMAP_ARGS="-T4 -A"
DEFAULT_MASSCAN_ARGS="--rate=1000"
DEFAULT_GOBUSTER_ARGS="-w $DIRB_COMMON_PATH"
DEFAULT_FFUF_ARGS="-w $DIRB_COMMON_PATH -mc 200,301,302,403"
DEFAULT_NUCLEI_ARGS="-severity low,medium,high,critical"
DEFAULT_NIKTO_ARGS="-Format txt"
DEFAULT_HYDRA_ARGS="-t 4"

# Default timeouts
DEFAULT_HTTP_TIMEOUT=10
DEFAULT_SCAN_TIMEOUT=300
DEFAULT_HOST_TIMEOUT=60

# Default threads
DEFAULT_THREADS=10

# Default scan limits
MAX_FILE_SIZE=5242880  # 5MB
MAX_SCAN_DURATION=14400  # 4 hours

###############################################################
# User Configuration Override
###############################################################

# Allow for user overrides from a local config file
USER_CONFIG_FILE="$HOME/.cyberkit.conf"
if [ -f "$USER_CONFIG_FILE" ]; then
    source "$USER_CONFIG_FILE"
fi

###############################################################
# Runtime Variables
###############################################################

# Variables that can be set at runtime
DEBUG=${DEBUG:-false}
VERBOSE=${VERBOSE:-false}
QUIET=${QUIET:-false}
NO_COLOR=${NO_COLOR:-false}

# Export variables so they're available to child scripts
export CYBERKIT_BASE OFFENSIVE_DIR DEFENSIVE_DIR COMMON_DIR TEMPLATES_DIR
export DEFAULT_ENGAGEMENTS_DIR DEFAULT_REPORTS_DIR DEFAULT_EVIDENCE_DIR DEFAULT_LOGS_DIR
export NMAP_PATH MASSCAN_PATH METASPLOIT_PATH BURPSUITE_PATH
export GOBUSTER_PATH FFUF_PATH NIKTO_PATH SQLMAP_PATH WPSCAN_PATH
export SUBFINDER_PATH AMASS_PATH HTTPX_PATH NUCLEI_PATH WHATWEB_PATH
export HASHCAT_PATH JOHN_PATH HYDRA_PATH
export MSFVENOM_PATH SEARCHSPLOIT_PATH
export SURICATA_PATH ZEEK_PATH WAZUH_PATH TOR_PATH PROXYCHAINS_PATH
export WORDLISTS_DIR ROCKYOU_PATH DIRB_COMMON_PATH SECLISTS_DIR
export DEFAULT_NMAP_ARGS DEFAULT_MASSCAN_ARGS DEFAULT_GOBUSTER_ARGS DEFAULT_FFUF_ARGS
export DEFAULT_NUCLEI_ARGS DEFAULT_NIKTO_ARGS DEFAULT_HYDRA_ARGS
export DEFAULT_HTTP_TIMEOUT DEFAULT_SCAN_TIMEOUT DEFAULT_HOST_TIMEOUT
export DEFAULT_THREADS MAX_FILE_SIZE MAX_SCAN_DURATION
export DEBUG VERBOSE QUIET NO_COLOR

# Function to display configuration
show_config() {
    echo "=== CyberKit Configuration ==="
    echo "Base Directory: $CYBERKIT_BASE"
    echo "Default Engagements Directory: $DEFAULT_ENGAGEMENTS_DIR"
    echo 
    echo "=== Tool Paths ==="
    echo "Nmap: $NMAP_PATH"
    echo "Masscan: $MASSCAN_PATH"
    echo "Gobuster: $GOBUSTER_PATH"
    echo "Nuclei: $NUCLEI_PATH"
    echo
    echo "=== Wordlists ==="
    echo "Wordlists Directory: $WORDLISTS_DIR"
    echo "Rockyou Path: $ROCKYOU_PATH"
    echo "Dirb Common Path: $DIRB_COMMON_PATH"
    echo
    echo "=== Runtime Settings ==="
    echo "Debug: $DEBUG"
    echo "Verbose: $VERBOSE"
    echo "Quiet: $QUIET"
    echo "No Color: $NO_COLOR"
}

# Export the function
export -f show_config