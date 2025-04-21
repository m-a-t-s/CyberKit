#!/bin/bash
#
# wifi-defence.sh - WiFi Security Defense Toolkit
# Part of CyberKit Defensive Tools Suite
#
# This script provides WiFi monitoring, intrusion detection, and active defense capabilities
# for both personal and enterprise wireless networks.
#

# Import common utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
source "$PROJECT_ROOT/common/utils.sh"
source "$PROJECT_ROOT/common/config.sh"
source "$PROJECT_ROOT/common/api-keys.sh"

# Constants
TEMP_DIR="/tmp/cyberkit-wifi-defence"
LOG_DIR="${LOG_BASE_DIR:-$HOME/.cyberkit/logs}/wifi-defence"
CONFIG_FILE="${CONFIG_DIR:-$HOME/.cyberkit}/wifi-defence.conf"
DEFAULT_MONITOR_TIME=300 # 5 minutes
DEFAULT_SCAN_INTERVAL=60 # 1 minute
DEFAULT_CAPTURE_DIR="$HOME/wifi_captures"
DEFAULT_DEAUTH_COUNT=5

# Ensure required directories exist
mkdir -p "$LOG_DIR" "$TEMP_DIR"
[[ ! -d "$DEFAULT_CAPTURE_DIR" ]] && mkdir -p "$DEFAULT_CAPTURE_DIR"

# Function to display help menu
show_help() {
    cat << EOF
WiFi Defence Toolkit - A component of CyberKit

Usage: $(basename "$0") [OPTIONS] COMMAND

Commands:
  monitor       Monitor WiFi networks and detect suspicious activities
  analyze       Analyze captured WiFi traffic or logs for threats
  defend        Implement active defense measures
  baseline      Create a baseline of trusted devices and normal activity
  alert         Configure alerting mechanisms for detected threats

Options:
  -i, --interface INTERFACE       Specify wireless interface to use
  -t, --time SECONDS              Time duration for monitoring (default: $DEFAULT_MONITOR_TIME)
  -n, --network SSID              Target network SSID
  -b, --bssid MAC                 Target network BSSID
  -o, --output DIR                Output directory (default: $DEFAULT_CAPTURE_DIR)
  -c, --config FILE               Use custom config file
  -m, --mode [personal|enterprise] Operation mode (default: personal)
  -l, --level [low|medium|high]   Security level (default: medium)
  -e, --exclude FILE              File containing MAC addresses to exclude
  -a, --alerts [email|sms|both]   Alert method when threats detected
  --threatintel                   Use threat intelligence APIs to identify malicious actors
  --no-deauth                     Disable deauthentication of unauthorized devices
  --background                    Run monitoring in background as a service
  --visualize                     Generate visual reports of network activity
  --test                          Run in test mode using sample data
  -v, --verbose                   Enable verbose output
  -h, --help                      Display this help message

Examples:
  $(basename "$0") monitor -i wlan0
  $(basename "$0") analyze -o /path/to/captures -m enterprise
  $(basename "$0") defend -i wlan0 -n "MyNetwork" --no-deauth
  $(basename "$0") baseline -i wlan0 -t 3600
  $(basename "$0") alert --alerts email -c /path/to/config

EOF
    exit 0
}

# Function to check required dependencies
check_dependencies() {
    local REQUIRED_TOOLS=("aircrack-ng" "tcpdump" "wireshark-cli" "hostapd" "wpa_supplicant" "nmap" "python3" "iw")
    local ENTERPRISE_TOOLS=("freeradius" "wpa_supplicant" "eapol_test")
    local MISSING_TOOLS=()
    
    log_info "Checking required dependencies..."
    
    for tool in "${REQUIRED_TOOLS[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            MISSING_TOOLS+=("$tool")
        fi
    done
    
    if [[ "$OPERATION_MODE" == "enterprise" ]]; then
        for tool in "${ENTERPRISE_TOOLS[@]}"; do
            if ! command -v "$tool" &>/dev/null; then
                MISSING_TOOLS+=("$tool")
            fi
        done
    fi
    
    if [[ ${#MISSING_TOOLS[@]} -gt 0 ]]; then
        log_warning "The following required tools are missing:"
        for tool in "${MISSING_TOOLS[@]}"; do
            echo "  - $tool"
        done
        
        read -p "Would you like to install them now? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            if command -v apt-get &>/dev/null; then
                sudo apt-get update
                sudo apt-get install -y "${MISSING_TOOLS[@]}"
            elif command -v yum &>/dev/null; then
                sudo yum install -y "${MISSING_TOOLS[@]}"
            elif command -v pacman &>/dev/null; then
                sudo pacman -S "${MISSING_TOOLS[@]}"
            else
                log_error "Could not determine package manager. Please install the missing tools manually."
                exit 1
            fi
        else
            log_warning "Some features may not work without required dependencies."
        fi
    else
        log_success "All required dependencies are installed."
    fi
}

# Function to validate wireless interface
validate_interface() {
    local INTERFACE="$1"
    
    # Check if interface exists
    if ! ip link show "$INTERFACE" &>/dev/null; then
        log_error "Interface $INTERFACE does not exist!"
        exit 1
    fi
    
    # Check if it's a wireless interface
    if ! iw dev "$INTERFACE" info &>/dev/null; then
        log_error "Interface $INTERFACE is not a wireless interface!"
        exit 1
    }
    
    # Check if interface supports monitor mode
    if ! iw phy "$(iw dev "$INTERFACE" info | grep wiphy | awk '{print $2}')" info | grep -q "monitor"; then
        log_warning "Interface $INTERFACE might not support monitor mode!"
    }
    
    log_success "Interface $INTERFACE is valid."
    return 0
}

# Function to put interface in monitor mode
enable_monitor_mode() {
    local INTERFACE="$1"
    local MONITOR_INTERFACE="${INTERFACE}mon"
    
    log_info "Enabling monitor mode on $INTERFACE..."
    
    # Ensure interface is up
    sudo ip link set "$INTERFACE" up
    
    # Kill any processes that might interfere
    sudo airmon-ng check kill &>/dev/null
    
    # Start monitor mode
    if sudo airmon-ng start "$INTERFACE" &>/dev/null; then
        if iw dev | grep -q "$MONITOR_INTERFACE"; then
            INTERFACE="$MONITOR_INTERFACE"
        fi
        log_success "Monitor mode enabled. Using interface: $INTERFACE"
        echo "$INTERFACE"
        return 0
    else
        log_error "Failed to enable monitor mode on $INTERFACE!"
        exit 1
    fi
}

# Function to disable monitor mode
disable_monitor_mode() {
    local INTERFACE="$1"
    
    log_info "Disabling monitor mode..."
    
    if [[ "$INTERFACE" == *"mon"* ]]; then
        local ORIGINAL_INTERFACE="${INTERFACE%mon}"
        sudo airmon-ng stop "$INTERFACE" &>/dev/null
        sudo ip link set "$ORIGINAL_INTERFACE" up
        log_success "Monitor mode disabled. Interface $ORIGINAL_INTERFACE restored."
    else
        log_warning "Interface $INTERFACE doesn't appear to be in monitor mode."
    fi
    
    # Restart network manager
    if command -v systemctl &>/dev/null; then
        sudo systemctl restart NetworkManager &>/dev/null
    elif command -v service &>/dev/null; then
        sudo service network-manager restart &>/dev/null
    fi
}

# Function to scan for WiFi networks
scan_networks() {
    local INTERFACE="$1"
    local OUTPUT_FILE="$TEMP_DIR/networks.txt"
    
    log_info "Scanning for WiFi networks..."
    
    # Ensure we have a clean output file
    rm -f "$OUTPUT_FILE"
    
    # Perform scan with timeout
    timeout 30s sudo airodump-ng -w "$TEMP_DIR/scan" --output-format csv "$INTERFACE" &>/dev/null
    
    # Process scan results
    if [[ -f "$TEMP_DIR/scan-01.csv" ]]; then
        # Extract network information (BSSID, ESSID, Channel, Encryption)
        grep -a -v "Station MAC" "$TEMP_DIR/scan-01.csv" | \
        awk -F, '{if(length($14)>0) print $1","$14","$4","$6}' > "$OUTPUT_FILE"
        
        # Clean up
        rm -f "$TEMP_DIR/scan-01.csv"
        
        log_success "Found $(wc -l < "$OUTPUT_FILE") networks."
        return 0
    else
        log_error "Failed to scan networks or no networks found."
        return 1
    fi
}

# Function to capture WiFi traffic
capture_traffic() {
    local INTERFACE="$1"
    local DURATION="$2"
    local OUTPUT_DIR="$3"
    local BSSID="$4"
    local CHANNEL="$5"
    local CAPTURE_FILE="$OUTPUT_DIR/capture_$(date +%Y%m%d_%H%M%S)"
    
    log_info "Capturing WiFi traffic for $DURATION seconds..."
    
    if [[ -n "$BSSID" && -n "$CHANNEL" ]]; then
        # Targeted capture for specific network
        sudo airodump-ng -c "$CHANNEL" --bssid "$BSSID" -w "$CAPTURE_FILE" "$INTERFACE" &
    else
        # General capture
        sudo airodump-ng -w "$CAPTURE_FILE" "$INTERFACE" &
    fi
    
    local PID=$!
    sleep "$DURATION"
    kill -15 "$PID" 2>/dev/null
    
    log_success "Traffic captured and saved to $CAPTURE_FILE"
    echo "$CAPTURE_FILE"
}

# Function to analyze WiFi traffic for threats
analyze_traffic() {
    local CAPTURE_FILE="$1"
    local OUTPUT_DIR="$2"
    local MODE="$3"
    local REPORT_FILE="$OUTPUT_DIR/analysis_report_$(date +%Y%m%d_%H%M%S).md"
    
    log_info "Analyzing WiFi traffic for potential threats..."
    
    # Create report header
    cat > "$REPORT_FILE" << EOF
# WiFi Security Analysis Report
Generated: $(date)
Capture File: $CAPTURE_FILE
Mode: $MODE

## Summary

EOF
    
    # Detect deauthentication attacks
    log_info "Checking for deauthentication attacks..."
    local DEAUTH_COUNT=$(tshark -r "$CAPTURE_FILE" -Y "wlan.fc.type_subtype == 0x0c" 2>/dev/null | wc -l)
    
    echo "### Deauthentication Packets" >> "$REPORT_FILE"
    echo "- Total detected: $DEAUTH_COUNT" >> "$REPORT_FILE"
    
    if [[ "$DEAUTH_COUNT" -gt 10 ]]; then
        echo "- **WARNING:** High number of deauthentication packets detected!" >> "$REPORT_FILE"
        echo "- Potential DoS attack in progress" >> "$REPORT_FILE"
        
        # Extract sources of deauth packets
        echo "- Sources:" >> "$REPORT_FILE"
        tshark -r "$CAPTURE_FILE" -Y "wlan.fc.type_subtype == 0x0c" -T fields -e wlan.sa 2>/dev/null | sort | uniq -c | sort -nr | head -5 | \
        while read count mac; do
            echo "  - $mac ($count packets)" >> "$REPORT_FILE"
        done
    else
        echo "- No significant deauthentication activity detected" >> "$REPORT_FILE"
    fi
    
    # Detect possible evil twin/rogue access points
    log_info "Checking for rogue access points..."
    echo -e "\n### Potential Rogue Access Points" >> "$REPORT_FILE"
    
    # Extract BSSIDs and SSIDs
    tshark -r "$CAPTURE_FILE" -Y "wlan.fc.type_subtype == 0x08" -T fields -e wlan.bssid -e wlan.ssid 2>/dev/null | sort | uniq > "$TEMP_DIR/aps.txt"
    
    # Look for duplicate SSIDs with different BSSIDs
    cat "$TEMP_DIR/aps.txt" | awk '{print $2}' | sort | uniq -d > "$TEMP_DIR/duplicate_ssids.txt"
    
    if [[ -s "$TEMP_DIR/duplicate_ssids.txt" ]]; then
        echo "- **WARNING:** Duplicate SSIDs detected (potential evil twin):" >> "$REPORT_FILE"
        while read ssid; do
            echo "  - SSID: $ssid" >> "$REPORT_FILE"
            grep "$ssid" "$TEMP_DIR/aps.txt" | while read bssid ssid_line; do
                echo "    - BSSID: $bssid" >> "$REPORT_FILE"
            done
        done < "$TEMP_DIR/duplicate_ssids.txt"
    else
        echo "- No duplicate SSIDs detected" >> "$REPORT_FILE"
    fi
    
    # Additional checks for enterprise mode
    if [[ "$MODE" == "enterprise" ]]; then
        log_info "Performing enterprise-specific checks..."
        echo -e "\n### Enterprise WiFi Security Checks" >> "$REPORT_FILE"
        
        # Check for RADIUS-related issues
        local EAPOL_COUNT=$(tshark -r "$CAPTURE_FILE" -Y "eapol" 2>/dev/null | wc -l)
        echo "- EAPOL Packets: $EAPOL_COUNT" >> "$REPORT_FILE"
        
        # Check for EAP identity responses (potential credential leakage)
        local EAP_IDENTITY=$(tshark -r "$CAPTURE_FILE" -Y "eap.type == 1" -T fields -e eap.identity 2>/dev/null | sort | uniq)
        if [[ -n "$EAP_IDENTITY" ]]; then
            echo "- **WARNING:** EAP identities exposed:" >> "$REPORT_FILE"
            echo "$EAP_IDENTITY" | while read identity; do
                echo "  - $identity" >> "$REPORT_FILE"
            done
        else
            echo "- No exposed EAP identities detected" >> "$REPORT_FILE"
        fi
    fi
    
    # Client vulnerability analysis
    log_info "Analyzing client vulnerabilities..."
    echo -e "\n### Client Vulnerability Analysis" >> "$REPORT_FILE"
    
    # Check for probe requests (indicates clients searching for networks)
    local PROBE_REQUESTS=$(tshark -r "$CAPTURE_FILE" -Y "wlan.fc.type_subtype == 0x04" -T fields -e wlan.sa -e wlan.ssid 2>/dev/null | sort | uniq)
    
    if [[ -n "$PROBE_REQUESTS" ]]; then
        echo "- Clients probing for networks:" >> "$REPORT_FILE"
        echo "$PROBE_REQUESTS" | while read mac ssid; do
            if [[ -n "$ssid" ]]; then
                echo "  - Device $mac searching for \"$ssid\"" >> "$REPORT_FILE"
            fi
        done
    else
        echo "- No significant probe request activity detected" >> "$REPORT_FILE"
    fi
    
    log_success "Analysis complete! Report saved to $REPORT_FILE"
    echo "$REPORT_FILE"
}

# Function to identify unauthorized devices
detect_unauthorized_devices() {
    local CAPTURE_FILE="$1"
    local BASELINE_FILE="$2"
    local OUTPUT_FILE="$TEMP_DIR/unauthorized_devices.txt"
    
    log_info "Detecting unauthorized devices..."
    
    # Extract all device MACs from capture
    tshark -r "$CAPTURE_FILE" -T fields -e wlan.sa -e wlan.da 2>/dev/null | tr '\t' '\n' | grep -E "^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$" | sort | uniq > "$TEMP_DIR/all_devices.txt"
    
    # Compare with baseline
    if [[ -f "$BASELINE_FILE" ]]; then
        grep -vFf "$BASELINE_FILE" "$TEMP_DIR/all_devices.txt" > "$OUTPUT_FILE"
        local COUNT=$(wc -l < "$OUTPUT_FILE")
        
        if [[ "$COUNT" -gt 0 ]]; then
            log_warning "Found $COUNT unauthorized devices!"
            cat "$OUTPUT_FILE" | while read mac; do
                log_info "Unauthorized device: $mac"
                
                # Try to get manufacturer info
                if command -v macchanger &>/dev/null; then
                    local VENDOR=$(macchanger -l | grep -i "${mac:0:8}" | cut -d' ' -f5-)
                    if [[ -n "$VENDOR" ]]; then
                        log_info "  Vendor: $VENDOR"
                    fi
                fi
            done
        else
            log_success "No unauthorized devices detected."
        fi
    else
        log_error "Baseline file not found! Run 'baseline' command first."
        cp "$TEMP_DIR/all_devices.txt" "$OUTPUT_FILE"
    fi
    
    echo "$OUTPUT_FILE"
}

# Function to deauthenticate unauthorized devices
deauth_devices() {
    local INTERFACE="$1"
    local DEVICES_FILE="$2"
    local BSSID="$3"
    local COUNT="$DEFAULT_DEAUTH_COUNT"
    
    if [[ ! -f "$DEVICES_FILE" || ! -s "$DEVICES_FILE" ]]; then
        log_warning "No devices to deauthenticate."
        return 0
    fi
    
    if [[ -z "$BSSID" ]]; then
        log_error "BSSID required for deauthentication!"
        return 1
    }
    
    log_warning "Deauthenticating unauthorized devices..."
    
    cat "$DEVICES_FILE" | while read mac; do
        log_info "Deauthenticating $mac..."
        sudo aireplay-ng --deauth "$COUNT" -a "$BSSID" -c "$mac" "$INTERFACE" &>/dev/null
    done
    
    log_success "Deauthentication complete."
    return 0
}

# Function to create baseline of trusted devices
create_baseline() {
    local INTERFACE="$1"
    local DURATION="$2"
    local SSID="$3"
    local BSSID="$4"
    local OUTPUT_FILE="$LOG_DIR/baseline_$(date +%Y%m%d_%H%M%S).txt"
    
    log_info "Creating baseline of trusted devices for $DURATION seconds..."
    
    # Find channel if BSSID is provided but channel isn't
    local CHANNEL=""
    if [[ -n "$BSSID" ]]; then
        log_info "Determining channel for BSSID $BSSID..."
        scan_networks "$INTERFACE" >/dev/null
        CHANNEL=$(grep "$BSSID" "$TEMP_DIR/networks.txt" | cut -d',' -f3 | tr -d ' ')
        log_info "Found channel: $CHANNEL"
    fi
    
    # Capture traffic
    local CAPTURE_FILE=$(capture_traffic "$INTERFACE" "$DURATION" "$TEMP_DIR" "$BSSID" "$CHANNEL")
    
    # Extract all device MACs
    tshark -r "$CAPTURE_FILE-01.cap" -T fields -e wlan.sa -e wlan.da 2>/dev/null | tr '\t' '\n' | grep -E "^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$" | sort | uniq > "$OUTPUT_FILE"
    
    local COUNT=$(wc -l < "$OUTPUT_FILE")
    log_success "Baseline created with $COUNT trusted devices."
    
    # Add metadata to baseline file
    sed -i "1i# WiFi Defense Toolkit - Trusted Devices Baseline\n# Created: $(date)\n# SSID: $SSID\n# BSSID: $BSSID\n# Duration: $DURATION seconds\n#" "$OUTPUT_FILE"
    
    echo "$OUTPUT_FILE"
}

# Function to integrate with threat intelligence
check_threat_intelligence() {
    local DEVICES_FILE="$1"
    local OUTPUT_FILE="$TEMP_DIR/threat_intel_results.txt"
    
    log_info "Checking threat intelligence databases..."
    
    # Check if threat intelligence is enabled
    if [[ "$USE_THREATINTEL" != "true" ]]; then
        log_warning "Threat intelligence not enabled."
        return 0
    fi
    
    # Check for API keys
    local ALIENVAULT_KEY=$(get_api_key "alienvault")
    local THREATCROWD_KEY=$(get_api_key "threatcrowd")
    
    if [[ -z "$ALIENVAULT_KEY" && -z "$THREATCROWD_KEY" ]]; then
        log_error "No threat intelligence API keys configured!"
        log_info "Configure API keys using './common/api-keys.sh set alienvault YOUR_API_KEY'"
        return 1
    fi
    
    # Initialize results file
    cat > "$OUTPUT_FILE" << EOF
# Threat Intelligence Results
Generated: $(date)

EOF
    
    # Check devices against threat intel
    cat "$DEVICES_FILE" | while read mac; do
        echo "## Device: $mac" >> "$OUTPUT_FILE"
        
        # AlienVault OTX check if key exists
        if [[ -n "$ALIENVAULT_KEY" ]]; then
            echo "### AlienVault OTX" >> "$OUTPUT_FILE"
            local RESPONSE=$(curl -s -H "X-OTX-API-KEY: $ALIENVAULT_KEY" "https://otx.alienvault.com/api/v1/indicators/IPv4/$ip/general")
            
            if echo "$RESPONSE" | grep -q "pulse_info"; then
                echo "- **WARNING:** Device MAC address associated with malicious activities" >> "$OUTPUT_FILE"
                echo "- Reputation Score: $(echo "$RESPONSE" | jq -r '.reputation' 2>/dev/null || echo "Unknown")" >> "$OUTPUT_FILE"
            else
                echo "- No threats detected" >> "$OUTPUT_FILE"
            fi
        fi
        
        # Add more threat intel sources as needed
    done
    
    log_success "Threat intelligence check complete."
    echo "$OUTPUT_FILE"
}

# Function to setup monitoring as a service
setup_monitoring_service() {
    local INTERFACE="$1"
    local SERVICE_FILE="/etc/systemd/system/cyberkit-wifi-monitor.service"
    
    log_info "Setting up WiFi monitoring as a background service..."
    
    # Create systemd service file
    cat > "/tmp/cyberkit-wifi-monitor.service" << EOF
[Unit]
Description=CyberKit WiFi Defense Monitoring Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=$(realpath "$0") monitor -i $INTERFACE --background
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    
    # Install service
    sudo mv "/tmp/cyberkit-wifi-monitor.service" "$SERVICE_FILE"
    sudo systemctl daemon-reload
    sudo systemctl enable cyberkit-wifi-monitor.service
    sudo systemctl start cyberkit-wifi-monitor.service
    
    log_success "WiFi monitoring service installed and started."
    log_info "Check status with: sudo systemctl status cyberkit-wifi-monitor.service"
}

# Function to configure alerts
configure_alerts() {
    local ALERT_TYPE="$1"
    local CONFIG_FILE="$2"
    
    log_info "Configuring alerts..."
    
    # Create/update config file
    if [[ ! -f "$CONFIG_FILE" ]]; then
        cat > "$CONFIG_FILE" << EOF
# CyberKit WiFi Defense Toolkit Alert Configuration
# Generated: $(date)

ALERT_ENABLED=true
ALERT_TYPE=$ALERT_TYPE
EOF
    else
        sed -i "s/ALERT_ENABLED=.*/ALERT_ENABLED=true/" "$CONFIG_FILE"
        sed -i "s/ALERT_TYPE=.*/ALERT_TYPE=$ALERT_TYPE/" "$CONFIG_FILE"
    fi
    
    case "$ALERT_TYPE" in
        email)
            read -p "Enter email address for alerts: " EMAIL_ADDRESS
            echo "ALERT_EMAIL=$EMAIL_ADDRESS" >> "$CONFIG_FILE"
            log_success "Email alerts configured to $EMAIL_ADDRESS"
            ;;
        sms)
            read -p "Enter phone number for SMS alerts: " PHONE_NUMBER
            echo "ALERT_PHONE=$PHONE_NUMBER" >> "$CONFIG_FILE"
            log_success "SMS alerts configured to $PHONE_NUMBER"
            ;;
        both)
            read -p "Enter email address for alerts: " EMAIL_ADDRESS
            read -p "Enter phone number for SMS alerts: " PHONE_NUMBER
            echo "ALERT_EMAIL=$EMAIL_ADDRESS" >> "$CONFIG_FILE"
            echo "ALERT_PHONE=$PHONE_NUMBER" >> "$CONFIG_FILE"
            log_success "Email and SMS alerts configured"
            ;;
        *)
            log_error "Unknown alert type: $ALERT_TYPE"
            return 1
            ;;
    esac
    
    echo "$CONFIG_FILE"
}

# Function to send alerts
send_alert() {
    local MESSAGE="$1"
    local CONFIG_FILE="$2"
    
    # Load alert configuration
    if [[ -f "$CONFIG_FILE" ]]; then
        source "$CONFIG_FILE"
    else
        log_error "Alert configuration file not found!"
        return 1
    fi
    
    if [[ "$ALERT_ENABLED" != "true" ]]; then
        log_info "Alerts are disabled."
        return 0
    fi
    
    log_info "Sending alert: $MESSAGE"
    
    case "$ALERT_TYPE" in
        email)
            if [[ -n "$ALERT_EMAIL" ]]; then
                echo "$MESSAGE" | mail -s "CyberKit WiFi Defense Alert" "$ALERT_EMAIL"
                log_success "Email alert sent to $ALERT_EMAIL"
            fi
            ;;
        sms)
            if [[ -n "$ALERT_PHONE" ]]; then
                # This is a placeholder - implementation depends on your SMS gateway
                log_info "SMS alert would be sent to $ALERT_PHONE"
            fi
            ;;
        both)
            if [[ -n "$ALERT_EMAIL" ]]; then
                echo "$MESSAGE" | mail -s "CyberKit WiFi Defense Alert" "$ALERT_EMAIL"
                log_success "Email alert sent to $ALERT_EMAIL"
            fi
            if [[ -n "$ALERT_PHONE" ]]; then
                # SMS placeholder
                log_info "SMS alert would be sent to $ALERT_PHONE"
            fi
            ;;
    esac
}

# Function to generate visual reports
generate_visuals() {
    local CAPTURE_FILE="$1"
    local OUTPUT_DIR="$2"
    local HTML_REPORT="$OUTPUT_DIR/visual_report_$(date +%Y%m%d_%H%M%S).html"
    
    log_info "Generating visual network activity report..."
    
    # Create HTML report with embedded JavaScript for visualization
    cat > "$HTML_REPORT" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>WiFi Network Activity Visualization</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        .chart-container { margin-bottom: 30px; }
        h1, h2 { color: #333; }
    </style>
</head>
<body>
    <div class="container">
        <h1>WiFi Network Activity Visualization</h1>
        <p>Generated: $(date)</p>
        <p>Capture File: $CAPTURE_FILE</p>
        
        <div class="chart-container">
            <h2>Packet Type Distribution</h2>
            <canvas id="packetTypeChart"></canvas>
        </div>
        
        <div class="chart-container">
            <h2>Top Talkers</h2>
            <canvas id="topTalkersChart"></canvas>
        </div>
        
        <div class="chart-container">
            <h2>Activity Timeline</h2>
            <canvas id="timelineChart"></canvas>
        </div>
    </div>

    <script>
        // Data would be inserted here dynamically with real values
        // This is placeholder data
        const packetTypes = {
            labels: ['Management', 'Control', 'Data', 'Other'],
            datasets: [{
                label: 'Packet Count',
                data: [120, 78, 320, 12],
                backgroundColor: [
                    'rgba(255, 99, 132, 0.6)',
                    'rgba(54, 162, 235, 0.6)',
                    'rgba(255, 206, 86, 0.6)',
                    'rgba(75, 192, 192, 0.6)'
                ]
            }]
        };
        
        const topTalkers = {
            labels: ['00:11:22:33:44:55', 'AA:BB:CC:DD:EE:FF', '11:22:33:44:55:66', '22:33:44:55:66:77', '33:44:55:66:77:88'],
            datasets: [{
                label: 'Packets Sent/Received',
                data: [245, 187, 134, 98, 75],
                backgroundColor: 'rgba(54, 162, 235, 0.6)'
            }]
        };
        
        // Create charts
        new Chart(document.getElementById('packetTypeChart'), {
            type: 'pie',
            data: packetTypes,
            options: {
                responsive: true,
                plugins: { legend: { position: 'right' } }
            }
        });
        
        new Chart(document.getElementById('topTalkersChart'), {
            type: 'bar',
            data: topTalkers,
            options: {
                responsive: true,
                scales: { y: { beginAtZero: true } }
            }
        });
        
        // Timeline chart would be populated with real data
        // This is just placeholder setup
        new Chart(document.getElementById('timelineChart'), {
            type: 'line',
            data: {
                labels: Array.from({length: 10}, (_, i) => i*5 + ' min'),
                datasets: [{
                    label: 'Activity Volume',
                    data: [12, 19, 3, 5, 2, 3, 20, 33, 25, 10],
                    borderColor: 'rgba(75, 192, 192, 1)',
                    tension: 0.1
                }]
            },
            options: {
                responsive: true
            }
        });
    </script>
</body>
</html>
EOF
    
    log_success "Visual report generated: $HTML_REPORT"
    echo "$HTML_REPORT"
}

# Main function: Monitor WiFi network
monitor_wifi() {
    log_section "WiFi MONITORING"
    
    # Prepare interface
    local MONITOR_INTERFACE=$(enable_monitor_mode "$INTERFACE")
    
    log_info "Starting WiFi monitoring for $MONITOR_TIME seconds..."
    
    # Continuous monitoring loop
    local START_TIME=$(date +%s)
    local END_TIME=$((START_TIME + MONITOR_TIME))
    local CURRENT_TIME=0
    
    while [[ $CURRENT_TIME -lt $END_TIME || $MONITOR_TIME -eq 0 ]]; do
        # Short capture
        local CAPTURE_FILE=$(capture_traffic "$MONITOR_INTERFACE" "$SCAN_INTERVAL" "$CAPTURE_DIR" "$BSSID" "$CHANNEL")
        
        # Analyze for threats
        local ANALYSIS_REPORT=$(analyze_traffic "$CAPTURE_FILE-01.cap" "$CAPTURE_DIR" "$OPERATION_MODE")
        
        # Detect unauthorized devices
        local UNAUTHORIZED_DEVICES=$(detect_unauthorized_devices "$CAPTURE_FILE-01.cap" "$BASELINE_FILE")
        
        # Check if any unauthorized devices were found
        if [[ -s "$UNAUTHORIZED_DEVICES" ]]; then
            log_warning "Unauthorized devices detected!"
            
            # Check against threat intelligence if enabled
            if [[ "$USE_THREATINTEL" == "true" ]]; then
                check_threat_intelligence "$UNAUTHORIZED_DEVICES" >/dev/null
            fi
            
            # Deauthenticate if enabled
            if [[ "$ENABLE_DEAUTH" == "true" && -n "$BSSID" ]]; then
                deauth_devices "$MONITOR_INTERFACE" "$UNAUTHORIZED_DEVICES" "$BSSID"
            fi
            
            # Send alerts
            if [[ -f "$CONFIG_FILE" ]]; then
                local DEVICE_COUNT=$(wc -l < "$UNAUTHORIZED_DEVICES")
                send_alert "ALERT: $DEVICE_COUNT unauthorized devices detected on WiFi network." "$CONFIG_FILE"
            fi
        fi
        
        # Update current time
        CURRENT_TIME=$(date +%s)
        
        # If running in background mode, continue indefinitely
        if [[ "$BACKGROUND_MODE" == "true" ]]; then
            END_TIME=$((CURRENT_TIME + 1))
        fi
        
        # Sleep between scans (only if not in background mode)
        if [[ "$BACKGROUND_MODE" != "true" ]]; then
            local REMAINING=$((END_TIME - CURRENT_TIME))
            if [[ $REMAINING -gt 0 && $REMAINING -lt $SCAN_INTERVAL ]]; then
                log_info "Monitoring will complete in $REMAINING seconds..."
                sleep $REMAINING
            fi
        fi
    done
    
    # Disable monitor mode when done (not for background mode)
    if [[ "$BACKGROUND_MODE" != "true" ]]; then
        disable_monitor_mode "$MONITOR_INTERFACE"
    fi
    
    log_success "WiFi monitoring complete!"
}

# Main function: Analyze WiFi logs/captures
analyze_wifi() {
    log_section "WiFi ANALYSIS"
    
    # Check if directory exists
    if [[ ! -d "$CAPTURE_DIR" ]]; then
        log_error "Capture directory $CAPTURE_DIR does not exist!"
        exit 1
    fi
    
    # Find capture files
    local CAPTURE_FILES=()
    while IFS= read -r -d '' file; do
        CAPTURE_FILES+=("$file")
    done < <(find "$CAPTURE_DIR" -name "*.cap" -o -name "*.pcap" -print0)
    
    if [[ ${#CAPTURE_FILES[@]} -eq 0 ]]; then
        log_error "No capture files found in $CAPTURE_DIR!"
        exit 1
    fi
    
    # Let user select a file if there are multiple
    if [[ ${#CAPTURE_FILES[@]} -gt 1 ]]; then
        echo "Multiple capture files found. Please select one:"
        for i in "${!CAPTURE_FILES[@]}"; do
            echo "$((i+1)). ${CAPTURE_FILES[$i]}"
        done
        
        read -p "Enter number: " SELECTION
        SELECTED_FILE="${CAPTURE_FILES[$((SELECTION-1))]}"
    else
        SELECTED_FILE="${CAPTURE_FILES[0]}"
    fi
    
    log_info "Analyzing file: $SELECTED_FILE"
    
    # Analyze the selected file
    local ANALYSIS_REPORT=$(analyze_traffic "$SELECTED_FILE" "$CAPTURE_DIR" "$OPERATION_MODE")
    
    # Generate visual report if requested
    if [[ "$VISUALIZE" == "true" ]]; then
        generate_visuals "$SELECTED_FILE" "$CAPTURE_DIR"
    fi
    
    log_success "Analysis complete! Report saved to $ANALYSIS_REPORT"
}

# Main function: Implement active defense measures
defend_wifi() {
    log_section "WiFi DEFENSE"
    
    # Ensure we have required parameters
    if [[ -z "$BSSID" ]]; then
        log_error "BSSID is required for defense mode! Use -b/--bssid option."
        exit 1
    fi
    
    # Prepare interface
    local MONITOR_INTERFACE=$(enable_monitor_mode "$INTERFACE")
    
    log_info "Starting WiFi defense for $MONITOR_TIME seconds..."
    
    # First do a scan to get the channel
    scan_networks "$MONITOR_INTERFACE" >/dev/null
    local CHANNEL=$(grep "$BSSID" "$TEMP_DIR/networks.txt" | cut -d',' -f3 | tr -d ' ')
    
    if [[ -z "$CHANNEL" ]]; then
        log_warning "Could not determine channel for BSSID $BSSID. Using default scan."
        # Capture traffic without channel/BSSID filter
        local CAPTURE_FILE=$(capture_traffic "$MONITOR_INTERFACE" "$MONITOR_TIME" "$CAPTURE_DIR")
    else
        log_info "Found network on channel $CHANNEL"
        # Targeted capture
        local CAPTURE_FILE=$(capture_traffic "$MONITOR_INTERFACE" "$MONITOR_TIME" "$CAPTURE_DIR" "$BSSID" "$CHANNEL")
    fi
    
    # Analyze traffic
    local ANALYSIS_REPORT=$(analyze_traffic "$CAPTURE_FILE-01.cap" "$CAPTURE_DIR" "$OPERATION_MODE")
    
    # Detect unauthorized devices
    local UNAUTHORIZED_DEVICES=$(detect_unauthorized_devices "$CAPTURE_FILE-01.cap" "$BASELINE_FILE")
    
    # Take action against unauthorized devices
    if [[ -s "$UNAUTHORIZED_DEVICES" ]]; then
        log_warning "Unauthorized devices detected!"
        
        # Check against threat intelligence if enabled
        if [[ "$USE_THREATINTEL" == "true" ]]; then
            check_threat_intelligence "$UNAUTHORIZED_DEVICES" >/dev/null
        fi
        
        # Deauthenticate if enabled
        if [[ "$ENABLE_DEAUTH" == "true" ]]; then
            deauth_devices "$MONITOR_INTERFACE" "$UNAUTHORIZED_DEVICES" "$BSSID"
        fi
        
        # Send alerts
        if [[ -f "$CONFIG_FILE" ]]; then
            local DEVICE_COUNT=$(wc -l < "$UNAUTHORIZED_DEVICES")
            send_alert "ALERT: $DEVICE_COUNT unauthorized devices detected and defensive actions taken." "$CONFIG_FILE"
        fi
    else
        log_success "No unauthorized devices detected."
    fi
    
    # Disable monitor mode
    disable_monitor_mode "$MONITOR_INTERFACE"
    
    log_success "WiFi defense operations complete!"
}

# Parse command line arguments
parse_args() {
    # Default values
    INTERFACE=""
    MONITOR_TIME=$DEFAULT_MONITOR_TIME
    SCAN_INTERVAL=$DEFAULT_SCAN_INTERVAL
    CAPTURE_DIR=$DEFAULT_CAPTURE_DIR
    OPERATION_MODE="personal"
    SECURITY_LEVEL="medium"
    NETWORK_SSID=""
    BSSID=""
    EXCLUDE_FILE=""
    ENABLE_DEAUTH=true
    USE_THREATINTEL=false
    BACKGROUND_MODE=false
    VISUALIZE=false
    TEST_MODE=false
    VERBOSE=false
    BASELINE_FILE=""
    ALERT_METHOD=""
    CONFIG_FILE="$HOME/.cyberkit/wifi-defence.conf"
    COMMAND=""

    # Process options
    while [[ $# -gt 0 ]]; do
        case "$1" in
            monitor|analyze|defend|baseline|alert)
                COMMAND="$1"
                shift
                ;;
            -i|--interface)
                INTERFACE="$2"
                shift 2
                ;;
            -t|--time)
                MONITOR_TIME="$2"
                shift 2
                ;;
            -n|--network)
                NETWORK_SSID="$2"
                shift 2
                ;;
            -b|--bssid)
                BSSID="$2"
                shift 2
                ;;
            -o|--output)
                CAPTURE_DIR="$2"
                shift 2
                ;;
            -c|--config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            -m|--mode)
                OPERATION_MODE="$2"
                shift 2
                ;;
            -l|--level)
                SECURITY_LEVEL="$2"
                shift 2
                ;;
            -e|--exclude)
                EXCLUDE_FILE="$2"
                shift 2
                ;;
            -a|--alerts)
                ALERT_METHOD="$2"
                shift 2
                ;;
            --threatintel)
                USE_THREATINTEL=true
                shift
                ;;
            --no-deauth)
                ENABLE_DEAUTH=false
                shift
                ;;
            --background)
                BACKGROUND_MODE=true
                shift
                ;;
            --visualize)
                VISUALIZE=true
                shift
                ;;
            --test)
                TEST_MODE=true
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -h|--help)
                show_help
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                ;;
        esac
    done

    # Validate command
    if [[ -z "$COMMAND" ]]; then
        log_error "No command specified!"
        show_help
    fi

    # Validate required options
    if [[ "$COMMAND" != "analyze" && "$COMMAND" != "alert" && -z "$INTERFACE" ]]; then
        log_error "Interface (-i) is required for $COMMAND command!"
        exit 1
    fi

    # Find baseline file if operation mode is specified but baseline file isn't
    if [[ -z "$BASELINE_FILE" && "$COMMAND" != "baseline" ]]; then
        if [[ -n "$NETWORK_SSID" ]]; then
            # Try to find most recent baseline for this SSID
            BASELINE_FILE=$(grep -l "SSID: $NETWORK_SSID" "$LOG_DIR"/baseline_*.txt 2>/dev/null | sort -r | head -1)
        elif [[ -n "$BSSID" ]]; then
            # Try to find most recent baseline for this BSSID
            BASELINE_FILE=$(grep -l "BSSID: $BSSID" "$LOG_DIR"/baseline_*.txt 2>/dev/null | sort -r | head -1)
        fi
        
        if [[ -n "$BASELINE_FILE" ]]; then
            log_info "Using baseline file: $BASELINE_FILE"
        else
            log_warning "No baseline file found! Some features may not work correctly."
        fi
    fi
}

# Main execution flow
main() {
    header "WiFi Defence Toolkit"
    log_info "Starting WiFi Defence Toolkit..."
    
    # Parse command line arguments
    parse_args "$@"
    
    # Check for root permissions
    if [[ $EUID -ne 0 ]]; then
        log_warning "This script requires root privileges for WiFi operations."
        log_info "Please run with sudo or as root."
        exit 1
    fi
    
    # Check dependencies
    check_dependencies
    
    # Create capture directory if it doesn't exist
    mkdir -p "$CAPTURE_DIR"
    
    # Execute command
    case "$COMMAND" in
        monitor)
            monitor_wifi
            ;;
        analyze)
            analyze_wifi
            ;;
        defend)
            defend_wifi
            ;;
        baseline)
            create_baseline "$INTERFACE" "$MONITOR_TIME" "$NETWORK_SSID" "$BSSID"
            ;;
        alert)
            configure_alerts "$ALERT_METHOD" "$CONFIG_FILE"
            ;;
        *)
            log_error "Unknown command: $COMMAND"
            show_help
            ;;
    esac
    
    # Clean up temp files
    rm -rf "$TEMP_DIR"/*
    
    log_success "WiFi Defence Toolkit operation complete!"
}

# Run main function with all arguments
main "$@"