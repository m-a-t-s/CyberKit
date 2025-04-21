#!/bin/bash
# network-scan.sh - Network Penetration Testing Script
# ===================================================
# This script automates network penetration testing tasks, including
# host discovery, port scanning, service enumeration, and vulnerability assessment.

# Source common utilities and configuration
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$SCRIPT_DIR/../common/utils.sh"
source "$SCRIPT_DIR/../common/config.sh"

# Display banner
print_banner "Network Penetration Testing Tool"

# Global variables
TARGET=""
OUTPUT_DIR=""
SCAN_TYPE="default" # default, quick, comprehensive, stealth
SCAN_TIMING=3 # 0-5, default is 3 (normal)
PORT_RANGE="default" # default, all, top-100, top-1000, custom
CUSTOM_PORTS=""
SERVICE_DETECT=true
OS_DETECT=true
VULN_SCAN=false
THREADS=10
IP_VERSION=4 # 4, 6, both
EXCLUDE_HOSTS=""
MAX_RETRIES=3
HOST_TIMEOUT=900 # 15 minutes in seconds
MAX_SCAN_TIME=14400 # 4 hours in seconds
SCRIPT_INTENSITY="default" # default, light, version-only, safe, intrusive, all
CUSTOM_SCRIPTS=""
PACKET_TRACE=false
INTERFACE=""
USE_MASSCAN=false
USE_PROXYCHAINS=false
OPSEC_LEVEL="low" # low, medium, high
REPORT_FORMAT="all" # all, txt, html, xml

# Function to check dependencies
check_dependencies() {
    log "INFO" "Checking dependencies..."
    
    local required_tools=("nmap" "jq" "xsltproc")
    local missing=()
    
    for tool in "${required_tools[@]}"; do
        if ! check_tool "$tool"; then
            missing+=("$tool")
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        log "ERROR" "Missing required tools: ${missing[*]}"
        log "WARNING" "Please install missing tools before continuing."
        exit 1
    fi
    
    # Check for optional tools
    if [ "$USE_MASSCAN" = true ] && ! check_tool "masscan"; then
        log "WARNING" "Masscan requested but not found, falling back to Nmap."
        USE_MASSCAN=false
    fi
    
    if [ "$USE_PROXYCHAINS" = true ] && ! check_tool "proxychains"; then
        log "WARNING" "Proxychains requested but not found, proceeding without it."
        USE_PROXYCHAINS=false
    fi
    
    log "SUCCESS" "All required dependencies are installed."
}

# Function to parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -t|--target)
                TARGET="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -s|--scan-type)
                if [[ "$2" == "default" || "$2" == "quick" || "$2" == "comprehensive" || "$2" == "stealth" ]]; then
                    SCAN_TYPE="$2"
                    shift 2
                else
                    log "ERROR" "Invalid scan type: $2"
                    echo "Valid types: default, quick, comprehensive, stealth"
                    exit 1
                fi
                ;;
            --timing)
                if [[ "$2" =~ ^[0-5]$ ]]; then
                    SCAN_TIMING="$2"
                    shift 2
                else
                    log "ERROR" "Invalid timing: $2"
                    echo "Valid timing: 0-5 (0=paranoid, 5=insane)"
                    exit 1
                fi
                ;;
            -p|--ports)
                if [[ "$2" == "default" || "$2" == "all" || "$2" == "top-100" || "$2" == "top-1000" ]]; then
                    PORT_RANGE="$2"
                    shift 2
                else
                    PORT_RANGE="custom"
                    CUSTOM_PORTS="$2"
                    shift 2
                fi
                ;;
            --no-service-detect)
                SERVICE_DETECT=false
                shift
                ;;
            --no-os-detect)
                OS_DETECT=false
                shift
                ;;
            --vuln-scan)
                VULN_SCAN=true
                shift
                ;;
            -th|--threads)
                THREADS="$2"
                shift 2
                ;;
            --ipv6)
                IP_VERSION=6
                shift
                ;;
            --ip-all)
                IP_VERSION="both"
                shift
                ;;
            -e|--exclude)
                EXCLUDE_HOSTS="$2"
                shift 2
                ;;
            --max-retries)
                MAX_RETRIES="$2"
                shift 2
                ;;
            --host-timeout)
                HOST_TIMEOUT="$2"
                shift 2
                ;;
            --max-scan-time)
                MAX_SCAN_TIME="$2"
                shift 2
                ;;
            --script-intensity)
                if [[ "$2" == "default" || "$2" == "light" || "$2" == "version-only" || "$2" == "safe" || "$2" == "intrusive" || "$2" == "all" ]]; then
                    SCRIPT_INTENSITY="$2"
                    shift 2
                else
                    log "ERROR" "Invalid script intensity: $2"
                    echo "Valid intensities: default, light, version-only, safe, intrusive, all"
                    exit 1
                fi
                ;;
            --custom-scripts)
                CUSTOM_SCRIPTS="$2"
                shift 2
                ;;
            --packet-trace)
                PACKET_TRACE=true
                shift
                ;;
            -i|--interface)
                INTERFACE="$2"
                shift 2
                ;;
            --masscan)
                USE_MASSCAN=true
                shift
                ;;
            --proxychains)
                USE_PROXYCHAINS=true
                shift
                ;;
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
            --report)
                if [[ "$2" == "all" || "$2" == "txt" || "$2" == "html" || "$2" == "xml" ]]; then
                    REPORT_FORMAT="$2"
                    shift 2
                else
                    log "ERROR" "Invalid report format: $2"
                    echo "Valid formats: all, txt, html, xml"
                    exit 1
                fi
                ;;
            -h|--help)
                echo "Usage: $0 [options]"
                echo ""
                echo "Options:"
                echo "  -t, --target TARGET      Target IP, range (CIDR), or hostname (required)"
                echo "  -o, --output DIR         Output directory (default: ./results/TARGET)"
                echo "  -s, --scan-type TYPE     Scan type: default, quick, comprehensive, stealth"
                echo "  --timing LEVEL           Timing template: 0-5 (default: 3)"
                echo "  -p, --ports RANGE        Port range: default, all, top-100, top-1000, or custom"
                echo "  --no-service-detect      Disable service version detection"
                echo "  --no-os-detect           Disable OS detection"
                echo "  --vuln-scan              Enable vulnerability scanning"
                echo "  -th, --threads NUM       Number of threads/parallel processes"
                echo "  --ipv6                   Use IPv6 instead of IPv4"
                echo "  --ip-all                 Scan both IPv4 and IPv6"
                echo "  -e, --exclude HOSTS      Exclude hosts from scan"
                echo "  --max-retries NUM        Maximum number of retries"
                echo "  --host-timeout SECONDS   Host timeout in seconds"
                echo "  --max-scan-time SECONDS  Maximum scan time in seconds"
                echo "  --script-intensity LEVEL Script intensity: default, light, version-only, safe, intrusive, all"
                echo "  --custom-scripts SCRIPTS Custom Nmap scripts to run"
                echo "  --packet-trace           Enable packet tracing (for debugging)"
                echo "  -i, --interface IFACE    Network interface to use"
                echo "  --masscan                Use Masscan for initial port discovery (if available)"
                echo "  --proxychains            Route scan through Proxychains (if available)"
                echo "  --opsec LEVEL            OPSEC level: low, medium, high"
                echo "  --report FORMAT          Report format: all, txt, html, xml"
                echo "  -h, --help               Show this help message"
                exit 0
                ;;
            *)
                log "ERROR" "Unknown option: $1"
                echo "Use -h or --help for usage information"
                exit 1
                ;;
        esac
    done
    
    # Check required arguments
    if [ -z "$TARGET" ]; then
        log "ERROR" "Target is required. Use -t or --target to specify."
        exit 1
    fi
    
    # Set default output directory if not specified
    if [ -z "$OUTPUT_DIR" ]; then
        # Sanitize target for directory name
        local safe_target=$(echo "$TARGET" | tr '/' '_' | tr ':' '_')
        OUTPUT_DIR="$DEFAULT_ENGAGEMENTS_DIR/network-scan/$safe_target-$(date +%Y%m%d-%H%M%S)"
    fi
    
    # Ensure output directory exists
    ensure_dir "$OUTPUT_DIR"
    ensure_dir "$OUTPUT_DIR"/{discovery,services,vulnerabilities,evidence,reports}
    
    # Set up logging
    LOG_FILE="$OUTPUT_DIR/network-scan.log"
    log "INFO" "Logs will be saved to $LOG_FILE"
}

# Adjust scan parameters based on OPSEC level
adjust_for_opsec() {
    log "INFO" "Adjusting scan parameters for OPSEC level: $OPSEC_LEVEL"
    
    case "$OPSEC_LEVEL" in
        "low")
            # No adjustments for low OPSEC
            log "INFO" "Using standard scan parameters (low OPSEC)"
            ;;
        "medium")
            # Medium OPSEC - adjust for lower detectability
            log "INFO" "Applying medium OPSEC adjustments"
            if [ $SCAN_TIMING -gt 3 ]; then
                SCAN_TIMING=3
            fi
            SERVICE_DETECT=true
            SCRIPT_INTENSITY="safe"
            if [ "$SCAN_TYPE" = "comprehensive" ]; then
                SCAN_TYPE="default"
            fi
            if [ "$PORT_RANGE" = "all" ]; then
                PORT_RANGE="top-1000"
            fi
            ;;
        "high")
            # High OPSEC - stealth mode
            log "INFO" "Applying high OPSEC adjustments (stealth mode)"
            SCAN_TYPE="stealth"
            SCAN_TIMING=2
            SERVICE_DETECT=false
            OS_DETECT=false
            SCRIPT_INTENSITY="version-only"
            VULN_SCAN=false
            if [ "$PORT_RANGE" = "all" ] || [ "$PORT_RANGE" = "top-1000" ]; then
                PORT_RANGE="top-100"
            fi
            ;;
    esac
}

# Function to perform host discovery
do_host_discovery() {
    log "INFO" "Starting host discovery phase..."
    
    local discovery_dir="$OUTPUT_DIR/discovery"
    local start_time=$(date +%s)
    
    # Adjust command for IPv6 if needed
    local ip_option=""
    if [ "$IP_VERSION" = "6" ]; then
        ip_option="-6"
    elif [ "$IP_VERSION" = "both" ]; then
        log "INFO" "Scanning both IPv4 and IPv6"
        ip_option="-4 -6"
    fi
    
    # Exclude hosts if specified
    local exclude_option=""
    if [ ! -z "$EXCLUDE_HOSTS" ]; then
        exclude_option="--exclude $EXCLUDE_HOSTS"
    fi
    
    # Interface option if specified
    local interface_option=""
    if [ ! -z "$INTERFACE" ]; then
        interface_option="-e $INTERFACE"
    fi
    
    # Set base command with common options
    local base_cmd=""
    if [ "$USE_PROXYCHAINS" = true ]; then
        base_cmd="proxychains "
    fi
    
    # Adjust the discovery method based on scan type
    case "$SCAN_TYPE" in
        "quick")
            log "INFO" "Performing quick host discovery..."
            ${base_cmd}nmap -sn -T$SCAN_TIMING $ip_option $exclude_option $interface_option \
                --max-retries $MAX_RETRIES --host-timeout ${HOST_TIMEOUT}s \
                -oA "$discovery_dir/quick-discovery" "$TARGET"
            ;;
        "stealth")
            log "INFO" "Performing stealth host discovery..."
            ${base_cmd}nmap -sn -T$SCAN_TIMING $ip_option $exclude_option $interface_option \
                --max-retries $MAX_RETRIES --host-timeout ${HOST_TIMING}s --data-length 15 \
                -oA "$discovery_dir/stealth-discovery" "$TARGET"
            ;;
        "comprehensive"|"default")
            log "INFO" "Performing comprehensive host discovery..."
            ${base_cmd}nmap -sn -PE -PP -PS22,80,443,3389 -PA80,443,3389 -PU53,161 \
                