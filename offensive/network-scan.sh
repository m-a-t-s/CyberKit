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
USE_CVE_LOOKUP=false
USE_THREAT_INTEL=false

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
            --cve-lookup)
                USE_CVE_LOOKUP=true
                shift
                ;;
            --threatintel)
                USE_THREAT_INTEL=true
                shift
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
                echo "  --cve-lookup             Look up CVE details for identified vulnerabilities"
                echo "  --threatintel            Check target IPs against threat intelligence"
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
                --max-retries $MAX_RETRIES --host-timeout ${HOST_TIMEOUT}s --data-length 15 \
                -oA "$discovery_dir/stealth-discovery" "$TARGET"
            ;;
        "comprehensive"|"default")
            log "INFO" "Performing comprehensive host discovery..."
            ${base_cmd}nmap -sn -PE -PP -PS22,80,443,3389 -PA80,443,3389 -PU53,161 \
                -T$SCAN_TIMING $ip_option $exclude_option $interface_option \
                --max-retries $MAX_RETRIES --host-timeout ${HOST_TIMEOUT}s \
                -oA "$discovery_dir/comprehensive-discovery" "$TARGET"
            ;;
    esac
    
    # Extract live hosts
    log "INFO" "Extracting live hosts from discovery results..."
    grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" "$discovery_dir/"*".gnmap" 2>/dev/null | sort -u > "$discovery_dir/live-hosts.txt"
    
    # Count discovered hosts
    local host_count=$(wc -l < "$discovery_dir/live-hosts.txt")
    log "SUCCESS" "Host discovery completed. Found $host_count live hosts."
    
    # Log completion time
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    log "INFO" "Host discovery completed in $(seconds_to_time $duration)."
    
    # Return the count of hosts found
    echo $host_count
}

# Function to perform port scanning
do_port_scanning() {
    log "INFO" "Starting port scanning phase..."
    
    local discovery_dir="$OUTPUT_DIR/discovery"
    local services_dir="$OUTPUT_DIR/services"
    local start_time=$(date +%s)
    
    # Check if we have live hosts
    if [ ! -s "$discovery_dir/live-hosts.txt" ]; then
        log "WARNING" "No live hosts found. Skipping port scanning."
        return 0
    fi
    
    # Setup port range based on selected option
    local port_option=""
    case "$PORT_RANGE" in
        "default")
            # Default Nmap ports
            port_option=""
            ;;
        "all")
            port_option="-p-"
            ;;
        "top-100")
            port_option="--top-ports 100"
            ;;
        "top-1000")
            port_option="--top-ports 1000"
            ;;
        "custom")
            port_option="-p $CUSTOM_PORTS"
            ;;
    esac
    
    # Adjust command for IPv6 if needed
    local ip_option=""
    if [ "$IP_VERSION" = "6" ]; then
        ip_option="-6"
    elif [ "$IP_VERSION" = "both" ]; then
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
    
    # If using Masscan for initial port discovery
    if [ "$USE_MASSCAN" = true ] && [ "$IP_VERSION" != "6" ]; then
        log "INFO" "Using Masscan for initial port discovery..."
        
        local masscan_ports=""
        case "$PORT_RANGE" in
            "default"|"top-1000")
                masscan_ports="0-1000,1433,3306,3389,5432,5900,5901,6379,8080,8443,27017,27018"
                ;;
            "top-100")
                masscan_ports="20-25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080"
                ;;
            "all")
                masscan_ports="0-65535"
                ;;
            "custom")
                masscan_ports="$CUSTOM_PORTS"
                ;;
        esac
        
        # Run Masscan
        ${base_cmd}masscan -iL "$discovery_dir/live-hosts.txt" -p$masscan_ports --rate=1000 \
            --retries=$MAX_RETRIES $([ ! -z "$INTERFACE" ] && echo "--interface=$INTERFACE") \
            -oJ "$discovery_dir/masscan-results.json"
        
        # Extract ports from Masscan results for Nmap to scan
        if [ -f "$discovery_dir/masscan-results.json" ]; then
            jq -r '.[] | .ports[] | .port' "$discovery_dir/masscan-results.json" 2>/dev/null | \
                sort -n | uniq | tr '\n' ',' | sed 's/,$//' > "$discovery_dir/masscan-ports.txt"
            
            if [ -s "$discovery_dir/masscan-ports.txt" ]; then
                port_option="-p $(cat "$discovery_dir/masscan-ports.txt")"
                log "INFO" "Masscan discovered ports: $(cat "$discovery_dir/masscan-ports.txt")"
            else
                log "WARNING" "Masscan didn't find any open ports. Falling back to Nmap."
            fi
        else
            log "WARNING" "Masscan results not found. Falling back to Nmap."
        fi
    fi
    
    # Service detection option
    local service_option=""
    if [ "$SERVICE_DETECT" = true ]; then
        service_option="-sV"
        if [ "$SCRIPT_INTENSITY" = "version-only" ]; then
            service_option="$service_option --version-intensity 2"
        elif [ "$SCRIPT_INTENSITY" = "light" ]; then
            service_option="$service_option --version-intensity 4"
        elif [ "$SCRIPT_INTENSITY" = "intrusive" ] || [ "$SCRIPT_INTENSITY" = "all" ]; then
            service_option="$service_option --version-intensity 9"
        else
            service_option="$service_option --version-intensity 7"
        fi
    fi
    
    # OS detection option
    local os_option=""
    if [ "$OS_DETECT" = true ]; then
        os_option="-O"
    fi
    
    # Script option based on intensity
    local script_option=""
    case "$SCRIPT_INTENSITY" in
        "default")
            script_option="-sC"
            ;;
        "safe")
            script_option="--script=safe"
            ;;
        "intrusive")
            script_option="--script=default,auth,vuln"
            ;;
        "all")
            script_option="--script=all"
            ;;
        "version-only"|"light")
            # No additional scripts, just version detection
            script_option=""
            ;;
    esac
    
    # Add custom scripts if specified
    if [ ! -z "$CUSTOM_SCRIPTS" ]; then
        if [ -z "$script_option" ]; then
            script_option="--script=$CUSTOM_SCRIPTS"
        else
            script_option="$script_option,$CUSTOM_SCRIPTS"
        fi
    fi
    
    # Packet trace option
    local trace_option=""
    if [ "$PACKET_TRACE" = true ]; then
        trace_option="--packet-trace"
    fi
    
    # Configure scan type
    local scan_type_option=""
    case "$SCAN_TYPE" in
        "quick")
            scan_type_option="-sS"
            ;;
        "stealth")
            scan_type_option="-sS -D RND:5"
            ;;
        "comprehensive")
            scan_type_option="-sS -sU"
            ;;
        "default")
            scan_type_option="-sS"
            ;;
    esac
    
    # Combine all options for Nmap
    log "INFO" "Running port scan with Nmap..."
    ${base_cmd}nmap $scan_type_option $port_option $service_option $os_option $script_option \
        -T$SCAN_TIMING $ip_option $exclude_option $interface_option $trace_option \
        --max-retries $MAX_RETRIES --host-timeout ${HOST_TIMEOUT}s --max-scan-delay 10ms \
        -iL "$discovery_dir/live-hosts.txt" \
        -oA "$services_dir/port-scan"
    
    # Extract open ports
    log "INFO" "Extracting open ports from scan results..."
    grep "open" "$services_dir/port-scan.nmap" | grep -v "filtered" > "$services_dir/open-ports.txt"
    
    # Count open ports
    local port_count=$(grep -c "open" "$services_dir/open-ports.txt")
    log "SUCCESS" "Port scanning completed. Found $port_count open ports."
    
    # Log completion time
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    log "INFO" "Port scanning completed in $(seconds_to_time $duration)."
    
    # Return the count of ports found
    echo $port_count
}

# Function to perform vulnerability scanning
do_vulnerability_scanning() {
    if [ "$VULN_SCAN" != "true" ]; then
        log "INFO" "Vulnerability scanning disabled. Skipping."
        return 0
    fi
    
    log "INFO" "Starting vulnerability scanning phase..."
    
    local services_dir="$OUTPUT_DIR/services"
    local vuln_dir="$OUTPUT_DIR/vulnerabilities"
    local start_time=$(date +%s)
    
    # Check if we have scan results
    if [ ! -f "$services_dir/port-scan.nmap" ]; then
        log "WARNING" "No port scan results found. Skipping vulnerability scanning."
        return 0
    fi
    
    # Adjust command for IPv6 if needed
    local ip_option=""
    if [ "$IP_VERSION" = "6" ]; then
        ip_option="-6"
    elif [ "$IP_VERSION" = "both" ]; then
        ip_option="-4 -6"
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
    
    # Run vulnerability scan with appropriate scripts
    log "INFO" "Running vulnerability scripts against discovered services..."
    ${base_cmd}nmap --script vuln -T$SCAN_TIMING $ip_option $interface_option \
        --max-retries $MAX_RETRIES --host-timeout ${HOST_TIMEOUT}s \
        -iL "$discovery_dir/live-hosts.txt" \
        -oA "$vuln_dir/vuln-scan"
    
    # Count vulnerabilities (approximate based on "VULNERABLE" keyword)
    local vuln_count=$(grep -c "VULNERABLE" "$vuln_dir/vuln-scan.nmap")
    log "SUCCESS" "Vulnerability scanning completed. Found approximately $vuln_count potential vulnerabilities."
    
    # Enhanced vulnerability assessment with external APIs if requested
    if [ "$USE_CVE_LOOKUP" = true ] || [ "$USE_THREAT_INTEL" = true ]; then
        log "INFO" "Performing enhanced vulnerability assessment with external APIs..."
        
        # Create external APIs directory
        local api_dir="$vuln_dir/external-apis"
        ensure_dir "$api_dir"
        
        # CVE lookup with NVD API
        if [ "$USE_CVE_LOOKUP" = true ]; then
            log "INFO" "Looking up CVE details for identified vulnerabilities..."
            
            # Try to get API key (NVD API allows limited usage without a key but higher rate limits with one)
            local nvd_key=$("$SCRIPT_DIR/../common/api-keys.sh" get nvd 2>/dev/null)
            
            # Extract CVEs from vulnerability scan
            grep -o "CVE-[0-9]\{4\}-[0-9]\{4,\}" "$vuln_dir/vuln-scan.nmap" | sort -u > "$api_dir/found-cves.txt"
            
            if [ -s "$api_dir/found-cves.txt" ]; then
                # Create a summary file
                echo "# CVE Details for Identified Vulnerabilities" > "$api_dir/cve-details.md"
                echo "" >> "$api_dir/cve-details.md"
                
                # Process each CVE
                while read -r cve; do
                    log "INFO" "Looking up details for $cve..."
                    
                    # Construct request URL
                    local api_url="https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=$cve"
                    local api_headers=""
                    if [ ! -z "$nvd_key" ]; then
                        api_headers="-H \"apiKey: $nvd_key\""
                    fi
                    
                    # Make API request
                    local tmp_file=$(create_temp_file)
                    eval curl -s $api_headers "$api_url" > "$tmp_file"
                    
                    # Check if we got a valid response
                    if jq -e '.vulnerabilities[0]' "$tmp_file" >/dev/null 2>&1; then
                        # Extract key information
                        local cve_description=$(jq -r '.vulnerabilities[0].cve.descriptions[] | select(.lang=="en") | .value' "$tmp_file")
                        local cve_severity=$(jq -r '.vulnerabilities[0].cve.metrics.cvssMetricV31[0].cvssData.baseSeverity // "Unknown"' "$tmp_file")
                        local cve_score=$(jq -r '.vulnerabilities[0].cve.metrics.cvssMetricV31[0].cvssData.baseScore // "Unknown"' "$tmp_file")
                        local cve_published=$(jq -r '.vulnerabilities[0].cve.published // "Unknown"' "$tmp_file" | cut -d'T' -f1)
                        
                        # Add to summary file
                        echo "## $cve (Severity: $cve_severity, Score: $cve_score)" >> "$api_dir/cve-details.md"
                        echo "Published: $cve_published" >> "$api_dir/cve-details.md"
                        echo "" >> "$api_dir/cve-details.md"
                        echo "$cve_description" >> "$api_dir/cve-details.md"
                        echo "" >> "$api_dir/cve-details.md"
                        echo "---" >> "$api_dir/cve-details.md"
                        echo "" >> "$api_dir/cve-details.md"
                        
                        # Save full response
                        jq '.' "$tmp_file" > "$api_dir/$cve.json"
                    else
                        log "WARNING" "Failed to retrieve details for $cve"
                    fi
                    
                    # Respect rate limits - sleep between requests
                    sleep 2
                done < "$api_dir/found-cves.txt"
                
                log "SUCCESS" "CVE details lookup completed."
            else
                log "INFO" "No CVEs identified in vulnerability scan."
            fi
        fi
        
        # Threat intelligence lookup
        if [ "$USE_THREAT_INTEL" = true ]; then
            log "INFO" "Checking threat intelligence for target IPs..."
            
            # Try to get AlienVault OTX API key
            local otx_key=$("$SCRIPT_DIR/../common/api-keys.sh" get alienvault 2>/dev/null)
            if [ $? -eq 0 ] && [ ! -z "$otx_key" ]; then
                # Extract IPs from host discovery
                if [ -f "$discovery_dir/live-hosts.txt" ]; then
                    # Create a summary file
                    echo "# Threat Intelligence Report" > "$api_dir/threat-intel-report.md"
                    echo "" >> "$api_dir/threat-intel-report.md"
                    
                    # Process each IP
                    while read -r ip; do
                        log "INFO" "Checking threat intelligence for $ip..."
                        
                        # Query AlienVault OTX
                        local tmp_file=$(create_temp_file)
                        curl -s -H "X-OTX-API-KEY: $otx_key" "https://otx.alienvault.com/api/v1/indicators/IPv4/$ip/general" > "$tmp_file"
                        
                        # Check if we got a valid response
                        if jq -e '.pulse_info' "$tmp_file" >/dev/null 2>&1; then
                            local pulse_count=$(jq -r '.pulse_info.count' "$tmp_file")
                            
                            # Add to summary file
                            echo "## IP: $ip" >> "$api_dir/threat-intel-report.md"
                            echo "" >> "$api_dir/threat-intel-report.md"
                            
                            if [ "$pulse_count" -gt 0 ]; then
                                echo "**WARNING: This IP appears in $pulse_count threat intelligence reports!**" >> "$api_dir/threat-intel-report.md"
                                echo "" >> "$api_dir/threat-intel-report.md"
                                
                                # Extract pulse names
                                echo "### Threat Reports" >> "$api_dir/threat-intel-report.md"
                                jq -r '.pulse_info.pulses[] | "- " + .name + " (" + .created + ")"' "$tmp_file" >> "$api_dir/threat-intel-report.md"
                                echo "" >> "$api_dir/threat-intel-report.md"
                            else
                                echo "No threat intelligence reports found for this IP." >> "$api_dir/threat-intel-report.md"
                                echo "" >> "$api_dir/threat-intel-report.md"
                            fi
                            
                            # Save full response
                            jq '.' "$tmp_file" > "$api_dir/threatintel-$ip.json"
                        else
                            log "WARNING" "Failed to retrieve threat intelligence for $ip"
                        fi
                        
                        # Respect rate limits
                        sleep 2
                    done < "$discovery_dir/live-hosts.txt"
                    
                    log "SUCCESS" "Threat intelligence lookup completed."
                else
                    log "WARNING" "No live hosts found to check for threat intelligence."
                fi
            else
                log "WARNING" "AlienVault OTX API key not found. Run 'common/api-keys.sh set alienvault YOUR_API_KEY' to configure."
            fi
        fi
    fi
    
    # Log completion time
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    log "INFO" "Vulnerability scanning completed in $(seconds_to_time $duration)."
    
    # Return the count of vulnerabilities found
    echo $vuln_count
}

# Function to generate reports
generate_reports() {
    log "INFO" "Generating reports..."
    
    local reports_dir="$OUTPUT_DIR/reports"
    local start_time=$(date +%s)
    
    # Generate summary report
    log "INFO" "Creating summary report..."
    
    local summary_file="$reports_dir/scan-summary.md"
    
    # Create report header
    cat > "$summary_file" << EOF
# Network Scan Summary Report

## Overview

- **Target:** $TARGET
- **Scan Date:** $(date +"%Y-%m-%d")
- **Scan Type:** $SCAN_TYPE
- **Port Range:** $PORT_RANGE$([ "$PORT_RANGE" = "custom" ] && echo " ($CUSTOM_PORTS)")

## Summary Statistics

EOF
    
    # Add host discovery statistics
    local host_count=$(wc -l < "$discovery_dir/live-hosts.txt" 2>/dev/null || echo "0")
    echo "- **Live Hosts:** $host_count hosts discovered" >> "$summary_file"
    
    # Add port scanning statistics
    local port_count=$(grep -c "open" "$services_dir/open-ports.txt" 2>/dev/null || echo "0")
    echo "- **Open Ports:** $port_count ports discovered" >> "$summary_file"
    
    # Add vulnerability statistics if performed
    if [ "$VULN_SCAN" = "true" ] && [ -f "$vuln_dir/vuln-scan.nmap" ]; then
        local vuln_count=$(grep -c "VULNERABLE" "$vuln_dir/vuln-scan.nmap")
        echo "- **Potential Vulnerabilities:** $vuln_count vulnerabilities identified" >> "$summary_file"
    fi
    
    # Add discovered hosts
    cat >> "$summary_file" << EOF

## Discovered Hosts

EOF
    
    if [ "$host_count" -gt 0 ]; then
        cat "$discovery_dir/live-hosts.txt" | sed 's/^/- /' >> "$summary_file"
    else
        echo "No live hosts discovered." >> "$summary_file"
    fi
    
    # Add service summary
    cat >> "$summary_file" << EOF

## Service Summary

The most common services discovered:

EOF
    
    if [ -f "$services_dir/port-scan.nmap" ]; then
        grep "open" "$services_dir/port-scan.nmap" | grep -v "filtered" | awk -F/ '{print $1 " " $5}' | sort | uniq -c | sort -nr | head -10 | while read -r line; do
            echo "- $line" >> "$summary_file"
        done
    else
        echo "No services discovered." >> "$summary_file"
    fi
    
    # Add vulnerability summary if available
    if [ "$VULN_SCAN" = "true" ] && [ -f "$vuln_dir/vuln-scan.nmap" ]; then
        cat >> "$summary_file" << EOF

## Vulnerability Summary

The following potential vulnerabilities were identified:

EOF
        
        if grep -q "VULNERABLE" "$vuln_dir/vuln-scan.nmap"; then
            grep -A 2 "VULNERABLE" "$vuln_dir/vuln-scan.nmap" | grep -v "\-\-" | sed 's/^/- /' >> "$summary_file"
        else
            echo "No significant vulnerabilities found." >> "$summary_file"
        fi
    fi
    
    # Add API-based intelligence if available
    if [ -d "$vuln_dir/external-apis" ]; then
        # Add CVE details if available
        if [ -f "$vuln_dir/external-apis/cve-details.md" ]; then
            cat >> "$summary_file" << EOF

## CVE Details

Detailed information about identified CVEs (abbreviated):

EOF
            # Include first part of the CVE details file (first 3 CVEs or so)
            head -30 "$vuln_dir/external-apis/cve-details.md" >> "$summary_file"
            echo "...(see full CVE details in the external-apis directory)..." >> "$summary_file"
        fi
        
        # Add threat intelligence if available
        if [ -f "$vuln_dir/external-apis/threat-intel-report.md" ]; then
            cat >> "$summary_file" << EOF

## Threat Intelligence Findings

EOF
            # Extract any hosts with warnings
            grep -A 1 "WARNING" "$vuln_dir/external-apis/threat-intel-report.md" > "$reports_dir/threat-warnings.tmp"
            
            if [ -s "$reports_dir/threat-warnings.tmp" ]; then
                cat "$reports_dir/threat-warnings.tmp" >> "$summary_file"
                echo "(see full threat intelligence report in the external-apis directory)" >> "$summary_file"
            else
                echo "No significant threat intelligence findings." >> "$summary_file"
            fi
            
            # Clean up temp file
            rm -f "$reports_dir/threat-warnings.tmp"
        fi
    fi
    
    # Add recommendations
    cat >> "$summary_file" << EOF

## Recommendations

Based on the scan results, consider the following actions:

1. Review and verify all open ports and services
2. Implement appropriate access controls for exposed services
3. Apply security patches and updates to address potential vulnerabilities
4. Consider additional targeted testing for critical systems
5. Implement network segmentation to reduce attack surface

## Detailed Results

For detailed scan results, refer to the following files:

- Host Discovery: $discovery_dir/
- Port Scanning: $services_dir/
- Vulnerability Scanning: $vuln_dir/
EOF
    
    log "SUCCESS" "Summary report generated at $summary_file"
    
    # Generate HTML report if requested
    if [[ "$REPORT_FORMAT" == "all" || "$REPORT_FORMAT" == "html" ]]; then
        log "INFO" "Generating HTML report..."
        
        if [ -f "$services_dir/port-scan.xml" ]; then
            xsltproc -o "$reports_dir/port-scan.html" /usr/share/nmap/nmap.xsl "$services_dir/port-scan.xml"
            log "SUCCESS" "HTML port scan report generated at $reports_dir/port-scan.html"
        fi
        
        if [ "$VULN_SCAN" = "true" ] && [ -f "$vuln_dir/vuln-scan.xml" ]; then
            xsltproc -o "$reports_dir/vuln-scan.html" /usr/share/nmap/nmap.xsl "$vuln_dir/vuln-scan.xml"
            log "SUCCESS" "HTML vulnerability scan report generated at $reports_dir/vuln-scan.html"
        fi
    fi
    
    # Log completion time
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    log "INFO" "Report generation completed in $(seconds_to_time $duration)."
}

# Main function
main() {
    # Parse command line arguments
    parse_arguments "$@"
    
    # Check dependencies
    check_dependencies
    
    # Adjust scan parameters based on OPSEC level
    adjust_for_opsec
    
    # Display banner with target info
    echo "${BLUE}${BOLD}"
    echo "============================================================"
    echo "Network Penetration Testing: $TARGET"
    echo "Scan Type: $SCAN_TYPE"
    echo "Port Range: $PORT_RANGE"
    echo "Output Directory: $OUTPUT_DIR"
    echo "============================================================"
    echo "${RESET}"
    
    # Set start time for total duration
    TOTAL_START_TIME=$(date +%s)
    
    # Perform host discovery
    host_count=$(do_host_discovery)
    
    # If we found hosts, continue with port scanning
    if [ "$host_count" -gt 0 ]; then
        port_count=$(do_port_scanning)
        
        # If we found open ports and vulnerability scanning is enabled, scan for vulnerabilities
        if [ "$port_count" -gt 0 ] && [ "$VULN_SCAN" = "true" ]; then
            vuln_count=$(do_vulnerability_scanning)
        fi
    fi
    
    # Generate reports
    generate_reports
    
    # Calculate total duration
    TOTAL_END_TIME=$(date +%s)
    TOTAL_DURATION=$((TOTAL_END_TIME - TOTAL_START_TIME))
    
    # Display completion message
    echo "${GREEN}${BOLD}"
    echo "============================================================"
    echo "Network Scan Complete!"
    echo "Total time: $(seconds_to_time $TOTAL_DURATION)"
    echo "============================================================"
    echo "${RESET}"
    echo "Scan results saved to: ${YELLOW}$OUTPUT_DIR${RESET}"
    echo ""
    echo "Key files:"
    echo "1. Summary Report: ${YELLOW}$OUTPUT_DIR/reports/scan-summary.md${RESET}"
    if [[ "$REPORT_FORMAT" == "all" || "$REPORT_FORMAT" == "html" ]]; then
        echo "2. HTML Reports: ${YELLOW}$OUTPUT_DIR/reports/*.html${RESET}"
    fi
    echo "3. Live Hosts: ${YELLOW}$OUTPUT_DIR/discovery/live-hosts.txt${RESET}"
    echo "4. Open Ports: ${YELLOW}$OUTPUT_DIR/services/open-ports.txt${RESET}"
    
    # Suggest next steps
    echo ""
    echo "Recommended next steps:"
    echo "1. Review the summary report for an overview of findings"
    echo "2. Investigate open services and potential vulnerabilities"
    echo "3. Consider targeted exploitation for confirmed vulnerabilities"
    echo "4. Document findings and recommendations"
}

# Execute main if script is run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi