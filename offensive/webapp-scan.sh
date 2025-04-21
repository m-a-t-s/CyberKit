#!/bin/bash
# webapp-scan.sh - Web Application Assessment Script
# ===================================================
# This script automates web application security testing,
# including reconnaissance, mapping, and vulnerability scanning.

# Source common utilities and configuration
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$SCRIPT_DIR/../common/utils.sh"
source "$SCRIPT_DIR/../common/config.sh"

# Display banner
print_banner "Web Application Assessment Tool"

# Global variables
TARGET=""
OUTPUT_DIR=""
DEPTH=2
THREADS=10
WORDLIST="$DIRB_COMMON_PATH"
HEADERS=""
COOKIES=""
USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36"
TIMEOUT=10
PROXY=""
SCREENSHOT=false
SCAN_LEVEL="medium" # low, medium, high
AUTH_METHOD="" # basic, digest, ntlm, form
AUTH_CREDS=""
SKIP_SSL=false
USE_NUCLEI=true
USE_ZAP=false
USE_BURP=false
USE_SHODAN=false
USE_VIRUSTOTAL=false
USE_SECURITYTRAILS=false

# Function to check dependencies
check_dependencies() {
    log "INFO" "Checking dependencies..."
    
    local required_tools=("curl" "httpx" "whatweb" "ffuf" "gobuster" "nuclei")
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
    local optional_tools=("nikto" "wpscan" "zap-cli" "sqlmap")
    for tool in "${optional_tools[@]}"; do
        if ! check_tool "$tool"; then
            log "WARNING" "Optional tool not found: $tool"
        fi
    done
    
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
            -d|--depth)
                DEPTH="$2"
                shift 2
                ;;
            -th|--threads)
                THREADS="$2"
                shift 2
                ;;
            -w|--wordlist)
                WORDLIST="$2"
                shift 2
                ;;
            -H|--header)
                HEADERS="${HEADERS}${2}\n"
                shift 2
                ;;
            -c|--cookie)
                COOKIES="$2"
                shift 2
                ;;
            -ua|--user-agent)
                USER_AGENT="$2"
                shift 2
                ;;
            -to|--timeout)
                TIMEOUT="$2"
                shift 2
                ;;
            -p|--proxy)
                PROXY="$2"
                shift 2
                ;;
            -s|--screenshot)
                SCREENSHOT=true
                shift
                ;;
            -l|--level)
                if [[ "$2" == "low" || "$2" == "medium" || "$2" == "high" ]]; then
                    SCAN_LEVEL="$2"
                    shift 2
                else
                    log "ERROR" "Invalid scan level: $2"
                    echo "Valid levels: low, medium, high"
                    exit 1
                fi
                ;;
            -a|--auth)
                AUTH_METHOD="$2"
                AUTH_CREDS="$3"
                shift 3
                ;;
            --skip-ssl)
                SKIP_SSL=true
                shift
                ;;
            --no-nuclei)
                USE_NUCLEI=false
                shift
                ;;
            --zap)
                USE_ZAP=true
                shift
                ;;
            --burp)
                USE_BURP=true
                shift
                ;;
            --shodan)
                USE_SHODAN=true
                shift
                ;;
            --virustotal)
                USE_VIRUSTOTAL=true
                shift
                ;;
            --securitytrails)
                USE_SECURITYTRAILS=true
                shift
                ;;
            -h|--help)
                echo "Usage: $0 [options]"
                echo ""
                echo "Options:"
                echo "  -t, --target TARGET      Target URL or domain (required)"
                echo "  -o, --output DIR         Output directory (default: ./results/TARGET)"
                echo "  -d, --depth DEPTH        Directory scan depth (default: 2)"
                echo "  -th, --threads THREADS   Number of threads (default: 10)"
                echo "  -w, --wordlist FILE      Wordlist for directory scanning (default: dirb common)"
                echo "  -H, --header HEADER      Custom header (can be used multiple times)"
                echo "  -c, --cookie COOKIE      Cookies to include in requests"
                echo "  -ua, --user-agent UA     Custom User-Agent string"
                echo "  -to, --timeout SECONDS   Request timeout in seconds (default: 10)"
                echo "  -p, --proxy PROXY        Proxy to use (e.g., http://127.0.0.1:8080)"
                echo "  -s, --screenshot         Take screenshots of discovered pages"
                echo "  -l, --level LEVEL        Scan level: low, medium, high (default: medium)"
                echo "  -a, --auth TYPE CREDS    Authentication type and credentials"
                echo "  --skip-ssl               Skip SSL verification"
                echo "  --no-nuclei              Skip Nuclei vulnerability scanning"
                echo "  --zap                    Use OWASP ZAP for scanning (if available)"
                echo "  --burp                   Generate Burp Suite project file"
                echo "  --shodan                 Use Shodan API for enhanced reconnaissance"
                echo "  --virustotal             Check domain with VirusTotal API"
                echo "  --securitytrails         Use SecurityTrails API for subdomain discovery"
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
        log "ERROR" "Target URL is required. Use -t or --target to specify."
        exit 1
    fi
    
    # Clean up target URL
    if [[ ! $TARGET =~ ^https?:// ]]; then
        TARGET="http://$TARGET"
    fi
    
    # Set default output directory if not specified
    if [ -z "$OUTPUT_DIR" ]; then
        # Extract domain from target
        DOMAIN=$(echo "$TARGET" | sed -E 's#https?://##' | sed -E 's#/.*##' | sed -E 's#:.*##')
        OUTPUT_DIR="$DEFAULT_ENGAGEMENTS_DIR/webapp-scan/$DOMAIN-$(date +%Y%m%d-%H%M%S)"
    fi
    
    # Ensure output directory exists
    ensure_dir "$OUTPUT_DIR"
    ensure_dir "$OUTPUT_DIR"/{recon,mapping,vulnerabilities,evidence,reports,tools}
    
    # Set up logging
    LOG_FILE="$OUTPUT_DIR/webapp-scan.log"
    log "INFO" "Logs will be saved to $LOG_FILE"
}

# Function to perform initial reconnaissance
do_reconnaissance() {
    log "INFO" "Starting initial reconnaissance..."
    
    local recon_dir="$OUTPUT_DIR/recon"
    local start_time=$(date +%s)
    
    # Basic information gathering with curl
    log "INFO" "Gathering basic information with curl..."
    
    local curl_opts="-s -L -o /dev/null -w \"%{http_code} %{content_type} %{size_download} %{time_total} %{num_redirects} %{url_effective}\""
    if [ "$SKIP_SSL" = true ]; then
        curl_opts="$curl_opts -k"
    fi
    if [ ! -z "$PROXY" ]; then
        curl_opts="$curl_opts -x $PROXY"
    fi
    if [ ! -z "$COOKIES" ]; then
        curl_opts="$curl_opts -b \"$COOKIES\""
    fi
    if [ ! -z "$HEADERS" ]; then
        # Add each header as a separate -H option
        for header in $(echo -e "$HEADERS" | sed '/^\s*$/d'); do
            curl_opts="$curl_opts -H \"$header\""
        fi
    fi
    
    # Get basic information
    log "INFO" "Sending initial request to $TARGET..."
    eval curl $curl_opts "$TARGET" > "$recon_dir/basic-info.txt"
    
    # Use whatweb for technology fingerprinting
    log "INFO" "Fingerprinting technologies with WhatWeb..."
    local whatweb_opts="--no-errors -a 3 -v"
    if [ "$SKIP_SSL" = true ]; then
        whatweb_opts="$whatweb_opts --no-check-certificate"
    fi
    if [ ! -z "$PROXY" ]; then
        whatweb_opts="$whatweb_opts --proxy $PROXY"
    fi
    if [ ! -z "$COOKIES" ]; then
        whatweb_opts="$whatweb_opts --cookie \"$COOKIES\""
    }
    if [ ! -z "$USER_AGENT" ]; then
        whatweb_opts="$whatweb_opts --user-agent \"$USER_AGENT\""
    fi
    
    whatweb $whatweb_opts "$TARGET" -o "$recon_dir/whatweb.json" --log-json="$recon_dir/whatweb.json"
    
    # Extract and display basic info
    log "INFO" "Extracting key information from WhatWeb results..."
    jq -r '.[] | "URL: \(.target)\nStatus: \(.http_status)\nTitle: \(.plugins.Title.string[0] // "N/A")\nIP: \(.plugins.IP.string[0] // "N/A")\nServer: \(.plugins.HTTPServer.string[0] // "N/A")\nTechnologies: \(.plugins | keys | join(", "))"' "$recon_dir/whatweb.json" > "$recon_dir/tech-summary.txt"
    
    # Get headers with curl
    log "INFO" "Retrieving HTTP headers..."
    curl_opts="-s -I"
    if [ "$SKIP_SSL" = true ]; then
        curl_opts="$curl_opts -k"
    fi
    if [ ! -z "$PROXY" ]; then
        curl_opts="$curl_opts -x $PROXY"
    fi
    if [ ! -z "$COOKIES" ]; then
        curl_opts="$curl_opts -b \"$COOKIES\""
    fi
    if [ ! -z "$USER_AGENT" ]; then
        curl_opts="$curl_opts -A \"$USER_AGENT\""
    fi
    
    eval curl $curl_opts "$TARGET" > "$recon_dir/headers.txt"
    
    # Check for robots.txt
    log "INFO" "Checking for robots.txt..."
    local robots_url="${TARGET%/}/robots.txt"
    curl -s "$robots_url" -o "$recon_dir/robots.txt"
    
    # Check for sitemap.xml
    log "INFO" "Checking for sitemap.xml..."
    local sitemap_url="${TARGET%/}/sitemap.xml"
    curl -s "$sitemap_url" -o "$recon_dir/sitemap.xml"
    
    # For medium and high scan levels, perform more detailed recon
    if [[ "$SCAN_LEVEL" != "low" ]]; then
        # Get SSL/TLS information if HTTPS
        if [[ "$TARGET" == https://* ]]; then
            log "INFO" "Gathering SSL/TLS information..."
            local domain=$(echo "$TARGET" | sed -E 's#https?://##' | sed -E 's#/.*##' | sed -E 's#:.*##')
            openssl s_client -connect "${domain}:443" -servername "$domain" </dev/null 2>/dev/null | openssl x509 -text > "$recon_dir/ssl-cert.txt"
        fi
        
        # Check for common well-known files
        log "INFO" "Checking for common well-known files..."
        for file in .well-known/security.txt .well-known/webconfiguration security.txt; do
            curl -s "${TARGET%/}/$file" -o "$recon_dir/wellknown-$file.txt"
        done
        
        # Check for common backup and config files
        if [[ "$SCAN_LEVEL" == "high" ]]; then
            log "INFO" "Checking for sensitive files..."
            for file in .git/HEAD .env .htaccess wp-config.php config.php; do
                curl -s "${TARGET%/}/$file" -o "$recon_dir/sensitive-$file.txt"
            done
        fi
    fi
    
    # Enhanced reconnaissance with external APIs if requested
    if [ "$USE_SHODAN" = true ] || [ "$USE_VIRUSTOTAL" = true ] || [ "$USE_SECURITYTRAILS" = true ]; then
        log "INFO" "Performing enhanced reconnaissance with external APIs..."
        
        # Create external APIs directory
        local external_dir="$recon_dir/external-apis"
        ensure_dir "$external_dir"
        
        # Shodan API integration
        if [ "$USE_SHODAN" = true ]; then
            log "INFO" "Attempting to use Shodan API..."
            # Try to get API key
            local shodan_key=$("$SCRIPT_DIR/../common/api-keys.sh" get shodan 2>/dev/null)
            if [ $? -eq 0 ] && [ ! -z "$shodan_key" ]; then
                local domain=$(echo "$TARGET" | sed -E 's#https?://##' | sed -E 's#/.*##' | sed -E 's#:.*##')
                log "INFO" "Querying Shodan for information about $domain..."
                
                # Use the key to query Shodan
                curl -s "https://api.shodan.io/shodan/host/search?key=$shodan_key&query=hostname:$domain" \
                    > "$external_dir/shodan-$domain.json"
                
                # Extract key information
                if [ -s "$external_dir/shodan-$domain.json" ] && grep -q "matches" "$external_dir/shodan-$domain.json"; then
                    log "SUCCESS" "Shodan data retrieved successfully."
                    jq -r '.matches[] | "IP: \(.ip_str), Port: \(.port), Service: \(.product // "Unknown")"' \
                        "$external_dir/shodan-$domain.json" > "$external_dir/shodan-summary.txt"
                else
                    log "WARNING" "No Shodan data found for $domain or API key may be invalid."
                fi
            else
                log "WARNING" "Shodan API key not found. Run 'common/api-keys.sh set shodan YOUR_API_KEY' to configure."
            fi
        fi
        
        # VirusTotal API integration
        if [ "$USE_VIRUSTOTAL" = true ]; then
            log "INFO" "Attempting to use VirusTotal API..."
            # Try to get API key
            local vt_key=$("$SCRIPT_DIR/../common/api-keys.sh" get virustotal 2>/dev/null)
            if [ $? -eq 0 ] && [ ! -z "$vt_key" ]; then
                local domain=$(echo "$TARGET" | sed -E 's#https?://##' | sed -E 's#/.*##' | sed -E 's#:.*##')
                log "INFO" "Querying VirusTotal for information about $domain..."
                
                # Use the key to query VirusTotal
                curl -s -H "x-apikey: $vt_key" "https://www.virustotal.com/api/v3/domains/$domain" \
                    > "$external_dir/virustotal-$domain.json"
                
                # Extract key information
                if [ -s "$external_dir/virustotal-$domain.json" ] && ! grep -q "error" "$external_dir/virustotal-$domain.json"; then
                    log "SUCCESS" "VirusTotal data retrieved successfully."
                    jq '.data.attributes.last_analysis_stats' "$external_dir/virustotal-$domain.json" \
                        > "$external_dir/virustotal-summary.txt"
                else
                    log "WARNING" "No VirusTotal data found for $domain or API key may be invalid."
                fi
            else
                log "WARNING" "VirusTotal API key not found. Run 'common/api-keys.sh set virustotal YOUR_API_KEY' to configure."
            fi
        fi
        
        # SecurityTrails API integration
        if [ "$USE_SECURITYTRAILS" = true ]; then
            log "INFO" "Attempting to use SecurityTrails API..."
            # Try to get API key
            local st_key=$("$SCRIPT_DIR/../common/api-keys.sh" get securitytrails 2>/dev/null)
            if [ $? -eq 0 ] && [ ! -z "$st_key" ]; then
                local domain=$(echo "$TARGET" | sed -E 's#https?://##' | sed -E 's#/.*##' | sed -E 's#:.*##')
                log "INFO" "Querying SecurityTrails for subdomains of $domain..."
                
                # Use the key to query SecurityTrails
                curl -s -H "APIKEY: $st_key" "https://api.securitytrails.com/v1/domain/$domain/subdomains" \
                    > "$external_dir/securitytrails-$domain.json"
                
                # Extract subdomains
                if [ -s "$external_dir/securitytrails-$domain.json" ] && ! grep -q "message" "$external_dir/securitytrails-$domain.json"; then
                    log "SUCCESS" "SecurityTrails data retrieved successfully."
                    jq -r '.subdomains[]' "$external_dir/securitytrails-$domain.json" | \
                        sed "s/$/.$domain/" > "$external_dir/securitytrails-subdomains.txt"
                    
                    # Combine with other subdomains if found
                    if [ -f "$recon_dir/web/subdomains-combined-$domain.txt" ]; then
                        cat "$external_dir/securitytrails-subdomains.txt" "$recon_dir/web/subdomains-combined-$domain.txt" | \
                            sort -u > "$recon_dir/web/subdomains-combined-$domain.txt.new"
                        mv "$recon_dir/web/subdomains-combined-$domain.txt.new" "$recon_dir/web/subdomains-combined-$domain.txt"
                    fi
                else
                    log "WARNING" "No SecurityTrails data found for $domain or API key may be invalid."
                fi
            else
                log "WARNING" "SecurityTrails API key not found. Run 'common/api-keys.sh set securitytrails YOUR_API_KEY' to configure."
            fi
        fi
    fi
    
    # Log completion time
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    log "SUCCESS" "Initial reconnaissance completed in $(seconds_to_time $duration)."
}

# Function to map the application structure
do_mapping() {
    log "INFO" "Starting application mapping..."
    
    local mapping_dir="$OUTPUT_DIR/mapping"
    local start_time=$(date +%s)
    
    # Directory enumeration with gobuster
    log "INFO" "Enumerating directories with gobuster..."
    local gobuster_opts="dir -u $TARGET -w $WORDLIST -t $THREADS"
    if [ "$SKIP_SSL" = true ]; then
        gobuster_opts="$gobuster_opts -k"
    fi
    if [ ! -z "$PROXY" ]; then
        gobuster_opts="$gobuster_opts -p $PROXY"
    fi
    if [ ! -z "$COOKIES" ]; then
        gobuster_opts="$gobuster_opts -c \"$COOKIES\""
    fi
    if [ ! -z "$USER_AGENT" ]; then
        gobuster_opts="$gobuster_opts -a \"$USER_AGENT\""
    fi
    
    gobuster $gobuster_opts -o "$mapping_dir/gobuster-dirs.txt"
    
    # Extract found directories for further scanning
    grep -o 'http.*$' "$mapping_dir/gobuster-dirs.txt" 2>/dev/null > "$mapping_dir/found-dirs.txt"
    
    # Parameter discovery with ffuf for medium and high scan levels
    if [[ "$SCAN_LEVEL" != "low" ]]; then
        log "INFO" "Discovering parameters with ffuf..."
        local ffuf_opts="-u ${TARGET%/}/FUZZ -w $WORDLIST -t $THREADS -mc 200,301,302,403"
        if [ "$SKIP_SSL" = true ]; then
            ffuf_opts="$ffuf_opts -k"
        fi
        if [ ! -z "$PROXY" ]; then
            ffuf_opts="$ffuf_opts -x $PROXY"
        fi
        if [ ! -z "$COOKIES" ]; then
            ffuf_opts="$ffuf_opts -b \"$COOKIES\""
        fi
        if [ ! -z "$HEADERS" ]; then
            for header in $(echo -e "$HEADERS" | sed '/^\s*$/d'); do
                ffuf_opts="$ffuf_opts -H \"$header\""
            fi
        fi
        
        ffuf $ffuf_opts -o "$mapping_dir/ffuf-params.json" -of json
        
        # Extract parameters for further testing
        jq -r '.results[] | .url' "$mapping_dir/ffuf-params.json" 2>/dev/null > "$mapping_dir/found-params.txt"
    fi
    
    # Take screenshots if enabled and if gowitness is available
    if [ "$SCREENSHOT" = true ]; then
        if check_tool "gowitness"; then
            log "INFO" "Taking screenshots of discovered pages..."
            local screenshot_dir="$mapping_dir/screenshots"
            ensure_dir "$screenshot_dir"
            
            # Take screenshot of main page
            gowitness single "$TARGET" --destination "$screenshot_dir"
            
            # Take screenshots of found directories
            if [ -f "$mapping_dir/found-dirs.txt" ]; then
                gowitness file -f "$mapping_dir/found-dirs.txt" --destination "$screenshot_dir"
            fi
        else
            log "WARNING" "gowitness not found, skipping screenshots."
        fi
    fi
    
    # For high scan level, perform deeper crawling
    if [[ "$SCAN_LEVEL" == "high" ]]; then
        if check_tool "gospider"; then
            log "INFO" "Performing deep crawling with gospider..."
            local gospider_opts="-s $TARGET -d $DEPTH -c $THREADS"
            if [ ! -z "$COOKIES" ]; then
                gospider_opts="$gospider_opts -c \"$COOKIES\""
            fi
            
            gospider $gospider_opts -o "$mapping_dir/gospider"
            
            # Combine and deduplicate all found URLs
            cat "$mapping_dir/gospider"/* 2>/dev/null | grep -o 'http.*$' | sort -u > "$mapping_dir/all-urls.txt"
        else
            log "WARNING" "gospider not found, skipping deep crawling."
        fi
    fi
    
    # Log completion time
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    log "SUCCESS" "Application mapping completed in $(seconds_to_time $duration)."
}

# Function to scan for vulnerabilities
do_vulnerability_scanning() {
    log "INFO" "Starting vulnerability scanning..."
    
    local vuln_dir="$OUTPUT_DIR/vulnerabilities"
    local start_time=$(date +%s)
    
    # Basic checks with nikto if available
    if check_tool "nikto"; then
        log "INFO" "Running Nikto scan..."
        local nikto_opts="-h $TARGET"
        if [ "$SKIP_SSL" = true ]; then
            nikto_opts="$nikto_opts -ssl"
        fi
        if [ ! -z "$PROXY" ]; then
            nikto_opts="$nikto_opts -useproxy $PROXY"
        }
        if [ ! -z "$COOKIES" ]; then
            nikto_opts="$nikto_opts -cookies \"$COOKIES\""
        fi
        
        nikto $nikto_opts -o "$vuln_dir/nikto.txt" -Format txt
    else
        log "WARNING" "Nikto not found, skipping basic vulnerability scan."
    fi
    
    # Nuclei scanning if enabled
    if [ "$USE_NUCLEI" = true ]; then
        log "INFO" "Running Nuclei vulnerability scan..."
        local nuclei_opts="-u $TARGET -o $vuln_dir/nuclei.txt"
        
        # Set scan level for nuclei
        case "$SCAN_LEVEL" in
            "low")
                nuclei_opts="$nuclei_opts -severity critical,high"
                ;;
            "medium")
                nuclei_opts="$nuclei_opts -severity critical,high,medium"
                ;;
            "high")
                nuclei_opts="$nuclei_opts -severity critical,high,medium,low"
                ;;
        esac
        
        if [ "$SKIP_SSL" = true ]; then
            nuclei_opts="$nuclei_opts -insecure"
        fi
        if [ ! -z "$PROXY" ]; then
            nuclei_opts="$nuclei_opts -proxy $PROXY"
        fi
        if [ ! -z "$HEADERS" ]; then
            for header in $(echo -e "$HEADERS" | sed '/^\s*$/d'); do
                nuclei_opts="$nuclei_opts -H \"$header\""
            fi
        fi
        
        nuclei $nuclei_opts
    fi
    
    # WordPress scanning if WordPress is detected
    if grep -q "WordPress" "$OUTPUT_DIR/recon/tech-summary.txt"; then
        if check_tool "wpscan"; then
            log "INFO" "WordPress detected, running WPScan..."
            local wpscan_opts="--url $TARGET"
            if [ "$SKIP_SSL" = true ]; then
                wpscan_opts="$wpscan_opts --disable-tls-checks"
            fi
            if [ ! -z "$PROXY" ]; then
                wpscan_opts="$wpscan_opts --proxy $PROXY"
            }
            if [ ! -z "$COOKIES" ]; then
                wpscan_opts="$wpscan_opts --cookie-string \"$COOKIES\""
            fi
            
            wpscan $wpscan_opts --output "$vuln_dir/wpscan.txt" --format cli
        else
            log "WARNING" "WordPress detected but WPScan not found."
        fi
    fi
    
    # ZAP scanning if enabled and available
    if [ "$USE_ZAP" = true ]; then
        if check_tool "zap-cli"; then
            log "INFO" "Running OWASP ZAP scan..."
            
            # Start ZAP daemon if not already running
            if ! pgrep -f "zap.jar" > /dev/null; then
                log "INFO" "Starting ZAP daemon..."
                zap-cli start >/dev/null 2>&1
                sleep 10 # Wait for ZAP to initialize
            fi
            
            # Configure ZAP
            zap-cli -v open-url "$TARGET"
            zap-cli -v spider "$TARGET"
            
            # Active scan based on scan level
            case "$SCAN_LEVEL" in
                "low")
                    zap-cli -v active-scan "$TARGET" --recursive -s insane
                    ;;
                "medium")
                    zap-cli -v active-scan "$TARGET" --recursive
                    ;;
                "high")
                    zap-cli -v active-scan "$TARGET" --recursive -s all
                    ;;
            esac
            
            # Generate report
            zap-cli -v report -o "$vuln_dir/zap-report.html" -f html
            
            # Optionally shutdown ZAP
            # zap-cli shutdown
        else
            log "WARNING" "ZAP CLI not found, skipping ZAP scan."
        fi
    fi
    
    # For high scan level, run additional targeted scans
    if [[ "$SCAN_LEVEL" == "high" ]]; then
        # SQLMap if available
        if check_tool "sqlmap"; then
            log "INFO" "Running SQLMap scan for parameter injection..."
            
            # Check if we have any parameters to test
            if [ -f "$OUTPUT_DIR/mapping/found-params.txt" ]; then
                log "INFO" "Testing discovered parameters with SQLMap..."
                
                # Get first 5 parameters to test
                head -5 "$OUTPUT_DIR/mapping/found-params.txt" | while read -r url; do
                    local sqlmap_opts="-u \"$url\" --batch"
                    if [ "$SKIP_SSL" = true ]; then
                        sqlmap_opts="$sqlmap_opts --skip-ssl-verification"
                    fi
                    if [ ! -z "$PROXY" ]; then
                        sqlmap_opts="$sqlmap_opts --proxy=$PROXY"
                    }
                    if [ ! -z "$COOKIES" ]; then
                        sqlmap_opts="$sqlmap_opts --cookie=\"$COOKIES\""
                    fi
                    
                    sqlmap $sqlmap_opts --output-dir="$vuln_dir/sqlmap"
                done
            else
                log "WARNING" "No parameters found for SQLMap testing."
            fi
        else
            log "WARNING" "SQLMap not found, skipping SQL injection tests."
        fi
    fi
    
    # Generate Burp Suite project file if requested
    if [ "$USE_BURP" = true ]; then
        log "INFO" "Generating Burp Suite configuration..."
        
        local burp_dir="$OUTPUT_DIR/tools"
        local burp_config="$burp_dir/burp-config.txt"
        
        cat > "$burp_config" << EOF
# Burp Suite Project Configuration
# Generated for: $TARGET

## Target Scope
Target: $TARGET

## Discovered URLs
EOF
        
        # Add discovered URLs to scope
        if [ -f "$OUTPUT_DIR/mapping/all-urls.txt" ]; then
            cat "$OUTPUT_DIR/mapping/all-urls.txt" >> "$burp_config"
        elif [ -f "$OUTPUT_DIR/mapping/found-dirs.txt" ]; then
            cat "$OUTPUT_DIR/mapping/found-dirs.txt" >> "$burp_config"
        fi
        
        # Add instructions
        cat >> "$burp_config" << EOF

## Usage Instructions
1. Open Burp Suite and create a new project
2. Configure your browser to use Burp's proxy
3. Import these discovered URLs into scope
4. Run active scanning on discovered endpoints
5. Export results to "$OUTPUT_DIR/vulnerabilities/burp-findings.html"
EOF
        
        log "SUCCESS" "Burp Suite configuration created at $burp_config"
    fi
    
    # Log completion time
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    log "SUCCESS" "Vulnerability scanning completed in $(seconds_to_time $duration)."
}

# Function to generate final report
generate_report() {
    log "INFO" "Generating final report..."
    
    local reports_dir="$OUTPUT_DIR/reports"
    local evidence_dir="$OUTPUT_DIR/evidence"
    local start_time=$(date +%s)
    
    # Create evidence directory
    ensure_dir "$evidence_dir/screenshots"
    
    # Create report header
    local report_file="$reports_dir/web-assessment-report.md"
    
    # Create report header
    cat > "$report_file" << EOF
# Web Application Security Assessment Report

## Executive Summary

This report presents the findings of a security assessment conducted on $TARGET on $(date +"%Y-%m-%d").

- **Target:** $TARGET
- **Scan Level:** $SCAN_LEVEL
- **Assessment Date:** $(date +"%Y-%m-%d")

## Methodology

The assessment followed a structured approach:

1. **Reconnaissance:** Gathering information about the target application
2. **Mapping:** Discovering the application structure and functionality
3. **Vulnerability Scanning:** Identifying security issues using automated tools
4. **Analysis:** Evaluating the findings and determining their severity

## Key Findings
EOF
    
    # Add key findings from Nuclei if available
    if [ -f "$OUTPUT_DIR/vulnerabilities/nuclei.txt" ]; then
        log "INFO" "Adding Nuclei findings to report..."
        
        cat >> "$report_file" << EOF

### Security Vulnerabilities

| Severity | Issue | URL |
|----------|-------|-----|
EOF
        
        # Extract and format findings
        grep -i "\[critical\]\|\[high\]\|\[medium\]\|\[low\]" "$OUTPUT_DIR/vulnerabilities/nuclei.txt" 2>/dev/null | while read -r line; do
            severity=$(echo "$line" | grep -o '\[[^]]*\]' | head -1)
            url=$(echo "$line" | grep -o 'http[^ ]*' | head -1)
            issue=$(echo "$line" | sed -E "s/\[[^]]*\]//g" | sed -E "s/http[^ ]*//g" | sed -E "s/^\s+|\s+$//g")
            
            echo "| $severity | $issue | $url |" >> "$report_file"
        done
    else
        echo "No vulnerabilities were identified by Nuclei." >> "$report_file"
    fi
    
    # Add information from WhatWeb
    if [ -f "$OUTPUT_DIR/recon/tech-summary.txt" ]; then
        log "INFO" "Adding technology information to report..."
        
        cat >> "$report_file" << EOF

## Technology Profile

$(cat "$OUTPUT_DIR/recon/tech-summary.txt")

EOF
    fi
    
    # Add discovered endpoints
    if [ -f "$OUTPUT_DIR/mapping/found-dirs.txt" ]; then
        log "INFO" "Adding discovered endpoints to report..."
        
        cat >> "$report_file" << EOF

## Discovered Endpoints

The following endpoints were discovered during the assessment:

EOF
        
        cat "$OUTPUT_DIR/mapping/found-dirs.txt" | sed 's/^/- /' >> "$report_file"
    fi
    
    # Add API-based findings if available
    if [ -d "$OUTPUT_DIR/recon/external-apis" ]; then
        log "INFO" "Adding API-based findings to report..."
        
        cat >> "$report_file" << EOF

## External Intelligence Information
EOF
        
        # Add Shodan findings
        if [ -f "$OUTPUT_DIR/recon/external-apis/shodan-summary.txt" ]; then
            cat >> "$report_file" << EOF

### Shodan Intelligence

The following services and exposures were identified via Shodan:

$(cat "$OUTPUT_DIR/recon/external-apis/shodan-summary.txt")
EOF
        fi
        
        # Add VirusTotal findings
        if [ -f "$OUTPUT_DIR/recon/external-apis/virustotal-summary.txt" ]; then
            cat >> "$report_file" << EOF

### VirusTotal Analysis

Threat analysis from VirusTotal:

\`\`\`
$(cat "$OUTPUT_DIR/recon/external-apis/virustotal-summary.txt")
\`\`\`
EOF
        fi
        
        # Add SecurityTrails findings
        if [ -f "$OUTPUT_DIR/recon/external-apis/securitytrails-subdomains.txt" ]; then
            local subdomain_count=$(wc -l < "$OUTPUT_DIR/recon/external-apis/securitytrails-subdomains.txt")
            
            cat >> "$report_file" << EOF

### Subdomain Intelligence

$subdomain_count subdomains were identified via SecurityTrails:

$(head -10 "$OUTPUT_DIR/recon/external-apis/securitytrails-subdomains.txt" | sed 's/^/- /')
EOF
            
            if [ "$subdomain_count" -gt 10 ]; then
                echo "- ... and $(($subdomain_count - 10)) more subdomains" >> "$report_file"
            fi
            
            echo "" >> "$report_file"
        fi
    fi
    
    # Add recommendations based on scan level
    cat >> "$report_file" << EOF

## Recommendations

Based on the findings, the following recommendations are provided:

EOF
    
    case "$SCAN_LEVEL" in
        "low")
            cat >> "$report_file" << EOF
1. **Address Critical Vulnerabilities:** Prioritize fixing any critical vulnerabilities identified in this report
2. **Update Web Technologies:** Ensure all web technologies and frameworks are updated to the latest secure versions
3. **Implement Basic Security Headers:** Add security headers such as Content-Security-Policy and X-XSS-Protection
EOF
            ;;
        "medium")
            cat >> "$report_file" << EOF
1. **Address High and Critical Vulnerabilities:** Immediately fix all high and critical severity issues
2. **Implement Web Application Firewall:** Consider implementing a WAF to provide additional protection
3. **Conduct Regular Security Assessments:** Schedule regular security assessments to identify new vulnerabilities
4. **Enhance Authentication Mechanisms:** Review and strengthen authentication mechanisms where applicable
5. **Implement Secure Development Practices:** Adopt secure coding practices in the development lifecycle
EOF
            ;;
        "high")
            cat >> "$report_file" << EOF
1. **Comprehensive Vulnerability Remediation:** Address all identified vulnerabilities according to risk
2. **Implement Defense-in-Depth Strategy:** Layer multiple security controls to protect critical assets
3. **Security Monitoring and Incident Response:** Establish robust monitoring and incident response capabilities
4. **Regular Penetration Testing:** Conduct thorough penetration testing at least annually
5. **Security Training:** Provide security awareness training for developers and administrators
6. **API Security:** Review and enhance security for any APIs exposed by the application
7. **Data Protection:** Ensure sensitive data is properly encrypted both in transit and at rest
EOF
            ;;
    esac
    
    # Add appendices
    cat >> "$report_file" << EOF

## Appendices

### Tools Used

The following tools were used during this assessment:

- **Information Gathering:** curl, WhatWeb
- **Application Mapping:** gobuster, ffuf
- **Vulnerability Scanning:** Nuclei$(check_tool "nikto" && echo ", Nikto")$(check_tool "wpscan" && [[ $(grep -c "WordPress" "$OUTPUT_DIR/recon/tech-summary.txt") -gt 0 ]] && echo ", WPScan")$([ "$USE_ZAP" = true ] && check_tool "zap-cli" && echo ", OWASP ZAP")$([ "$SCAN_LEVEL" == "high" ] && check_tool "sqlmap" && echo ", SQLMap")
EOF
    
    # Finalize report
    log "SUCCESS" "Final report generated at $report_file"
    
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
    
    # Display banner with target info
    echo "${BLUE}${BOLD}"
    echo "============================================================"
    echo "Web Application Assessment: $TARGET"
    echo "Scan Level: $SCAN_LEVEL"
    echo "Output Directory: $OUTPUT_DIR"
    echo "============================================================"
    echo "${RESET}"
    
    # Set start time for total duration
    TOTAL_START_TIME=$(date +%s)
    
    # Perform reconnaissance
    do_reconnaissance
    
    # Perform application mapping
    do_mapping
    
    # Perform vulnerability scanning
    do_vulnerability_scanning
    
    # Generate final report
    generate_report
    
    # Calculate total duration
    TOTAL_END_TIME=$(date +%s)
    TOTAL_DURATION=$((TOTAL_END_TIME - TOTAL_START_TIME))
    
    # Display completion message
    echo "${GREEN}${BOLD}"
    echo "============================================================"
    echo "Web Application Assessment Complete!"
    echo "Total time: $(seconds_to_time $TOTAL_DURATION)"
    echo "============================================================"
    echo "${RESET}"
    echo "Assessment results saved to: ${YELLOW}$OUTPUT_DIR${RESET}"
    echo ""
    echo "Key files:"
    echo "1. Final Report: ${YELLOW}$OUTPUT_DIR/reports/web-assessment-report.md${RESET}"
    echo "2. Technology Profile: ${YELLOW}$OUTPUT_DIR/recon/tech-summary.txt${RESET}"
    echo "3. Discovered Endpoints: ${YELLOW}$OUTPUT_DIR/mapping/found-dirs.txt${RESET}"
    echo "4. Vulnerability Findings: ${YELLOW}$OUTPUT_DIR/vulnerabilities/nuclei.txt${RESET}"
    
    # Suggest next steps based on scan level
    echo ""
    echo "Recommended next steps:"
    case "$SCAN_LEVEL" in
        "low")
            echo "1. Review the final report and address any critical findings"
            echo "2. Consider running a more comprehensive scan with --level medium"
            ;;
        "medium")
            echo "1. Review the vulnerability findings and prioritize remediation"
            echo "2. Perform manual testing of discovered endpoints"
            echo "3. Consider importing results into Burp Suite for further analysis"
            ;;
        "high")
            echo "1. Review all findings and create a remediation plan"
            echo "2. Perform in-depth manual testing of critical functionality"
            echo "3. Consider conducting a full penetration test based on these findings"
            ;;
    esac
}

# Execute main if script is run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi