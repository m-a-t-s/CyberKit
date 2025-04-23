#!/bin/bash
#
# url-scanner.sh - Advanced URL Analysis & Threat Detection Tool
# Part of CyberKit Defensive Tools Suite
#
# This script analyzes URLs for potential phishing, malware, and other threats
# using multiple techniques and integrates with threat intelligence APIs.
#

# Import common utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
source "$PROJECT_ROOT/common/utils.sh"
source "$PROJECT_ROOT/common/config.sh"
source "$PROJECT_ROOT/common/api-keys.sh"

# Constants
VERSION="1.0.0"
TEMP_DIR="/tmp/cyberkit-url-scanner"
LOG_DIR="${LOG_BASE_DIR:-$HOME/.cyberkit/logs}/url-scanner"
RESULTS_DIR="${OUTPUT_BASE_DIR:-$HOME/.cyberkit/results}/url-scanner"
USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
DEFAULT_TIMEOUT=30
VT_API_ENDPOINT="https://www.virustotal.com/api/v3"
PHISHTANK_API_ENDPOINT="https://checkurl.phishtank.com/checkurl/"
URLSCAN_API_ENDPOINT="https://urlscan.io/api/v1"
CACHE_EXPIRY=86400  # 24 hours
SCORE_THRESHOLD_HIGH=6  # Likely malicious
SCORE_THRESHOLD_MEDIUM=3  # Suspicious

# Ensure required directories exist
mkdir -p "$LOG_DIR" "$TEMP_DIR" "$RESULTS_DIR"

# Function to display help menu
show_help() {
    cat << EOF
URL Scanner - Advanced URL Analysis & Threat Detection Tool
Part of CyberKit Defensive Tools Suite (v$VERSION)

Usage: $(basename "$0") [OPTIONS] <URL>

Options:
  -o, --output DIR            Custom output directory (default: $RESULTS_DIR)
  -t, --timeout SECONDS       Connection timeout (default: $DEFAULT_TIMEOUT)
  -u, --user-agent STRING     Custom user agent string
  -c, --cache-results         Cache results of API lookups
  -n, --no-cache              Bypass cache and force fresh scans
  -f, --format [json|md|txt]  Output format (default: txt)
  -s, --silent                Silent mode, output only final verdict
  -d, --detailed              Detailed output mode
  -p, --passive               Passive mode (no active connections to target)
  -a, --all-checks            Run all available checks (including paid APIs)
  -l, --list-apis             List configured API integrations
      --vt                    Use VirusTotal for URL reputation
      --urlscan               Use urlscan.io for URL analysis
      --phishtank             Use PhishTank for phishing detection
      --abuseipdb             Use AbuseIPDB for IP reputation
      --no-browser            Skip browser emulation checks
      --no-sslyze             Skip SSL/TLS analysis
      --no-screenshot         Skip taking screenshot
      --no-dns                Skip DNS analysis
      --batch FILE            Process multiple URLs from file
      --export-iocs           Export detected IOCs for SIEM/EDR
      --check-redirects       Follow and analyze redirects
      --max-redirects NUM     Maximum number of redirects to follow (default: 5)
  -v, --verbose               Verbose output
  -q, --quiet                 Minimal output
  -h, --help                  Display this help message

Examples:
  $(basename "$0") https://example.com
  $(basename "$0") --all-checks --detailed https://example.com
  $(basename "$0") --passive --vt --phishtank https://example.com
  $(basename "$0") --batch urls.txt --format json --output /path/to/results

Notes:
  - For API-based scans (--vt, --urlscan, etc.), API keys must be configured
  - Use './common/api-keys.sh set virustotal YOUR_API_KEY' to configure
  - Cache (24hr by default) can be bypassed with --no-cache or disabled with --cache-results=false

EOF
    exit 0
}

# Function to check dependencies
check_dependencies() {
    # Core dependencies
    local CORE_DEPS=("curl" "dig" "openssl" "grep" "awk")
    # Extended dependencies
    local EXTENDED_DEPS=("jq" "sslyze" "nmap" "whois")
    # Platform-specific dependencies
    local KALI_DEPS=("amass" "httpx" "subjack")
    
    local MISSING_DEPS=()
    local RECOMMEND_DEPS=()
    
    log_info "Checking required dependencies..."
    
    # Check core dependencies
    for dep in "${CORE_DEPS[@]}"; do
        if ! command -v "$dep" &>/dev/null; then
            MISSING_DEPS+=("$dep")
        fi
    done
    
    # Check extended dependencies
    for dep in "${EXTENDED_DEPS[@]}"; do
        if ! command -v "$dep" &>/dev/null; then
            RECOMMEND_DEPS+=("$dep")
        fi
    done
    
    # If we're on Kali, check for specialized tools
    if [[ -f /etc/os-release && $(grep -i "ID=" /etc/os-release) == *"kali"* ]]; then
        for dep in "${KALI_DEPS[@]}"; do
            if ! command -v "$dep" &>/dev/null; then
                RECOMMEND_DEPS+=("$dep")
            fi
        done
    fi
    
    # Install core dependencies if missing
    if [[ ${#MISSING_DEPS[@]} -gt 0 ]]; then
        log_warning "Missing core dependencies: ${MISSING_DEPS[*]}"
        
        # Determine package manager and install
        if command -v apt-get &>/dev/null; then
            log_info "Installing with apt..."
            sudo apt-get update -qq
            sudo apt-get install -y "${MISSING_DEPS[@]}"
        elif command -v brew &>/dev/null; then
            log_info "Installing with Homebrew..."
            brew install "${MISSING_DEPS[@]}"
        elif command -v yum &>/dev/null; then
            log_info "Installing with yum..."
            sudo yum install -y "${MISSING_DEPS[@]}"
        elif command -v pacman &>/dev/null; then
            log_info "Installing with pacman..."
            sudo pacman -S --noconfirm "${MISSING_DEPS[@]}"
        else
            log_error "Unable to automatically install dependencies. Please install: ${MISSING_DEPS[*]}"
            exit 1
        fi
    fi
    
    # Recommend installing extended dependencies
    if [[ ${#RECOMMEND_DEPS[@]} -gt 0 ]]; then
        log_warning "Optional tools not found: ${RECOMMEND_DEPS[*]}"
        log_info "While not required, these tools enhance scan capabilities."
        
        if [[ "$BATCH_MODE" != "true" ]]; then
            read -p "Would you like to install them? (y/n): " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                if command -v apt-get &>/dev/null; then
                    sudo apt-get update -qq
                    sudo apt-get install -y "${RECOMMEND_DEPS[@]}"
                elif command -v brew &>/dev/null; then
                    brew install "${RECOMMEND_DEPS[@]}"
                elif command -v yum &>/dev/null; then
                    sudo yum install -y "${RECOMMEND_DEPS[@]}"
                elif command -v pacman &>/dev/null; then
                    sudo pacman -S --noconfirm "${RECOMMEND_DEPS[@]}"
                else
                    log_warning "Unable to automatically install. Please manually install: ${RECOMMEND_DEPS[*]}"
                fi
            fi
        fi
    fi
    
    log_success "Dependency check completed."
}

# Function to check if a tool is available
is_tool_available() {
    command -v "$1" &>/dev/null
}

# Function to validate URL
validate_url() {
    local url="$1"
    
    # Add https:// if no protocol specified
    if [[ ! "$url" =~ ^https?:// ]]; then
        url="https://$url"
        log_info "Protocol not specified, using: $url"
    fi
    
    # Simple regex for URL validation
    if [[ ! "$url" =~ ^https?://[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*(/[a-zA-Z0-9\-\._~:/%\?#\[\]@!\$&\'\(\)\*\+,;=]*)? ]]; then
        log_error "Invalid URL format: $url"
        return 1
    fi
    
    echo "$url"
    return 0
}

# Function to extract domain from URL
extract_domain() {
    local url="$1"
    
    # Extract domain portion
    local domain=$(echo "$url" | awk -F/ '{print $3}' | awk -F: '{print $1}')
    
    echo "$domain"
}

# Function to normalize URL for caching
normalize_url() {
    local url="$1"
    
    # Remove protocol, trailing slashes, and query parameters for consistent cache key
    url=$(echo "$url" | sed -E 's|^https?://||' | sed -E 's|/$||' | cut -d'?' -f1)
    
    echo "$url"
}

# Function to check cache for URL
check_cache() {
    local url="$1"
    local cache_key=$(normalize_url "$url")
    local cache_file="$TEMP_DIR/$cache_key.cache"
    
    # Check if no-cache flag is set
    if [[ "$NO_CACHE" == "true" ]]; then
        return 1
    fi
    
    # Check if cache file exists and is recent
    if [[ -f "$cache_file" ]]; then
        local cache_time=$(stat -c %Y "$cache_file" 2>/dev/null || stat -f %m "$cache_file" 2>/dev/null)
        local current_time=$(date +%s)
        local cache_age=$((current_time - cache_time))
        
        if [[ "$cache_age" -lt "$CACHE_EXPIRY" ]]; then
            log_info "Using cached results for $url (age: $(format_time $cache_age))"
            cat "$cache_file"
            return 0
        else
            log_info "Cache expired for $url (age: $(format_time $cache_age))"
            return 1
        fi
    fi
    
    return 1
}

# Function to update cache for URL
update_cache() {
    local url="$1"
    local data="$2"
    local cache_key=$(normalize_url "$url")
    local cache_file="$TEMP_DIR/$cache_key.cache"
    
    # Check if caching is enabled
    if [[ "$CACHE_RESULTS" == "true" ]]; then
        echo "$data" > "$cache_file"
        log_info "Updated cache for $url"
    fi
}

# Function to format time in human-readable format
format_time() {
    local seconds="$1"
    
    if [[ "$seconds" -lt 60 ]]; then
        echo "${seconds}s"
    elif [[ "$seconds" -lt 3600 ]]; then
        echo "$((seconds / 60))m $((seconds % 60))s"
    else
        echo "$((seconds / 3600))h $(((seconds % 3600) / 60))m"
    fi
}

# Function to get IP from domain
get_ip_from_domain() {
    local domain="$1"
    local resolved_ip=""
    
    # Use dig to resolve domain
    resolved_ip=$(dig +short "$domain" | grep -v ";" | head -n 1)
    
    # If dig failed or returned nothing, try alternative methods
    if [[ -z "$resolved_ip" ]]; then
        # Try host command
        if command -v host &>/dev/null; then
            resolved_ip=$(host "$domain" | grep "has address" | head -n 1 | awk '{print $NF}')
        fi
        
        # If still empty, try nslookup
        if [[ -z "$resolved_ip" ]] && command -v nslookup &>/dev/null; then
            resolved_ip=$(nslookup "$domain" | grep -A2 "Name:" | grep "Address:" | head -n 1 | awk '{print $2}')
        fi
    fi
    
    echo "$resolved_ip"
}

# Function to perform DNS checks
perform_dns_checks() {
    local domain="$1"
    local results_file="$2"
    local score=0
    local reasons=()
    
    if [[ "$SKIP_DNS" == "true" ]]; then
        log_info "DNS checks skipped."
        update_results "$results_file" "dns" "skipped" "" 0 "[]"
        return 0
    fi
    
    log_info "Performing DNS checks for $domain..."
    
    # Check if domain is an IP address
    if [[ "$domain" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        score=$((score + 3))
        reasons+=("URL uses raw IP address - possible phishing indicator")
    fi
    
    # Try to resolve domain
    local resolved_ip=$(get_ip_from_domain "$domain")
    local dns_data="{\"resolved_ip\": \"$resolved_ip\"}"
    
    if [[ -z "$resolved_ip" ]]; then
        score=$((score + 2))
        reasons+=("Domain did not resolve to any IP address")
    else
        log_info "Domain resolves to: $resolved_ip"
        
        # Check if IP is in private range
        if [[ "$resolved_ip" =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.) ]]; then
            score=$((score + 2))
            reasons+=("Domain resolves to private IP range")
        fi
        
        # Check for DNS-based blacklists if available
        if is_tool_available "host"; then
            # Check common DNSBL
            local dnsbl_checks=("zen.spamhaus.org" "dnsbl.sorbs.net" "bl.spamcop.net")
            local dnsbl_results=()
            
            for dnsbl in "${dnsbl_checks[@]}"; do
                local reversed_ip=$(echo "$resolved_ip" | awk -F. '{print $4"."$3"."$2"."$1}')
                local dnsbl_result=$(host "$reversed_ip.$dnsbl" 2>/dev/null)
                
                if [[ "$dnsbl_result" == *"has address"* || "$dnsbl_result" == *"domain name pointer"* ]]; then
                    score=$((score + 1))
                    reasons+=("IP is listed in $dnsbl blocklist")
                    dnsbl_results+=("\"$dnsbl\": \"listed\"")
                else
                    dnsbl_results+=("\"$dnsbl\": \"not_listed\"")
                fi
            done
            
            # Add DNSBL results to DNS data
            dns_data=$(echo "$dns_data" | jq -c ". += {\"dnsbl\": {$(IFS=,; echo "${dnsbl_results[*]}")}}")
        fi
        
        # Perform advanced DNS checks with dig
        local mx_records=$(dig +short MX "$domain" 2>/dev/null)
        local ns_records=$(dig +short NS "$domain" 2>/dev/null)
        local txt_records=$(dig +short TXT "$domain" 2>/dev/null)
        local cname_records=$(dig +short CNAME "$domain" 2>/dev/null)
        
        # Check for SPF and DMARC records
        local has_spf=false
        local has_dmarc=false
        
        if echo "$txt_records" | grep -q "v=spf1"; then
            has_spf=true
        fi
        
        if dig +short TXT "_dmarc.$domain" 2>/dev/null | grep -q "v=DMARC1"; then
            has_dmarc=true
        fi
        
        # Add DNS records to data
        dns_data=$(echo "$dns_data" | jq -c ". += {\"has_mx\": $([ -n \"$mx_records\" ] && echo \"true\" || echo \"false\"), \"has_ns\": $([ -n \"$ns_records\" ] && echo \"true\" || echo \"false\"), \"has_spf\": $has_spf, \"has_dmarc\": $has_dmarc}")
        
        # Check newly registered domains
        if is_tool_available "whois"; then
            local domain_info=$(whois "$domain" 2>/dev/null)
            local creation_date=$(echo "$domain_info" | grep -i "Creation Date" | head -n 1 | cut -d: -f2- | xargs)
            
            if [[ -n "$creation_date" ]]; then
                # Try to parse date in various formats
                local creation_timestamp=0
                
                # Try common date formats
                if [[ "$creation_date" =~ [0-9]{4}-[0-9]{2}-[0-9]{2} ]]; then
                    # YYYY-MM-DD format
                    creation_timestamp=$(date -d "${creation_date}" +%s 2>/dev/null || date -j -f "%Y-%m-%d" "${creation_date}" +%s 2>/dev/null)
                elif [[ "$creation_date" =~ [0-9]{2}/[0-9]{2}/[0-9]{4} ]]; then
                    # MM/DD/YYYY format
                    creation_timestamp=$(date -d "${creation_date}" +%s 2>/dev/null || date -j -f "%m/%d/%Y" "${creation_date}" +%s 2>/dev/null)
                fi
                
                if [[ "$creation_timestamp" -ne 0 ]]; then
                    local current_timestamp=$(date +%s)
                    local domain_age_days=$(( (current_timestamp - creation_timestamp) / 86400 ))
                    
                    dns_data=$(echo "$dns_data" | jq -c ". += {\"domain_age_days\": $domain_age_days}")
                    
                    if [[ "$domain_age_days" -lt 30 ]]; then
                        score=$((score + 2))
                        reasons+=("Domain was registered less than 30 days ago")
                    elif [[ "$domain_age_days" -lt 90 ]]; then
                        score=$((score + 1))
                        reasons+=("Domain was registered less than 90 days ago")
                    fi
                fi
            fi
        fi
    fi
    
    # Check for suspicious domain patterns
    if echo "$domain" | grep -E -q '[0-9]{5,}'; then
        score=$((score + 1))
        reasons+=("Domain contains unusual number sequences")
    fi
    
    if echo "$domain" | grep -E -q '([a-zA-Z0-9])\1{3,}'; then
        score=$((score + 1))
        reasons+=("Domain contains repeated characters")
    fi
    
    # Check for typosquatting (basic check)
    local popular_domains=("google" "facebook" "microsoft" "apple" "amazon" "paypal" "netflix" "twitter" "instagram" "tiktok")
    for popular in "${popular_domains[@]}"; do
        # Check for domain containing popular name with slight misspelling
        if [[ "$domain" != *"$popular"* ]] && echo "$domain" | grep -E -q "$popular[a-z]|$popular-|[a-z]$popular"; then
            score=$((score + 2))
            reasons+=("Possible typosquatting of $popular")
            break
        fi
    done
    
    # Add a reason JSON array
    local reasons_json="[$(for reason in "${reasons[@]}"; do echo "\"$reason\""; done | paste -sd,)]"
    
    # Update results
    update_results "$results_file" "dns" "completed" "$dns_data" "$score" "$reasons_json"
    
    return "$score"
}

# Function to perform TLS/SSL checks
perform_tls_checks() {
    local domain="$1"
    local results_file="$2"
    local score=0
    local reasons=()
    
    if [[ "$SKIP_SSLYZE" == "true" ]]; then
        log_info "TLS/SSL checks skipped."
        update_results "$results_file" "tls" "skipped" "" 0 "[]"
        return 0
    fi
    
    log_info "Performing TLS/SSL certificate checks for $domain..."
    
    # Use OpenSSL to check certificate
    local cert_info=""
    cert_info=$(echo | openssl s_client -servername "$domain" -connect "$domain:443" -timeout "$CONNECTION_TIMEOUT" 2>/dev/null | openssl x509 -noout -text 2>/dev/null)
    local openssl_exit=$?
    
    # Prepare JSON data structure
    local tls_data="{\"has_valid_cert\": $([ $openssl_exit -eq 0 ] && echo \"true\" || echo \"false\")}"
    
    if [[ $openssl_exit -ne 0 ]]; then
        score=$((score + 2))
        reasons+=("SSL/TLS certificate issues or connection failed")
    else
        # Extract certificate details
        local cert_subject=$(echo "$cert_info" | grep "Subject:" | sed 's/^[[:space:]]*//')
        local cert_issuer=$(echo "$cert_info" | grep "Issuer:" | sed 's/^[[:space:]]*//')
        local cert_dates=$(echo "$cert_info" | grep -A 2 "Validity" | grep "Not")
        local cert_not_before=$(echo "$cert_dates" | grep "Not Before:" | cut -d: -f2- | xargs)
        local cert_not_after=$(echo "$cert_dates" | grep "Not After :" | cut -d: -f2- | xargs)
        
        # Parse dates
        local cert_expiry=""
        if [[ -n "$cert_not_after" ]]; then
            cert_expiry=$(date -d "$cert_not_after" +%s 2>/dev/null || date -j -f "%b %d %H:%M:%S %Y %Z" "$cert_not_after" +%s 2>/dev/null)
            local current_time=$(date +%s)
            
            # Check if certificate is expired or about to expire
            if [[ "$cert_expiry" -lt "$current_time" ]]; then
                score=$((score + 3))
                reasons+=("SSL/TLS certificate has expired")
            elif [[ "$cert_expiry" -lt $((current_time + 2592000)) ]]; then
                # Less than 30 days until expiry
                score=$((score + 1))
                reasons+=("SSL/TLS certificate will expire in less than 30 days")
            fi
            
            # Add days until expiry to data
            local days_until_expiry=$(( (cert_expiry - current_time) / 86400 ))
            tls_data=$(echo "$tls_data" | jq -c ". += {\"days_until_expiry\": $days_until_expiry}")
        fi
        
        # Check certificate issuer for well-known CAs
        if ! echo "$cert_issuer" | grep -iq "DigiCert\|GlobalSign\|Amazon\|Google\|Let's Encrypt\|Sectigo\|GoDaddy\|Comodo\|GeoTrust\|RapidSSL\|Thawte\|Verisign"; then
            score=$((score + 1))
            reasons+=("SSL/TLS certificate issued by uncommon Certificate Authority")
        fi
        
        # Extract and check Subject Alternative Names
        local san=$(echo "$cert_info" | grep -A1 "Subject Alternative Name" | grep "DNS:" | sed 's/^[[:space:]]*//')
        local domain_in_san=false
        
        if [[ -n "$san" ]]; then
            if echo "$san" | grep -q "DNS:$domain"; then
                domain_in_san=true
            fi
            
            # Add sanitized SAN to data (remove DNS: prefix)
            local sans_array=$(echo "$san" | sed 's/DNS://g' | tr ',' '\n' | xargs | tr ' ' ',' | sed 's/,/","/g' | sed 's/^/"/' | sed 's/$/"/')
            tls_data=$(echo "$tls_data" | jq -c ". += {\"alternative_names\": [$sans_array]}")
        fi
        
        if [[ "$domain_in_san" == false ]]; then
            score=$((score + 1))
            reasons+=("Domain not found in certificate's Subject Alternative Names")
        fi
        
        # Add issuer information
        local issuer_org=$(echo "$cert_issuer" | grep -o "O = [^,]*" | cut -d= -f2 | xargs)
        tls_data=$(echo "$tls_data" | jq -c ". += {\"issuer\": \"$issuer_org\"}")
        
        # Check for extended validation
        if echo "$cert_subject" | grep -q "jurisdictionC="; then
            tls_data=$(echo "$tls_data" | jq -c ". += {\"is_ev\": true}")
        else
            tls_data=$(echo "$tls_data" | jq -c ". += {\"is_ev\": false}")
        fi
        
        # Run sslyze for more detailed checks if available
        if is_tool_available "sslyze" && [[ "$VERBOSE" == "true" ]]; then
            log_info "Running sslyze for detailed TLS analysis..."
            local sslyze_output=""
            sslyze_output=$(sslyze --certinfo --json "$domain" 2>/dev/null)
            
            if [[ -n "$sslyze_output" ]]; then
                # Extract relevant information from sslyze JSON output
                local weak_cipher=$(echo "$sslyze_output" | jq -r '.server_scan_results[] | .scan_commands_results | .[] | select(.scan_command == "ssl_2_0_cipher_suites" or .scan_command == "ssl_3_0_cipher_suites" or .scan_command == "tls_1_0_cipher_suites") | .result | .accepted_cipher_suites | length')
                
                if [[ -n "$weak_cipher" && "$weak_cipher" -gt 0 ]]; then
                    score=$((score + 1))
                    reasons+=("Server supports weak SSL/TLS protocols")
                    tls_data=$(echo "$tls_data" | jq -c ". += {\"supports_weak_protocols\": true}")
                else
                    tls_data=$(echo "$tls_data" | jq -c ". += {\"supports_weak_protocols\": false}")
                fi
            fi
        fi
    fi
    
    # Add a reason JSON array
    local reasons_json="[$(for reason in "${reasons[@]}"; do echo "\"$reason\""; done | paste -sd,)]"
    
    # Update results
    update_results "$results_file" "tls" "completed" "$tls_data" "$score" "$reasons_json"
    
    return "$score"
}

# Function to perform HTTP checks
perform_http_checks() {
    local url="$1"
    local results_file="$2"
    local score=0
    local reasons=()
    
    if [[ "$PASSIVE_MODE" == "true" ]]; then
        log_info "HTTP checks skipped (passive mode)."
        update_results "$results_file" "http" "skipped" "" 0 "[]"
        return 0
    fi
    
    log_info "Performing HTTP checks for $url..."
    
    # Get HTTP headers and response
    local headers_file="$TEMP_DIR/headers_$(date +%s%N).txt"
    local response_file="$TEMP_DIR/response_$(date +%s%N).txt"
    
    # Use curl to fetch headers with timeout and follow redirects if enabled
    local curl_opts=("-s" "-I" "-A" "$USER_AGENT" "-m" "$CONNECTION_TIMEOUT" "-o" "$headers_file")
    
    if [[ "$CHECK_REDIRECTS" == "true" ]]; then
        curl_opts+=("-L" "--max-redirs" "$MAX_REDIRECTS")
    fi
    
    curl "${curl_opts[@]}" "$url" &>/dev/null
    local curl_exit=$?
    
    # Initialize HTTP data JSON
    local http_data="{\"status_code\": null, \"server\": null, \"content_type\": null}"
    
    if [[ $curl_exit -ne 0 ]]; then
        score=$((score + 1))
        reasons+=("Failed to connect or timeout when retrieving HTTP headers")
    else
        # Extract status code
        local status_code=$(grep -i "^HTTP" "$headers_file" | tail -n 1 | awk '{print $2}')
        local server_header=$(grep -i "^Server:" "$headers_file" | cut -d: -f2- | xargs)
        local content_type=$(grep -i "^Content-Type:" "$headers_file" | cut -d: -f2- | xargs)
        local location_header=$(grep -i "^Location:" "$headers_file" | cut -d: -f2- | xargs)
        
        # Update HTTP data
        http_data=$(echo "$http_data" | jq -c ".status_code = \"$status_code\"")
        
        if [[ -n "$server_header" ]]; then
            http_data=$(echo "$http_data" | jq -c ".server = \"$server_header\"")
        fi
        
        if [[ -n "$content_type" ]]; then
            http_data=$(echo "$http_data" | jq -c ".content_type = \"$content_type\"")
        fi
        
        if [[ -n "$location_header" ]]; then
            http_data=$(echo "$http_data" | jq -c ".redirect_location = \"$location_header\"")
        fi
        
        # Check status code
        if [[ ! "$status_code" =~ ^2[0-9][0-9]$ && ! "$status_code" =~ ^3[0-9][0-9]$ ]]; then
            score=$((score + 1))
            reasons+=("HTTP response status code not 2XX or 3XX: $status_code")
        fi
        
        # Check security headers
        local security_headers=()
        if ! grep -qi "^Strict-Transport-Security:" "$headers_file"; then
            security_headers+=("HSTS")
        fi
        
        if ! grep -qi "^X-Content-Type-Options:" "$headers_file"; then
            security_headers+=("X-Content-Type-Options")
        fi
        
        if ! grep -qi "^X-Frame-Options:" "$headers_file"; then
            security_headers+=("X-Frame-Options")
        fi
        
        if ! grep -qi "^Content-Security-Policy:" "$headers_file"; then
            security_headers+=("CSP")
        fi
        
        if [[ ${#security_headers[@]} -gt 2 ]]; then
            score=$((score + 1))
            reasons+=("Missing important security headers: ${security_headers[*]}")
        fi
        
        # Add security headers data
        http_data=$(echo "$http_data" | jq -c ". += {\"has_hsts\": $(grep -qi "^Strict-Transport-Security:" "$headers_file" && echo true || echo false)}")
        http_data=$(echo "$http_data" | jq -c ". += {\"has_csp\": $(grep -qi "^Content-Security-Policy:" "$headers_file" && echo true || echo false)}")
        
        # Now get the page content if not already in passive mode
        if [[ "$PASSIVE_MODE" != "true" ]]; then
            curl_opts=("-s" "-A" "$USER_AGENT" "-m" "$CONNECTION_TIMEOUT" "-o" "$response_file")
            
            if [[ "$CHECK_REDIRECTS" == "true" ]]; then
                curl_opts+=("-L" "--max-redirs" "$MAX_REDIRECTS")
            fi
            
            curl "${curl_opts[@]}" "$url" &>/dev/null
            curl_exit=$?
            
            if [[ $curl_exit -eq 0 && -f "$response_file" ]]; then
                # Check page content
                local page_size=$(stat -c %s "$response_file" 2>/dev/null || stat -f %z "$response_file" 2>/dev/null)
                http_data=$(echo "$http_data" | jq -c ". += {\"page_size_bytes\": $page_size}")
                
                # Check for suspicious content
                if grep -qi "password\|login\|signin\|verify\|account\|billing\|update\|confirm" "$response_file"; then
                    local login_form=$(grep -i "<form" "$response_file" | grep -i "password")
                    
                    if [[ -n "$login_form" ]]; then
                        score=$((score + 1))
                        reasons+=("Page contains login/authentication form")
                        http_data=$(echo "$http_data" | jq -c ". += {\"has_login_form\": true}")
                    fi
                fi
                
                # Check if page is unusually small
                if [[ "$page_size" -lt 1000 ]]; then
                    score=$((score + 1))
                    reasons+=("Page content is suspiciously small")
                fi
                
                # Check for brand names in content but not in domain
                local domain=$(extract_domain "$url")
                local brands=("paypal" "apple" "microsoft" "amazon" "google" "facebook" "bank" "wellsfargo" "chase" "citibank" "bankofamerica")
                
                for brand in "${brands[@]}"; do
                    if grep -qi "$brand" "$response_file" && [[ "$domain" != *"$brand"* ]]; then
                        score=$((score + 1))
                        reasons+=("Page content mentions $brand but domain doesn't contain this brand name")
                        break
                    fi
                done
                
                # Check for obfuscated JavaScript
                if grep -qi "eval(" "$response_file" || grep -qi "String.fromCharCode" "$response_file" || grep -qi "unescape(" "$response_file"; then
                    score=$((score + 1))
                    reasons+=("Page contains potentially obfuscated JavaScript")
                    http_data=$(echo "$http_data" | jq -c ". += {\"has_obfuscated_js\": true}")
                else
                    http_data=$(echo "$http_data" | jq -c ". += {\"has_obfuscated_js\": false}")
                fi
                
                # Check for iframes
                if grep -qi "<iframe" "$response_file"; then
                    http_data=$(echo "$http_data" | jq -c ". += {\"has_iframes\": true}")
                    
                    # Check for hidden iframes
                    if grep -qi "<iframe.*hidden\|<iframe.*display:[ ]*none\|<iframe.*visibility:[ ]*hidden" "$response_file"; then
                        score=$((score + 2))
                        reasons+=("Page contains hidden iframes - potential security risk")
                    fi
                else
                    http_data=$(echo "$http_data" | jq -c ". += {\"has_iframes\": false}")
                fi
            fi
        fi
    fi
    
    # Add a reason JSON array
    local reasons_json="[$(for reason in "${reasons[@]}"; do echo "\"$reason\""; done | paste -sd,)]"
    
    # Update results
    update_results "$results_file" "http" "completed" "$http_data" "$score" "$reasons_json"
    
    # Clean up temp files
    rm -f "$headers_file" "$response_file"
    
    return "$score"
}

# Function to check URL against VirusTotal
check_virustotal() {
    local url="$1"
    local results_file="$2"
    local score=0
    local reasons=()
    
    if [[ "$USE_VIRUSTOTAL" != "true" ]]; then
        log_info "VirusTotal check skipped."
        update_results "$results_file" "virustotal" "skipped" "" 0 "[]"
        return 0
    fi
    
    log_info "Checking URL against VirusTotal..."
    
    # Get API key
    local api_key=$(get_api_key "virustotal")
    
    if [[ -z "$api_key" ]]; then
        log_warning "VirusTotal API key not found. Configure with './common/api-keys.sh set virustotal YOUR_API_KEY'"
        update_results "$results_file" "virustotal" "error" "{\"error\":\"API key not configured\"}" 0 "[]"
        return 0
    fi
    
    # URL-encode the URL
    local encoded_url=$(echo "$url" | jq -sRr @uri)
    
    # Check cache first
    local cache_data=$(check_cache "vt_$url")
    
    if [[ -n "$cache_data" ]]; then
        update_results "$results_file" "virustotal" "completed" "$cache_data" 0 "[]"
        
        # Extract score from cached data
        local cached_score=$(echo "$cache_data" | jq -r '.detection_score // 0')
        return "$cached_score"
    fi
    
    # Query VirusTotal API
    local response=$(curl -s -X GET "$VT_API_ENDPOINT/urls/$encoded_url" -H "x-apikey: $api_key")
    local api_error=$(echo "$response" | jq -r '.error.code // ""')
    
    # If URL not found, submit it for analysis
    if [[ "$api_error" == "NotFoundError" ]]; then
        log_info "URL not found in VirusTotal, submitting for analysis..."
        
        # Submit URL for analysis
        local submit_response=$(curl -s -X POST "$VT_API_ENDPOINT/urls" -H "x-apikey: $api_key" -d "url=$url")
        local analysis_id=$(echo "$submit_response" | jq -r '.data.id // ""')
        
        if [[ -z "$analysis_id" ]]; then
            log_error "Failed to submit URL to VirusTotal"
            update_results "$results_file" "virustotal" "error" "{\"error\":\"Failed to submit URL\"}" 0 "[]"
            return 0
        fi
        
        # Wait for analysis to complete (up to 60 seconds)
        local max_attempts=6
        local attempt=0
        local analysis_response=""
        
        while [[ $attempt -lt $max_attempts ]]; do
            log_info "Waiting for VirusTotal analysis to complete... (attempt $((attempt+1))/$max_attempts)"
            sleep 10
            
            analysis_response=$(curl -s -X GET "$VT_API_ENDPOINT/analyses/$analysis_id" -H "x-apikey: $api_key")
            local status=$(echo "$analysis_response" | jq -r '.data.attributes.status // ""')
            
            if [[ "$status" == "completed" ]]; then
                break
            fi
            
            attempt=$((attempt + 1))
        done
        
        if [[ $attempt -eq $max_attempts ]]; then
            log_warning "VirusTotal analysis did not complete in time"
            update_results "$results_file" "virustotal" "timeout" "{\"error\":\"Analysis timeout\"}" 0 "[]"
            return 0
        fi
        
        # Get results of the analysis
        response=$(curl -s -X GET "$VT_API_ENDPOINT/urls/$encoded_url" -H "x-apikey: $api_key")
    fi
    
    # Process response
    local malicious=$(echo "$response" | jq -r '.data.attributes.last_analysis_stats.malicious // 0')
    local suspicious=$(echo "$response" | jq -r '.data.attributes.last_analysis_stats.suspicious // 0')
    local total_engines=$(echo "$response" | jq -r '.data.attributes.last_analysis_stats | .malicious + .suspicious + .undetected + .harmless' 2>/dev/null || echo "0")
    local categories=$(echo "$response" | jq -r '.data.attributes.categories // {}')
    
    # Calculate detection ratio
    local detection_ratio=0
    if [[ "$total_engines" -gt 0 ]]; then
        detection_ratio=$(echo "scale=2; ($malicious + $suspicious) / $total_engines" | bc)
    fi
    
    # Prepare data
    local vt_data=$(echo "$response" | jq -c '{
        detection_score: '"$malicious"' + '"$suspicious"',
        total_engines: '"$total_engines"',
        detection_ratio: '"$detection_ratio"',
        categories: .data.attributes.categories,
        first_seen: .data.attributes.first_submission_date,
        last_seen: .data.attributes.last_analysis_date
    }')
    
    # Update cache
    update_cache "vt_$url" "$vt_data"
    
    # Determine score based on detections
    if [[ "$malicious" -gt 3 ]]; then
        score=$((score + 4))
        reasons+=("VirusTotal: $malicious security vendors flagged this URL as malicious")
    elif [[ "$malicious" -gt 0 ]]; then
        score=$((score + 2))
        reasons+=("VirusTotal: $malicious security vendors flagged this URL as malicious")
    fi
    
    if [[ "$suspicious" -gt 0 ]]; then
        score=$((score + 1))
        reasons+=("VirusTotal: $suspicious security vendors flagged this URL as suspicious")
    fi
    
    # Check categories
    if echo "$categories" | grep -qi "phishing\|malicious\|malware\|suspicious"; then
        score=$((score + 2))
        reasons+=("VirusTotal: URL is categorized as potentially harmful")
    fi
    
    # Add a reason JSON array
    local reasons_json="[$(for reason in "${reasons[@]}"; do echo "\"$reason\""; done | paste -sd,)]"
    
    # Update results
    update_results "$results_file" "virustotal" "completed" "$vt_data" "$score" "$reasons_json"
    
    return "$score"
}

# Function to check URL against PhishTank
check_phishtank() {
    local url="$1"
    local results_file="$2"
    local score=0
    local reasons=()
    
    if [[ "$USE_PHISHTANK" != "true" ]]; then
        log_info "PhishTank check skipped."
        update_results "$results_file" "phishtank" "skipped" "" 0 "[]"
        return 0
    fi
    
    log_info "Checking URL against PhishTank..."
    
    # Get API key (optional for PhishTank)
    local api_key=$(get_api_key "phishtank")
    
    # Check cache first
    local cache_data=$(check_cache "pt_$url")
    
    if [[ -n "$cache_data" ]]; then
        update_results "$results_file" "phishtank" "completed" "$cache_data" 0 "[]"
        
        # Extract score from cached data
        local cached_score=$(echo "$cache_data" | jq -r '.is_phishing // 0')
        return "$cached_score"
    fi
    
    # URL-encode the URL
    local encoded_url=$(echo "$url" | jq -sRr @uri)
    
    # Query PhishTank API
    local api_url="$PHISHTANK_API_ENDPOINT"
    local response=""
    
    if [[ -n "$api_key" ]]; then
        response=$(curl -s -X POST "$api_url" -d "url=$encoded_url&format=json&app_key=$api_key")
    else
        response=$(curl -s -X POST "$api_url" -d "url=$encoded_url&format=json")
    fi
    
    # Process response
    local status=$(echo "$response" | jq -r '.status // "error"')
    
    if [[ "$status" != "success" ]]; then
        log_warning "PhishTank API error or rate limited"
        update_results "$results_file" "phishtank" "error" "{\"error\":\"API error\"}" 0 "[]"
        return 0
    fi
    
    local is_phishing=$(echo "$response" | jq -r '.results.in_database // false')
    local phish_id=$(echo "$response" | jq -r '.results.phish_id // ""')
    local verified=$(echo "$response" | jq -r '.results.verified // false')
    
    # Prepare data
    local pt_data="{
        \"is_phishing\": $is_phishing,
        \"phish_id\": \"$phish_id\",
        \"verified\": $verified
    }"
    
    # Update cache
    update_cache "pt_$url" "$pt_data"
    
    # Determine score based on result
    if [[ "$is_phishing" == "true" ]]; then
        score=$((score + 5))
        reasons+=("PhishTank: URL is a known phishing site")
    fi
    
    # Add a reason JSON array
    local reasons_json="[$(for reason in "${reasons[@]}"; do echo "\"$reason\""; done | paste -sd,)]"
    
    # Update results
    update_results "$results_file" "phishtank" "completed" "$pt_data" "$score" "$reasons_json"
    
    return "$score"
}

# Function to check URL against URLScan.io
check_urlscan() {
    local url="$1"
    local results_file="$2"
    local score=0
    local reasons=()
    
    if [[ "$USE_URLSCAN" != "true" ]]; then
        log_info "URLScan.io check skipped."
        update_results "$results_file" "urlscan" "skipped" "" 0 "[]"
        return 0
    fi
    
    log_info "Checking URL against URLScan.io..."
    
    # Get API key
    local api_key=$(get_api_key "urlscan")
    
    if [[ -z "$api_key" ]]; then
        log_warning "URLScan.io API key not found. Configure with './common/api-keys.sh set urlscan YOUR_API_KEY'"
        update_results "$results_file" "urlscan" "error" "{\"error\":\"API key not configured\"}" 0 "[]"
        return 0
    fi
    
    # Check cache first
    local cache_data=$(check_cache "us_$url")
    
    if [[ -n "$cache_data" ]]; then
        update_results "$results_file" "urlscan" "completed" "$cache_data" 0 "[]"
        
        # Extract score from cached data
        local cached_score=$(echo "$cache_data" | jq -r '.malicious // 0')
        return "$cached_score"
    fi
    
    # Query URLScan.io API for existing scans
    local search_response=$(curl -s -H "API-Key: $api_key" "$URLSCAN_API_ENDPOINT/search/?q=page.url:\"$url\"")
    local total_results=$(echo "$search_response" | jq -r '.total // 0')
    
    local urlscan_data=""
    
    if [[ "$total_results" -gt 0 ]]; then
        # Get most recent result
        local result_uuid=$(echo "$search_response" | jq -r '.results[0]._id')
        local result_response=$(curl -s -H "API-Key: $api_key" "$URLSCAN_API_ENDPOINT/result/$result_uuid")
        
        # Extract relevant data
        local malicious=$(echo "$result_response" | jq -r '.verdicts.overall.malicious // false')
        local suspicious=$(echo "$result_response" | jq -r '.verdicts.overall.suspicious // false')
        local category=$(echo "$result_response" | jq -r '.verdicts.overall.categories // []')
        local score_value=$(echo "$result_response" | jq -r '.verdicts.overall.score // 0')
        local tags=$(echo "$result_response" | jq -r '.tags // []')
        
        # Prepare data
        urlscan_data="{
            \"malicious\": $([ "$malicious" == "true" ] && echo "true" || echo "false"),
            \"suspicious\": $([ "$suspicious" == "true" ] && echo "true" || echo "false"),
            \"score\": $score_value,
            \"categories\": $category,
            \"tags\": $tags,
            \"scan_uuid\": \"$result_uuid\"
        }"
        
        # Determine score based on result
        if [[ "$malicious" == "true" ]]; then
            score=$((score + 4))
            reasons+=("URLScan.io: URL is flagged as malicious")
        elif [[ "$suspicious" == "true" ]]; then
            score=$((score + 2))
            reasons+=("URLScan.io: URL is flagged as suspicious")
        fi
        
        # Check for phishing or malware categories
        if echo "$category" | grep -qi "phishing\|malware\|scam"; then
            score=$((score + 2))
            reasons+=("URLScan.io: URL is categorized as potentially harmful")
        fi
    else
        # Submit new scan
        log_info "No existing URLScan.io results, submitting new scan..."
        
        local scan_request="{\"url\": \"$url\", \"visibility\": \"private\"}"
        local submit_response=$(curl -s -X POST -H "Content-Type: application/json" -H "API-Key: $api_key" -d "$scan_request" "$URLSCAN_API_ENDPOINT/scan/")
        local scan_uuid=$(echo "$submit_response" | jq -r '.uuid // ""')
        
        if [[ -z "$scan_uuid" ]]; then
            log_error "Failed to submit URL to URLScan.io"
            update_results "$results_file" "urlscan" "error" "{\"error\":\"Failed to submit scan\"}" 0 "[]"
            return 0
        fi
        
        # Wait for scan to complete (up to 60 seconds)
        log_info "Waiting for URLScan.io scan to complete..."
        local max_attempts=12
        local attempt=0
        local scan_complete=false
        
        while [[ $attempt -lt $max_attempts ]]; do
            sleep 5
            local result_response=$(curl -s -H "API-Key: $api_key" "$URLSCAN_API_ENDPOINT/result/$scan_uuid")
            local status=$(echo "$result_response" | jq -r '.status // "pending"')
            
            if [[ "$status" == "complete" ]]; then
                scan_complete=true
                
                # Extract relevant data
                local malicious=$(echo "$result_response" | jq -r '.verdicts.overall.malicious // false')
                local suspicious=$(echo "$result_response" | jq -r '.verdicts.overall.suspicious // false')
                local category=$(echo "$result_response" | jq -r '.verdicts.overall.categories // []')
                local score_value=$(echo "$result_response" | jq -r '.verdicts.overall.score // 0')
                local tags=$(echo "$result_response" | jq -r '.tags // []')
                
                # Prepare data
                urlscan_data="{
                    \"malicious\": $([ "$malicious" == "true" ] && echo "true" || echo "false"),
                    \"suspicious\": $([ "$suspicious" == "true" ] && echo "true" || echo "false"),
                    \"score\": $score_value,
                    \"categories\": $category,
                    \"tags\": $tags,
                    \"scan_uuid\": \"$scan_uuid\"
                }"
                
                # Determine score based on result
                if [[ "$malicious" == "true" ]]; then
                    score=$((score + 4))
                    reasons+=("URLScan.io: URL is flagged as malicious")
                elif [[ "$suspicious" == "true" ]]; then
                    score=$((score + 2))
                    reasons+=("URLScan.io: URL is flagged as suspicious")
                fi
                
                # Check for phishing or malware categories
                if echo "$category" | grep -qi "phishing\|malware\|scam"; then
                    score=$((score + 2))
                    reasons+=("URLScan.io: URL is categorized as potentially harmful")
                fi
                
                break
            fi
            
            attempt=$((attempt + 1))
        done
        
        if [[ "$scan_complete" != "true" ]]; then
            log_warning "URLScan.io scan did not complete in time"
            urlscan_data="{\"error\":\"Scan timeout\", \"scan_uuid\":\"$scan_uuid\"}"
        fi
    fi
    
    # Update cache only if we have data
    if [[ -n "$urlscan_data" ]]; then
        update_cache "us_$url" "$urlscan_data"
    fi
    
    # Add a reason JSON array
    local reasons_json="[$(for reason in "${reasons[@]}"; do echo "\"$reason\""; done | paste -sd,)]"
    
    # Update results
    update_results "$results_file" "urlscan" "completed" "$urlscan_data" "$score" "$reasons_json"
    
    return "$score"
}

# Function to check IP reputation
check_ip_reputation() {
    local ip="$1"
    local results_file="$2"
    local score=0
    local reasons=()
    
    if [[ "$USE_ABUSEIPDB" != "true" ]]; then
        log_info "IP reputation check skipped."
        update_results "$results_file" "ip_reputation" "skipped" "" 0 "[]"
        return 0
    fi
    
    log_info "Checking IP reputation for $ip..."
    
    # Get API key
    local api_key=$(get_api_key "abuseipdb")
    
    if [[ -z "$api_key" ]]; then
        log_warning "AbuseIPDB API key not found. Configure with './common/api-keys.sh set abuseipdb YOUR_API_KEY'"
        update_results "$results_file" "ip_reputation" "error" "{\"error\":\"API key not configured\"}" 0 "[]"
        return 0
    fi
    
    # Check cache first
    local cache_data=$(check_cache "ip_$ip")
    
    if [[ -n "$cache_data" ]]; then
        update_results "$results_file" "ip_reputation" "completed" "$cache_data" 0 "[]"
        
        # Extract score from cached data
        local cached_score=$(echo "$cache_data" | jq -r '.malicious_score // 0')
        return "$cached_score"
    fi
    
    # Query AbuseIPDB API
    local response=$(curl -s -G --data-urlencode "ipAddress=$ip" -H "Key: $api_key" -H "Accept: application/json" "https://api.abuseipdb.com/api/v2/check")
    
    # Process response
    local abuse_score=$(echo "$response" | jq -r '.data.abuseConfidenceScore // "0"')
    local domain=$(echo "$response" | jq -r '.data.domain // ""')
    local country_code=$(echo "$response" | jq -r '.data.countryCode // ""')
    local usage_type=$(echo "$response" | jq -r '.data.usageType // ""')
    local isp=$(echo "$response" | jq -r '.data.isp // ""')
    local total_reports=$(echo "$response" | jq -r '.data.totalReports // "0"')
    
    # Prepare data
    local ip_data="{
        \"abuse_score\": $abuse_score,
        \"domain\": \"$domain\",
        \"country_code\": \"$country_code\",
        \"usage_type\": \"$usage_type\",
        \"isp\": \"$isp\",
        \"total_reports\": $total_reports
    }"
    
    # Calculate malicious score based on abuse confidence
    local malicious_score=0
    
    if [[ "$abuse_score" -ge 80 ]]; then
        malicious_score=3
    elif [[ "$abuse_score" -ge 50 ]]; then
        malicious_score=2
    elif [[ "$abuse_score" -ge 25 ]]; then
        malicious_score=1
    fi
    
    ip_data=$(echo "$ip_data" | jq -c ". += {\"malicious_score\": $malicious_score}")
    
    # Update cache
    update_cache "ip_$ip" "$ip_data"
    
    # Determine score and reasons
    if [[ "$abuse_score" -ge 80 ]]; then
        score=$((score + 3))
        reasons+=("IP has a high abuse confidence score: $abuse_score")
    elif [[ "$abuse_score" -ge 50 ]]; then
        score=$((score + 2))
        reasons+=("IP has a medium abuse confidence score: $abuse_score")
    elif [[ "$abuse_score" -ge 25 ]]; then
        score=$((score + 1))
        reasons+=("IP has a low abuse confidence score: $abuse_score")
    fi
    
    # Check for hosting providers or countries often associated with abuse
    local high_risk_countries=("RU" "CN" "IR" "KP" "TR")
    local high_risk_isps=("OVH" "DigitalOcean" "Vultr" "Linode" "Host")
    
    for country in "${high_risk_countries[@]}"; do
        if [[ "$country_code" == "$country" ]]; then
            score=$((score + 1))
            reasons+=("IP is located in $country, which is often associated with malicious activities")
            break
        fi
    done
    
    for risky_isp in "${high_risk_isps[@]}"; do
        if [[ "$isp" == *"$risky_isp"* ]]; then
            score=$((score + 1))
            reasons+=("IP belongs to $isp, which is commonly used for hosting malicious content")
            break
        fi
    done
    
    # Add a reason JSON array
    local reasons_json="[$(for reason in "${reasons[@]}"; do echo "\"$reason\""; done | paste -sd,)]"
    
    # Update results
    update_results "$results_file" "ip_reputation" "completed" "$ip_data" "$score" "$reasons_json"
    
    return "$score"
}

# Function to analyze URL for suspicious patterns
analyze_url_patterns() {
    local url="$1"
    local results_file="$2"
    local score=0
    local reasons=()
    
    log_info "Analyzing URL patterns for suspicious indicators..."
    
    # Extract different parts of the URL
    local domain=$(extract_domain "$url")
    local protocol=$(echo "$url" | grep -oP '^https?')
    local path=$(echo "$url" | awk -F/ '{for (i=4; i<=NF; i++) printf "/%s", $i; print ""}' | sed 's/?.*//')
    local query=$(echo "$url" | grep -oP '\?.*$' || echo "")
    
    # Initialize pattern data
    local pattern_data="{
        \"domain_length\": ${#domain},
        \"path_length\": ${#path},
        \"query_length\": ${#query},
        \"protocol\": \"$protocol\"
    }"
    
    # Check for excessively long domain name
    if [[ ${#domain} -gt 40 ]]; then
        score=$((score + 2))
        reasons+=("Unusually long domain name (${#domain} characters)")
    elif [[ ${#domain} -gt 25 ]]; then
        score=$((score + 1))
        reasons+=("Long domain name (${#domain} characters)")
    fi
    
    # Check for suspicious TLD
    local tld=$(echo "$domain" | grep -oP '\.[a-zA-Z]+$' | tr '[:upper:]' '[:lower:]')
    pattern_data=$(echo "$pattern_data" | jq -c ". += {\"tld\": \"${tld:1}\"}")
    
    local suspicious_tlds=(".top" ".xyz" ".club" ".app" ".buzz" ".tk" ".ml" ".ga" ".cf" ".gq")
    for suspicious_tld in "${suspicious_tlds[@]}"; do
        if [[ "$tld" == "$suspicious_tld" ]]; then
            score=$((score + 1))
            reasons+=("Suspicious TLD: $tld")
            break
        fi
    done
    
    # Check for numeric domain
    if echo "$domain" | grep -qP '^\d+\.\d+\.\d+\.\d+$'; then
        score=$((score + 3))
        reasons+=("Raw IP address used instead of domain name")
        pattern_data=$(echo "$pattern_data" | jq -c ". += {\"is_ip_address\": true}")
    else
        pattern_data=$(echo "$pattern_data" | jq -c ". += {\"is_ip_address\": false}")
        
        # Check for excessive numbers or hyphens in domain
        local num_count=$(echo "$domain" | grep -o '[0-9]' | wc -l)
        local hyphen_count=$(echo "$domain" | grep -o '-' | wc -l)
        
        pattern_data=$(echo "$pattern_data" | jq -c ". += {\"number_count\": $num_count, \"hyphen_count\": $hyphen_count}")
        
        if [[ "$num_count" -gt 5 ]]; then
            score=$((score + 1))
            reasons+=("Domain contains excessive numbers ($num_count)")
        fi
        
        if [[ "$hyphen_count" -gt 3 ]]; then
            score=$((score + 1))
            reasons+=("Domain contains excessive hyphens ($hyphen_count)")
        fi
    fi
    
    # Check for suspicious words in domain
    local suspicious_words=("secure" "account" "banking" "login" "verify" "signin" "update" "confirm" "paypal" "apple" "microsoft" "amazon" "netflix" "google")
    for word in "${suspicious_words[@]}"; do
        if [[ "$domain" == *"$word"* && "$domain" != *"$word.com"* ]]; then
            score=$((score + 1))
            reasons+=("Domain contains suspicious word: $word")
            break
        fi
    done
    
    # Check for suspicious URL path patterns
    if [[ "$path" == *"/login"* || "$path" == *"/signin"* || "$path" == *"/account"* || "$path" == *"/verify"* || "$path" == *"/secure"* ]]; then
        pattern_data=$(echo "$pattern_data" | jq -c ". += {\"has_auth_path\": true}")
        
        # Check if path contains these auth terms but domain doesn't match expected origin
        if [[ "$domain" != *"paypal"* && "$path" == *"/paypal"* ]] || \
           [[ "$domain" != *"apple"* && "$path" == *"/apple"* ]] || \
           [[ "$domain" != *"microsoft"* && "$path" == *"/microsoft"* ]] || \
           [[ "$domain" != *"google"* && "$path" == *"/google"* ]] || \
           [[ "$domain" != *"amazon"* && "$path" == *"/amazon"* ]]; then
            score=$((score + 3))
            reasons+=("URL path references brand not present in domain - possible phishing indicator")
        fi
    else
        pattern_data=$(echo "$pattern_data" | jq -c ". += {\"has_auth_path\": false}")
    fi
    
    # Check for excessively long paths (common in phishing URLs)
    if [[ ${#path} -gt 100 ]]; then
        score=$((score + 2))
        reasons+=("Excessively long URL path (${#path} characters)")
    elif [[ ${#path} -gt 50 ]]; then
        score=$((score + 1))
        reasons+=("Long URL path (${#path} characters)")
    fi
    
    # Check for data/file URIs (often used in phishing attacks)
    if [[ "$url" == "data:"* || "$url" == "file:"* ]]; then
        score=$((score + 4))
        reasons+=("URL uses data: or file: URI scheme - commonly used in phishing")
        pattern_data=$(echo "$pattern_data" | jq -c ". += {\"suspicious_scheme\": true}")
    else
        pattern_data=$(echo "$pattern_data" | jq -c ". += {\"suspicious_scheme\": false}")
    fi
    
    # Check for suspicious parameters in query string
    if [[ "$query" == *"email="* || "$query" == *"password="* || "$query" == *"token="* || "$query" == *"account="* ]]; then
        score=$((score + 1))
        reasons+=("URL query contains sensitive parameters")
        pattern_data=$(echo "$pattern_data" | jq -c ". += {\"has_sensitive_params\": true}")
    else
        pattern_data=$(echo "$pattern_data" | jq -c ". += {\"has_sensitive_params\": false}")
    fi
    
    # Check for URL encoding abuse (common in phishing URLs)
    local encoding_count=$(echo "$url" | grep -o '%' | wc -l)
    pattern_data=$(echo "$pattern_data" | jq -c ". += {\"encoding_count\": $encoding_count}")
    
    if [[ "$encoding_count" -gt 10 ]]; then
        score=$((score + 2))
        reasons+=("Excessive URL encoding detected ($encoding_count occurrences)")
    elif [[ "$encoding_count" -gt 5 ]]; then
        score=$((score + 1))
        reasons+=("High amount of URL encoding ($encoding_count occurrences)")
    fi
    
    # Check for HTTP instead of HTTPS
    if [[ "$protocol" == "http" ]]; then
        score=$((score + 1))
        reasons+=("Uses insecure HTTP protocol instead of HTTPS")
    fi
    
    # Add a reason JSON array
    local reasons_json="[$(for reason in "${reasons[@]}"; do echo "\"$reason\""; done | paste -sd,)]"
    
    # Update results
    update_results "$results_file" "url_patterns" "completed" "$pattern_data" "$score" "$reasons_json"
    
    return "$score"
}

# Function to check for redirects
check_redirects() {
    local url="$1"
    local results_file="$2"
    local score=0
    local reasons=()
    
    if [[ "$CHECK_REDIRECTS" != "true" || "$PASSIVE_MODE" == "true" ]]; then
        log_info "Redirect checks skipped."
        update_results "$results_file" "redirects" "skipped" "" 0 "[]"
        return 0
    fi
    
    log_info "Checking for URL redirects..."
    
    # Follow redirects and log the chain
    local redirect_output="$TEMP_DIR/redirects_$(date +%s%N).txt"
    curl -s -L -o /dev/null -w "%{url_effective}\n%{redirect_url}\n%{http_code}\n%{redirect_count}\n%{time_total}\n" \
         --max-redirs "$MAX_REDIRECTS" -A "$USER_AGENT" "$url" > "$redirect_output"
    
    local final_url=$(sed -n '1p' "$redirect_output")
    local redirect_url=$(sed -n '2p' "$redirect_output")
    local http_code=$(sed -n '3p' "$redirect_output")
    local redirect_count=$(sed -n '4p' "$redirect_output")
    local time_total=$(sed -n '5p' "$redirect_output")
    
    # Prepare redirect data
    local redirect_data="{
        \"final_url\": \"$final_url\",
        \"redirect_count\": $redirect_count,
        \"time_total\": $time_total
    }"
    
    # If redirects occurred, get full chain
    if [[ "$redirect_count" -gt 0 ]]; then
        log_info "Found $redirect_count redirects, getting full redirect chain..."
        
        # Get full redirect chain
        local redirect_chain="$TEMP_DIR/redirect_chain_$(date +%s%N).txt"
        curl -s -L -o /dev/null -D "$redirect_chain" --max-redirs "$MAX_REDIRECTS" -A "$USER_AGENT" "$url"
        
        # Extract and process redirect chain
        local redirect_urls=()
        local redirect_codes=()
        
        while read -r line; do
            if [[ "$line" =~ ^HTTP/[0-9.]+ ]]; then
                local code=$(echo "$line" | awk '{print $2}')
                redirect_codes+=("$code")
            elif [[ "$line" =~ ^Location: ]]; then
                local location=$(echo "$line" | cut -d' ' -f2- | tr -d '\r')
                redirect_urls+=("$location")
            fi
        done < "$redirect_chain"
        
        # Add redirect chain to data
        local urls_json="[$(for u in "${redirect_urls[@]}"; do echo "\"$u\""; done | paste -sd,)]"
        local codes_json="[$(for c in "${redirect_codes[@]}"; do echo "\"$c\""; done | paste -sd,)]"
        
        redirect_data=$(echo "$redirect_data" | jq -c ". += {\"redirect_chain\": $urls_json, \"status_codes\": $codes_json}")
        
        # Clean up
        rm -f "$redirect_chain"
    fi
    
    # Analyze redirect behavior
    if [[ "$redirect_count" -gt 3 ]]; then
        score=$((score + 1))
        reasons+=("URL has multiple redirects ($redirect_count)")
    fi
    
    # Check if final domain is different from initial domain
    local initial_domain=$(extract_domain "$url")
    local final_domain=$(extract_domain "$final_url")
    
    if [[ "$initial_domain" != "$final_domain" ]]; then
        score=$((score + 2))
        reasons+=("URL redirects to a different domain: $final_domain")
        redirect_data=$(echo "$redirect_data" | jq -c ". += {\"domain_changed\": true, \"final_domain\": \"$final_domain\"}")
    else
        redirect_data=$(echo "$redirect_data" | jq -c ". += {\"domain_changed\": false}")
    fi
    
    # Check for common URL shorteners
    local shortener_domains=("bit.ly" "tinyurl.com" "goo.gl" "t.co" "is.gd" "ow.ly" "buff.ly" "rebrand.ly" "shorturl.at")
    for shortener in "${shortener_domains[@]}"; do
        if [[ "$initial_domain" == "$shortener" ]]; then
            score=$((score + 1))
            reasons+=("URL uses shortening service: $shortener")
            redirect_data=$(echo "$redirect_data" | jq -c ". += {\"uses_shortener\": true, \"shortener\": \"$shortener\"}")
            break
        fi
    done
    
    # Clean up
    rm -f "$redirect_output"
    
    # Add a reason JSON array
    local reasons_json="[$(for reason in "${reasons[@]}"; do echo "\"$reason\""; done | paste -sd,)]"
    
    # Update results
    update_results "$results_file" "redirects" "completed" "$redirect_data" "$score" "$reasons_json"
    
    return "$score"
}

# Function to update results for a specific check
update_results() {
    local results_file="$1"
    local check_name="$2"
    local status="$3"
    local data="$4"
    local score="$5"
    local reasons="$6"
    
    # Read current results if they exist
    local current_results="{}"
    if [[ -f "$results_file" ]]; then
        current_results=$(cat "$results_file")
    fi
    
    # Update with new check results
    local check_result="{
        \"status\": \"$status\",
        \"completed_at\": \"$(date -u "+%Y-%m-%dT%H:%M:%SZ")\",
        \"score\": $score,
        \"reasons\": $reasons"
    
    # Add data if provided
    if [[ -n "$data" ]]; then
        check_result="$check_result, \"data\": $data"
    fi
    
    # Close the JSON object
    check_result="$check_result }"
    
    # Update the check in results
    local updated_results=$(echo "$current_results" | jq -c ". + {\"$check_name\": $check_result}")
    
    # Recalculate total score and verdict
    local total_score=$(echo "$updated_results" | jq -r 'reduce (.[].score // 0) as $item (0; . + $item)')
    
    # Determine verdict based on score
    local verdict="safe"
    if [[ "$total_score" -ge "$SCORE_THRESHOLD_HIGH" ]]; then
        verdict="malicious"
    elif [[ "$total_score" -ge "$SCORE_THRESHOLD_MEDIUM" ]]; then
        verdict="suspicious"
    fi
    
    # Add summary to results
    local summary="{
        \"url\": \"$TARGET_URL\",
        \"score\": $total_score,
        \"verdict\": \"$verdict\",
        \"scanned_at\": \"$(date -u "+%Y-%m-%dT%H:%M:%SZ")\"
    }"
    
    updated_results=$(echo "$updated_results" | jq -c ". + {\"summary\": $summary}")
    
    # Write updated results
    echo "$updated_results" > "$results_file"
}

# Function to format results for output
format_results() {
    local results_file="$1"
    local format="$2"
    local output_file="$3"
    
    if [[ ! -f "$results_file" ]]; then
        log_error "Results file not found: $results_file"
        return 1
    fi
    
    # Read results
    local results=$(cat "$results_file")
    local url=$(echo "$results" | jq -r '.summary.url')
    local score=$(echo "$results" | jq -r '.summary.score')
    local verdict=$(echo "$results" | jq -r '.summary.verdict')
    local scanned_at=$(echo "$results" | jq -r '.summary.scanned_at')
    
    case "$format" in
        json)
            # Pretty print JSON
            jq . "$results_file" > "$output_file"
            ;;
        md)
            # Create markdown report
            {
                echo "# URL Security Analysis Report"
                echo
                echo "**URL:** $url"
                echo "**Scanned:** $scanned_at"
                echo "**Score:** $score"
                echo "**Verdict:** ${verdict^^}"
                echo
                echo "## Summary of Findings"
                echo
                
                # List all reasons
                echo "### Security Concerns"
                echo
                
                # Extract all reasons from results
                local all_reasons=($(echo "$results" | jq -r '.[].reasons[]? | select(. != null)' 2>/dev/null))
                
                if [[ ${#all_reasons[@]} -eq 0 ]]; then
                    echo "No significant security concerns identified."
                else
                    for reason in "${all_reasons[@]}"; do
                        echo "- $reason"
                    done
                fi
                
                echo
                echo "## Detailed Analysis"
                echo
                
                # DNS Checks
                if [[ $(echo "$results" | jq -r '.dns.status') == "completed" ]]; then
                    echo "### DNS Analysis"
                    echo
                    
                    local resolved_ip=$(echo "$results" | jq -r '.dns.data.resolved_ip // "N/A"')
                    echo "* Resolved IP: $resolved_ip"
                    
                    local domain_age=$(echo "$results" | jq -r '.dns.data.domain_age_days // "Unknown"')
                    if [[ "$domain_age" != "Unknown" && "$domain_age" != "null" ]]; then
                        echo "* Domain Age: $domain_age days"
                    fi
                    
                    local dns_score=$(echo "$results" | jq -r '.dns.score')
                    echo "* Risk Score: $dns_score"
                    
                    # List dns-specific reasons
                    local dns_reasons=($(echo "$results" | jq -r '.dns.reasons[]?' 2>/dev/null))
                    if [[ ${#dns_reasons[@]} -gt 0 ]]; then
                        echo
                        echo "**Issues Found:**"
                        for reason in "${dns_reasons[@]}"; do
                            echo "- $reason"
                        done
                    fi
                    
                    echo
                fi
                
                # TLS/SSL Checks
                if [[ $(echo "$results" | jq -r '.tls.status') == "completed" ]]; then
                    echo "### SSL/TLS Certificate Analysis"
                    echo
                    
                    local has_valid_cert=$(echo "$results" | jq -r '.tls.data.has_valid_cert // false')
                    echo "* Valid Certificate: $([ "$has_valid_cert" == "true" ] && echo "Yes" || echo "No")"
                    
                    local issuer=$(echo "$results" | jq -r '.tls.data.issuer // "Unknown"')
                    if [[ "$issuer" != "Unknown" && "$issuer" != "null" ]]; then
                        echo "* Certificate Issuer: $issuer"
                    fi
                    
                    local days_until_expiry=$(echo "$results" | jq -r '.tls.data.days_until_expiry // "Unknown"')
                    if [[ "$days_until_expiry" != "Unknown" && "$days_until_expiry" != "null" ]]; then
                        echo "* Days Until Expiry: $days_until_expiry"
                    fi
                    
                    local is_ev=$(echo "$results" | jq -r '.tls.data.is_ev // false')
                    echo "* Extended Validation: $([ "$is_ev" == "true" ] && echo "Yes" || echo "No")"
                    
                    local tls_score=$(echo "$results" | jq -r '.tls.score')
                    echo "* Risk Score: $tls_score"
                    
                    # List tls-specific reasons
                    local tls_reasons=($(echo "$results" | jq -r '.tls.reasons[]?' 2>/dev/null))
                    if [[ ${#tls_reasons[@]} -gt 0 ]]; then
                        echo
                        echo "**Issues Found:**"
                        for reason in "${tls_reasons[@]}"; do
                            echo "- $reason"
                        done
                    fi
                    
                    echo
                fi
                
                # HTTP Checks
                if [[ $(echo "$results" | jq -r '.http.status') == "completed" ]]; then
                    echo "### HTTP Response Analysis"
                    echo
                    
                    local status_code=$(echo "$results" | jq -r '.http.data.status_code // "Unknown"')
                    echo "* HTTP Status Code: $status_code"
                    
                    local server=$(echo "$results" | jq -r '.http.data.server // "Not disclosed"')
                    echo "* Server: $server"
                    
                    local content_type=$(echo "$results" | jq -r '.http.data.content_type // "Unknown"')
                    echo "* Content Type: $content_type"
                    
                    local has_login_form=$(echo "$results" | jq -r '.http.data.has_login_form // false')
                    if [[ "$has_login_form" == "true" ]]; then
                        echo "* Contains Login Form: Yes"
                    fi
                    
                    local has_hsts=$(echo "$results" | jq -r '.http.data.has_hsts // false')
                    echo "* HSTS Enabled: $([ "$has_hsts" == "true" ] && echo "Yes" || echo "No")"
                    
                    local has_csp=$(echo "$results" | jq -r '.http.data.has_csp // false')
                    echo "* Content Security Policy: $([ "$has_csp" == "true" ] && echo "Yes" || echo "No")"
                    
                    local http_score=$(echo "$results" | jq -r '.http.score')
                    echo "* Risk Score: $http_score"
                    
                    # List http-specific reasons
                    local http_reasons=($(echo "$results" | jq -r '.http.reasons[]?' 2>/dev/null))
                    if [[ ${#http_reasons[@]} -gt 0 ]]; then
                        echo
                        echo "**Issues Found:**"
                        for reason in "${http_reasons[@]}"; do
                            echo "- $reason"
                        done
                    fi
                    
                    echo
                fi
                
                # URL Pattern Analysis
                if [[ $(echo "$results" | jq -r '.url_patterns.status') == "completed" ]]; then
                    echo "### URL Pattern Analysis"
                    echo
                    
                    local domain_length=$(echo "$results" | jq -r '.url_patterns.data.domain_length // 0')
                    echo "* Domain Length: $domain_length characters"
                    
                    local tld=$(echo "$results" | jq -r '.url_patterns.data.tld // "Unknown"')
                    echo "* TLD: .$tld"
                    
                    local is_ip=$(echo "$results" | jq -r '.url_patterns.data.is_ip_address // false')
                    echo "* Uses IP Address: $([ "$is_ip" == "true" ] && echo "Yes" || echo "No")"
                    
                    local has_auth_path=$(echo "$results" | jq -r '.url_patterns.data.has_auth_path // false')
                    echo "* Contains Authentication Path: $([ "$has_auth_path" == "true" ] && echo "Yes" || echo "No")"
                    
                    local path_length=$(echo "$results" | jq -r '.url_patterns.data.path_length // 0')
                    if [[ "$path_length" -gt 0 ]]; then
                        echo "* Path Length: $path_length characters"
                    fi
                    
                    local pattern_score=$(echo "$results" | jq -r '.url_patterns.score')
                    echo "* Risk Score: $pattern_score"
                    
                    # List pattern-specific reasons
                    local pattern_reasons=($(echo "$results" | jq -r '.url_patterns.reasons[]?' 2>/dev/null))
                    if [[ ${#pattern_reasons[@]} -gt 0 ]]; then
                        echo
                        echo "**Issues Found:**"
                        for reason in "${pattern_reasons[@]}"; do
                            echo "- $reason"
                        done
                    fi
                    
                    echo
                fi
                
                # Redirect Analysis
                if [[ $(echo "$results" | jq -r '.redirects.status') == "completed" ]]; then
                    echo "### Redirect Analysis"
                    echo
                    
                    local redirect_count=$(echo "$results" | jq -r '.redirects.data.redirect_count // 0')
                    echo "* Redirect Count: $redirect_count"
                    
                    local domain_changed=$(echo "$results" | jq -r '.redirects.data.domain_changed // false')
                    if [[ "$domain_changed" == "true" ]]; then
                        local final_domain=$(echo "$results" | jq -r '.redirects.data.final_domain // "Unknown"')
                        echo "* Redirects to Different Domain: Yes (Final: $final_domain)"
                    else
                        echo "* Redirects to Different Domain: No"
                    fi
                    
                    local uses_shortener=$(echo "$results" | jq -r '.redirects.data.uses_shortener // false')
                    if [[ "$uses_shortener" == "true" ]]; then
                        local shortener=$(echo "$results" | jq -r '.redirects.data.shortener // "Unknown"')
                        echo "* Uses URL Shortener: Yes ($shortener)"
                    fi
                    
                    local redirect_score=$(echo "$results" | jq -r '.redirects.score')
                    echo "* Risk Score: $redirect_score"
                    
                    # List redirect-specific reasons
                    local redirect_reasons=($(echo "$results" | jq -r '.redirects.reasons[]?' 2>/dev/null))
                    if [[ ${#redirect_reasons[@]} -gt 0 ]]; then
                        echo
                        echo "**Issues Found:**"
                        for reason in "${redirect_reasons[@]}"; do
                            echo "- $reason"
                        done
                    fi
                    
                    echo
                fi
                
                # VirusTotal Results
                if [[ $(echo "$results" | jq -r '.virustotal.status') == "completed" ]]; then
                    echo "### VirusTotal Analysis"
                    echo
                    
                    local detection_score=$(echo "$results" | jq -r '.virustotal.data.detection_score // 0')
                    local total_engines=$(echo "$results" | jq -r '.virustotal.data.total_engines // 0')
                    
                    echo "* Detection Score: $detection_score / $total_engines"
                    
                    local first_seen=$(echo "$results" | jq -r '.virustotal.data.first_seen // null')
                    if [[ "$first_seen" != "null" && "$first_seen" != "" ]]; then
                        # Convert timestamp to human-readable date
                        local first_seen_date=$(date -d "@$first_seen" "+%Y-%m-%d" 2>/dev/null || date -r "$first_seen" "+%Y-%m-%d" 2>/dev/null)
                        echo "* First Seen: $first_seen_date"
                    fi
                    
                    local vt_score=$(echo "$results" | jq -r '.virustotal.score')
                    echo "* Risk Score: $vt_score"
                    
                    # List VirusTotal-specific reasons
                    local vt_reasons=($(echo "$results" | jq -r '.virustotal.reasons[]?' 2>/dev/null))
                    if [[ ${#vt_reasons[@]} -gt 0 ]]; then
                        echo
                        echo "**Issues Found:**"
                        for reason in "${vt_reasons[@]}"; do
                            echo "- $reason"
                        done
                    fi
                    
                    echo
                fi
                
                # PhishTank Results
                if [[ $(echo "$results" | jq -r '.phishtank.status') == "completed" ]]; then
                    echo "### PhishTank Analysis"
                    echo
                    
                    local is_phishing=$(echo "$results" | jq -r '.phishtank.data.is_phishing // false')
                    echo "* Known Phishing Site: $([ "$is_phishing" == "true" ] && echo "Yes" || echo "No")"
                    
                    if [[ "$is_phishing" == "true" ]]; then
                        local phish_id=$(echo "$results" | jq -r '.phishtank.data.phish_id // "Unknown"')
                        echo "* PhishTank ID: $phish_id"
                    fi
                    
                    local pt_score=$(echo "$results" | jq -r '.phishtank.score')
                    echo "* Risk Score: $pt_score"
                    
                    # List PhishTank-specific reasons
                    local pt_reasons=($(echo "$results" | jq -r '.phishtank.reasons[]?' 2>/dev/null))
                    if [[ ${#pt_reasons[@]} -gt 0 ]]; then
                        echo
                        for reason in "${pt_reasons[@]}"; do
                            echo "- $reason"
                        done
                    fi
                    
                    echo
                fi
                
                # URLScan Results
                if [[ $(echo "$results" | jq -r '.urlscan.status') == "completed" ]]; then
                    echo "### URLScan.io Analysis"
                    echo
                    
                    local malicious=$(echo "$results" | jq -r '.urlscan.data.malicious // false')
                    echo "* Flagged as Malicious: $([ "$malicious" == "true" ] && echo "Yes" || echo "No")"
                    
                    local suspicious=$(echo "$results" | jq -r '.urlscan.data.suspicious // false')
                    echo "* Flagged as Suspicious: $([ "$suspicious" == "true" ] && echo "Yes" || echo "No")"
                    
                    local score_value=$(echo "$results" | jq -r '.urlscan.data.score // 0')
                    echo "* URLScan Score: $score_value / 100"
                    
                    local scan_uuid=$(echo "$results" | jq -r '.urlscan.data.scan_uuid // "Unknown"')
                    if [[ "$scan_uuid" != "Unknown" && "$scan_uuid" != "null" ]]; then
                        echo "* Scan UUID: $scan_uuid"
                        echo "* Full Report: https://urlscan.io/result/$scan_uuid"
                    fi
                    
                    local us_score=$(echo "$results" | jq -r '.urlscan.score')
                    echo "* Risk Score: $us_score"
                    
                    # List URLScan-specific reasons
                    local us_reasons=($(echo "$results" | jq -r '.urlscan.reasons[]?' 2>/dev/null))
                    if [[ ${#us_reasons[@]} -gt 0 ]]; then
                        echo
                        echo "**Issues Found:**"
                        for reason in "${us_reasons[@]}"; do
                            echo "- $reason"
                        done
                    fi
                    
                    echo
                fi
                
                # IP Reputation Results
                if [[ $(echo "$results" | jq -r '.ip_reputation.status') == "completed" ]]; then
                    echo "### IP Reputation Analysis"
                    echo
                    
                    local abuse_score=$(echo "$results" | jq -r '.ip_reputation.data.abuse_score // 0')
                    echo "* Abuse Confidence Score: $abuse_score / 100"
                    
                    local country_code=$(echo "$results" | jq -r '.ip_reputation.data.country_code // "Unknown"')
                    if [[ "$country_code" != "Unknown" && "$country_code" != "null" ]]; then
                        echo "* Country: $country_code"
                    fi
                    
                    local usage_type=$(echo "$results" | jq -r '.ip_reputation.data.usage_type // "Unknown"')
                    if [[ "$usage_type" != "Unknown" && "$usage_type" != "null" ]]; then
                        echo "* Usage Type: $usage_type"
                    fi
                    
                    local isp=$(echo "$results" | jq -r '.ip_reputation.data.isp // "Unknown"')
                    if [[ "$isp" != "Unknown" && "$isp" != "null" ]]; then
                        echo "* ISP: $isp"
                    fi
                    
                    local total_reports=$(echo "$results" | jq -r '.ip_reputation.data.total_reports // 0')
                    echo "* Total Abuse Reports: $total_reports"
                    
                    local ip_score=$(echo "$results" | jq -r '.ip_reputation.score')
                    echo "* Risk Score: $ip_score"
                    
                    # List IP-specific reasons
                    local ip_reasons=($(echo "$results" | jq -r '.ip_reputation.reasons[]?' 2>/dev/null))
                    if [[ ${#ip_reasons[@]} -gt 0 ]]; then
                        echo
                        echo "**Issues Found:**"
                        for reason in "${ip_reasons[@]}"; do
                            echo "- $reason"
                        done
                    fi
                    
                    echo
                fi
                
                # Footer
                echo "## Verdict"
                echo
                
                case "$verdict" in
                    safe)
                        echo "**✅ LIKELY SAFE**"
                        echo
                        echo "This URL shows no significant indicators of being malicious."
                        ;;
                    suspicious)
                        echo "**⚠️ SUSPICIOUS**"
                        echo
                        echo "This URL shows some suspicious characteristics but isn't definitively malicious."
                        echo "Exercise caution when interacting with this site."
                        ;;
                    malicious)
                        echo "**🚩 LIKELY MALICIOUS**"
                        echo
                        echo "This URL shows strong indicators of being malicious or a phishing attempt."
                        echo "Avoid interacting with this site."
                        ;;
                esac
                
                echo
                echo "---"
                echo "Generated by CyberKit URL Scanner on $(date)"
                
            } > "$output_file"
            ;;
        *)
            # Plain text report
            {
                echo "URL Security Analysis Report"
                echo "================================="
                echo
                echo "URL: $url"
                echo "Scanned: $scanned_at"
                echo "Score: $score"
                echo "Verdict: ${verdict^^}"
                echo
                echo "Security Concerns:"
                echo "-----------------"
                
                # Extract all reasons from results
                local all_reasons=($(echo "$results" | jq -r '.[].reasons[]? | select(. != null)' 2>/dev/null))
                
                if [[ ${#all_reasons[@]} -eq 0 ]]; then
                    echo "No significant security concerns identified."
                else
                    for reason in "${all_reasons[@]}"; do
                        echo "- $reason"
                    done
                fi
                
                echo
                echo "Verdict:"
                echo "--------"
                
                case "$verdict" in
                    safe)
                        echo "LIKELY SAFE"
                        echo "This URL shows no significant indicators of being malicious."
                        ;;
                    suspicious)
                        echo "SUSPICIOUS"
                        echo "This URL shows some suspicious characteristics but isn't definitively malicious."
                        echo "Exercise caution when interacting with this site."
                        ;;
                    malicious)
                        echo "LIKELY MALICIOUS"
                        echo "This URL shows strong indicators of being malicious or a phishing attempt."
                        echo "Avoid interacting with this site."
                        ;;
                esac
                
                echo
                echo "Generated by CyberKit URL Scanner on $(date)"
                
            } > "$output_file"
            ;;
    esac
    
    return 0
}

# Function to export IOCs
export_iocs() {
    local results_file="$1"
    local output_file="$2"
    
    if [[ ! -f "$results_file" ]]; then
        log_error "Results file not found: $results_file"
        return 1
    fi
    
    log_info "Exporting IOCs for SIEM/EDR integration..."
    
    # Read results
    local results=$(cat "$results_file")
    local url=$(echo "$results" | jq -r '.summary.url')
    local domain=$(extract_domain "$url")
    local resolved_ip=$(echo "$results" | jq -r '.dns.data.resolved_ip // ""')
    
    # Create IOC file
    {
        echo "# CyberKit URL Scanner IOCs"
        echo "# Generated: $(date)"
        echo "# Original URL: $url"
        echo
        echo "# URLs"
        echo "url,$url"
        
        # Add redirect chain if available
        if [[ $(echo "$results" | jq -r '.redirects.status') == "completed" ]]; then
            local redirect_urls=($(echo "$results" | jq -r '.redirects.data.redirect_chain[]? // empty' 2>/dev/null))
            
            for redirect_url in "${redirect_urls[@]}"; do
                echo "url,$redirect_url"
            done
            
            local final_url=$(echo "$results" | jq -r '.redirects.data.final_url // empty')
            if [[ -n "$final_url" && "$final_url" != "$url" ]]; then
                echo "url,$final_url"
            fi
        fi
        
        echo
        echo "# Domains"
        echo "domain,$domain"
        
        # Extract additional domains from certificate if available
        if [[ $(echo "$results" | jq -r '.tls.status') == "completed" ]]; then
            local sans=($(echo "$results" | jq -r '.tls.data.alternative_names[]? // empty' 2>/dev/null))
            
            for san in "${sans[@]}"; do
                if [[ "$san" != "$domain" ]]; then
                    echo "domain,$san"
                fi
            done
        fi
        
        # Add redirect domains if available
        if [[ $(echo "$results" | jq -r '.redirects.status') == "completed" ]]; then
            local redirect_urls=($(echo "$results" | jq -r '.redirects.data.redirect_chain[]? // empty' 2>/dev/null))
            
            for redirect_url in "${redirect_urls[@]}"; do
                local redirect_domain=$(extract_domain "$redirect_url")
                if [[ -n "$redirect_domain" && "$redirect_domain" != "$domain" ]]; then
                    echo "domain,$redirect_domain"
                fi
            done
        fi
        
        echo
        echo "# IPs"
        if [[ -n "$resolved_ip" ]]; then
            echo "ip,$resolved_ip"
        fi
        
        echo
        echo "# Verdict"
        local verdict=$(echo "$results" | jq -r '.summary.verdict')
        echo "verdict,$verdict"
        
        echo
        echo "# Score"
        local score=$(echo "$results" | jq -r '.summary.score')
        echo "score,$score"
        
    } > "$output_file"
    
    log_success "IOCs exported to $output_file"
    return 0
}

# Function to list configured APIs
list_apis() {
    log_info "Checking configured API integrations..."
    
    local vt_key=$(get_api_key "virustotal")
    local pt_key=$(get_api_key "phishtank")
    local us_key=$(get_api_key "urlscan")
    local ab_key=$(get_api_key "abuseipdb")
    
    echo "Available API Integrations:"
    echo "---------------------------"
    
    if [[ -n "$vt_key" ]]; then
        echo "✅ VirusTotal: Configured"
    else
        echo "❌ VirusTotal: Not configured"
    fi
    
    if [[ -n "$pt_key" ]]; then
        echo "✅ PhishTank: Configured"
    else
        echo "❌ PhishTank: Not configured (optional)"
    fi
    
    if [[ -n "$us_key" ]]; then
        echo "✅ URLScan.io: Configured"
    else
        echo "❌ URLScan.io: Not configured"
    fi
    
    if [[ -n "$ab_key" ]]; then
        echo "✅ AbuseIPDB: Configured"
    else
        echo "❌ AbuseIPDB: Not configured"
    fi
    
    echo
    echo "To configure APIs, use:"
    echo "./common/api-keys.sh set <service> <api_key>"
    echo
    echo "Example:"
    echo "./common/api-keys.sh set virustotal YOUR_API_KEY"
    
    exit 0
}

# Function to parse command-line options
parse_args() {
    # Default values
    OUTPUT_DIR="$RESULTS_DIR"
    CONNECTION_TIMEOUT="$DEFAULT_TIMEOUT"
    OUTPUT_FORMAT="txt"
    SILENT_MODE=false
    DETAILED_MODE=false
    PASSIVE_MODE=false
    ALL_CHECKS=false
    USE_VIRUSTOTAL=false
    USE_URLSCAN=false
    USE_PHISHTANK=false
    USE_ABUSEIPDB=false
    SKIP_BROWSER=false
    SKIP_SSLYZE=false
    SKIP_SCREENSHOT=false
    SKIP_DNS=false
    BATCH_MODE=false
    BATCH_FILE=""
    EXPORT_IOCS=false
    CHECK_REDIRECTS=false
    MAX_REDIRECTS=5
    VERBOSE=false
    QUIET=false
    CACHE_RESULTS=true
    NO_CACHE=false
    TARGET_URL=""
    
    # If no arguments, show help
    if [[ $# -eq 0 ]]; then
        show_help
    fi
    
    # Process options
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -o|--output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -t|--timeout)
                CONNECTION_TIMEOUT="$2"
                shift 2
                ;;
            -u|--user-agent)
                USER_AGENT="$2"
                shift 2
                ;;
            -c|--cache-results)
                CACHE_RESULTS=true
                shift
                ;;
            -n|--no-cache)
                NO_CACHE=true
                shift
                ;;
            -f|--format)
                OUTPUT_FORMAT="$2"
                shift 2
                ;;
            -s|--silent)
                SILENT_MODE=true
                shift
                ;;
            -d|--detailed)
                DETAILED_MODE=true
                shift
                ;;
            -p|--passive)
                PASSIVE_MODE=true
                shift
                ;;
            -a|--all-checks)
                ALL_CHECKS=true
                USE_VIRUSTOTAL=true
                USE_URLSCAN=true
                USE_PHISHTANK=true
                USE_ABUSEIPDB=true
                CHECK_REDIRECTS=true
                shift
                ;;
            -l|--list-apis)
                list_apis
                ;;
            --vt)
                USE_VIRUSTOTAL=true
                shift
                ;;
            --urlscan)
                USE_URLSCAN=true
                shift
                ;;
            --phishtank)
                USE_PHISHTANK=true
                shift
                ;;
            --abuseipdb)
                USE_ABUSEIPDB=true
                shift
                ;;
            --no-browser)
                SKIP_BROWSER=true
                shift
                ;;
            --no-sslyze)
                SKIP_SSLYZE=true
                shift
                ;;
            --no-screenshot)
                SKIP_SCREENSHOT=true
                shift
                ;;
            --no-dns)
                SKIP_DNS=true
                shift
                ;;
            --batch)
                BATCH_MODE=true
                BATCH_FILE="$2"
                shift 2
                ;;
            --export-iocs)
                EXPORT_IOCS=true
                shift
                ;;
            --check-redirects)
                CHECK_REDIRECTS=true
                shift
                ;;
            --max-redirects)
                MAX_REDIRECTS="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -q|--quiet)
                QUIET=true
                shift
                ;;
            -h|--help)
                show_help
                ;;
            *)
                # Assume it's the URL if it doesn't start with -
                if [[ "$1" != -* ]]; then
                    TARGET_URL="$1"
                else
                    log_error "Unknown option: $1"
                    show_help
                fi
                shift
                ;;
        esac
    done
    
    # Validate required parameters
    if [[ "$BATCH_MODE" == "true" ]]; then
        if [[ ! -f "$BATCH_FILE" ]]; then
            log_error "Batch file not found: $BATCH_FILE"
            exit 1
        fi
    elif [[ -z "$TARGET_URL" ]]; then
        log_error "No URL specified!"
        show_help
    fi
    
    # Create output directory if it doesn't exist
    mkdir -p "$OUTPUT_DIR"
}

# Function to scan single URL
scan_url() {
    local url="$1"
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local sanitized_url=$(echo "$url" | sed 's/[^a-zA-Z0-9]/_/g')
    local results_file="$OUTPUT_DIR/${sanitized_url}_${timestamp}.json"
    local output_file=""
    
    # Validate URL
    url=$(validate_url "$url")
    if [[ $? -ne 0 ]]; then
        return 1
    fi
    
    if [[ "$SILENT_MODE" != "true" ]]; then
        log_section "URL ANALYSIS: $url"
    fi
    
    # Initialize results file
    echo "{}" > "$results_file"
    
    # Extract domain for later use
    local domain=$(extract_domain "$url")
    
    # Keep track of total score
    local total_score=0
    
    # Perform URL pattern analysis
    analyze_url_patterns "$url" "$results_file"
    ((total_score += $?))
    
    # Perform DNS checks if not skipped
    if [[ "$SKIP_DNS" != "true" ]]; then
        perform_dns_checks "$domain" "$results_file"
        ((total_score += $?))
        
        # Get IP for later use
        local resolved_ip=$(echo "$(cat "$results_file")" | jq -r '.dns.data.resolved_ip // ""')
        
        # Check IP reputation if API is configured and IP was resolved
        if [[ "$USE_ABUSEIPDB" == "true" && -n "$resolved_ip" ]]; then
            check_ip_reputation "$resolved_ip" "$results_file"
            ((total_score += $?))
        fi
    fi
    
    # Perform TLS/SSL certificate checks if not skipped
    if [[ "$SKIP_SSLYZE" != "true" ]]; then
        perform_tls_checks "$domain" "$results_file"
        ((total_score += $?))
    fi
    
    # Check for redirects if enabled and not in passive mode
    if [[ "$CHECK_REDIRECTS" == "true" && "$PASSIVE_MODE" != "true" ]]; then
        check_redirects "$url" "$results_file"
        ((total_score += $?))
    fi
    
    # Perform HTTP checks if not in passive mode
    if [[ "$PASSIVE_MODE" != "true" ]]; then
        perform_http_checks "$url" "$results_file"
        ((total_score += $?))
    fi
    
    # Perform API-based checks
    if [[ "$USE_VIRUSTOTAL" == "true" ]]; then
        check_virustotal "$url" "$results_file"
        ((total_score += $?))
    fi
    
    if [[ "$USE_PHISHTANK" == "true" ]]; then
        check_phishtank "$url" "$results_file"
        ((total_score += $?))
    fi
    
    if [[ "$USE_URLSCAN" == "true" ]]; then
        check_urlscan "$url" "$results_file"
        ((total_score += $?))
    fi
    
    # Format and output results
    if [[ "$OUTPUT_FORMAT" == "json" ]]; then
        output_file="$OUTPUT_DIR/${sanitized_url}_${timestamp}_report.json"
    elif [[ "$OUTPUT_FORMAT" == "md" ]]; then
        output_file="$OUTPUT_DIR/${sanitized_url}_${timestamp}_report.md"
    else
        output_file="$OUTPUT_DIR/${sanitized_url}_${timestamp}_report.txt"
    fi
    
    format_results "$results_file" "$OUTPUT_FORMAT" "$output_file"
    
    # Export IOCs if requested
    if [[ "$EXPORT_IOCS" == "true" ]]; then
        local ioc_file="$OUTPUT_DIR/${sanitized_url}_${timestamp}_iocs.csv"
        export_iocs "$results_file" "$ioc_file"
    fi
    
    # Determine verdict
    local verdict="safe"
    if [[ "$total_score" -ge "$SCORE_THRESHOLD_HIGH" ]]; then
        verdict="malicious"
    elif [[ "$total_score" -ge "$SCORE_THRESHOLD_MEDIUM" ]]; then
        verdict="suspicious"
    fi
    
    # Display brief results if not in silent mode
    if [[ "$SILENT_MODE" != "true" ]]; then
        echo
        echo "URL: $url"
        echo "Score: $total_score"
        
        case "$verdict" in
            safe)
                echo -e "Verdict: \e[32mLIKELY SAFE\e[0m"
                ;;
            suspicious)
                echo -e "Verdict: \e[33mSUSPICIOUS\e[0m"
                ;;
            malicious)
                echo -e "Verdict: \e[31mLIKELY MALICIOUS\e[0m"
                ;;
        esac
        
        echo "Report: $output_file"
        echo
    fi
    
    return 0
}

# Function to process batch of URLs
process_batch() {
    local batch_file="$1"
    local batch_results="$OUTPUT_DIR/batch_results_$(date +%Y%m%d_%H%M%S).csv"
    
    log_section "BATCH URL ANALYSIS"
    log_info "Processing URLs from: $batch_file"
    
    # Create batch results header
    echo "url,score,verdict,report_file" > "$batch_results"
    
    # Process each URL
    local count=0
    while IFS= read -r url || [[ -n "$url" ]]; do
        # Skip empty lines and comments
        if [[ -z "$url" || "$url" =~ ^# ]]; then
            continue
        fi
        
        ((count++))
        log_info "[$count] Processing: $url"
        
        # Store current stdout/stderr and redirect to /dev/null
        if [[ "$QUIET" == "true" ]]; then
            exec 3>&1 4>&2
            exec 1>/dev/null 2>/dev/null
        fi
        
        # Scan URL
        local timestamp=$(date +%Y%m%d_%H%M%S)
        local sanitized_url=$(echo "$url" | sed 's/[^a-zA-Z0-9]/_/g')
        local results_file="$OUTPUT_DIR/${sanitized_url}_${timestamp}.json"
        
        scan_url "$url"
        local scan_status=$?
        
        # Restore stdout/stderr
        if [[ "$QUIET" == "true" ]]; then
            exec 1>&3 2>&4
        fi
        
        if [[ "$scan_status" -eq 0 ]]; then
            # Extract verdict from results
            local results=$(cat "$results_file")
            local score=$(echo "$results" | jq -r '.summary.score')
            local verdict=$(echo "$results" | jq -r '.summary.verdict')
            
            # Determine report file
            local report_file=""
            if [[ "$OUTPUT_FORMAT" == "json" ]]; then
                report_file="$OUTPUT_DIR/${sanitized_url}_${timestamp}_report.json"
            elif [[ "$OUTPUT_FORMAT" == "md" ]]; then
                report_file="$OUTPUT_DIR/${sanitized_url}_${timestamp}_report.md"
            else
                report_file="$OUTPUT_DIR/${sanitized_url}_${timestamp}_report.txt"
            fi
            
            # Add to batch results
            echo "$url,$score,$verdict,$report_file" >> "$batch_results"
            
            # Display brief status
            if [[ "$verdict" == "malicious" ]]; then
                log_error "[$count] Result: MALICIOUS (Score: $score)"
            elif [[ "$verdict" == "suspicious" ]]; then
                log_warning "[$count] Result: SUSPICIOUS (Score: $score)"
            else
                log_success "[$count] Result: SAFE (Score: $score)"
            fi
        else
            echo "$url,0,error," >> "$batch_results"
            log_error "[$count] Failed to process URL"
        fi
    done < "$batch_file"
    
    log_success "Batch processing complete. Results saved to: $batch_results"
    
    # Display summary
    local total=$(grep -v "^url" "$batch_results" | wc -l)
    local malicious=$(grep -v "^url" "$batch_results" | grep ",malicious," | wc -l)
    local suspicious=$(grep -v "^url" "$batch_results" | grep ",suspicious," | wc -l)
    local safe=$(grep -v "^url" "$batch_results" | grep ",safe," | wc -l)
    local errors=$((total - malicious - suspicious - safe))
    
    echo
    echo "Summary:"
    echo "--------"
    echo "Total URLs processed: $total"
    echo "Malicious: $malicious"
    echo "Suspicious: $suspicious"
    echo "Safe: $safe"
    echo "Errors: $errors"
    echo
    echo "CSV results: $batch_results"
}

# Main execution flow
main() {
    # Display banner
    cat << EOF
╔═══════════════════════════════════════════╗
║                                           ║
║   CyberKit - URL Scan & Threat Analyzer   ║
║   Version: $VERSION                       ║
║                                           ║
╚═══════════════════════════════════════════╝
EOF
    
    # Parse command line arguments
    parse_args "$@"
    
    # Check dependencies
    check_dependencies
    
    # Process batch mode if specified
    if [[ "$BATCH_MODE" == "true" ]]; then
        process_batch "$BATCH_FILE"
        exit 0
    fi
    
    # Process single URL
    scan_url "$TARGET_URL"
    exit $?
}

# Run main function with all arguments
main "$@"