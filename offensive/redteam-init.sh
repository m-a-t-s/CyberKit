#!/bin/bash
# redteam-init.sh - Red Team Initial Engagement Automation Script
# ===============================================================
# Automates the initial phases of a red team engagement, creating
# a structured project directory and running reconnaissance tools.

# Source common utilities and configuration
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$SCRIPT_DIR/../common/utils.sh"
source "$SCRIPT_DIR/../common/config.sh"

# Display banner
print_banner "Red Team Initial Engagement Automation"

# Global variables
CLIENT_NAME=""
TARGET_NAME=""
IP_RANGE=""
ENGAGEMENT_TYPE="black-box"
TEST_MODE=false
USE_API_RECON=false

# Check for required tools
check_dependencies() {
    log "INFO" "Checking required dependencies..."
    
    local tools=("nmap" "gobuster" "whatweb" "subfinder" "amass" "httpx" "nuclei" "masscan" "ffuf" "curl" "jq")
    local missing=()
    
    for tool in "${tools[@]}"; do
        if ! check_tool "$tool"; then
            missing+=("$tool")
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        log "ERROR" "Missing required tools: ${missing[*]}"
        log "WARNING" "Please install missing tools before continuing."
        echo "    You can install most tools with: sudo apt install <tool-name>"
        echo "    For Go tools: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        exit 1
    fi
    
    log "SUCCESS" "All dependencies are installed."
}

# Get engagement information
get_engagement_info() {
    # Set defaults for testing environment
    if [ "$1" == "--test" ]; then
        CLIENT_NAME="test-client"
        TARGET_NAME="example.com"
        IP_RANGE="192.168.1.0/24"
        ENGAGEMENT_TYPE="black-box"
        return
    fi
    
    log "INFO" "Setting up new engagement..."
    read -p "Client name: " CLIENT_NAME
    read -p "Engagement name/ID: " TARGET_NAME
    read -p "Target IP range/domain (comma separated for multiple): " IP_RANGE
    PS3="Select engagement type: "
    select ENGAGEMENT_TYPE in "black-box" "grey-box" "white-box" "red-team"; do
        if [ -n "$ENGAGEMENT_TYPE" ]; then
            break
        fi
    done
    
    # Clean up inputs
    CLIENT_NAME=$(sanitize_input "$CLIENT_NAME")
    TARGET_NAME=$(sanitize_input "$TARGET_NAME")
}

# Create directory structure
create_directory_structure() {
    local base_dir="$DEFAULT_ENGAGEMENTS_DIR/$CLIENT_NAME/$TARGET_NAME-$(date +%Y%m%d)"
    
    log "INFO" "Creating directory structure at $base_dir"
    
    # Main directories
    ensure_dir "$base_dir"/{reconnaissance,scanning,enumeration,exploitation,post-exploitation,reporting,evidence/{screenshots,network-captures,credentials},resources,logs}
    
    # Reconnaissance subdirectories
    ensure_dir "$base_dir"/reconnaissance/{passive,active,osint,network,web}
    
    # Scanning subdirectories
    ensure_dir "$base_dir"/scanning/{ports,services,vulnerabilities,web}
    
    # Enumeration subdirectories
    ensure_dir "$base_dir"/enumeration/{users,systems,services,applications}
    
    # Exploitation subdirectories
    ensure_dir "$base_dir"/exploitation/{webapps,network,social-engineering,persistence}
    
    # Post-exploitation subdirectories
    ensure_dir "$base_dir"/post-exploitation/{privilege-escalation,lateral-movement,data-exfiltration,cleanup}
    
    log "SUCCESS" "Directory structure created successfully"
    
    # Create initial README and notes files
    cat > "$base_dir/README.md" << EOF
# $CLIENT_NAME - $TARGET_NAME Engagement

## Overview
- **Client**: $CLIENT_NAME
- **Target**: $TARGET_NAME
- **Date Started**: $(date +"%Y-%m-%d")
- **Engagement Type**: $ENGAGEMENT_TYPE

## Scope
- Target Range/Domain: $IP_RANGE

## Phases
1. Reconnaissance
2. Scanning and Enumeration
3. Vulnerability Assessment
4. Exploitation
5. Post-Exploitation
6. Reporting

## Quick Links
- [Reconnaissance Notes](./reconnaissance/README.md)
- [Scanning Results](./scanning/README.md)
- [Identified Vulnerabilities](./enumeration/README.md)
- [Exploitation Notes](./exploitation/README.md)
- [Evidence](./evidence/README.md)
- [Final Report](./reporting/report.md)
EOF

    # Create phase-specific README files
    for dir in reconnaissance scanning enumeration exploitation post-exploitation reporting evidence; do
        cat > "$base_dir/$dir/README.md" << EOF
# $dir Phase

## Overview
Notes and findings from the $dir phase.

## Contents
$(ls -la "$base_dir/$dir" 2>/dev/null | grep -v "README.md" | awk '{print "- " $9}' | grep -v "^- $" | grep -v "^- \.$" | grep -v "^- \.\.$")

## Timeline
- Started: $(date +"%Y-%m-%d")
- Completed: 

## Notes

EOF
    done
    
    # Return the base directory for future use
    echo "$base_dir"
}

# Function to perform API-enhanced reconnaissance
run_api_enhanced_reconnaissance() {
    local base_dir="$1"
    local targets=(${IP_RANGE//,/ })
    local recon_dir="$base_dir/reconnaissance"
    
    log "INFO" "Starting API-enhanced reconnaissance..."
    
    # Directory for API-based recon results
    local api_recon_dir="$recon_dir/api-enhanced"
    ensure_dir "$api_recon_dir"
    
    # Process each target that appears to be a domain (not an IP range)
    for target in "${targets[@]}"; do
        if [[ ! $target =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$ ]]; then
            # Target is likely a domain
            log "INFO" "Performing API-enhanced reconnaissance for domain: $target"
            
            # Check for SecurityTrails API key
            local securitytrails_key=$("$SCRIPT_DIR/../common/api-keys.sh" get securitytrails 2>/dev/null)
            if [ $? -eq 0 ] && [ ! -z "$securitytrails_key" ]; then
                log "INFO" "Using SecurityTrails API for subdomain enumeration..."
                
                # Query SecurityTrails API for subdomains
                curl -s -H "APIKEY: $securitytrails_key" "https://api.securitytrails.com/v1/domain/$target/subdomains" \
                    > "$api_recon_dir/securitytrails-$target.json"
                
                # Extract subdomains
                if [ -s "$api_recon_dir/securitytrails-$target.json" ] && ! grep -q "message" "$api_recon_dir/securitytrails-$target.json"; then
                    log "SUCCESS" "SecurityTrails subdomains retrieved successfully."
                    jq -r '.subdomains[]' "$api_recon_dir/securitytrails-$target.json" | \
                        sed "s/$/.$target/" > "$api_recon_dir/securitytrails-subdomains-$target.txt"
                    
                    # Merge with other subdomain discovery if it exists
                    if [ -f "$recon_dir/web/subdomains-combined-$target.txt" ]; then
                        cat "$api_recon_dir/securitytrails-subdomains-$target.txt" "$recon_dir/web/subdomains-combined-$target.txt" | \
                            sort -u > "$recon_dir/web/subdomains-combined-$target.txt.new"
                        mv "$recon_dir/web/subdomains-combined-$target.txt.new" "$recon_dir/web/subdomains-combined-$target.txt"
                        log "INFO" "Combined SecurityTrails subdomains with previously discovered subdomains."
                    else
                        # If no previous subdomain file exists, create one
                        cp "$api_recon_dir/securitytrails-subdomains-$target.txt" "$recon_dir/web/subdomains-combined-$target.txt"
                    fi
                else
                    log "WARNING" "Failed to retrieve SecurityTrails data for $target, or API key may be invalid."
                fi
            else
                log "WARNING" "SecurityTrails API key not found. Run 'common/api-keys.sh set securitytrails YOUR_API_KEY' to configure."
            fi
            
            # Check for Hunter.io API key for email harvesting
            local hunterio_key=$("$SCRIPT_DIR/../common/api-keys.sh" get hunterio 2>/dev/null)
            if [ $? -eq 0 ] && [ ! -z "$hunterio_key" ]; then
                log "INFO" "Using Hunter.io API for email harvesting..."
                
                # Query Hunter.io API for email addresses
                curl -s "https://api.hunter.io/v2/domain-search?domain=$target&api_key=$hunterio_key" \
                    > "$api_recon_dir/hunterio-$target.json"
                
                # Extract email addresses
                if [ -s "$api_recon_dir/hunterio-$target.json" ] && ! grep -q "error" "$api_recon_dir/hunterio-$target.json"; then
                    log "SUCCESS" "Hunter.io email data retrieved successfully."
                    
                    # Create email report
                    echo "# Email Addresses for $target" > "$api_recon_dir/email-report-$target.md"
                    echo "" >> "$api_recon_dir/email-report-$target.md"
                    
                    # Extract domain information
                    local domain_info=$(jq -r '.data.domain' "$api_recon_dir/hunterio-$target.json")
                    local email_count=$(jq -r '.data.emails | length' "$api_recon_dir/hunterio-$target.json")
                    
                    echo "## Domain Information" >> "$api_recon_dir/email-report-$target.md"
                    echo "* Domain: $target" >> "$api_recon_dir/email-report-$target.md"
                    echo "* Email count: $email_count" >> "$api_recon_dir/email-report-$target.md"
                    echo "" >> "$api_recon_dir/email-report-$target.md"
                    
                    # Extract and format email addresses
                    echo "## Email Addresses" >> "$api_recon_dir/email-report-$target.md"
                    jq -r '.data.emails[] | "* " + .value + " - " + (.first_name // "") + " " + (.last_name // "") + " (" + (.position // "Unknown Position") + ")"' \
                        "$api_recon_dir/hunterio-$target.json" >> "$api_recon_dir/email-report-$target.md"
                    
                    # Also save email addresses in a plain text file
                    jq -r '.data.emails[].value' "$api_recon_dir/hunterio-$target.json" | sort -u > "$api_recon_dir/emails-$target.txt"
                else
                    log "WARNING" "Failed to retrieve Hunter.io data for $target, or API key may be invalid."
                fi
            else
                log "WARNING" "Hunter.io API key not found. Run 'common/api-keys.sh set hunterio YOUR_API_KEY' to configure."
            fi
            
            # Check for WhoisXML API key for WHOIS data
            local whoisxml_key=$("$SCRIPT_DIR/../common/api-keys.sh" get whoisxml 2>/dev/null)
            if [ $? -eq 0 ] && [ ! -z "$whoisxml_key" ]; then
                log "INFO" "Using WhoisXML API for enhanced WHOIS data..."
                
                # Query WhoisXML API for detailed WHOIS information
                curl -s "https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=$whoisxml_key&domainName=$target&outputFormat=JSON" \
                    > "$api_recon_dir/whoisxml-$target.json"
                
                # Extract WHOIS information
                if [ -s "$api_recon_dir/whoisxml-$target.json" ] && ! grep -q "error" "$api_recon_dir/whoisxml-$target.json"; then
                    log "SUCCESS" "WhoisXML data retrieved successfully."
                    
                    # Create WHOIS report
                    echo "# Enhanced WHOIS Data for $target" > "$api_recon_dir/whois-report-$target.md"
                    echo "" >> "$api_recon_dir/whois-report-$target.md"
                    
                    # Extract registrar information
                    local registrar=$(jq -r '.WhoisRecord.registrarName // "Unknown"' "$api_recon_dir/whoisxml-$target.json")
                    local creation_date=$(jq -r '.WhoisRecord.createdDate // "Unknown"' "$api_recon_dir/whoisxml-$target.json")
                    local expiry_date=$(jq -r '.WhoisRecord.expiresDate // "Unknown"' "$api_recon_dir/whoisxml-$target.json")
                    
                    echo "## Domain Information" >> "$api_recon_dir/whois-report-$target.md"
                    echo "* Registrar: $registrar" >> "$api_recon_dir/whois-report-$target.md"
                    echo "* Creation Date: $creation_date" >> "$api_recon_dir/whois-report-$target.md"
                    echo "* Expiration Date: $expiry_date" >> "$api_recon_dir/whois-report-$target.md"
                    echo "" >> "$api_recon_dir/whois-report-$target.md"
                    
                    # Extract contact information if available
                    echo "## Contact Information" >> "$api_recon_dir/whois-report-$target.md"
                    if jq -e '.WhoisRecord.registrant' "$api_recon_dir/whoisxml-$target.json" >/dev/null 2>&1; then
                        local registrant_org=$(jq -r '.WhoisRecord.registrant.organization // "Unknown"' "$api_recon_dir/whoisxml-$target.json")
                        local registrant_country=$(jq -r '.WhoisRecord.registrant.country // "Unknown"' "$api_recon_dir/whoisxml-$target.json")
                        
                        echo "### Registrant" >> "$api_recon_dir/whois-report-$target.md"
                        echo "* Organization: $registrant_org" >> "$api_recon_dir/whois-report-$target.md"
                        echo "* Country: $registrant_country" >> "$api_recon_dir/whois-report-$target.md"
                        echo "" >> "$api_recon_dir/whois-report-$target.md"
                    else
                        echo "No detailed registrant information available." >> "$api_recon_dir/whois-report-$target.md"
                        echo "" >> "$api_recon_dir/whois-report-$target.md"
                    fi
                else
                    log "WARNING" "Failed to retrieve WhoisXML data for $target, or API key may be invalid."
                fi
            else
                log "WARNING" "WhoisXML API key not found. Run 'common/api-keys.sh set whoisxml YOUR_API_KEY' to configure."
            fi
        else
            # Target is an IP range - check for Shodan information
            log "INFO" "Target appears to be an IP range. Checking for Shodan intelligence..."
            
            # Check for Shodan API key
            local shodan_key=$("$SCRIPT_DIR/../common/api-keys.sh" get shodan 2>/dev/null)
            if [ $? -eq 0 ] && [ ! -z "$shodan_key" ]; then
                log "INFO" "Using Shodan API for network intelligence..."
                
                # If we have live hosts, query Shodan for each
                if [ -f "$recon_dir/network/live-hosts-$(echo $target | tr '/' '-').txt" ]; then
                    ensure_dir "$api_recon_dir/shodan"
                    echo "# Shodan Intelligence Report" > "$api_recon_dir/shodan-report.md"
                    echo "" >> "$api_recon_dir/shodan-report.md"
                    
                    while read -r ip; do
                        log "INFO" "Querying Shodan for information about $ip..."
                        
                        # Query Shodan API for host information
                        curl -s "https://api.shodan.io/shodan/host/$ip?key=$shodan_key" \
                            > "$api_recon_dir/shodan/shodan-$ip.json"
                        
                        # Extract Shodan information
                        if [ -s "$api_recon_dir/shodan/shodan-$ip.json" ] && ! grep -q "error" "$api_recon_dir/shodan/shodan-$ip.json"; then
                            log "SUCCESS" "Shodan data retrieved for $ip."
                            
                            # Extract key information
                            local ports=$(jq -r '.ports[]' "$api_recon_dir/shodan/shodan-$ip.json" 2>/dev/null | tr '\n' ',' | sed 's/,$//')
                            local hostnames=$(jq -r '.hostnames[]' "$api_recon_dir/shodan/shodan-$ip.json" 2>/dev/null | tr '\n' ',' | sed 's/,$//')
                            local country=$(jq -r '.country_name // "Unknown"' "$api_recon_dir/shodan/shodan-$ip.json")
                            local org=$(jq -r '.org // "Unknown"' "$api_recon_dir/shodan/shodan-$ip.json")
                            
                            # Add to report
                            echo "## IP: $ip" >> "$api_recon_dir/shodan-report.md"
                            echo "* Organization: $org" >> "$api_recon_dir/shodan-report.md"
                            echo "* Country: $country" >> "$api_recon_dir/shodan-report.md"
                            echo "* Hostnames: $hostnames" >> "$api_recon_dir/shodan-report.md"
                            echo "* Open Ports: $ports" >> "$api_recon_dir/shodan-report.md"
                            echo "" >> "$api_recon_dir/shodan-report.md"
                            
                            # Extract detailed service information
                            echo "### Services" >> "$api_recon_dir/shodan-report.md"
                            jq -r '.data[] | "* Port " + (.port|tostring) + "/" + .transport + " - " + (.product // "Unknown") + " " + (.version // "")' \
                                "$api_recon_dir/shodan/shodan-$ip.json" 2>/dev/null >> "$api_recon_dir/shodan-report.md"
                            echo "" >> "$api_recon_dir/shodan-report.md"
                            echo "---" >> "$api_recon_dir/shodan-report.md"
                            echo "" >> "$api_recon_dir/shodan-report.md"
                        else
                            log "WARNING" "No Shodan data found for $ip or API key may be invalid."
                        fi
                        
                        # Respect rate limits
                        sleep 2
                    done < "$recon_dir/network/live-hosts-$(echo $target | tr '/' '-').txt"
                else
                    log "WARNING" "No live hosts found to check with Shodan."
                fi
            else
                log "WARNING" "Shodan API key not found. Run 'common/api-keys.sh set shodan YOUR_API_KEY' to configure."
            fi
        fi
    done
    
    log "SUCCESS" "API-enhanced reconnaissance completed."
}

# Run initial reconnaissance
run_reconnaissance() {
    log "INFO" "Starting initial reconnaissance..."
    
    local base_dir="$1"
    local targets=(${IP_RANGE//,/ })
    local recon_dir="$base_dir/reconnaissance"
    local scan_dir="$base_dir/scanning"
    
    # Log start time
    local start_time=$(date +%s)
    echo "Reconnaissance started at $(date)" > "$base_dir/logs/recon.log"
    
    # Process each target
    for target in "${targets[@]}"; do
        log "INFO" "Processing target: $target"
        
        # Determine if target is IP range or domain
        if [[ $target =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$ ]]; then
            # Target is an IP or CIDR range
            log "WARNING" "Target appears to be an IP range. Running network reconnaissance."
            
            # Host discovery scan
            log "INFO" "Running host discovery scan..."
            nmap -sn "$target" -oA "$recon_dir/network/host-discovery-$(echo $target | tr '/' '-')" 2>&1 | tee -a "$base_dir/logs/recon.log"
            
            # Extract live hosts
            log "INFO" "Extracting live hosts..."
            grep "Nmap scan report for" "$recon_dir/network/host-discovery-$(echo $target | tr '/' '-').nmap" | awk '{print $NF}' | tr -d '()' > "$recon_dir/network/live-hosts-$(echo $target | tr '/' '-').txt"
            
            # Quick port scan on live hosts
            log "INFO" "Running quick port scan on live hosts..."
            if [ -s "$recon_dir/network/live-hosts-$(echo $target | tr '/' '-').txt" ]; then
                nmap -T4 -F -sV --version-intensity 2 -iL "$recon_dir/network/live-hosts-$(echo $target | tr '/' '-').txt" -oA "$scan_dir/ports/quick-scan-$(echo $target | tr '/' '-')" 2>&1 | tee -a "$base_dir/logs/recon.log"
            else
                log "ERROR" "No live hosts found for $target"
            fi
            
            # Find web servers
            log "INFO" "Identifying web servers..."
            grep -E "80/open|443/open|8080/open" "$scan_dir/ports/quick-scan-$(echo $target | tr '/' '-').nmap" 2>/dev/null | awk -F' ' '{print $2}' | sort -u > "$recon_dir/web/web-servers-$(echo $target | tr '/' '-').txt"
            
        else
            # Target is a domain
            log "WARNING" "Target appears to be a domain. Running web reconnaissance."
            
            # Subdomain enumeration
            log "INFO" "Enumerating subdomains..."
            subfinder -d "$target" -o "$recon_dir/web/subdomains-subfinder-$target.txt" 2>&1 | tee -a "$base_dir/logs/recon.log"
            amass enum -passive -d "$target" -o "$recon_dir/web/subdomains-amass-$target.txt" 2>&1 | tee -a "$base_dir/logs/recon.log"
            
            # Combine subdomain lists
            cat "$recon_dir/web/subdomains-subfinder-$target.txt" "$recon_dir/web/subdomains-amass-$target.txt" 2>/dev/null | sort -u > "$recon_dir/web/subdomains-combined-$target.txt"
            
            # Check for live subdomains
            log "INFO" "Checking for live web servers..."
            cat "$recon_dir/web/subdomains-combined-$target.txt" | httpx -silent -o "$recon_dir/web/live-web-$target.txt" 2>&1 | tee -a "$base_dir/logs/recon.log"
            
            # Web technology fingerprinting
            log "INFO" "Fingerprinting web technologies..."
            if [ -s "$recon_dir/web/live-web-$target.txt" ]; then
                whatweb -i "$recon_dir/web/live-web-$target.txt" --log-json="$recon_dir/web/whatweb-$target.json" 2>&1 | tee -a "$base_dir/logs/recon.log"
            else
                log "ERROR" "No live web servers found for $target"
            fi
            
            # DNS records
            log "INFO" "Gathering DNS records..."
            dig +nocmd "$target" ANY +multiline +noall +answer > "$recon_dir/passive/dns-records-$target.txt"
            
            # WHOIS information
            log "INFO" "Gathering WHOIS information..."
            whois "$target" > "$recon_dir/passive/whois-$target.txt"
        fi
    done
    
    # Generate summary report
    generate_recon_summary "$base_dir" "${targets[@]}"
    
    # Log completion time
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    log "SUCCESS" "Initial reconnaissance completed in $(seconds_to_time $duration). Results saved to $recon_dir"
}

# Generate a summary of the reconnaissance results
generate_recon_summary() {
    local base_dir="$1"
    shift
    local targets=("$@")
    
    log "INFO" "Generating reconnaissance summary..."
    
    local summary_file="$base_dir/reconnaissance/recon-summary.md"
    
    # Create summary header
    cat > "$summary_file" << EOF
# Reconnaissance Summary

## Overview
- **Client**: $CLIENT_NAME
- **Target**: $TARGET_NAME
- **Date**: $(date +"%Y-%m-%d")

## Targets Analyzed
$(printf "- %s\n" "${targets[@]}")

## Key Findings

EOF
    
    # Add IP-based findings
    for target in "${targets[@]}"; do
        if [[ $target =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$ ]]; then
            echo "### Network Summary for $target" >> "$summary_file"
            
            # Count live hosts
            if [ -f "$base_dir/reconnaissance/network/live-hosts-$(echo $target | tr '/' '-').txt" ]; then
                host_count=$(wc -l < "$base_dir/reconnaissance/network/live-hosts-$(echo $target | tr '/' '-').txt")
                echo "- **Live Hosts**: $host_count hosts discovered" >> "$summary_file"
            else
                echo "- **Live Hosts**: No scan results available" >> "$summary_file"
            fi
            
            # Summarize open ports
            if [ -f "$base_dir/scanning/ports/quick-scan-$(echo $target | tr '/' '-').nmap" ]; then
                echo "- **Common Open Ports**:" >> "$summary_file"
                grep "open" "$base_dir/scanning/ports/quick-scan-$(echo $target | tr '/' '-').nmap" | grep -v "filtered" | sort | uniq -c | sort -nr | head -10 | while read -r line; do
                    echo "  - $line" >> "$summary_file"
                done
            fi
            
            # Web servers found
            if [ -f "$base_dir/reconnaissance/web/web-servers-$(echo $target | tr '/' '-').txt" ]; then
                web_count=$(wc -l < "$base_dir/reconnaissance/web/web-servers-$(echo $target | tr '/' '-').txt")
                echo "- **Web Servers**: $web_count web servers identified" >> "$summary_file"
            fi
            
        else
            echo "### Web Summary for $target" >> "$summary_file"
            
            # Count subdomains
            if [ -f "$base_dir/reconnaissance/web/subdomains-combined-$target.txt" ]; then
                subdomain_count=$(wc -l < "$base_dir/reconnaissance/web/subdomains-combined-$target.txt")
                echo "- **Subdomains**: $subdomain_count subdomains discovered" >> "$summary_file"
            else
                echo "- **Subdomains**: No scan results available" >> "$summary_file"
            fi
            
            # Count live web servers
            if [ -f "$base_dir/reconnaissance/web/live-web-$target.txt" ]; then
                live_web_count=$(wc -l < "$base_dir/reconnaissance/web/live-web-$target.txt")
                echo "- **Live Web Servers**: $live_web_count live web endpoints" >> "$summary_file"
            else
                echo "- **Live Web Servers**: No scan results available" >> "$summary_file"
            fi
            
            # Web technologies summary
            if [ -f "$base_dir/reconnaissance/web/whatweb-$target.json" ]; then
                echo "- **Web Technologies**: Most common technologies identified" >> "$summary_file"
                cat "$base_dir/reconnaissance/web/whatweb-$target.json" | jq -r '.[] | .plugins | keys[]' 2>/dev/null | sort | uniq -c | sort -nr | head -10 | while read -r line; do
                    echo "  - $line" >> "$summary_file"
                done
            fi
        fi
    done
    
    # Add API-based findings if they exist
    if [ -d "$base_dir/reconnaissance/api-enhanced" ]; then
        echo "" >> "$summary_file"
        echo "## Enhanced Intelligence" >> "$summary_file"
        
        # Add SecurityTrails findings
        if ls "$base_dir/reconnaissance/api-enhanced/securitytrails-subdomains-"* 1> /dev/null 2>&1; then
            echo "" >> "$summary_file"
            echo "### SecurityTrails Intelligence" >> "$summary_file"
            for file in "$base_dir/reconnaissance/api-enhanced/securitytrails-subdomains-"*; do
                domain=$(basename "$file" | sed 's/securitytrails-subdomains-//' | sed 's/.txt//')
                count=$(wc -l < "$file")
                echo "- **$domain**: $count additional subdomains discovered" >> "$summary_file"
            done
        fi
        
        # Add Hunter.io findings
        if ls "$base_dir/reconnaissance/api-enhanced/emails-"* 1> /dev/null 2>&1; then
            echo "" >> "$summary_file"
            echo "### Email Intelligence" >> "$summary_file"
            for file in "$base_dir/reconnaissance/api-enhanced/emails-"*; do
                domain=$(basename "$file" | sed 's/emails-//' | sed 's/.txt//')
                count=$(wc -l < "$file")
                echo "- **$domain**: $count email addresses discovered" >> "$summary_file"
                echo "  - See detailed report in: reconnaissance/api-enhanced/email-report-$domain.md" >> "$summary_file"
            done
        fi
        
        # Add Shodan findings
        if [ -f "$base_dir/reconnaissance/api-enhanced/shodan-report.md" ]; then
            echo "" >> "$summary_file"
            echo "### Shodan Intelligence" >> "$summary_file"
            echo "Shodan intelligence report available at reconnaissance/api-enhanced/shodan-report.md" >> "$summary_file"
        fi
    fi
    
    # Add next steps section
    cat >> "$summary_file" << EOF

## Recommended Next Steps

1. **Vulnerability Scanning**:
   - Run comprehensive Nmap vulnerability scans against identified services
   - Use Nuclei for web vulnerability scanning on discovered web endpoints
   - Perform targeted service enumeration based on discovered services

2. **Web Application Testing**:
   - Set up Burp Suite Pro for detailed web application analysis
   - Run directory brute forcing on web servers
   - Check for common web vulnerabilities (SQLi, XSS, etc.)

3. **Network Exploitation**:
   - Identify potential entry points based on vulnerable services
   - Prepare exploitation strategies for identified vulnerabilities

4. **Command to Start Burp Pro**:
   \`\`\`
   java -jar ~/path/to/burpsuite_pro.jar -project "$base_dir/resources/burp-project.burp"
   \`\`\`

## Generated Artifacts

$(find "$base_dir/reconnaissance" "$base_dir/scanning" -type f 2>/dev/null | sort | sed 's|'"$base_dir"'|.|g' | sed 's|^|* |g')

EOF
    
    log "SUCCESS" "Reconnaissance summary generated at $summary_file"
}

# Run vulnerability scanning
run_vulnerability_scanning() {
    local base_dir="$1"
    local scan_dir="$base_dir/scanning"
    local vuln_dir="$base_dir/scanning/vulnerabilities"
    
    log "INFO" "Starting vulnerability scanning..."
    
    # Log start time
    local start_time=$(date +%s)
    echo "Vulnerability scanning started at $(date)" > "$base_dir/logs/vulnerability-scan.log"
    
    # Web vulnerability scanning with Nuclei
    if [ -d "$base_dir/reconnaissance/web" ]; then
        for target_file in "$base_dir/reconnaissance/web/live-web-"*.txt; do
            if [ -f "$target_file" ]; then
                target_name=$(basename "$target_file" | sed 's/live-web-//g' | sed 's/.txt//g')
                log "INFO" "Running Nuclei vulnerability scan on $target_name web endpoints..."
                
                nuclei -l "$target_file" -o "$vuln_dir/nuclei-$target_name.txt" -severity low,medium,high,critical 2>&1 | tee -a "$base_dir/logs/vulnerability-scan.log"
            fi
        done
    fi
    
    # Service vulnerability scanning with Nmap
    for target_file in "$base_dir/reconnaissance/network/live-hosts-"*.txt; do
        if [ -f "$target_file" ]; then
            target_name=$(basename "$target_file" | sed 's/live-hosts-//g' | sed 's/.txt//g')
            log "INFO" "Running Nmap vulnerability scan on $target_name hosts..."
            
            nmap -sV --script vuln -iL "$target_file" -oA "$vuln_dir/nmap-vuln-$target_name" 2>&1 | tee -a "$base_dir/logs/vulnerability-scan.log"
        fi
    done
    
    # Generate vulnerability summary
    generate_vulnerability_summary "$base_dir"
    
    # Log completion time
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    log "SUCCESS" "Vulnerability scanning completed in $(seconds_to_time $duration). Results saved to $vuln_dir/"
}

# Generate a summary of vulnerability findings
generate_vulnerability_summary() {
    local base_dir="$1"
    local summary_file="$base_dir/scanning/vulnerability-summary.md"
    
    log "INFO" "Generating vulnerability summary..."
    
    # Create summary header
    cat > "$summary_file" << EOF
# Vulnerability Scanning Summary

## Overview
- **Client**: $CLIENT_NAME
- **Target**: $TARGET_NAME
- **Date**: $(date +"%Y-%m-%d")

## Key Findings

EOF
    
    # Summarize Nuclei findings
    echo "### Web Vulnerabilities (Nuclei)" >> "$summary_file"
    for nuclei_file in "$base_dir/scanning/vulnerabilities/nuclei-"*.txt; do
        if [ -f "$nuclei_file" ]; then
            target_name=$(basename "$nuclei_file" | sed 's/nuclei-//g' | sed 's/.txt//g')
            echo "#### Findings for $target_name" >> "$summary_file"
            
            # Count vulnerabilities by severity
            if [ -s "$nuclei_file" ]; then
                echo "- **Vulnerability Count by Severity**:" >> "$summary_file"
                grep -i "\[critical\]" "$nuclei_file" 2>/dev/null | wc -l | xargs -I{} echo "  - Critical: {}" >> "$summary_file"
                grep -i "\[high\]" "$nuclei_file" 2>/dev/null | wc -l | xargs -I{} echo "  - High: {}" >> "$summary_file"
                grep -i "\[medium\]" "$nuclei_file" 2>/dev/null | wc -l | xargs -I{} echo "  - Medium: {}" >> "$summary_file"
                grep -i "\[low\]" "$nuclei_file" 2>/dev/null | wc -l | xargs -I{} echo "  - Low: {}" >> "$summary_file"
                
                # List critical and high findings
                if grep -q -i "\[critical\]" "$nuclei_file" 2>/dev/null || grep -q -i "\[high\]" "$nuclei_file" 2>/dev/null; then
                    echo "- **Critical and High Vulnerabilities**:" >> "$summary_file"
                    grep -i -E "\[critical\]|\[high\]" "$nuclei_file" 2>/dev/null | sed 's/^/  - /' >> "$summary_file"
                fi
            else
                echo "- No vulnerabilities found" >> "$summary_file"
            fi
        fi
    done
    
    # Summarize Nmap vulnerability findings
    echo "### Network Vulnerabilities (Nmap)" >> "$summary_file"
    for nmap_file in "$base_dir/scanning/vulnerabilities/nmap-vuln-"*.nmap; do
        if [ -f "$nmap_file" ]; then
            target_name=$(basename "$nmap_file" | sed 's/nmap-vuln-//g' | sed 's/.nmap//g')
            echo "#### Findings for $target_name" >> "$summary_file"
            
            # Extract vulnerability findings
            if grep -q "VULNERABLE" "$nmap_file" 2>/dev/null; then
                echo "- **Vulnerable Services**:" >> "$summary_file"
                grep -A 2 "VULNERABLE" "$nmap_file" 2>/dev/null | grep -v "\-\-" | sed 's/^/  - /' >> "$summary_file"
            else
                echo "- No significant vulnerabilities found" >> "$summary_file"
            fi
        fi
    done
    
    # Add recommendations section
    cat >> "$summary_file" << EOF

## Recommended Actions

1. **Critical Vulnerabilities**:
   - Address all critical and high vulnerabilities immediately
   - Create targeted exploitation plan for the most promising attack vectors

2. **Further Testing**:
   - Perform manual verification of identified vulnerabilities
   - Set up Burp Suite Pro for in-depth testing of web vulnerabilities
   - Conduct targeted password attacks on exposed services

3. **Initial Exploitation Targets**:
$(grep -i -E "\[critical\]|\[high\]" "$base_dir/scanning/vulnerabilities/nuclei-"*.txt 2>/dev/null | head -5 | sed 's/^/   - /' || echo "   - No critical/high web vulnerabilities found")
$(grep -A 2 "VULNERABLE" "$base_dir/scanning/vulnerabilities/nmap-vuln-"*.nmap 2>/dev/null | grep -v "\-\-" | head -5 | sed 's/^/   - /' || echo "   - No significant network vulnerabilities found")

EOF
    
    log "SUCCESS" "Vulnerability summary generated at $summary_file"
}

# Set up Burp Suite project
setup_burp() {
    local base_dir="$1"
    
    log "INFO" "Creating Burp Suite project configuration..."
    
    local resources_dir="$base_dir/resources"
    local burp_config="$resources_dir/burp-setup.txt"
    
    # Create Burp setup guidance file
    cat > "$burp_config" << EOF
# Burp Suite Pro Setup Guide

## Project Setup
1. Launch Burp Suite Pro with:
   \`\`\`
   java -jar /path/to/burpsuite_pro.jar
   \`\`\`

2. Create a new project:
   - Project name: $CLIENT_NAME-$TARGET_NAME
   - Save location: $resources_dir/$CLIENT_NAME-$TARGET_NAME.burp

## Target Scope Configuration
1. Go to the "Target" tab
2. Add the following targets to scope:

EOF
    
    # Add targets to the Burp configuration
    if [[ "$IP_RANGE" == *"."* ]]; then
        # IP-based targets
        echo "   - IP Range: $IP_RANGE" >> "$burp_config"
    else
        # Domain-based targets
        echo "   - Domain: $IP_RANGE" >> "$burp_config"
        
        # Add discovered subdomains
        if [ -f "$base_dir/reconnaissance/web/subdomains-combined-$IP_RANGE.txt" ]; then
            echo "   - Subdomains:" >> "$burp_config"
            head -10 "$base_dir/reconnaissance/web/subdomains-combined-$IP_RANGE.txt" | sed 's/^/     * /' >> "$burp_config"
            count=$(wc -l < "$base_dir/reconnaissance/web/subdomains-combined-$IP_RANGE.txt")
            if [ "$count" -gt 10 ]; then
                echo "     * ... and $(($count - 10)) more subdomains (see the full list in the reconnaissance directory)" >> "$burp_config"
            fi
        fi
    fi
    
    # Add scanning and attack guidance
    cat >> "$burp_config" << EOF

## Recommended Burp Suite Workflow

1. **Initial Spider/Crawl**:
   - Right-click on target in site map
   - Select "Spider this host"
   - Review discovered content in site map

2. **Active Scanning**:
   - Right-click on target in site map
   - Select "Actively scan this host"
   - Configure scan settings based on engagement requirements

3. **Manual Testing**:
   - Use Proxy to manually browse the application
   - Use Repeater to modify and repeat requests
   - Use Intruder for targeted parameter testing

4. **Extensions to Enable**:
   - Active Scanner
   - Autorize
   - JWT Decoder
   - Logger++
   - CSRF Scanner

5. **Export Results**:
   - Save all findings to: $base_dir/evidence/burp-findings.html

## Integration with Other Tools

- Send interesting endpoints to:
  - Directory brute force with gobuster
  - Parameter testing with ffuf
  - Custom exploitation scripts

EOF
    
    log "SUCCESS" "Burp Suite setup guide created at $burp_config"
}

# Parse command line arguments
parse_command_line() {
    # Handle test mode
    if [[ "$1" == "--test" ]]; then
        TEST_MODE=true
        log "WARNING" "Running in test mode"
    else
        TEST_MODE=false
    fi
    
    # Handle API-enhanced reconnaissance
    if [[ "$1" == "--api-recon" ]]; then
        USE_API_RECON=true
        shift
    fi
    
    # Handle help command
    if [[ "$1" == "--help" || "$1" == "-h" ]]; then
        echo "Usage: $0 [options]"
        echo ""
        echo "Options:"
        echo "  --test       Run in test mode with default values"
        echo "  --api-recon  Use API-enhanced reconnaissance (requires API keys)"
        echo "  --help, -h   Show this help message"
        echo ""
        echo "Description:"
        echo "  This script automates the initial phases of a red team engagement,"
        echo "  creating a structured project directory and running reconnaissance tools."
        exit 0
    fi
}

# Main function
main() {
    # Parse command line arguments
    parse_command_line "$@"
    
    # Check dependencies
    check_dependencies
    
    # Get engagement information
    if [ "$TEST_MODE" == "true" ]; then
        get_engagement_info "--test"
    else
        get_engagement_info
    fi
    
    # Create directory structure
    base_dir=$(create_directory_structure)
    
    # Run initial reconnaissance
    run_reconnaissance "$base_dir"
    
    # If API-enhanced reconnaissance is requested, run it
    if [ "$USE_API_RECON" = true ]; then
        run_api_enhanced_reconnaissance "$base_dir"
    fi
    
    # Run vulnerability scanning
    run_vulnerability_scanning "$base_dir"
    
    # Set up Burp Suite project
    setup_burp "$base_dir"
    
    # Completion message
    echo "${GREEN}${BOLD}"
    echo "============================================================"
    echo "Initial engagement setup complete!"
    echo "============================================================"
    echo "${RESET}"
    echo "Project directory: ${YELLOW}$base_dir${RESET}"
    echo ""
    echo "Key resources:"
    echo "- Reconnaissance summary: ${YELLOW}$base_dir/reconnaissance/recon-summary.md${RESET}"
    echo "- Vulnerability summary: ${YELLOW}$base_dir/scanning/vulnerability-summary.md${RESET}"
    echo "- Burp Suite setup: ${YELLOW}$base_dir/resources/burp-setup.txt${RESET}"
    echo ""
    echo "Next recommended steps:"
    echo "1. Review the reconnaissance summary"
    echo "2. Set up Burp Suite Pro using the configuration guide"
    echo "3. Begin targeted exploitation based on vulnerability findings"
    echo ""
    echo "To access the project directory:"
    echo "${YELLOW}cd $base_dir${RESET}"
}

# Execute main if script is run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi