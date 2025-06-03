#!/bin/bash

# Complete Domain Security Audit Script
# Comprehensive security assessment for domains including:
# - Web Security Headers, SSL/TLS, DNS, Email Security, Subdomains, Ports, etc.
# Usage: ./domain_security_audit.sh domain.com

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Configuration
DNS_SERVER="8.8.8.8"
COMMON_PORTS="21,22,23,25,53,80,110,143,443,993,995,8080,8443"
COMMON_SUBDOMAINS="www mail ftp admin blog shop api dev test staging vpn cdn"

# Counters for final summary
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
WARNINGS=0

# Function to print colored output
print_status() {
    local status=$1
    local message=$2
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    case $status in
        "PASS") 
            echo -e "${GREEN}✓ PASS${NC}: $message"
            PASSED_TESTS=$((PASSED_TESTS + 1))
            ;;
        "FAIL") 
            echo -e "${RED}✗ FAIL${NC}: $message"
            FAILED_TESTS=$((FAILED_TESTS + 1))
            ;;
        "WARN") 
            echo -e "${YELLOW}⚠ WARN${NC}: $message"
            WARNINGS=$((WARNINGS + 1))
            ;;
        "INFO") 
            echo -e "${BLUE}ℹ INFO${NC}: $message"
            ;;
        "HEADER") 
            echo -e "${PURPLE}━━━ $message ━━━${NC}"
            ;;
    esac
}

# Function to print section headers
print_section() {
    echo ""
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║ $(printf "%-69s" "$1")║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# Function to print recommendations
print_recommendation() {
    local title=$1
    local desc=$2
    local fix=$3
    echo ""
    echo -e "${RED}${BOLD}ISSUE:${NC} $title"
    echo -e "${BLUE}IMPACT:${NC} $desc"
    echo -e "${YELLOW}FIX:${NC} $fix"
    echo ""
}

# Function to check if domain exists
check_domain_exists() {
    local domain=$1
    print_section "Domain Validation"
    
    if dig @$DNS_SERVER $domain +short > /dev/null 2>&1; then
        print_status "PASS" "Domain $domain is resolvable"
        local ip=$(dig @$DNS_SERVER $domain +short | head -1)
        print_status "INFO" "Primary IP: $ip"
    else
        print_status "FAIL" "Domain $domain does not exist or is not resolvable"
        exit 1
    fi
}

# Function to check web security headers
check_web_security() {
    local domain=$1
    print_section "Web Security Headers Analysis"
    
    # Check if website is accessible
    if ! curl -s --connect-timeout 10 -I "https://$domain" > /dev/null 2>&1; then
        if ! curl -s --connect-timeout 10 -I "http://$domain" > /dev/null 2>&1; then
            print_status "FAIL" "Website not accessible on HTTP or HTTPS"
            return 1
        else
            local protocol="http"
            print_status "WARN" "Website only accessible via HTTP (insecure)"
        fi
    else
        local protocol="https"
        print_status "PASS" "Website accessible via HTTPS"
    fi
    
    # Get headers
    local headers=$(curl -s --connect-timeout 10 -I "$protocol://$domain" 2>/dev/null)
    
    # Check security headers
    if echo "$headers" | grep -qi "strict-transport-security"; then
        print_status "PASS" "HSTS (HTTP Strict Transport Security) enabled"
    else
        print_status "FAIL" "HSTS header missing"
        print_recommendation "Missing HSTS Header" \
            "Browsers can be tricked into using HTTP instead of HTTPS" \
            "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"
    fi
    
    if echo "$headers" | grep -qi "x-frame-options"; then
        print_status "PASS" "X-Frame-Options header present"
    else
        print_status "FAIL" "X-Frame-Options header missing"
        print_recommendation "Missing X-Frame-Options" \
            "Site vulnerable to clickjacking attacks" \
            "Add: X-Frame-Options: DENY or SAMEORIGIN"
    fi
    
    if echo "$headers" | grep -qi "x-content-type-options"; then
        print_status "PASS" "X-Content-Type-Options header present"
    else
        print_status "FAIL" "X-Content-Type-Options header missing"
        print_recommendation "Missing X-Content-Type-Options" \
            "Browser may incorrectly interpret file types" \
            "Add: X-Content-Type-Options: nosniff"
    fi
    
    if echo "$headers" | grep -qi "content-security-policy"; then
        print_status "PASS" "Content Security Policy (CSP) header present"
    else
        print_status "FAIL" "Content Security Policy header missing"
        print_recommendation "Missing CSP Header" \
            "No protection against XSS and data injection attacks" \
            "Add: Content-Security-Policy: default-src 'self'"
    fi
    
    if echo "$headers" | grep -qi "referrer-policy"; then
        print_status "PASS" "Referrer-Policy header present"
    else
        print_status "WARN" "Referrer-Policy header missing"
    fi
    
    if echo "$headers" | grep -qi "permissions-policy"; then
        print_status "PASS" "Permissions-Policy header present"
    else
        print_status "WARN" "Permissions-Policy header missing"
    fi
}

# Function to check SSL/TLS configuration
check_ssl_tls() {
    local domain=$1
    print_section "SSL/TLS Certificate Analysis"
    
    # Check if SSL is available
    if ! openssl s_client -connect "$domain:443" -servername "$domain" </dev/null 2>/dev/null | grep -q "CONNECTED"; then
        print_status "FAIL" "No SSL/TLS certificate found"
        print_recommendation "No SSL Certificate" \
            "All traffic is unencrypted and vulnerable to interception" \
            "Install an SSL certificate (free options: Let's Encrypt, Cloudflare)"
        return 1
    fi
    
    print_status "PASS" "SSL/TLS certificate is present"
    
    # Get certificate details
    local cert_info=$(openssl s_client -connect "$domain:443" -servername "$domain" </dev/null 2>/dev/null | openssl x509 -noout -dates -subject -issuer 2>/dev/null)
    
    # Check certificate expiry
    local expiry_date=$(echo "$cert_info" | grep "notAfter" | cut -d= -f2)
    if [ ! -z "$expiry_date" ]; then
        local expiry_epoch=$(date -d "$expiry_date" +%s 2>/dev/null)
        local current_epoch=$(date +%s)
        local days_left=$(( (expiry_epoch - current_epoch) / 86400 ))
        
        if [ $days_left -lt 0 ]; then
            print_status "FAIL" "SSL certificate has EXPIRED"
        elif [ $days_left -lt 30 ]; then
            print_status "WARN" "SSL certificate expires in $days_left days"
        else
            print_status "PASS" "SSL certificate valid for $days_left days"
        fi
    fi
    
    # Check certificate issuer
    local issuer=$(echo "$cert_info" | grep "issuer" | cut -d= -f2-)
    if [[ $issuer == *"Let's Encrypt"* ]]; then
        print_status "INFO" "Certificate issued by Let's Encrypt"
    elif [[ $issuer == *"Cloudflare"* ]]; then
        print_status "INFO" "Certificate issued by Cloudflare"
    else
        print_status "INFO" "Certificate issuer: $issuer"
    fi
    
    # Test SSL Labs grade (simplified check)
    local ssl_test=$(echo | openssl s_client -connect "$domain:443" -cipher 'ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS' 2>/dev/null)
    if echo "$ssl_test" | grep -q "Cipher.*AES.*GCM\|ChaCha20"; then
        print_status "PASS" "Strong cipher suites supported"
    else
        print_status "WARN" "Weak cipher suites may be supported"
    fi
}

# Function to check DNS configuration
check_dns_config() {
    local domain=$1
    print_section "DNS Configuration Analysis"
    
    # Check for common DNS records
    local mx_records=$(dig @$DNS_SERVER MX $domain +short)
    if [ ! -z "$mx_records" ]; then
        print_status "PASS" "MX records found"
        echo "$mx_records" | while read -r mx; do
            print_status "INFO" "Mail server: $mx"
        done
    else
        print_status "WARN" "No MX records found (no email capability)"
    fi
    
    # Check for CAA records
    local caa_records=$(dig @$DNS_SERVER CAA $domain +short)
    if [ ! -z "$caa_records" ]; then
        print_status "PASS" "CAA records found (certificate authority restrictions)"
    else
        print_status "WARN" "No CAA records (any CA can issue certificates)"
        print_recommendation "Missing CAA Records" \
            "Any Certificate Authority can issue certificates for your domain" \
            "Add CAA records to restrict which CAs can issue certificates"
    fi
    
    # Check for DNSSEC
    if dig @$DNS_SERVER $domain +dnssec +short | grep -q "RRSIG"; then
        print_status "PASS" "DNSSEC enabled"
    else
        print_status "WARN" "DNSSEC not enabled"
    fi
    
    # Check nameservers
    local ns_records=$(dig @$DNS_SERVER NS $domain +short)
    local ns_count=$(echo "$ns_records" | wc -l)
    if [ $ns_count -ge 2 ]; then
        print_status "PASS" "Multiple nameservers configured ($ns_count)"
    else
        print_status "WARN" "Only $ns_count nameserver configured (recommend 2+)"
    fi
}

# Function to check email security
check_email_security() {
    local domain=$1
    print_section "Email Security Configuration"
    
    # Check SPF
    local spf_record=$(dig @$DNS_SERVER TXT $domain +short | grep -i "v=spf1" | tr -d '"')
    if [ -z "$spf_record" ]; then
        print_status "FAIL" "No SPF record found"
        print_recommendation "Missing SPF Record" \
            "Anyone can spoof emails from your domain" \
            "Add TXT record: v=spf1 include:_spf.google.com ~all (adjust for your email provider)"
    else
        print_status "PASS" "SPF record found: $spf_record"
        
        if [[ $spf_record == *"~all"* ]]; then
            print_status "PASS" "SPF uses soft fail (~all)"
        elif [[ $spf_record == *"-all"* ]]; then
            print_status "PASS" "SPF uses hard fail (-all) - maximum security"
        elif [[ $spf_record == *"+all"* ]]; then
            print_status "FAIL" "SPF uses pass all (+all) - no protection"
        fi
    fi
    
    # Check DMARC
    local dmarc_record=$(dig @$DNS_SERVER TXT _dmarc.$domain +short | tr -d '"' | grep -i "v=DMARC1")
    if [ -z "$dmarc_record" ]; then
        print_status "FAIL" "No DMARC record found"
        print_recommendation "Missing DMARC Record" \
            "No policy for handling failed email authentication" \
            "Add TXT record at _dmarc.$domain: v=DMARC1; p=quarantine; rua=mailto:dmarc@$domain"
    else
        print_status "PASS" "DMARC record found: $dmarc_record"
        
        if [[ $dmarc_record == *"p=reject"* ]]; then
            print_status "PASS" "DMARC policy set to reject"
        elif [[ $dmarc_record == *"p=quarantine"* ]]; then
            print_status "PASS" "DMARC policy set to quarantine"
        elif [[ $dmarc_record == *"p=none"* ]]; then
            print_status "WARN" "DMARC policy set to none (monitoring only)"
        fi
    fi
    
    # Check common DKIM selectors
    local dkim_found=false
    for selector in default selector1 selector2 dkim google; do
        local dkim_record=$(dig @$DNS_SERVER TXT ${selector}._domainkey.$domain +short 2>/dev/null)
        if [ ! -z "$dkim_record" ]; then
            print_status "PASS" "DKIM record found for selector: $selector"
            dkim_found=true
            break
        fi
    done
    
    if [ "$dkim_found" = false ]; then
        print_status "WARN" "No DKIM records found (checked common selectors)"
    fi
}

# Function to check subdomain enumeration
check_subdomains() {
    local domain=$1
    print_section "Subdomain Discovery"
    
    local found_subdomains=0
    
    for subdomain in $COMMON_SUBDOMAINS; do
        if dig @$DNS_SERVER $subdomain.$domain +short | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' > /dev/null; then
            print_status "INFO" "Subdomain found: $subdomain.$domain"
            found_subdomains=$((found_subdomains + 1))
        fi
    done
    
    if [ $found_subdomains -eq 0 ]; then
        print_status "INFO" "No common subdomains found"
    else
        print_status "INFO" "Found $found_subdomains subdomains"
    fi
    
    # Check for wildcard DNS
    if dig @$DNS_SERVER "randomtest12345.$domain" +short | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' > /dev/null; then
        print_status "WARN" "Wildcard DNS detected - all subdomains resolve"
        print_recommendation "Wildcard DNS Configuration" \
            "All subdomains resolve, potentially exposing internal services" \
            "Remove wildcard DNS records and only create specific subdomain records"
    fi
}

# Function to check open ports
check_open_ports() {
    local domain=$1
    print_section "Open Ports Analysis"
    
    local ip=$(dig @$DNS_SERVER $domain +short | head -1)
    if [ -z "$ip" ]; then
        print_status "FAIL" "Cannot resolve domain to IP for port scanning"
        return 1
    fi
    
    print_status "INFO" "Scanning ports on $ip"
    local open_ports=""
    
    # Check common ports
    IFS=',' read -ra PORTS <<< "$COMMON_PORTS"
    for port in "${PORTS[@]}"; do
        if timeout 3 bash -c "echo >/dev/tcp/$ip/$port" 2>/dev/null; then
            open_ports="$open_ports $port"
            case $port in
                21) print_status "WARN" "FTP (port 21) is open - consider SFTP instead" ;;
                22) print_status "PASS" "SSH (port 22) is open" ;;
                23) print_status "FAIL" "Telnet (port 23) is open - highly insecure!" ;;
                25) print_status "INFO" "SMTP (port 25) is open" ;;
                53) print_status "INFO" "DNS (port 53) is open" ;;
                80) print_status "PASS" "HTTP (port 80) is open" ;;
                110) print_status "WARN" "POP3 (port 110) is open - consider secure alternatives" ;;
                143) print_status "WARN" "IMAP (port 143) is open - consider IMAPS (993)" ;;
                443) print_status "PASS" "HTTPS (port 443) is open" ;;
                993) print_status "PASS" "IMAPS (port 993) is open" ;;
                995) print_status "PASS" "POP3S (port 995) is open" ;;
                8080) print_status "WARN" "HTTP alternate (port 8080) is open" ;;
                8443) print_status "WARN" "HTTPS alternate (port 8443) is open" ;;
                *) print_status "INFO" "Port $port is open" ;;
            esac
        fi
    done
    
    if [ -z "$open_ports" ]; then
        print_status "INFO" "No common ports found open"
    fi
}

# Function to check for common vulnerabilities
check_vulnerabilities() {
    local domain=$1
    print_section "Common Vulnerability Checks"
    
    # Check for server information disclosure
    local server_header=$(curl -s --connect-timeout 10 -I "https://$domain" 2>/dev/null | grep -i "^server:" | cut -d: -f2- | tr -d ' \r\n')
    if [ ! -z "$server_header" ]; then
        print_status "WARN" "Server information disclosed: $server_header"
        print_recommendation "Server Information Disclosure" \
            "Server version information can help attackers find known vulnerabilities" \
            "Configure web server to hide version information"
    else
        print_status "PASS" "Server information not disclosed"
    fi
    
    # Check for common directories
    local common_dirs="admin backup config old test tmp"
    for dir in $common_dirs; do
        local response=$(curl -s --connect-timeout 5 -o /dev/null -w "%{http_code}" "https://$domain/$dir/")
        if [ "$response" = "200" ]; then
            print_status "WARN" "Potentially sensitive directory accessible: /$dir/"
        fi
    done
    
    # Check for common files
    local common_files="robots.txt sitemap.xml .htaccess phpinfo.php"
    for file in $common_files; do
        local response=$(curl -s --connect-timeout 5 -o /dev/null -w "%{http_code}" "https://$domain/$file")
        if [ "$response" = "200" ]; then
            case $file in
                "robots.txt") print_status "INFO" "robots.txt found (normal)" ;;
                "sitemap.xml") print_status "INFO" "sitemap.xml found (normal)" ;;
                ".htaccess") print_status "WARN" ".htaccess file accessible (may leak configuration)" ;;
                "phpinfo.php") print_status "FAIL" "phpinfo.php accessible (severe information disclosure)" ;;
            esac
        fi
    done
}

# Function to generate final summary
print_summary() {
    print_section "SECURITY AUDIT SUMMARY"
    
    local total_issues=$((FAILED_TESTS + WARNINGS))
    
    echo -e "${BOLD}Domain:${NC} $1"
    echo -e "${BOLD}Total Tests:${NC} $TOTAL_TESTS"
    echo -e "${GREEN}${BOLD}Passed:${NC} $PASSED_TESTS"
    echo -e "${RED}${BOLD}Failed:${NC} $FAILED_TESTS"
    echo -e "${YELLOW}${BOLD}Warnings:${NC} $WARNINGS"
    echo ""
    
    # Calculate security score
    local score=0
    if [ $TOTAL_TESTS -gt 0 ]; then
        score=$(( (PASSED_TESTS * 100) / TOTAL_TESTS ))
    fi
    
    echo -e "${BOLD}Security Score: $score/100${NC}"
    
    if [ $score -ge 80 ]; then
        echo -e "${GREEN}${BOLD}Overall Status: GOOD${NC}"
    elif [ $score -ge 60 ]; then
        echo -e "${YELLOW}${BOLD}Overall Status: NEEDS IMPROVEMENT${NC}"
    else
        echo -e "${RED}${BOLD}Overall Status: POOR - IMMEDIATE ACTION REQUIRED${NC}"
    fi
    
    echo ""
    echo -e "${PURPLE}${BOLD}PRIORITY ACTIONS:${NC}"
    if [ $FAILED_TESTS -gt 0 ]; then
        echo "1. Address all FAILED items immediately"
    fi
    if [ $WARNINGS -gt 0 ]; then
        echo "2. Review and fix WARNING items"
    fi
    echo "3. Implement missing security headers"
    echo "4. Enable DNSSEC if not already enabled"
    echo "5. Set up proper email authentication (SPF, DKIM, DMARC)"
    
    echo ""
    echo -e "${BLUE}For detailed security analysis, consider using additional tools:${NC}"
    echo "• SSL Labs SSL Test: https://www.ssllabs.com/ssltest/"
    echo "• Security Headers: https://securityheaders.io/"
    echo "• DMARC Analyzer: https://dmarc.org/dmarc-tools/"
}

# Main function
main() {
    if [ $# -eq 0 ]; then
        echo "Usage: $0 <domain>"
        echo "Example: $0 example.com"
        exit 1
    fi
    
    local domain=$1
    
    # Remove protocol if provided
    domain=$(echo $domain | sed 's|^https\?://||' | sed 's|/.*||')
    
    echo -e "${BOLD}${CYAN}Complete Domain Security Audit${NC}"
    echo -e "${BOLD}${CYAN}==============================${NC}"
    echo -e "${BOLD}Domain:${NC} $domain"
    echo -e "${BOLD}Date:${NC} $(date)"
    echo ""
    
    # Run all checks
    check_domain_exists "$domain"
    check_web_security "$domain"
    check_ssl_tls "$domain"
    check_dns_config "$domain"
    check_email_security "$domain"
    check_subdomains "$domain"
    check_open_ports "$domain"
    check_vulnerabilities "$domain"
    
    # Generate summary
    print_summary "$domain"
}

# Check dependencies
command -v dig >/dev/null 2>&1 || { echo "dig is required but not installed. Install bind-utils or dnsutils."; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "curl is required but not installed."; exit 1; }
command -v openssl >/dev/null 2>&1 || { echo "openssl is required but not installed."; exit 1; }

# Run main function
main "$@"