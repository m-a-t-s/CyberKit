#!/bin/bash
# opsec-config.sh - Operational Security Configuration Script
# ==========================================================
# This script helps configure operational security measures for
# red team operations, ensuring proper protection and monitoring.

# Source common utilities and configuration
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$SCRIPT_DIR/../common/utils.sh"
source "$SCRIPT_DIR/../common/config.sh"

# Display banner
print_banner "Operational Security Configuration"

# Security levels and their configurations
declare -A SECURITY_CONFIGS
SECURITY_CONFIGS=(
    ["low"]="Basic security measures for low-risk engagements"
    ["medium"]="Enhanced security for standard engagements"
    ["high"]="Maximum security for high-risk/sensitive engagements"
)

# Function to check prerequisites
check_prerequisites() {
    log "INFO" "Checking prerequisites..."
    
    local tools=("iptables" "tor" "proxychains" "macchanger" "wireshark" "tcpdump")
    local missing=()
    
    for tool in "${tools[@]}"; do
        if ! check_tool "$tool"; then
            missing+=("$tool")
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        log "WARNING" "Some recommended tools are missing: ${missing[*]}"
        read -p "Continue anyway? (y/n): " continue_anyway
        if [[ ! $continue_anyway =~ ^[Yy]$ ]]; then
            log "ERROR" "Exiting due to missing dependencies."
            exit 1
        fi
    else
        log "SUCCESS" "All recommended tools are installed."
    fi
    
    # Check if running as root
    if ! check_root; then
        log "WARNING" "Some operations require root privileges."
        read -p "Continue without root privileges? (y/n): " continue_anyway
        if [[ ! $continue_anyway =~ ^[Yy]$ ]]; then
            log "ERROR" "Please run this script as root or with sudo."
            exit 1
        fi
    fi
}

# Function to parse command line arguments
parse_arguments() {
    SECURITY_LEVEL="medium" # Default level
    OUTPUT_DIR="$HOME/opsec-configs"
    INTERFACE=""
    
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -l|--level)
                if [[ "$2" == "low" || "$2" == "medium" || "$2" == "high" ]]; then
                    SECURITY_LEVEL="$2"
                    shift 2
                else
                    log "ERROR" "Invalid security level: $2"
                    echo "Valid levels: low, medium, high"
                    exit 1
                fi
                ;;
            -o|--output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -i|--interface)
                INTERFACE="$2"
                shift 2
                ;;
            -h|--help)
                echo "Usage: $0 [options]"
                echo ""
                echo "Options:"
                echo "  -l, --level LEVEL      Set security level (low, medium, high) [default: medium]"
                echo "  -o, --output DIR       Set output directory for configs [default: $HOME/opsec-configs]"
                echo "  -i, --interface IFACE  Specify network interface to configure"
                echo "  -h, --help             Show this help message"
                echo ""
                echo "Description:"
                echo "  This script helps configure operational security measures for"
                echo "  red team operations, ensuring proper protection and monitoring."
                exit 0
                ;;
            *)
                log "ERROR" "Unknown option: $1"
                echo "Use -h or --help for usage information"
                exit 1
                ;;
        esac
    done
    
    # If no interface was provided, try to detect the primary one
    if [ -z "$INTERFACE" ]; then
        INTERFACE=$(ip -o -4 route show to default | awk '{print $5}' | head -1)
        if [ -z "$INTERFACE" ]; then
            log "ERROR" "Could not detect primary network interface."
            log "ERROR" "Please specify an interface with -i or --interface."
            exit 1
        fi
        log "WARNING" "No interface specified, using detected interface: $INTERFACE"
    fi
    
    # Ensure output directory exists
    ensure_dir "$OUTPUT_DIR"
}

# Function to backup current network configuration
backup_network_config() {
    local backup_dir="$OUTPUT_DIR/backups/$(date +%Y%m%d-%H%M%S)"
    ensure_dir "$backup_dir"
    
    log "INFO" "Backing up current network configuration to $backup_dir..."
    
    # Backup network interfaces
    ip addr show > "$backup_dir/ip-addr.txt"
    ip route show > "$backup_dir/ip-route.txt"
    
    # Backup DNS configuration
    if [ -f /etc/resolv.conf ]; then
        cp /etc/resolv.conf "$backup_dir/"
    fi
    
    # Backup iptables rules
    if check_tool "iptables-save"; then
        iptables-save > "$backup_dir/iptables-rules.txt"
    fi
    
    # Backup hosts file
    if [ -f /etc/hosts ]; then
        cp /etc/hosts "$backup_dir/"
    fi
    
    # Create a restore script
    cat > "$backup_dir/restore.sh" << 'EOF'
#!/bin/bash
# Restore network configuration from backup

BACKUP_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

echo "Restoring network configuration from backup at $BACKUP_DIR..."

# Restore iptables rules if backup exists
if [ -f "$BACKUP_DIR/iptables-rules.txt" ]; then
    echo "Restoring iptables rules..."
    iptables-restore < "$BACKUP_DIR/iptables-rules.txt"
fi

# Restore DNS configuration if backup exists
if [ -f "$BACKUP_DIR/resolv.conf" ]; then
    echo "Restoring DNS configuration..."
    cp "$BACKUP_DIR/resolv.conf" /etc/resolv.conf
fi

# Restore hosts file if backup exists
if [ -f "$BACKUP_DIR/hosts" ]; then
    echo "Restoring hosts file..."
    cp "$BACKUP_DIR/hosts" /etc/hosts
fi

echo "Network configuration restored. You may need to restart networking services."
EOF
    
    chmod +x "$backup_dir/restore.sh"
    
    log "SUCCESS" "Network configuration backed up successfully."
    log "INFO" "You can restore this configuration using: $backup_dir/restore.sh"
}

# Configure network anonymization based on security level
configure_network_anonymization() {
    log "INFO" "Configuring network anonymization (Level: $SECURITY_LEVEL)..."
    
    local config_dir="$OUTPUT_DIR/network"
    ensure_dir "$config_dir"
    
    # Create base configuration script
    local config_script="$config_dir/network-anonymize.sh"
    
    cat > "$config_script" << EOF
#!/bin/bash
# Network Anonymization Script - Security Level: $SECURITY_LEVEL
# Generated on $(date)

# Check if running as root
if [ "\$EUID" -ne 0 ]; then
    echo "This script must be run as root"
    exit 1
fi

# Define network interface
INTERFACE="$INTERFACE"
echo "Configuring network interface: \$INTERFACE"

# Backup current MAC address
CURRENT_MAC=\$(ip link show \$INTERFACE | grep link/ether | awk '{print \$2}')
echo "Current MAC address: \$CURRENT_MAC"

# Disable network interface
echo "Disabling network interface \$INTERFACE..."
ip link set \$INTERFACE down

# Change MAC address (if security level is medium or high)
if [[ "$SECURITY_LEVEL" != "low" ]]; then
    echo "Changing MAC address..."
    macchanger -r \$INTERFACE
fi

# Re-enable network interface
echo "Enabling network interface \$INTERFACE..."
ip link set \$INTERFACE up

# Configure firewall rules
echo "Configuring iptables firewall rules..."

# Flush existing rules
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

# Set default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT $([ "$SECURITY_LEVEL" == "high" ] && echo "DROP" || echo "ACCEPT")

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow established connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow DNS (if not high security)
if [[ "$SECURITY_LEVEL" != "high" ]]; then
    iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT
fi

# Allow common ports (if low security)
if [[ "$SECURITY_LEVEL" == "low" ]]; then
    # HTTP/HTTPS
    iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT
    # SSH
    iptables -A OUTPUT -p tcp --dport 22 -j ACCEPT
fi

# Configure Tor routing (if medium or high security)
if [[ "$SECURITY_LEVEL" != "low" ]]; then
    # Allow Tor ports
    iptables -A OUTPUT -p tcp --dport 9050 -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 9051 -j ACCEPT
    
    # Start Tor service
    systemctl start tor.service
    
    if [[ "$SECURITY_LEVEL" == "high" ]]; then
        # In high security, route everything through Tor
        # Create user for transparent proxying
        iptables -t nat -A OUTPUT -m owner --uid-owner debian-tor -j RETURN
        iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-ports 53
        iptables -t nat -A OUTPUT -p tcp --syn -j REDIRECT --to-ports 9040
        iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
        iptables -A OUTPUT -j DROP
    fi
fi

echo "Network anonymization complete."
EOF
    
    chmod +x "$config_script"
    
    # Create proxychains configuration
    local proxychains_config="$config_dir/proxychains.conf"
    
    cat > "$proxychains_config" << EOF
# ProxyChains configuration - Security Level: $SECURITY_LEVEL
# Generated on $(date)
#
# This configuration routes your traffic through multiple proxies for anonymization

# Default settings
random_chain
quiet_mode
proxy_dns
remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
# Tor SOCKS5 proxy
socks5 127.0.0.1 9050
EOF
    
    # Add additional proxies for medium/high security
    if [[ "$SECURITY_LEVEL" != "low" ]]; then
        cat >> "$proxychains_config" << EOF
# Additional proxies can be added here
# Example: socks4 proxy-server.example.com 1080
EOF
    fi
    
    # For high security, add multiple proxy chains
    if [[ "$SECURITY_LEVEL" == "high" ]]; then
        cat > "$config_dir/multi-proxy.sh" << 'EOF'
#!/bin/bash
# Multi-proxy setup for high security operations
# This script helps set up a chain of proxies through SSH tunnels

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "This script must be run as root"
    exit 1
fi

# Start Tor service
systemctl start tor.service

# Create SSH tunnels (these are examples, replace with your actual servers)
# You need to have properly configured SSH keys for passwordless authentication
echo "Setting up SSH tunnels..."

# First hop - Local to Server 1
ssh -f -N -D 8080 user@server1.example.com -i ~/.ssh/jump_server_key

# Second hop - Through Server 1 to Server 2
ssh -f -N -D 8081 -o "ProxyCommand nc -X 5 -x localhost:8080 %h %p" user@server2.example.com -i ~/.ssh/jump_server_key

# Configure proxychains to use all tunnels
cat > /etc/proxychains.conf << 'INNEREOF'
# Multi-hop ProxyChains configuration
random_chain
quiet_mode
proxy_dns
remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
# Local SSH tunnels
socks5 127.0.0.1 8081
socks5 127.0.0.1 8080
# Tor as the final hop
socks5 127.0.0.1 9050
INNEREOF

echo "Multi-proxy setup complete. Use 'proxychains' to route traffic through the proxy chain."
EOF
        
        chmod +x "$config_dir/multi-proxy.sh"
    fi
    
    log "SUCCESS" "Network anonymization configurations created successfully."
}

# Configure system security hardening
configure_system_hardening() {
    log "INFO" "Configuring system security hardening (Level: $SECURITY_LEVEL)..."
    
    local config_dir="$OUTPUT_DIR/system"
    ensure_dir "$config_dir"
    
    # Create system hardening script
    local hardening_script="$config_dir/system-harden.sh"
    
    cat > "$hardening_script" << EOF
#!/bin/bash
# System Hardening Script - Security Level: $SECURITY_LEVEL
# Generated on $(date)

# Check if running as root
if [ "\$EUID" -ne 0 ]; then
    echo "This script must be run as root"
    exit 1
fi

echo "Starting system hardening process..."

# Disable unnecessary services
echo "Disabling unnecessary services..."
SERVICES_TO_DISABLE=(
    "avahi-daemon"
    "cups"
    "bluetooth"
)

for service in "\${SERVICES_TO_DISABLE[@]}"; do
    if systemctl is-active --quiet "\$service"; then
        systemctl stop "\$service"
        systemctl disable "\$service"
        echo "  - Disabled \$service"
    fi
done

# Secure SSH configuration
echo "Securing SSH configuration..."
if [ -f /etc/ssh/sshd_config ]; then
    # Backup original config
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
    
    # Apply secure settings
    sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    sed -i 's/#X11Forwarding yes/X11Forwarding no/' /etc/ssh/sshd_config
    sed -i 's/#LogLevel INFO/LogLevel VERBOSE/' /etc/ssh/sshd_config
    
    # Additional settings for medium/high security
    if [[ "$SECURITY_LEVEL" != "low" ]]; then
        # Use only strong crypto
        echo "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr" >> /etc/ssh/sshd_config
        echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com" >> /etc/ssh/sshd_config
        echo "KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256" >> /etc/ssh/sshd_config
    fi
    
    # Restart SSH service
    systemctl restart sshd
fi

# Secure sysctl settings
echo "Applying secure kernel parameters..."
cat > /etc/sysctl.d/99-security.conf << 'INNEREOF'
# IP Spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP broadcast requests
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Ignore send redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Block SYN attacks
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# Log Martians
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Disable IPv6 if not used
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
INNEREOF

# Apply sysctl settings
sysctl -p /etc/sysctl.d/99-security.conf

# Set up auditd (for medium/high security)
if [[ "$SECURITY_LEVEL" != "low" ]]; then
    echo "Setting up audit daemon..."
    if ! command -v auditd &> /dev/null; then
        apt-get update && apt-get install -y auditd audispd-plugins
    fi
    
    # Configure basic audit rules
    cat > /etc/audit/rules.d/audit.rules << 'INNEREOF'
# Delete all existing rules
-D

# Set buffer size
-b 8192

# Monitor for changes to system files
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k actions
-w /etc/sudoers.d/ -p wa -k actions

# Monitor for unsuccessful login attempts
-w /var/log/auth.log -p wa -k auth
-w /var/log/faillog -p wa -k auth

# Monitor for unsuccessful authorization attempts
-a always,exit -F arch=b64 -S open -F exit=-EACCES -k access
-a always,exit -F arch=b32 -S open -F exit=-EACCES -k access
-a always,exit -F arch=b64 -S open -F exit=-EPERM -k access
-a always,exit -F arch=b32 -S open -F exit=-EPERM -k access

# Monitor for use of privileged commands
-a always,exit -F path=/usr/bin/sudo -F perm=x -k privileged
-a always,exit -F path=/usr/bin/su -F perm=x -k privileged
-a always,exit -F path=/usr/bin/newgrp -F perm=x -k privileged
-a always,exit -F path=/usr/bin/chsh -F perm=x -k privileged
-a always,exit -F path=/usr/bin/chfn -F perm=x -k privileged

# Limit events based on system activity
-a never,user -F subj_type=unconfined_t
-a never,exit -F arch=b64 -S fork -F success=1 -F exe=/usr/lib/firefox/firefox
-a never,exit -F arch=b64 -S connect -F success=1 -F exe=/usr/lib/firefox/firefox
INNEREOF

    # Restart audit daemon
    systemctl restart auditd
fi

# Configure memory protection (for high security)
if [[ "$SECURITY_LEVEL" == "high" ]]; then
    echo "Configuring memory protection..."
    
    # Enable ASLR
    echo 2 > /proc/sys/kernel/randomize_va_space
    
    # Disable core dumps
    echo "* hard core 0" >> /etc/security/limits.conf
    echo "ProcessSizeMax=0" >> /etc/systemd/system.conf
    echo "Storage=none" >> /etc/systemd/coredump.conf
    
    # Setup fail2ban if available
    if command -v fail2ban-client &> /dev/null; then
        echo "Configuring fail2ban..."
        cat > /etc/fail2ban/jail.local << 'INNEREOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 86400
INNEREOF

        systemctl restart fail2ban
    fi
fi

echo "System hardening complete."
EOF
    
    chmod +x "$hardening_script"
    
    log "SUCCESS" "System hardening configuration created successfully."
}

# Configure monitoring and logging
configure_monitoring() {
    log "INFO" "Configuring monitoring and logging (Level: $SECURITY_LEVEL)..."
    
    local config_dir="$OUTPUT_DIR/monitoring"
    ensure_dir "$config_dir"
    
    # Create monitoring script
    local monitoring_script="$config_dir/setup-monitoring.sh"
    
    cat > "$monitoring_script" << EOF
#!/bin/bash
# Monitoring and Logging Setup - Security Level: $SECURITY_LEVEL
# Generated on $(date)

# Check if running as root
if [ "\$EUID" -ne 0 ]; then
    echo "This script must be run as root"
    exit 1
fi

echo "Setting up monitoring and logging..."

# Configure centralized logging
LOG_DIR="/var/log/security"
mkdir -p "\$LOG_DIR"
chmod 750 "\$LOG_DIR"

# Set up log rotation
cat > /etc/logrotate.d/security << 'INNEREOF'
/var/log/security/*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    create 0640 root adm
    sharedscripts
    postrotate
        systemctl restart rsyslog >/dev/null 2>&1 || true
    endscript
}
INNEREOF

# Configure rsyslog for security events
cat > /etc/rsyslog.d/30-security.conf << 'INNEREOF'
# Security logging
auth,authpriv.*                 /var/log/security/auth.log
kern.warning                    /var/log/security/kernel.log
daemon.notice                   /var/log/security/daemon.log
*.emerg                         /var/log/security/emergency.log
INNEREOF

# Set up network traffic monitoring
echo "Setting up network traffic monitoring..."

# Create network monitoring script
cat > "$config_dir/network-monitor.sh" << 'INNEREOF'
#!/bin/bash
# Network Traffic Monitoring Script

INTERFACE="$INTERFACE"
LOG_DIR="/var/log/security"

# Create tcpdump capture script
mkdir -p "$LOG_DIR/pcap"

# Start tcpdump in background with rotation
nohup tcpdump -i $INTERFACE -G 3600 -w "$LOG_DIR/pcap/capture-%Y%m%d-%H%M%S.pcap" -z gzip 'not port 22' &
echo "Tcpdump started with hourly rotation. PID: $!"

# Start basic traffic stats collection
while true; do
    DATE=$(date +"%Y-%m-%d %H:%M:%S")
    echo "=== Network Stats $DATE ===" >> "$LOG_DIR/network-stats.log"
    echo "-- Connection Summary --" >> "$LOG_DIR/network-stats.log"
    ss -tuplan | grep ESTAB | awk '{print $1,$5,$6}' | sort | uniq -c | sort -nr >> "$LOG_DIR/network-stats.log"
    echo "-- Interface Statistics --" >> "$LOG_DIR/network-stats.log"
    ip -s link show $INTERFACE >> "$LOG_DIR/network-stats.log"
    echo "" >> "$LOG_DIR/network-stats.log"
    sleep 300
done
INNEREOF

chmod +x "$config_dir/network-monitor.sh"

# Restart rsyslog
systemctl restart rsyslog

# Create monitoring dashboard script (if security level is medium or high)
if [[ "$SECURITY_LEVEL" != "low" ]]; then
    echo "Setting up monitoring dashboard..."
    
    cat > "$config_dir/dashboard.sh" << 'INNEREOF'
#!/bin/bash
# Security Monitoring Dashboard

# Function to show current connections
show_connections() {
    echo "==== Current Connections ===="
    ss -tuplan | grep ESTAB | awk '{print $1,$5,$6}' | sort | uniq -c | sort -nr | head -10
    echo ""
}

# Function to show authentication attempts
show_auth_attempts() {
    echo "==== Recent Authentication Attempts ===="
    grep -i "authentication failure\|failed password" /var/log/auth.log | tail -10
    echo ""
}

# Function to show system load
show_system_load() {
    echo "==== System Resources ===="
    uptime
    echo ""
    free -h
    echo ""
    df -h | grep -v tmpfs
    echo ""
}

# Function to show firewall status
show_firewall() {
    echo "==== Firewall Rules ===="
    iptables -L -v --line-numbers | head -20
    echo "(showing first 20 rules only)"
    echo ""
}

# Function to show unsuccessful login attempts
show_failed_logins() {
    echo "==== Failed Login Attempts (last 24h) ===="
    if [ -f /var/log/auth.log ]; then
        grep -i "failed\|invalid\|error" /var/log/auth.log | grep -i "login\|authentication\|password" | grep "$(date -d '24 hours ago' +'%b %d')\|$(date +'%b %d')" | tail -10
    else
        echo "No auth.log found"
    fi
    echo ""
}

# Main dashboard loop
clear
while true; do
    echo "==============================================="
    echo "Security Monitoring Dashboard - $(date)"
    echo "==============================================="
    echo ""
    
    show_system_load
    show_connections
    show_failed_logins
    show_firewall
    
    echo "Dashboard will refresh in 60 seconds. Press Ctrl+C to exit."
    sleep 60
    clear
done
INNEREOF

    chmod +x "$config_dir/dashboard.sh"
fi

# For high security level, add additional monitoring tools
if [[ "$SECURITY_LEVEL" == "high" ]]; then
    # Setup process monitoring
    cat > "$config_dir/process-monitor.sh" << 'INNEREOF'
#!/bin/bash
# Process Monitoring for High Security Operations

LOG_DIR="/var/log/security"
BASELINE_FILE="$LOG_DIR/process-baseline.txt"
ALERT_FILE="$LOG_DIR/process-alerts.log"

# Create baseline if it doesn't exist
if [ ! -f "$BASELINE_FILE" ]; then
    echo "Creating process baseline..."
    ps -eo pid,ppid,user,cmd --sort=pid > "$BASELINE_FILE"
    echo "Baseline created at $(date)" >> "$BASELINE_FILE"
else
    echo "Using existing baseline from $(grep "Baseline created" "$BASELINE_FILE" | tail -1)"
fi

# Monitor for new processes
while true; do
    CURRENT_PROCESSES=$(mktemp)
    ps -eo pid,ppid,user,cmd --sort=pid > "$CURRENT_PROCESSES"
    
    # Compare with baseline and log differences
    echo "=== Process Changes $(date) ===" >> "$ALERT_FILE"
    diff "$BASELINE_FILE" "$CURRENT_PROCESSES" | grep -E "^>" | sed 's/^> //' >> "$ALERT_FILE"
    
    # Clean up
    rm "$CURRENT_PROCESSES"
    
    # Wait before next check
    sleep 60
done
INNEREOF

    chmod +x "$config_dir/process-monitor.sh"
    
    # Setup file integrity monitoring
    cat > "$config_dir/file-integrity.sh" << 'INNEREOF'
#!/bin/bash
# File Integrity Monitoring

LOG_DIR="/var/log/security"
HASH_DB="$LOG_DIR/file-hashes.db"
ALERT_FILE="$LOG_DIR/file-integrity-alerts.log"

# Directories to monitor
MONITOR_DIRS=(
    "/bin"
    "/sbin"
    "/usr/bin"
    "/usr/sbin"
    "/etc"
)

# Create hash database if it doesn't exist
if [ ! -f "$HASH_DB" ]; then
    echo "Creating file hash database..."
    for dir in "${MONITOR_DIRS[@]}"; do
        find "$dir" -type f -exec sha256sum {} \; >> "$HASH_DB"
    done
    echo "Hash database created at $(date)" >> "$HASH_DB"
else
    echo "Using existing hash database from $(grep "Hash database created" "$HASH_DB" | tail -1)"
fi

# Check file integrity
while true; do
    echo "=== File Integrity Check $(date) ===" >> "$ALERT_FILE"
    
    for dir in "${MONITOR_DIRS[@]}"; do
        find "$dir" -type f -exec sha256sum {} \; | while read -r line; do
            HASH=$(echo "$line" | awk '{print $1}')
            FILE=$(echo "$line" | awk '{$1=""; print $0}' | sed 's/^ //')
            
            # Check if file exists in database
            if grep -q "$FILE" "$HASH_DB"; then
                # Check if hash matches
                OLD_HASH=$(grep "$FILE" "$HASH_DB" | awk '{print $1}')
                if [ "$HASH" != "$OLD_HASH" ]; then
                    echo "ALERT: File changed: $FILE" >> "$ALERT_FILE"
                    echo "  Old hash: $OLD_HASH" >> "$ALERT_FILE"
                    echo "  New hash: $HASH" >> "$ALERT_FILE"
                fi
            else
                echo "ALERT: New file detected: $FILE" >> "$ALERT_FILE"
            fi
        done
    done
    
    # Wait before next check (default: 6 hours)
    sleep 21600
done
INNEREOF

    chmod +x "$config_dir/file-integrity.sh"
fi

echo "Monitoring and logging setup complete."
EOF
    
    chmod +x "$monitoring_script"
    
    log "SUCCESS" "Monitoring and logging configuration created successfully."
}

# Generate documentation
generate_documentation() {
    log "INFO" "Generating documentation..."
    
    local doc_file="$OUTPUT_DIR/README.md"
    
    cat > "$doc_file" << EOF
# Operational Security Configuration

## Overview
This directory contains operational security configurations and scripts generated for security level: **$SECURITY_LEVEL**.

## Generated on
$(date)

## Configuration Files

### Network Anonymization
- **network/network-anonymize.sh**: Script to configure network anonymization
- **network/proxychains.conf**: ProxyChains configuration for traffic routing

### System Hardening
- **system/system-harden.sh**: Script to harden system security settings

### Monitoring
- **monitoring/setup-monitoring.sh**: Script to set up security monitoring
- **monitoring/network-monitor.sh**: Network traffic monitoring script
EOF
    
    # Add additional documentation for medium/high security
    if [[ "$SECURITY_LEVEL" != "low" ]]; then
        cat >> "$doc_file" << EOF
- **monitoring/dashboard.sh**: Real-time security monitoring dashboard
EOF
    fi
    
    # Add additional documentation for high security
    if [[ "$SECURITY_LEVEL" == "high" ]]; then
        cat >> "$doc_file" << EOF
- **monitoring/process-monitor.sh**: Process monitoring and alerting
- **monitoring/file-integrity.sh**: File integrity monitoring
- **network/multi-proxy.sh**: Multi-hop proxy configuration
EOF
    fi
    
    cat >> "$doc_file" << EOF

## Usage Instructions

1. Review each script before running it to ensure it meets your specific needs
2. Execute scripts with root privileges:
   \`\`\`
   sudo ./network/network-anonymize.sh
   sudo ./system/system-harden.sh
   sudo ./monitoring/setup-monitoring.sh
   \`\`\`
3. If you need to restore original network settings, use the backup:
   \`\`\`
   sudo ./backups/YYYYMMDD-HHMMSS/restore.sh
   \`\`\`

## Security Notes

- **Security Level**: $SECURITY_LEVEL
- **Network Interface**: $INTERFACE
- **Backup Location**: $OUTPUT_DIR/backups

### Key Security Features

EOF
    
    # Add security features based on level
    case "$SECURITY_LEVEL" in
        "low")
            cat >> "$doc_file" << EOF
- Basic firewall rules
- System service hardening
- Simple network monitoring
- Limited logging configuration
EOF
            ;;
        "medium")
            cat >> "$doc_file" << EOF
- MAC address randomization
- Tor proxying for selected traffic
- Enhanced firewall rules
- System hardening with audit capabilities
- Comprehensive logging and monitoring
- Security dashboard for real-time monitoring
EOF
            ;;
        "high")
            cat >> "$doc_file" << EOF
- Full traffic anonymization through Tor
- Multi-hop proxy configuration
- Advanced system hardening
- Memory protection enhancements
- Process monitoring and alerting
- File integrity monitoring
- Comprehensive audit rules
- Advanced intrusion detection
EOF
            ;;
    esac
    
    log "SUCCESS" "Documentation generated successfully at $doc_file"
}

# Main function
main() {
    # Display banner
    print_banner "Operational Security Configuration"
    
    # Parse command line arguments
    parse_arguments "$@"
    
    # Check prerequisites
    check_prerequisites
    
    # Backup current configuration
    backup_network_config
    
    # Configure network anonymization
    configure_network_anonymization
    
    # Configure system hardening
    configure_system_hardening
    
    # Configure monitoring and logging
    configure_monitoring
    
    # Generate documentation
    generate_documentation
    
    # Display completion message
    log "SUCCESS" "Operational security configuration complete!"
    log "INFO" "Configuration files are located at: $OUTPUT_DIR"
    log "INFO" "Review README.md for usage instructions."
    
    # Display key scripts to run
    echo ""
    echo "Key scripts to run:"
    echo "1. Network anonymization: ${YELLOW}sudo $OUTPUT_DIR/network/network-anonymize.sh${RESET}"
    echo "2. System hardening: ${YELLOW}sudo $OUTPUT_DIR/system/system-harden.sh${RESET}"
    echo "3. Monitoring setup: ${YELLOW}sudo $OUTPUT_DIR/monitoring/setup-monitoring.sh${RESET}"
    
    # Additional instructions for medium/high security
    if [[ "$SECURITY_LEVEL" != "low" ]]; then
        echo "4. Security dashboard: ${YELLOW}sudo $OUTPUT_DIR/monitoring/dashboard.sh${RESET}"
    fi
    
    # Additional instructions for high security
    if [[ "$SECURITY_LEVEL" == "high" ]]; then
        echo "5. Multi-proxy setup: ${YELLOW}sudo $OUTPUT_DIR/network/multi-proxy.sh${RESET}"
        echo "6. Process monitoring: ${YELLOW}sudo $OUTPUT_DIR/monitoring/process-monitor.sh${RESET}"
        echo "7. File integrity: ${YELLOW}sudo $OUTPUT_DIR/monitoring/file-integrity.sh${RESET}"
    fi
}

# Execute main if script is run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi