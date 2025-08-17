# Incident Response Playbook

## Overview
This playbook provides a structured approach to cybersecurity incident response using CyberKit's defensive tools and capabilities.

## Prerequisites
- CyberKit Docker container with defensive tools
- Network access to affected systems
- Proper incident response authorization
- Evidence collection capabilities

## Phase 1: Preparation

### 1.1 Incident Response Setup
```bash
# Create incident directory structure
./common/engagement-setup.sh -c "IR-Case" -e "$(date +%Y%m%d)-incident" -t defensive

# Set up evidence collection
mkdir -p /home/cyberkit/evidence/incident-$(date +%Y%m%d)/
mkdir -p /home/cyberkit/evidence/incident-$(date +%Y%m%d)/{network,host,malware,logs}
```

### 1.2 Tool Preparation
```bash
# Verify defensive tools availability
which tcpdump wireshark suricata
./defensive/opsec-config.sh --status

# Network monitoring setup
./defensive/wifi-defence.sh baseline -i eth0 -t 3600
```

## Phase 2: Identification

### 2.1 Initial Triage
```bash
# URL/domain reputation check
./defensive/url-scanner.sh --all-checks suspicious-domain.com

# IP reputation analysis (using Shodan/VirusTotal APIs)
./defensive/url-scanner.sh --passive --vt --shodan suspicious-ip

# File hash analysis
echo "suspicious_hash" | ./defensive/url-scanner.sh --hash-check
```

### 2.2 Network Analysis
```bash
# Network traffic capture
tcpdump -i eth0 -w /home/cyberkit/evidence/incident-$(date +%Y%m%d)/network/traffic-$(date +%H%M).pcap

# Real-time traffic monitoring
tcpdump -i eth0 host suspicious-ip -n -v

# DNS query analysis
tcpdump -i eth0 port 53 -v -n
```

### 2.3 Log Analysis
```bash
# System log examination
grep -i "error\|fail\|attack\|breach" /var/log/syslog > /home/cyberkit/evidence/incident-$(date +%Y%m%d)/logs/syslog-analysis.txt

# Authentication log review
grep -i "failed\|invalid\|break-in" /var/log/auth.log > /home/cyberkit/evidence/incident-$(date +%Y%m%d)/logs/auth-failures.txt

# Web server log analysis (if applicable)
grep -E "(40[0-9]|50[0-9])" /var/log/apache2/access.log | tail -100
```

## Phase 3: Containment

### 3.1 Network Containment
```bash
# Block suspicious IP addresses
iptables -A INPUT -s suspicious-ip -j DROP
iptables -A OUTPUT -d suspicious-ip -j DROP

# DNS sinkholing for malicious domains
echo "127.0.0.1 malicious-domain.com" >> /etc/hosts

# Network segmentation verification
./defensive/wifi-defence.sh defend -i eth0 -b suspicious-mac-address
```

### 3.2 Host-Based Containment
```bash
# Process analysis and termination
ps aux | grep suspicious-process
kill -9 suspicious-pid

# Network connection monitoring
netstat -tulpn | grep suspicious-port
ss -tulpn | grep suspicious-ip
```

### 3.3 User Account Security
```bash
# Disable compromised accounts
usermod -L compromised-user
passwd -l compromised-user

# Review active sessions
who -a
last | head -20
```

## Phase 4: Eradication

### 4.1 Malware Analysis
```bash
# File integrity checking
find /usr/bin /usr/sbin -type f -exec md5sum {} \; > system-hashes.txt

# Suspicious file identification
find / -name "*.exe" -o -name "*.scr" -o -name "*.bat" 2>/dev/null | head -50

# Hidden files discovery
find / -name ".*" -type f 2>/dev/null | grep -v "/proc\|/sys"
```

### 4.2 System Cleaning
```bash
# Remove malicious files (with evidence preservation)
cp malicious-file /home/cyberkit/evidence/incident-$(date +%Y%m%d)/malware/
rm malicious-file

# Clean temporary directories
find /tmp /var/tmp -type f -mtime -1 -exec ls -la {} \;
```

### 4.3 Vulnerability Patching
```bash
# System update verification
apt list --upgradable
yum check-update

# Security patch installation
apt update && apt upgrade -y
```

## Phase 5: Recovery

### 5.1 System Restoration
```bash
# Service restoration verification
systemctl status critical-service
systemctl restart critical-service

# Network connectivity testing
ping -c 4 8.8.8.8
nslookup google.com
```

### 5.2 Monitoring Setup
```bash
# Enhanced monitoring activation
./defensive/wifi-defence.sh monitor -i eth0 -m enterprise --threatintel

# Log monitoring configuration
tail -f /var/log/syslog | grep -i "suspicious\|attack\|breach"
```

## Phase 6: Lessons Learned

### 6.1 Incident Documentation
```bash
# Create incident timeline
echo "# Incident Response Timeline" > /home/cyberkit/reports/incident-timeline.md
echo "## Incident Details" >> /home/cyberkit/reports/incident-timeline.md
echo "Date: $(date)" >> /home/cyberkit/reports/incident-timeline.md
echo "Initial Detection: [TIME]" >> /home/cyberkit/reports/incident-timeline.md
echo "Containment: [TIME]" >> /home/cyberkit/reports/incident-timeline.md
echo "Eradication: [TIME]" >> /home/cyberkit/reports/incident-timeline.md
echo "Recovery: [TIME]" >> /home/cyberkit/reports/incident-timeline.md
```

### 6.2 Evidence Preservation
```bash
# Create forensic image (if required)
dd if=/dev/sda of=/home/cyberkit/evidence/incident-$(date +%Y%m%d)/disk-image.img bs=4M status=progress

# Hash all evidence files
find /home/cyberkit/evidence/incident-$(date +%Y%m%d)/ -type f -exec sha256sum {} \; > evidence-hashes.txt
```

## Threat Intelligence Collection

### IOC Extraction
```bash
# Extract IP addresses from logs
grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" suspicious-log.txt | sort -u > extracted-ips.txt

# Extract domain names
grep -oE "\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b" suspicious-log.txt | sort -u > extracted-domains.txt

# Extract file hashes
grep -oE "\b[a-f0-9]{32,64}\b" malware-analysis.txt > extracted-hashes.txt
```

### Threat Intelligence Enrichment
```bash
# Check extracted IOCs
for ip in $(cat extracted-ips.txt); do
    ./defensive/url-scanner.sh --passive --vt $ip
done

for domain in $(cat extracted-domains.txt); do
    ./defensive/url-scanner.sh --all-checks $domain
done
```

## Communication Templates

### 6.3 Incident Notification
```bash
# Create incident notification template
cat > incident-notification.txt << EOF
SECURITY INCIDENT NOTIFICATION

Incident ID: IR-$(date +%Y%m%d-%H%M)
Detection Time: $(date)
Severity: [HIGH/MEDIUM/LOW]
Affected Systems: [LIST]
Initial Impact Assessment: [DESCRIPTION]
Current Status: [INVESTIGATION/CONTAINED/RESOLVED]
Next Update: [TIME]

Contact: [IR TEAM CONTACT]
EOF
```

## Automated Response Workflows

### 6.4 Automated Containment
```bash
# Create automated response script
cat > auto-response.sh << 'EOF'
#!/bin/bash
# Automated incident response actions

SUSPICIOUS_IP=$1
LOGFILE="/home/cyberkit/logs/auto-response-$(date +%Y%m%d).log"

echo "$(date): Starting automated response for $SUSPICIOUS_IP" >> $LOGFILE

# Block IP
iptables -A INPUT -s $SUSPICIOUS_IP -j DROP
echo "$(date): Blocked IP $SUSPICIOUS_IP" >> $LOGFILE

# Log network connections
netstat -tulpn | grep $SUSPICIOUS_IP >> $LOGFILE

# Send notification
echo "Suspicious IP $SUSPICIOUS_IP has been automatically blocked" | mail -s "Security Alert" admin@company.com

echo "$(date): Automated response completed" >> $LOGFILE
EOF

chmod +x auto-response.sh
```

## Tools Used
- **tcpdump/wireshark** - Network traffic analysis
- **iptables** - Network access control
- **netstat/ss** - Network connection monitoring
- **grep/awk/sed** - Log analysis
- **find** - File system analysis
- **CyberKit url-scanner** - Threat intelligence
- **CyberKit wifi-defence** - Network monitoring

## Evidence Chain of Custody

### Documentation Requirements
1. **Who** collected the evidence
2. **What** was collected
3. **When** it was collected
4. **Where** it was found
5. **Why** it was collected
6. **How** it was collected

### Evidence Handling
```bash
# Evidence documentation template
cat > evidence-log.txt << EOF
DIGITAL EVIDENCE LOG

Case Number: IR-$(date +%Y%m%d)
Evidence Item: [DESCRIPTION]
Collection Date/Time: $(date)
Collected By: [NAME]
Source System: [HOSTNAME/IP]
File Path: [ORIGINAL LOCATION]
Hash (SHA256): [HASH VALUE]
Storage Location: [CURRENT LOCATION]
Chain of Custody: [HANDLER NAMES/DATES]
EOF
```

## Legal Considerations

### 6.5 Legal Hold Procedures
- Preserve all relevant digital evidence
- Document chain of custody
- Coordinate with legal counsel
- Follow data retention policies
- Prepare for potential litigation

### 6.6 Regulatory Compliance
- GDPR notification requirements (72 hours)
- HIPAA breach notification (60 days)
- PCI DSS incident response procedures
- SOX compliance documentation
- Industry-specific requirements

## Post-Incident Activities

### 6.7 Forensic Analysis
```bash
# Detailed forensic examination
file suspicious-binary
strings suspicious-binary | grep -i "http\|ip\|domain"
hexdump -C suspicious-binary | head -20
```

### 6.8 Threat Hunting
```bash
# Proactive threat hunting based on incident IOCs
grep -r "known-malicious-string" /var/log/
find / -name "*malicious-filename*" 2>/dev/null
```

## Best Practices
1. **Speed vs. Accuracy**: Balance quick response with thorough investigation
2. **Evidence Preservation**: Always preserve before analyze
3. **Communication**: Keep stakeholders informed regularly
4. **Documentation**: Record everything with timestamps
5. **Legal Compliance**: Follow all applicable regulations
6. **Continuous Improvement**: Update procedures based on lessons learned

## Common Incident Types
- **Malware Infections**: Ransomware, trojans, worms
- **Data Breaches**: Unauthorized data access/exfiltration
- **Phishing Attacks**: Email-based social engineering
- **DDoS Attacks**: Distributed denial of service
- **Insider Threats**: Malicious or negligent employees
- **Advanced Persistent Threats (APT)**: Sophisticated long-term attacks