# CyberKit - Cybersecurity Offensive & Defensive Toolkit

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A comprehensive, modular toolkit for cybersecurity professionals that automates both offensive and defensive security operations. CyberKit provides command-line utilities that streamline engagements from initial setup through reporting.

## Overview

CyberKit is divided into two main components:

- **OffensiveKit**: Tools for red team operations, penetration testing, and offensive security
- **DefensiveKit**: Tools for blue team operations, security monitoring, and defensive measures

## Features

### Offensive Capabilities
- Automated engagement setup and directory structure creation
- Comprehensive reconnaissance workflows
- Vulnerability scanning and assessment
- Web application testing integration
- Reporting and documentation generation
- API-enhanced intelligence gathering

### Defensive Capabilities
- Security monitoring and baseline configuration
- Operational security (OPSEC) hardening
- Network traffic anonymization
- Security policy enforcement
- Monitoring and alerting setup

### Core Features
- Secure API key management
- Standardized project structures
- Integration with industry standard tools
- Detailed markdown reporting
- OPSEC considerations at multiple levels

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/cyberkit.git

# Move to the cyberkit directory
cd cyberkit

# Install required dependencies
./install.sh

# Make scripts executable (if they aren't already)
chmod +x offensive/*.sh defensive/*.sh common/*.sh
```

## Dependencies

CyberKit integrates with and requires the following tools:
- Nmap, Masscan
- Gobuster, Ffuf
- Subfinder, Amass, httpx
- Nuclei, WhatWeb
- Suricata/Zeek (optional, for defensive toolkit)
- And various others that will be checked and prompted during installation

## Usage

### Offensive Tools

#### Initial Engagement Setup
```bash
./offensive/redteam-init.sh

# With API-enhanced reconnaissance
./offensive/redteam-init.sh --api-recon

# Or use test mode
./offensive/redteam-init.sh --test
```

#### Web Application Assessment
```bash
# Basic scan
./offensive/webapp-scan.sh -t target.com -o output_dir

# With API-enhanced reconnaissance
./offensive/webapp-scan.sh -t target.com --shodan --virustotal --securitytrails
```

#### Network Penetration Testing
```bash
# Basic scan
./offensive/network-scan.sh -t 192.168.1.0/24 -o output_dir

# With vulnerability scanning
./offensive/network-scan.sh -t 192.168.1.0/24 --vuln-scan

# With API-enhanced intelligence
./offensive/network-scan.sh -t 192.168.1.0/24 --vuln-scan --cve-lookup --threatintel
```

### Defensive Tools

#### Operational Security Configuration
```bash
# Basic configuration
./defensive/opsec-config.sh -i eth0

# High security level
./defensive/opsec-config.sh -i eth0 -l high
```

### Shared Utilities

#### API Key Management
```bash
# Initialize API key store
./common/api-keys.sh init

# Add an API key
./common/api-keys.sh set shodan YOUR_API_KEY

# List configured services
./common/api-keys.sh list
```

#### Project Setup
```bash
# Create a new engagement directory structure
./common/engagement-setup.sh -c client-name -e engagement-name -t offensive
```

## API Integration

CyberKit can integrate with various external APIs to enhance reconnaissance and intelligence gathering:

- **Shodan** - Network intelligence and exposed services
- **VirusTotal** - Malware and malicious site detection
- **SecurityTrails** - Historical DNS data and subdomain enumeration
- **Hunter.io** - Email address discovery
- **WhoisXML API** - Enhanced WHOIS information
- **NVD** - CVE details and vulnerability information
- **AlienVault OTX** - Threat intelligence

See [API Key Usage](docs/api-keys-usage.md) for setup instructions.

## Directory Structure

```
cyberkit/
├── offensive/               # Offensive security tools
│   ├── redteam-init.sh      # Initial engagement setup
│   ├── webapp-scan.sh       # Web application scanning
│   └── network-scan.sh      # Network penetration testing
├── defensive/               # Defensive security tools
│   └── opsec-config.sh      # Operational security configuration
├── common/                  # Shared utilities
│   ├── utils.sh             # Common utility functions
│   ├── config.sh            # Configuration handling
│   ├── api-keys.sh          # API key management
│   ├── engagement-setup.sh  # Project setup utility
│   └── zshrc-config         # Shell configuration for cybersecurity
├── docs/                    # Documentation
│   └── api-keys-usage.md    # API keys usage guide
├── install.sh               # Installation script
└── README.md                # Repository documentation
```

## Configuration

Edit the `common/config.sh` file to customize paths, default settings, and tool preferences. You can also create a user configuration file at `~/.cyberkit.conf` to override default settings.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

Distributed under the MIT License. See `LICENSE` for more information.

## Disclaimer

This toolkit is provided for legitimate security testing and educational purposes only. Always ensure you have proper authorization before testing any systems or networks. The author is not responsible for misuse or illegal activities conducted with this toolkit.
