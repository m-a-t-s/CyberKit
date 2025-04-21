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

### Defensive Capabilities
- Security monitoring and baseline configuration
- Log collection and analysis
- Network traffic analysis
- Digital forensics automation
- Incident response preparation

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/cyberkit.git

# Move to the cyberkit directory
cd cyberkit

# Install required dependencies
./install.sh

# Make scripts executable
chmod +x offensive/*.sh defensive/*.sh
```

## Dependencies

CyberKit requires the following tools:
- Nmap, Masscan
- Gobuster, Ffuf
- Subfinder, Amass, httpx
- Nuclei, WhatWeb
- Wazuh (optional, for defensive toolkit)
- Suricata/Zeek (optional, for defensive toolkit)
- Volatility, KAPE (optional, for forensics)

## Usage

### Offensive Tools

#### Initial Engagement Setup
```bash
./offensive/redteam-init.sh

# Or use test mode
./offensive/redteam-init.sh --test
```

#### Web Application Assessment
```bash
./offensive/webapp-scan.sh -t target.com -o output_dir
```

#### Network Penetration Testing
```bash
./offensive/network-scan.sh -r 192.168.1.0/24 -o output_dir
```

### Defensive Tools

#### Security Monitoring Setup
```bash
./defensive/monitor-setup.sh -i eth0 -d /var/log
```

#### Incident Response Preparation
```bash
./defensive/ir-prepare.sh -s system_name
```

#### Operational Security Configuration
```bash
./defensive/opsec-config.sh -l high
```

## Directory Structure

```
cyberkit/
├── offensive/               # Offensive security tools
│   ├── redteam-init.sh      # Initial engagement setup
│   ├── webapp-scan.sh       # Web application scanning
│   ├── network-scan.sh      # Network penetration testing
│   └── lib/                 # Shared libraries for offensive tools
│       ├── recon.sh
│       ├── exploit.sh
│       └── report.sh
├── defensive/               # Defensive security tools
│   ├── monitor-setup.sh     # Security monitoring setup
│   ├── ir-prepare.sh        # Incident response preparation
│   ├── opsec-config.sh      # Operational security configuration
│   └── lib/                 # Shared libraries for defensive tools
│       ├── logging.sh
│       ├── detection.sh
│       └── forensics.sh
├── common/                  # Shared utilities
│   ├── utils.sh             # Common utility functions
│   └── config.sh            # Configuration handling
├── templates/               # Report and documentation templates
├── install.sh               # Installation script
└── README.md                # Repository documentation
```

## Configuration

Edit the `common/config.sh` file to customize paths, default settings, and tool preferences.

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
