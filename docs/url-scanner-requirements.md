# URL Scanner Tool Requirements and Setup Guide

## Overview

The URL Scanner tool is a comprehensive solution for analyzing URLs to detect phishing, malware, and other threats. The tool follows the modular design of CyberKit and integrates with both offensive and defensive workflows.

## Core Features

- Comprehensive URL analysis using multiple techniques
- Integration with threat intelligence APIs
- Support for both Kali Linux and macOS environments
- Detailed reporting in multiple formats (text, markdown, JSON)
- Detection of typical phishing and malicious URL patterns
- SSL/TLS certificate analysis
- Domain and DNS validation
- HTTP response analysis
- Redirect chain tracking
- Score-based threat classification

## Requirements

### Core Dependencies

The URL Scanner requires the following core dependencies:

- bash (version 4.0+)
- curl
- dig (part of dnsutils/bind-utils)
- openssl
- grep
- awk
- jq (for JSON processing)

### Extended Dependencies

For enhanced functionality, the following tools are recommended:

- sslyze (for detailed SSL/TLS analysis)
- nmap (for port scanning)
- whois (for domain information)

### Kali Linux-Specific Tools (Optional)

These tools provide additional capabilities when running on Kali Linux:

- amass (for subdomain enumeration)
- httpx (for web server fingerprinting)
- subjack (for subdomain takeover checking)

### API Integrations (Optional)

The URL Scanner can integrate with the following threat intelligence services:

- VirusTotal
- PhishTank
- URLScan.io
- AbuseIPDB

## Installation

### On Kali Linux

```bash
# Install core dependencies
sudo apt update
sudo apt install -y curl dnsutils openssl jq whois

# Install extended dependencies
sudo apt install -y sslyze nmap

# Install Kali-specific tools (optional)
sudo apt install -y amass httpx subjack
```

### On macOS

```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install core dependencies
brew install curl bind openssl jq

# Install extended dependencies
brew install sslyze nmap whois
```

## API Key Configuration

To use threat intelligence services, configure API keys using the CyberKit API key management utility:

```bash
# Configure VirusTotal API key
./common/api-keys.sh set virustotal YOUR_API_KEY

# Configure URLScan.io API key
./common/api-keys.sh set urlscan YOUR_API_KEY

# Configure PhishTank API key (optional)
./common/api-keys.sh set phishtank YOUR_API_KEY

# Configure AbuseIPDB API key
./common/api-keys.sh set abuseipdb YOUR_API_KEY
```

### Obtaining API Keys

- **VirusTotal**: Register at [virustotal.com](https://www.virustotal.com/gui/join-us)
- **URLScan.io**: Register at [urlscan.io](https://urlscan.io/user/register)
- **PhishTank**: Register at [phishtank.org](https://www.phishtank.com/register.php)
- **AbuseIPDB**: Register at [abuseipdb.com](https://www.abuseipdb.com/register)

## Integration with CyberKit

After following the installation steps, the URL Scanner integrates with CyberKit's structure:

1. Place the `url-scanner.sh` script in the `defensive/` directory
2. Make it executable with `chmod +x defensive/url-scanner.sh`
3. Configure API keys as described above

The tool will use CyberKit's common utilities for logging, configuration, and API key management.

## Usage Examples

### Basic Scan

```bash
./defensive/url-scanner.sh https://example.com
```

### Comprehensive Analysis

```bash
./defensive/url-scanner.sh --all-checks --detailed https://example.com
```

### Passive Mode (No Direct Connection to Target)

```bash
./defensive/url-scanner.sh --passive --vt --phishtank https://example.com
```

### Batch Processing

```bash
./defensive/url-scanner.sh --batch urls.txt --format json --output /path/to/results
```

### SIEM/EDR Integration

```bash
./defensive/url-scanner.sh https://example.com --export-iocs
```

## Troubleshooting

### Common Issues

1. **Missing Dependencies**: Run with verbose mode to see dependency checks:
   ```bash
   ./defensive/url-scanner.sh -v https://example.com
   ```

2. **API Key Issues**: Verify your API key configuration:
   ```bash
   ./defensive/url-scanner.sh --list-apis
   ```

3. **Permission Denied**: Ensure the script is executable:
   ```bash
   chmod +x defensive/url-scanner.sh
   ```

### Cross-Platform Considerations

- **macOS**: Some commands like `date` and `stat` have different syntax on macOS. The script accounts for these differences.
- **API Rate Limits**: Be aware of rate limits for the threat intelligence APIs, especially when batch processing many URLs.

## Security Considerations

- The tool generates temporary files in `/tmp/cyberkit-url-scanner`. These are cleaned up automatically but may contain URL data.
- API keys are stored in CyberKit's secure key store and are never exposed in reports.
- Consider using passive mode when analyzing potentially malicious URLs to prevent accidental execution of browser exploits.
