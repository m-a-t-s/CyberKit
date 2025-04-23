# URL Scanner Usage Guide

## Overview

The URL Scanner tool provides comprehensive analysis of URLs to detect phishing attempts, malware, and other threats. This guide explains how to use the tool effectively and interpret its results.

## Basic Usage

The simplest way to scan a single URL:

```bash
./defensive/url-scanner.sh https://example.com
```

This performs a basic analysis and outputs a text report with a threat score and verdict.

## Command Line Options

### Output Options

| Option | Description |
|--------|-------------|
| `-o, --output DIR` | Specify custom output directory |
| `-f, --format [json\|md\|txt]` | Output format (default: txt) |
| `-s, --silent` | Silent mode, output only final verdict |
| `-d, --detailed` | Detailed output mode |
| `-v, --verbose` | Verbose output |
| `-q, --quiet` | Minimal output |

### Analysis Configuration

| Option | Description |
|--------|-------------|
| `-p, --passive` | Passive mode (no active connections to target) |
| `-a, --all-checks` | Run all available checks (including APIs) |
| `-t, --timeout SECONDS` | Connection timeout (default: 30s) |
| `-u, --user-agent STRING` | Custom user agent string |
| `--check-redirects` | Follow and analyze redirects |
| `--max-redirects NUM` | Maximum redirects to follow (default: 5) |

### API Integration Options

| Option | Description |
|--------|-------------|
| `--vt` | Use VirusTotal for URL reputation |
| `--urlscan` | Use urlscan.io for URL analysis |
| `--phishtank` | Use PhishTank for phishing detection |
| `--abuseipdb` | Use AbuseIPDB for IP reputation |
| `-l, --list-apis` | List configured API integrations |

### Advanced Options

| Option | Description |
|--------|-------------|
| `-c, --cache-results` | Cache results of API lookups |
| `-n, --no-cache` | Bypass cache and force fresh scans |
| `--no-browser` | Skip browser emulation checks |
| `--no-sslyze` | Skip SSL/TLS analysis |
| `--no-screenshot` | Skip taking screenshot |
| `--no-dns` | Skip DNS analysis |
| `--batch FILE` | Process multiple URLs from file |
| `--export-iocs` | Export detected IOCs for SIEM/EDR |

## Use Cases

### Case 1: Quick Analysis of a Suspicious Link

When you need to quickly determine if a URL is safe:

```bash
./defensive/url-scanner.sh -s https://example.com
```

This runs a basic analysis and displays only the final verdict.

### Case 2: Comprehensive Analysis with All Checks

For detailed security assessment:

```bash
./defensive/url-scanner.sh --all-checks --detailed https://example.com
```

This enables all available checks including API integrations and produces a detailed report.

### Case 3: Analyzing an Email Attachment Link Without Connecting to It

For safely checking links without visiting them:

```bash
./defensive/url-scanner.sh --passive --vt --urlscan https://example.com
```

This uses passive analysis techniques and threat intelligence APIs without making direct connections to the target.

### Case 4: Batch Processing Multiple URLs

For security teams analyzing multiple links:

```bash
./defensive/url-scanner.sh --batch urls.txt --format json --output /path/to/results
```

This processes a file containing multiple URLs and outputs results in JSON format.

### Case 5: SIEM/EDR Integration

For automated security workflows:

```bash
./defensive/url-scanner.sh https://example.com --export-iocs --format json
```

This exports Indicators of Compromise (IOCs) in a format suitable for SIEM/EDR systems.

## Interpreting Results

The URL Scanner assigns a threat score to each analyzed URL based on various checks:

### Threat Score Interpretation

| Score Range | Verdict | Interpretation |
|-------------|---------|----------------|
| 0-2 | LIKELY SAFE | URL shows no significant indicators of being malicious |
| 3-5 | SUSPICIOUS | URL shows some suspicious characteristics but isn't definitively malicious |
| 6+ | LIKELY MALICIOUS | URL shows strong indicators of being malicious or a phishing attempt |

### Common Warning Signs

The tool looks for multiple indicators including:

- Domain characteristics (newly registered, suspicious TLDs)
- SSL/TLS certificate issues
- Redirect chains that change domains
- Presence of login forms on suspicious domains
- Matches in threat intelligence databases
- Suspicious URL patterns (excessive length, encoding, etc.)
- URL shorteners and redirection services
- Missing security headers
- Domain/IP reputation issues

### Sample Report

A typical text report includes:

```
URL Security Analysis Report
=================================

URL: https://example.com
Scanned: 2023-04-23T14:25:30Z
Score: 7
Verdict: LIKELY MALICIOUS

Security Concerns:
-----------------
- Domain was registered less than 30 days ago
- SSL/TLS certificate issued by uncommon Certificate Authority
- URL redirects to a different domain
- Page contains login form
- VirusTotal: 3 security vendors flagged this URL as malicious

Verdict:
--------
LIKELY MALICIOUS
This URL shows strong indicators of being malicious or a phishing attempt.
Avoid interacting with this site.
```

Markdown and JSON formats provide more detailed information about each check performed.

## Integration with CyberKit

The URL Scanner integrates with CyberKit's offensive and defensive workflows:

### Defensive Integration

- Analyze incoming URLs from threat intelligence feeds
- Validate URLs found in security alerts
- Screen URLs before allowing them in your environment

### Offensive Integration

- Test effectiveness of security awareness training
- Validate if phishing simulations would be flagged by security tools
- Assess URL filtering capabilities

## Advanced Features

### Caching

The tool caches API results for 24 hours by default to improve performance and reduce API usage:

```bash
# Force fresh scan ignoring cache
./defensive/url-scanner.sh --no-cache https://example.com

# Explicitly enable caching
./defensive/url-scanner.sh --cache-results https://example.com
```

### Redirect Analysis

Follow and analyze redirect chains (common in phishing attacks):

```bash
./defensive/url-scanner.sh --check-redirects --max-redirects 10 https://example.com
```

### IoC Export

Export indicators of compromise for integration with security tools:

```bash
./defensive/url-scanner.sh --export-iocs https://example.com
```

This creates a CSV file with domains, IPs, and URLs extracted from the analysis.

## Performance Considerations

- **API Rate Limits**: Most threat intelligence APIs have rate limits. Use caching for batch analysis.
- **Timeouts**: Adjust the timeout (`--timeout`) for slow-responding sites.
- **Resource Usage**: Full analysis with browser emulation can be resource-intensive. Use passive mode for bulk processing.

## Best Practices

1. **Start with Basic Analysis**: Begin with a standard scan before enabling all checks
2. **Use Passive Mode for Unknown URLs**: When analyzing potentially malicious URLs, start with passive mode
3. **Combine Multiple Intelligence Sources**: Enable multiple APIs for better accuracy
4. **Customize User-Agent**: Some phishing sites behave differently based on user agent
5. **Export IOCs**: Regularly export indicators of compromise to update security tools

## Troubleshooting

### Common Error Messages

- **"API key not configured"**: Use `./common/api-keys.sh set servicename YOUR_API_KEY` to configure
- **"Failed to connect or timeout"**: Increase timeout with `--timeout` option
- **"Domain did not resolve"**: URL may be malformed or domain no longer exists

### Performance Issues

If scans are taking too long:

1. Disable unused checks (`--no-sslyze`, `--no-screenshot`)
2. Reduce timeout value (`--timeout 10`)
3. Use cached results when possible

## Conclusion

The URL Scanner tool provides a powerful framework for analyzing URLs for security threats. By combining multiple analysis techniques and threat intelligence sources, it can effectively identify malicious URLs while minimizing false positives.

For additional help, run:

```bash
./defensive/url-scanner.sh --help
```