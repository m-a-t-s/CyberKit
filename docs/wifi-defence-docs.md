# WiFi Defence Toolkit Usage Guide

The WiFi Defence Toolkit is a comprehensive solution for detecting, monitoring, and defending WiFi networks against malicious actors. It provides capabilities for both personal and enterprise environments, automated detection of threats, and active countermeasures when unauthorized access is detected.

## Overview

The WiFi Defence Toolkit provides several core capabilities:

- **Real-time Monitoring**: Continuously scan WiFi traffic to detect unauthorized access and suspicious activities
- **Log Analysis**: Parse WiFi logs and packet captures to identify security threats after the fact
- **Threat Intelligence**: Integrate with external threat intelligence to identify known malicious actors
- **Active Defence**: Implement countermeasures against detected threats, including deauthentication
- **Alerting**: Configurable alerts via email or SMS when security incidents are detected
- **Visualization**: Generate visual reports of network activity for easier threat identification
- **Enterprise Support**: Enhanced features for enterprise WiFi environments with 802.1X/RADIUS security

## Key Features

### Detection Capabilities
- Unauthorized devices (comparison against trusted baseline)
- Deauthentication attacks (WiFi DoS)
- Evil twin/rogue access points
- Client-side vulnerabilities (exposed probe requests)
- Enterprise-specific threats (EAP identity exposure)

### Defence Capabilities
- Deauthentication of unauthorized devices
- Blacklisting of suspicious MAC addresses
- BSSID/ESSID monitoring and alerting
- Integrated threat intelligence lookups

### Reporting & Visualization
- Comprehensive markdown reports of security analysis
- Visual representation of network activity
- Timeline analysis of significant events
- Top talkers and packet type distribution charts

## Usage Examples

### Monitor a WiFi Network

Monitor your WiFi network for suspicious activities:

```bash
sudo ./defensive/wifi-defence.sh monitor -i wlan0 -n "MyHomeNetwork" -t 300
```

This will:
1. Monitor the specified network for 5 minutes
2. Detect any unauthorized devices by comparing against a baseline
3. Generate a report of findings

### Set Up a Baseline of Trusted Devices

Create a baseline of trusted devices to detect intruders later:

```bash
sudo ./defensive/wifi-defence.sh baseline -i wlan0 -n "OfficeNetwork" -t 1800
```

This will monitor your network for 30 minutes and create a baseline of devices that should be allowed on the network.

### Analyze Existing Capture Files

Analyze previously captured WiFi traffic:

```bash
./defensive/wifi-defence.sh analyze -o /path/to/captures -m enterprise --visualize
```

This will:
1. Find packet captures in the specified directory
2. Analyze them for security threats
3. Generate a detailed report and visual representation of the findings

### Configure Alerting for Security Incidents

Set up email alerts when security incidents are detected:

```bash
./defensive/wifi-defence.sh alert --alerts email
```

### Active Defence Against Unauthorized Access

Actively defend against unauthorized access:

```bash
sudo ./defensive/wifi-defence.sh defend -i wlan0 -b 00:11:22:33:44:55 -t 600
```

This will:
1. Monitor the specified access point for 10 minutes
2. Detect any unauthorized devices
3. Deauthenticate unauthorized devices from the network
4. Send alerts if configured

### Enterprise WiFi Monitoring

For enterprise environments with more complex requirements:

```bash
sudo ./defensive/wifi-defence.sh monitor -i wlan0 -m enterprise --threatintel
```

This provides enhanced monitoring for enterprise WiFi networks, including EAP/RADIUS security checks and integration with threat intelligence sources.

## Integration with Other CyberKit Components

The WiFi Defence Toolkit integrates seamlessly with other components of CyberKit:

- **API Key Management**: Uses the shared API keys for threat intelligence integration
- **Engagement Setup**: Functions within the standard project structure
- **Reporting**: Generates standardized markdown reports for consistency across engagements

## Advanced Configuration

For advanced usage and configuration options, edit the configuration file:

```bash
nano ~/.cyberkit/wifi-defence.conf
```

Key settings include:
- Alert configurations (email/SMS recipients)
- Default monitoring duration
- Trusted networks and BSSIDs
- Threat intelligence API settings
- Security level presets

## Enterprise Usage

For enterprise environments, consider:

1. Setting up the monitoring as a background service
   ```bash
   sudo ./defensive/wifi-defence.sh monitor -i wlan0 --background
   ```

2. Integrating with your existing SIEM by configuring alerts to send to log files or APIs

3. Using the enterprise mode for enhanced 802.1X/RADIUS security monitoring
   ```bash
   sudo ./defensive/wifi-defence.sh monitor -i wlan0 -m enterprise -l high
   ```

## Troubleshooting

Common issues and solutions:

- **Interface not found**: Ensure your wireless adapter is connected and recognized by the system
- **Monitor mode failed**: Some wireless adapters don't support monitor mode; try with a compatible adapter
- **Permission denied**: The tool requires root privileges for most operations
- **Missing dependencies**: Run the built-in dependency check and install required packages

## Security Considerations

When using the WiFi Defence Toolkit:

- Always ensure you have proper authorization to monitor the network
- Use the deauthentication feature responsibly, as it can disrupt legitimate users
- Secure your baseline files as they contain sensitive information about your network
- Regularly update threat intelligence sources for the most effective protection

## Disclaimer

This toolkit is provided for legitimate security monitoring and defense of authorized networks only. Unauthorized use against networks you do not own or have explicit permission to test may violate local laws and regulations.
