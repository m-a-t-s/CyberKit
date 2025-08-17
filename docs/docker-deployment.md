# CyberKit Docker Deployment Guide

This guide explains how to deploy CyberKit using Docker containers for consistent, portable security testing environments.

## Overview

The Docker deployment provides:
- Pre-configured Kali Linux environment with all security tools
- Persistent data storage for engagements and reports
- Easy deployment across different systems
- Isolated and reproducible testing environment

## Prerequisites

- Docker Engine 20.10 or later
- Docker Compose 2.0 or later
- At least 4GB RAM and 10GB disk space
- Linux, macOS, or Windows with WSL2

### Installing Docker

#### Linux (Ubuntu/Debian)
```bash
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER
```

#### macOS
```bash
brew install --cask docker
```

#### Windows
Download Docker Desktop from https://www.docker.com/products/docker-desktop

## Quick Start

1. **Deploy CyberKit**:
   ```bash
   ./docker-deploy.sh deploy
   ```

2. **Access the container**:
   ```bash
   ./docker-deploy.sh shell
   ```

3. **Run a test**:
   ```bash
   ./offensive/redteam-init.sh --test
   ```

## Deployment Commands

### Build and Deploy
```bash
# Full deployment (recommended for first time)
./docker-deploy.sh deploy

# Or step by step
./docker-deploy.sh build
./docker-deploy.sh start
```

### Container Management
```bash
# Check status
./docker-deploy.sh status

# Access shell
./docker-deploy.sh shell

# Restart container
./docker-deploy.sh restart

# Stop container
./docker-deploy.sh stop
```

### Cleanup
```bash
# Clean up resources
./docker-deploy.sh cleanup
```

## Directory Structure

After deployment, the following directories will be created:

```
cyberkit/
├── data/                    # Persistent data (mounted as volumes)
│   ├── engagements/        # Engagement data
│   ├── reports/            # Generated reports
│   ├── evidence/           # Evidence files
│   └── logs/               # Log files
├── config/
│   └── user.conf           # User configuration overrides
├── Dockerfile              # Container definition
├── docker-compose.yml      # Service configuration
└── docker-deploy.sh        # Deployment script
```

## Configuration

### User Configuration

Edit `config/user.conf` to customize settings:

```bash
# Debug and verbosity
DEBUG=false
VERBOSE=true

# Custom tool paths
CUSTOM_NMAP_PATH="/usr/local/bin/nmap"

# API keys (use environment variables)
SHODAN_API_KEY="${SHODAN_API_KEY}"
VT_API_KEY="${VIRUSTOTAL_API_KEY}"
```

### Environment Variables

Set API keys and other sensitive data using environment variables:

```bash
export SHODAN_API_KEY="your_api_key_here"
export VIRUSTOTAL_API_KEY="your_api_key_here"
export SECURITYTRAILS_API_KEY="your_api_key_here"

# Then start the container
./docker-deploy.sh start
```

### Docker Compose Profiles

Enable additional services:

```bash
# Start with web interface for reports
docker-compose --profile web up -d

# Or using the deployment script
COMPOSE_PROFILES=web ./docker-deploy.sh start
```

## Usage Examples

### Offensive Security Testing

1. **Start an engagement**:
   ```bash
   ./docker-deploy.sh shell
   ./offensive/redteam-init.sh
   ```

2. **Web application scanning**:
   ```bash
   ./offensive/webapp-scan.sh -t target.com -o /home/cyberkit/engagements/target
   ```

3. **Network scanning**:
   ```bash
   ./offensive/network-scan.sh -t 192.168.1.0/24 --vuln-scan
   ```

### Defensive Security

1. **URL analysis**:
   ```bash
   ./defensive/url-scanner.sh --all-checks https://suspicious-site.com
   ```

2. **WiFi monitoring**:
   ```bash
   ./defensive/wifi-defence.sh monitor -i wlan0 -n "MyNetwork"
   ```

### Data Persistence

All engagement data is automatically saved to the mounted volumes:

- **Engagements**: `/home/cyberkit/engagements` → `./data/engagements`
- **Reports**: `/home/cyberkit/reports` → `./data/reports`
- **Evidence**: `/home/cyberkit/evidence` → `./data/evidence`
- **Logs**: `/home/cyberkit/logs` → `./data/logs`

## Advanced Configuration

### Custom Wordlists

Add custom wordlists to the container:

```bash
# Copy to the running container
docker cp custom-wordlist.txt cyberkit-toolkit:/usr/share/wordlists/

# Or mount during startup
docker run -v ./wordlists:/usr/share/wordlists/custom cyberkit:latest
```

### Network Configuration

For advanced network testing, use host networking:

```yaml
# In docker-compose.yml
services:
  cyberkit:
    network_mode: host
```

### GUI Applications

To run GUI applications (like Wireshark), enable X11 forwarding:

```bash
# Linux
xhost +local:docker
./docker-deploy.sh start

# Then run GUI apps
./docker-deploy.sh shell
wireshark &
```

## Troubleshooting

### Common Issues

1. **Permission denied errors**:
   ```bash
   # Fix file permissions
   sudo chown -R $USER:$USER ./data
   ```

2. **Container won't start**:
   ```bash
   # Check logs
   docker logs cyberkit-toolkit
   
   # Rebuild image
   ./docker-deploy.sh cleanup
   ./docker-deploy.sh build
   ```

3. **Network tools require privileges**:
   The container runs with necessary privileges for network tools. If issues persist, try:
   ```bash
   docker run --privileged --cap-add=ALL cyberkit:latest
   ```

### Performance Optimization

1. **Increase container resources**:
   ```yaml
   # In docker-compose.yml
   deploy:
     resources:
       limits:
         memory: 8G
         cpus: '4.0'
   ```

2. **Use bind mounts for better performance**:
   ```yaml
   volumes:
     - type: bind
       source: ./data/engagements
       target: /home/cyberkit/engagements
   ```

## Security Considerations

1. **API Keys**: Never include API keys in the image. Use environment variables or mounted config files.

2. **Network Isolation**: Consider using custom Docker networks for isolation.

3. **Volume Permissions**: Ensure proper permissions on mounted volumes.

4. **Regular Updates**: Rebuild the image regularly to get security updates:
   ```bash
   ./docker-deploy.sh cleanup
   ./docker-deploy.sh build
   ```

## Integration with CI/CD

### GitHub Actions Example

```yaml
name: CyberKit Security Scan
on: [push]
jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Build CyberKit
        run: ./docker-deploy.sh build
      - name: Run Security Scan
        run: |
          ./docker-deploy.sh start
          docker exec cyberkit-toolkit ./offensive/webapp-scan.sh -t ${{ github.event.repository.clone_url }}
```

## Support

For issues and questions:
- Check the [main documentation](../README.md)
- Review container logs: `docker logs cyberkit-toolkit`
- Verify configuration: `./docker-deploy.sh status`

## Next Steps

After successful deployment:
1. Review the [API Keys Usage Guide](api-keys-usage.md)
2. Explore individual tool documentation
3. Set up regular container updates
4. Consider integration with your security workflow