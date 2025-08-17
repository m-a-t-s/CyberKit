# CyberKit Docker Container
# Based on Kali Linux with all security tools pre-installed
FROM kalilinux/kali-rolling:latest

# Metadata
LABEL maintainer="CyberKit Team"
LABEL description="CyberKit - Cybersecurity Offensive & Defensive Toolkit"
LABEL version="1.0"

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV CYBERKIT_HOME=/opt/cyberkit
ENV PATH=$PATH:$CYBERKIT_HOME/offensive:$CYBERKIT_HOME/defensive:$CYBERKIT_HOME/common
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

# Update package lists and install base dependencies
RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y \
    # Base system tools
    curl wget git vim nano sudo \
    # Network tools
    nmap masscan netcat-traditional dnsutils whois \
    # Programming languages and package managers
    python3 python3-pip golang-go nodejs npm \
    # Common utilities
    jq unzip zip gzip tar \
    # Development tools
    build-essential \
    # Clean up
    && apt-get autoremove -y \
    && apt-get autoclean \
    && rm -rf /var/lib/apt/lists/*

# Install Kali security tools
RUN apt-get update && \
    apt-get install -y \
    # Web application testing
    gobuster nikto sqlmap dirb \
    # Password cracking
    hashcat john hydra \
    # Exploitation tools
    metasploit-framework exploitdb \
    # Network analysis
    wireshark-common tcpdump \
    # Defensive tools
    suricata fail2ban \
    # WiFi tools
    aircrack-ng \
    # Additional utilities
    proxychains4 tor whatweb \
    && apt-get autoremove -y \
    && apt-get autoclean \
    && rm -rf /var/lib/apt/lists/*

# Install Go-based security tools
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/owasp-amass/amass/v4/...@latest && \
    go install -v github.com/ffuf/ffuf/v2@latest && \
    # Clean up Go cache
    go clean -cache -modcache

# Install Python security tools
RUN pip3 install --no-cache-dir --break-system-packages \
    httpx \
    requests \
    beautifulsoup4 \
    dnspython \
    shodan \
    virustotal-api

# Create cyberkit user and group
RUN groupadd -r cyberkit && \
    useradd -r -g cyberkit -d $CYBERKIT_HOME -s /bin/bash cyberkit && \
    mkdir -p $CYBERKIT_HOME && \
    chown -R cyberkit:cyberkit $CYBERKIT_HOME

# Create necessary directories
RUN mkdir -p /home/cyberkit/{engagements,reports,evidence,logs} && \
    mkdir -p /usr/share/wordlists && \
    chown -R cyberkit:cyberkit /home/cyberkit

# Copy CyberKit files
COPY --chown=cyberkit:cyberkit . $CYBERKIT_HOME/

# Set up wordlists
RUN if [ -f /usr/share/wordlists/rockyou.txt.gz ]; then \
        gunzip /usr/share/wordlists/rockyou.txt.gz; \
    fi
    # Note: SecLists can be added later with: 
    # docker exec cyberkit-toolkit git clone https://github.com/danielmiessler/SecLists.git /usr/share/seclists

# Make scripts executable
RUN chmod +x $CYBERKIT_HOME/offensive/*.sh && \
    chmod +x $CYBERKIT_HOME/defensive/*.sh && \
    chmod +x $CYBERKIT_HOME/common/*.sh && \
    chmod +x $CYBERKIT_HOME/install.sh

# Set up PATH for Go binaries and copy them to accessible location
ENV PATH=$PATH:/root/go/bin:/home/cyberkit/go/bin:/usr/local/bin
RUN cp -r /root/go/bin/* /usr/local/bin/ 2>/dev/null || true

# Create entrypoint script
RUN echo '#!/bin/bash\n\
# CyberKit Docker Entrypoint\n\
echo "=== CyberKit Container Started ==="\n\
echo "Available tools:"\n\
echo "  Offensive: ls $CYBERKIT_HOME/offensive/"\n\
echo "  Defensive: ls $CYBERKIT_HOME/defensive/"\n\
echo "  Common: ls $CYBERKIT_HOME/common/"\n\
echo ""\n\
echo "Example usage:"\n\
echo "  ./offensive/redteam-init.sh --test"\n\
echo "  ./defensive/url-scanner.sh https://example.com"\n\
echo ""\n\
echo "Data directories mounted at:"\n\
echo "  /home/cyberkit/engagements"\n\
echo "  /home/cyberkit/reports"\n\
echo "  /home/cyberkit/evidence"\n\
echo "  /home/cyberkit/logs"\n\
echo ""\n\
# Execute the command passed to docker run\n\
if [ $# -eq 0 ]; then\n\
    exec /bin/bash\n\
else\n\
    exec "$@"\n\
fi' > /entrypoint.sh && \
    chmod +x /entrypoint.sh

# Switch to cyberkit user
USER cyberkit
WORKDIR $CYBERKIT_HOME

# Expose common ports that might be used by tools
EXPOSE 8080 8443 9090

# Set volumes for persistent data
VOLUME ["/home/cyberkit/engagements", "/home/cyberkit/reports", "/home/cyberkit/evidence", "/home/cyberkit/logs"]

# Set entrypoint
ENTRYPOINT ["/entrypoint.sh"]
CMD ["/bin/bash"]