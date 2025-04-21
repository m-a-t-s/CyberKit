#!/bin/bash
# CyberKit Installation Script
# This script installs dependencies and sets up the CyberKit environment

# Text formatting
bold=$(tput bold)
red=$(tput setaf 1)
green=$(tput setaf 2)
yellow=$(tput setaf 3)
blue=$(tput setaf 4)
reset=$(tput sgr0)

# Banner
echo "${bold}${blue}"
echo " ██████╗██╗   ██╗██████╗ ███████╗██████╗ ██╗  ██╗██╗████████╗"
echo "██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██║ ██╔╝██║╚══██╔══╝"
echo "██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝█████╔╝ ██║   ██║   "
echo "██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██╔═██╗ ██║   ██║   "
echo "╚██████╗   ██║   ██████╔╝███████╗██║  ██║██║  ██╗██║   ██║   "
echo " ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝   ╚═╝   "
echo "                                                             "
echo "Installation Script"
echo "${reset}"

# Detect OS
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$NAME
    elif type lsb_release >/dev/null 2>&1; then
        OS=$(lsb_release -si)
    elif [ -f /etc/lsb-release ]; then
        . /etc/lsb-release
        OS=$DISTRIB_ID
    else
        OS=$(uname -s)
    fi
    
    if [[ "$OS" == *"Kali"* ]]; then
        OS="Kali"
    elif [[ "$OS" == *"Ubuntu"* ]]; then
        OS="Ubuntu"
    elif [[ "$OS" == *"Debian"* ]]; then
        OS="Debian"
    elif [[ "$OS" == *"CentOS"* ]]; then
        OS="CentOS"
    elif [[ "$OS" == *"Fedora"* ]]; then
        OS="Fedora"
    elif [[ "$OS" == *"Arch"* ]]; then
        OS="Arch"
    elif [[ "$OS" == *"Darwin"* ]]; then
        OS="macOS"
    else
        OS="Unknown"
    fi
    
    echo "${blue}[*] Detected operating system: ${OS}${reset}"
}

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo "${yellow}[!] This script requires root privileges for installing packages.${reset}"
        echo "${yellow}[!] Please run as root or use sudo.${reset}"
        exit 1
    fi
}

# Create directories if they don't exist
create_directories() {
    echo "${blue}[*] Creating directory structure...${reset}"
    
    # Make scripts executable
    chmod +x offensive/*.sh defensive/*.sh 2>/dev/null || echo "${yellow}[!] Warning: Some scripts could not be made executable${reset}"
    
    # Ensure lib directories exist
    mkdir -p offensive/lib
    mkdir -p defensive/lib
    mkdir -p common
    mkdir -p templates
    
    echo "${green}[+] Directory structure created successfully${reset}"
}

# Install basic dependencies based on OS
install_basic_dependencies() {
    echo "${blue}[*] Installing basic dependencies...${reset}"
    
    case $OS in
        "Kali")
            apt-get update
            apt-get install -y git curl wget netcat-traditional nmap masscan gobuster ffuf python3-pip jq whois
            ;;
        "Ubuntu"|"Debian")
            apt-get update
            apt-get install -y git curl wget netcat nmap masscan python3-pip jq whois
            # Additional steps for tools not in standard repos
            echo "${yellow}[!] Installing additional tools from non-standard repositories...${reset}"
            pip3 install httpx-toolkit
            ;;
        "CentOS"|"Fedora")
            if [ "$OS" = "CentOS" ]; then
                yum update -y
                yum install -y git curl wget nmap python3-pip jq whois
            else
                dnf update -y
                dnf install -y git curl wget nmap python3-pip jq whois
            fi
            # Additional steps for tools not in standard repos
            echo "${yellow}[!] Installing additional tools from non-standard repositories...${reset}"
            pip3 install httpx-toolkit
            ;;
        "Arch")
            pacman -Syu --noconfirm
            pacman -S --noconfirm git curl wget nmap masscan python-pip jq whois
            ;;
        "macOS")
            echo "${yellow}[!] For macOS, it's recommended to use Homebrew to install dependencies${reset}"
            echo "${yellow}[!] Run the following commands manually:${reset}"
            echo "brew install git curl wget nmap jq whois python"
            echo "pip3 install httpx-toolkit"
            ;;
        *)
            echo "${red}[!] Unsupported operating system: $OS${reset}"
            echo "${yellow}[!] Please install the required dependencies manually:${reset}"
            echo "- git, curl, wget, netcat, nmap, masscan, gobuster, ffuf, python3-pip, jq, whois"
            ;;
    esac
    
    echo "${green}[+] Basic dependencies installed successfully${reset}"
}

# Install offensive security tools
install_offensive_tools() {
    echo "${blue}[*] Installing offensive security tools...${reset}"
    
    case $OS in
        "Kali")
            echo "${green}[+] Most offensive tools come pre-installed with Kali Linux${reset}"
            # Install additional tools not pre-installed
            apt-get install -y nuclei subfinder amass whatweb
            ;;
        "Ubuntu"|"Debian")
            apt-get install -y dirb nikto
            
            # Install Go if not already installed
            if ! command -v go >/dev/null 2>&1; then
                echo "${blue}[*] Installing Go...${reset}"
                wget https://go.dev/dl/go1.21.3.linux-amd64.tar.gz
                rm -rf /usr/local/go && tar -C /usr/local -xzf go1.21.3.linux-amd64.tar.gz
                echo 'export PATH=$PATH:/usr/local/go/bin' > /etc/profile.d/go.sh
                source /etc/profile.d/go.sh
                rm go1.21.3.linux-amd64.tar.gz
            fi
            
            # Install Go-based tools
            echo "${blue}[*] Installing Go-based security tools...${reset}"
            go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
            go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
            go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
            go install -v github.com/OWASP/Amass/v3/...@latest
            
            # Add Go bin to PATH
            echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
            echo "${green}[+] Go-based tools installed. Please run 'source ~/.bashrc' after installation${reset}"
            ;;
        "CentOS"|"Fedora")
            # Similar to Ubuntu/Debian but with different package manager
            if [ "$OS" = "CentOS" ]; then
                yum install -y epel-release
                yum install -y dirb nikto
            else
                dnf install -y dirb nikto
            fi
            
            # Install Go and Go-based tools (similar to Ubuntu/Debian section)
            echo "${yellow}[!] Manual installation of some offensive tools required${reset}"
            ;;
        "Arch")
            pacman -S --noconfirm dirb nikto
            # Install Go-based tools via AUR or manually
            echo "${yellow}[!] Some tools may need to be installed from AUR or manually${reset}"
            ;;
        "macOS")
            echo "${yellow}[!] For macOS, install offensive tools via Homebrew:${reset}"
            echo "brew install nuclei subfinder amass dirb nikto"
            ;;
        *)
            echo "${red}[!] Unsupported operating system for automated offensive tool installation${reset}"
            echo "${yellow}[!] Please install the offensive tools manually${reset}"
            ;;
    esac
    
    echo "${green}[+] Offensive security tools installed successfully${reset}"
}

# Install defensive security tools
install_defensive_tools() {
    echo "${blue}[*] Installing defensive security tools...${reset}"
    
    case $OS in
        "Kali"|"Ubuntu"|"Debian")
            apt-get install -y wireshark tcpdump suricata fail2ban
            # Optional: Configure repositories for Wazuh and ELK
            echo "${yellow}[!] For full defensive capabilities, consider installing:${reset}"
            echo "- Wazuh: https://documentation.wazuh.com/current/installation-guide/index.html"
            echo "- ELK Stack: https://www.elastic.co/guide/en/elasticsearch/reference/current/install-elasticsearch.html"
            echo "- Zeek: https://docs.zeek.org/en/master/install/install.html"
            ;;
        "CentOS"|"Fedora")
            if [ "$OS" = "CentOS" ]; then
                yum install -y wireshark tcpdump fail2ban
            else
                dnf install -y wireshark tcpdump fail2ban
            fi
            echo "${yellow}[!] Some defensive tools require manual installation${reset}"
            ;;
        "Arch")
            pacman -S --noconfirm wireshark-qt tcpdump suricata fail2ban
            ;;
        "macOS")
            echo "${yellow}[!] For macOS, install defensive tools via Homebrew:${reset}"
            echo "brew install wireshark tcpdump suricata"
            ;;
        *)
            echo "${red}[!] Unsupported operating system for automated defensive tool installation${reset}"
            echo "${yellow}[!] Please install the defensive tools manually${reset}"
            ;;
    esac
    
    echo "${green}[+] Defensive security tools installed successfully${reset}"
}

# Configure settings
configure_settings() {
    echo "${blue}[*] Configuring settings...${reset}"
    
    # Create basic configuration file
    cat > common/config.sh << 'EOF'
#!/bin/bash
# CyberKit Configuration File

# Base directories
CYBERKIT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )/.."
OFFENSIVE_DIR="$CYBERKIT_DIR/offensive"
DEFENSIVE_DIR="$CYBERKIT_DIR/defensive"
COMMON_DIR="$CYBERKIT_DIR/common"
TEMPLATES_DIR="$CYBERKIT_DIR/templates"

# Default output locations
DEFAULT_ENGAGEMENTS_DIR="$HOME/engagements"
DEFAULT_REPORTS_DIR="$HOME/reports"
DEFAULT_LOGS_DIR="$HOME/logs"

# Tool paths (modify these based on your installation)
NMAP_PATH="$(which nmap)"
MASSCAN_PATH="$(which masscan)"
NUCLEI_PATH="$(which nuclei)"
SUBFINDER_PATH="$(which subfinder)"
AMASS_PATH="$(which amass)"
HTTPX_PATH="$(which httpx)"
GOBUSTER_PATH="$(which gobuster)"
FFUF_PATH="$(which ffuf)"
SURICATA_PATH="$(which suricata)"
ZEEK_PATH="$(which zeek)"

# Default scan settings
DEFAULT_NMAP_ARGS="-T4 -A -v"
DEFAULT_MASSCAN_ARGS="--rate=1000"
DEFAULT_NUCLEI_ARGS="-severity low,medium,high,critical"
DEFAULT_GOBUSTER_ARGS="-w /usr/share/wordlists/dirb/common.txt"

# Default security levels
DEFAULT_OPSEC_LEVEL="medium"  # Options: low, medium, high

# Custom wordlists
WORDLIST_DIR="/usr/share/wordlists"
ROCKYOU_PATH="$WORDLIST_DIR/rockyou.txt"
DIRB_COMMON_PATH="$WORDLIST_DIR/dirb/common.txt"
SECLISTS_DIR="/usr/share/seclists"

# Check if wordlists exist, use defaults if not
if [ ! -d "$WORDLIST_DIR" ]; then
    echo "Wordlists directory not found at $WORDLIST_DIR. Using fallback paths."
    WORDLIST_DIR="$CYBERKIT_DIR/wordlists"
    mkdir -p "$WORDLIST_DIR"
fi

# Color formatting
BOLD="\033[1m"
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[34m"
RESET="\033[0m"
EOF
    
    chmod +x common/config.sh
    
    echo "${green}[+] Settings configured successfully${reset}"
}

# Create basic utilities
create_utilities() {
    echo "${blue}[*] Creating utility scripts...${reset}"
    
    # Create common utilities file
    cat > common/utils.sh << 'EOF'
#!/bin/bash
# CyberKit Common Utilities

# Source configuration
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$SCRIPT_DIR/config.sh"

# Print banner
print_banner() {
    echo -e "${BOLD}${BLUE}"
    echo " ██████╗██╗   ██╗██████╗ ███████╗██████╗ ██╗  ██╗██╗████████╗"
    echo "██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██║ ██╔╝██║╚══██╔══╝"
    echo "██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝█████╔╝ ██║   ██║   "
    echo "██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██╔═██╗ ██║   ██║   "
    echo "╚██████╗   ██║   ██████╔╝███████╗██║  ██║██║  ██╗██║   ██║   "
    echo " ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝   ╚═╝   "
    echo "                                                             "
    echo -e "$1 - v1.0"
    echo -e "${RESET}"
}

# Log message with timestamp
log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    case "$level" in
        "INFO")
            echo -e "${BLUE}[*] ${timestamp} - ${message}${RESET}"
            ;;
        "SUCCESS")
            echo -e "${GREEN}[+] ${timestamp} - ${message}${RESET}"
            ;;
        "WARNING")
            echo -e "${YELLOW}[!] ${timestamp} - ${message}${RESET}"
            ;;
        "ERROR")
            echo -e "${RED}[!] ${timestamp} - ${message}${RESET}"
            ;;
        *)
            echo -e "${timestamp} - ${message}"
            ;;
    esac
    
    # Log to file if LOG_FILE is defined
    if [ -n "$LOG_FILE" ]; then
        echo "${timestamp} - ${level} - ${message}" >> "$LOG_FILE"
    fi
}

# Check if a tool exists and is executable
check_tool() {
    local tool="$1"
    if ! command -v "$tool" &> /dev/null; then
        log "ERROR" "Required tool not found: $tool"
        return 1
    fi
    return 0
}

# Create directory if it doesn't exist
ensure_dir() {
    local dir="$1"
    if [ ! -d "$dir" ]; then
        mkdir -p "$dir"
        log "INFO" "Created directory: $dir"
    fi
}

# Extract IPs from a file
extract_ips() {
    local file="$1"
    grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" "$file" | sort -u
}

# Extract domains from a file
extract_domains() {
    local file="$1"
    grep -oE "\b([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}\b" "$file" | sort -u
}

# Parse command line arguments
parse_args() {
    local script_name="$1"
    shift
    
    # Help message
    if [[ "$1" == "-h" || "$1" == "--help" ]]; then
        echo "Usage: $script_name [options]"
        echo "Options:"
        echo "  -h, --help            Show this help message"
        # Add script-specific options here
        exit 0
    fi
    
    # Parse other arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            # Add script-specific argument handling here
            *)
                log "ERROR" "Unknown option: $1"
                echo "Use -h or --help for usage information"
                exit 1
                ;;
        esac
    done
}

# Generate a timestamp string
get_timestamp() {
    date +"%Y%m%d-%H%M%S"
}

# Function to sanitize input (remove special characters)
sanitize_input() {
    local input="$1"
    echo "$input" | tr -cd '[:alnum:]._-' | tr '[:upper:]' '[:lower:]'
}

# Check if running with root privileges
check_root() {
    if [ "$EUID" -ne 0 ]; then
        log "WARNING" "This script may require root privileges for some operations"
        return 1
    fi
    return 0
}

# Generate a random string
generate_random_string() {
    local length="${1:-12}"
    cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w "$length" | head -n 1
}

# Convert seconds to human-readable time
seconds_to_time() {
    local seconds="$1"
    printf "%dh:%dm:%ds" $((seconds/3600)) $((seconds%3600/60)) $((seconds%60))
}
EOF
    
    chmod +x common/utils.sh
    
    echo "${green}[+] Utility scripts created successfully${reset}"
}

# Final setup message
final_setup() {
    echo "${green}${bold}"
    echo "============================================================"
    echo "CyberKit installation completed!"
    echo "============================================================"
    echo "${reset}"
    echo "Key directories:"
    echo "- Offensive tools: ./offensive/"
    echo "- Defensive tools: ./defensive/"
    echo "- Common utilities: ./common/"
    echo "- Templates: ./templates/"
    echo ""
    echo "Next steps:"
    echo "1. Review the configuration in common/config.sh"
    echo "2. Try running an offensive tool: ./offensive/redteam-init.sh --test"
    echo "3. Try running a defensive tool: ./defensive/opsec-config.sh"
    echo ""
    echo "${yellow}Note: Some tools may require additional configuration or permissions.${reset}"
    echo ""
    echo "For more information, see the README.md file."
}

# Main installation flow
main() {
    detect_os
    check_root
    create_directories
    install_basic_dependencies
    install_offensive_tools
    install_defensive_tools
    configure_settings
    create_utilities
    final_setup
}

# Run the main installation
main