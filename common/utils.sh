#!/bin/bash
# utils.sh - Common utility functions for CyberKit
# =================================================
# This script provides shared utility functions used across
# both offensive and defensive tools in the CyberKit toolkit.

# Determine script directory for relative paths
UTILS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Global variables for log file
LOG_FILE=""

# Text formatting if terminal supports it
if [ -t 1 ]; then
    BOLD=$(tput bold)
    RED=$(tput setaf 1)
    GREEN=$(tput setaf 2)
    YELLOW=$(tput setaf 3)
    BLUE=$(tput setaf 4)
    MAGENTA=$(tput setaf 5)
    CYAN=$(tput setaf 6)
    WHITE=$(tput setaf 7)
    RESET=$(tput sgr0)
else
    BOLD=""
    RED=""
    GREEN=""
    YELLOW=""
    BLUE=""
    MAGENTA=""
    CYAN=""
    WHITE=""
    RESET=""
fi

# Function to print a banner with the tool name
print_banner() {
    local tool_name="$1"
    echo "${BLUE}${BOLD}"
    echo " ██████╗██╗   ██╗██████╗ ███████╗██████╗ ██╗  ██╗██╗████████╗"
    echo "██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██║ ██╔╝██║╚══██╔══╝"
    echo "██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝█████╔╝ ██║   ██║   "
    echo "██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██╔═██╗ ██║   ██║   "
    echo "╚██████╗   ██║   ██████╔╝███████╗██║  ██║██║  ██╗██║   ██║   "
    echo " ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝   ╚═╝   "
    echo "                                                             "
    echo "$tool_name"
    echo "${RESET}"
}

# Function to log messages with timestamp and appropriate coloring
# Usage: log "INFO" "This is an information message"
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
        "DEBUG")
            if [ "${DEBUG:-false}" = true ]; then
                echo -e "${MAGENTA}[D] ${timestamp} - ${message}${RESET}"
            fi
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

# Check if a command exists and is executable
# Usage: if check_tool "nmap"; then ...
check_tool() {
    local tool="$1"
    if command -v "$tool" &> /dev/null; then
        return 0  # Tool exists
    else
        return 1  # Tool does not exist
    fi
}

# Ensure a directory exists, creating it if necessary
# Usage: ensure_dir "/path/to/directory"
ensure_dir() {
    local dir="$1"
    if [ ! -d "$dir" ]; then
        mkdir -p "$dir"
    fi
}

# Convert seconds to human-readable time format
# Usage: seconds_to_time 3661 -> "1h:1m:1s"
seconds_to_time() {
    local seconds="$1"
    printf "%dh:%dm:%ds" $((seconds/3600)) $((seconds%3600/60)) $((seconds%60))
}

# Sanitize input to make it safe for filenames and paths
# Usage: sanitize_input "User Input"
sanitize_input() {
    local input="$1"
    echo "$input" | tr -cd '[:alnum:]._-' | tr '[:upper:]' '[:lower:]'
}

# Check if the script is being run as root
# Usage: if check_root; then ...
check_root() {
    if [ "$EUID" -ne 0 ]; then
        return 1  # Not root
    else
        return 0  # Root
    fi
}

# Generate a random string of specified length
# Usage: random_string 12
random_string() {
    local length="${1:-12}"
    cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w "$length" | head -n 1
}

# Extract IP addresses from a file
# Usage: extract_ips "/path/to/file.txt"
extract_ips() {
    local file="$1"
    grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" "$file" | sort -u
}

# Extract domains from a file
# Usage: extract_domains "/path/to/file.txt"
extract_domains() {
    local file="$1"
    grep -oE "\b([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}\b" "$file" | sort -u
}

# Check if a URL is alive using curl
# Usage: if is_url_alive "https://example.com"; then ...
is_url_alive() {
    local url="$1"
    local timeout="${2:-5}"
    if curl --output /dev/null --silent --head --fail --max-time "$timeout" "$url"; then
        return 0  # URL is alive
    else
        return 1  # URL is not alive
    fi
}

# Get the primary network interface
# Usage: primary_interface=$(get_primary_interface)
get_primary_interface() {
    ip -o -4 route show to default | awk '{print $5}' | head -1
}

# Check if a given IP is in a CIDR range
# Usage: if is_ip_in_cidr "192.168.1.5" "192.168.1.0/24"; then ...
is_ip_in_cidr() {
    local ip="$1"
    local cidr="$2"
    
    # Extract base address and prefix length from CIDR
    local cidr_ip=$(echo "$cidr" | cut -d '/' -f 1)
    local cidr_prefix=$(echo "$cidr" | cut -d '/' -f 2)
    
    # Convert IP addresses to integer representation
    local ip_int=0
    local cidr_ip_int=0
    local i=1
    
    for octet in $(echo "$ip" | tr '.' ' '); do
        ip_int=$((ip_int + (octet << (8 * (4 - i)))))
        i=$((i + 1))
    done
    
    i=1
    for octet in $(echo "$cidr_ip" | tr '.' ' '); do
        cidr_ip_int=$((cidr_ip_int + (octet << (8 * (4 - i)))))
        i=$((i + 1))
    done
    
    # Calculate netmask from prefix length
    local netmask=$(( 0xffffffff << (32 - cidr_prefix) & 0xffffffff ))
    
    # Check if IP is in the CIDR range
    if (( (ip_int & netmask) == (cidr_ip_int & netmask) )); then
        return 0  # IP is in CIDR range
    else
        return 1  # IP is not in CIDR range
    fi
}

# Wait for user confirmation
# Usage: confirm_action "Are you sure you want to continue?" || exit 1
confirm_action() {
    local prompt="${1:-Are you sure you want to continue?}"
    local response
    
    echo -e "${YELLOW}${prompt} (y/n)${RESET}"
    read -r response
    
    case "$response" in
        [yY][eE][sS]|[yY])
            return 0  # User confirmed
            ;;
        *)
            return 1  # User declined
            ;;
    esac
}

# Print a horizontal separator line
# Usage: print_separator
print_separator() {
    local char="${1:-=}"
    local width="${2:-80}"
    printf "%${width}s\n" | tr ' ' "$char"
}

# Format a JSON string to be more readable
# Usage: format_json '{"key":"value"}'
format_json() {
    local json="$1"
    if check_tool "jq"; then
        echo "$json" | jq .
    else
        echo "$json" | python -m json.tool 2>/dev/null || echo "$json"
    fi
}

# Check if a port is open on a host
# Usage: if is_port_open "192.168.1.1" 80; then ...
is_port_open() {
    local host="$1"
    local port="$2"
    local timeout="${3:-2}"
    
    (echo > /dev/tcp/"$host"/"$port") >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        return 0  # Port is open
    else
        return 1  # Port is closed or filtered
    fi
}

# Create a backup of a file
# Usage: backup_file "/etc/passwd"
backup_file() {
    local file="$1"
    local backup_dir="${2:-./backups}"
    
    if [ -f "$file" ]; then
        ensure_dir "$backup_dir"
        local basename=$(basename "$file")
        local timestamp=$(date +"%Y%m%d-%H%M%S")
        cp "$file" "$backup_dir/${basename}.${timestamp}.bak"
        return 0
    else
        return 1  # File doesn't exist
    fi
}

# Parse a URL into its components
# Usage: parse_url "https://user:pass@example.com:8080/path?query=value#fragment"
parse_url() {
    local url="$1"
    local protocol=$(echo "$url" | grep -o '^\w\+://')
    local auth=$(echo "$url" | sed -E 's|^\w+://||' | grep -o '^[^@]\+@' | sed 's/@$//')
    local host=$(echo "$url" | sed -E 's|^\w+://||' | sed -E 's|^[^@]+@||' | grep -o '^[^:/]\+')
    local port=$(echo "$url" | sed -E 's|^\w+://||' | sed -E 's|^[^@]+@||' | grep -o ':[0-9]\+' | sed 's/^://')
    local path=$(echo "$url" | sed -E 's|^\w+://||' | sed -E 's|^[^@]+@||' | sed -E 's|^[^:/]+||' | sed -E 's|^(:[0-9]+)?||' | grep -o '^/[^?#]*' | sed 's/^\///' | sed 's/$/\//' | sed 's/\/\//\//')
    local query=$(echo "$url" | grep -o '\?[^#]\+' | sed 's/^\?//')
    local fragment=$(echo "$url" | grep -o '#.\+$' | sed 's/^#//')
    
    echo "Protocol: ${protocol%://}"
    echo "Auth: $auth"
    echo "Host: $host"
    echo "Port: $port"
    echo "Path: /$path"
    echo "Query: $query"
    echo "Fragment: $fragment"
}

# Generate a simple hash of a string (for non-cryptographic uses)
# Usage: hash=$(simple_hash "string to hash")
simple_hash() {
    local input="$1"
    echo "$input" | md5sum | awk '{print $1}'
}

# Check if a value exists in an array
# Usage: if array_contains "value" "${array[@]}"; then ...
array_contains() {
    local search="$1"
    shift
    local array=("$@")
    for element in "${array[@]}"; do
        if [[ "$element" == "$search" ]]; then
            return 0  # Value exists in array
        fi
    done
    return 1  # Value does not exist in array
}

# Calculate elapsed time between two timestamps
# Usage: start=$(date +%s); sleep 5; elapsed=$(calc_elapsed_time "$start")
calc_elapsed_time() {
    local start_time="$1"
    local end_time="${2:-$(date +%s)}"
    local elapsed=$((end_time - start_time))
    echo "$elapsed"
}

# Clean up temporary files on exit
# Usage: trap cleanup EXIT; create_temp_files; do_work
cleanup() {
    # Remove all temporary files
    if [ -n "${TEMP_FILES[*]}" ]; then
        rm -f "${TEMP_FILES[@]}" 2>/dev/null
    fi
    
    # Remove temporary directory if it exists
    if [ -n "$TEMP_DIR" ] && [ -d "$TEMP_DIR" ]; then
        rm -rf "$TEMP_DIR" 2>/dev/null
    fi
    
    log "DEBUG" "Cleanup complete"
}

# Create a temporary file and register it for cleanup
# Usage: tmp_file=$(create_temp_file)
TEMP_FILES=()
create_temp_file() {
    local tmp=$(mktemp)
    TEMP_FILES+=("$tmp")
    echo "$tmp"
}

# Create a temporary directory and register it for cleanup
# Usage: tmp_dir=$(create_temp_dir)
TEMP_DIR=""
create_temp_dir() {
    TEMP_DIR=$(mktemp -d)
    echo "$TEMP_DIR"
}

# Export functions and variables
export BOLD RED GREEN YELLOW BLUE MAGENTA CYAN WHITE RESET
export -f print_banner log check_tool ensure_dir seconds_to_time sanitize_input check_root
export -f random_string extract_ips extract_domains is_url_alive get_primary_interface
export -f is_ip_in_cidr confirm_action print_separator format_json is_port_open backup_file
export -f parse_url simple_hash array_contains calc_elapsed_time cleanup create_temp_file create_temp_dir