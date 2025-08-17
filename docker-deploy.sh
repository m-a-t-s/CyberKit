#!/bin/bash
# CyberKit Docker Deployment Script
# This script helps build and deploy CyberKit using Docker

set -e

# Text formatting
BOLD='\033[1m'
RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
BLUE='\033[34m'
RESET='\033[0m'

# Configuration
DOCKER_IMAGE="cyberkit:latest"
CONTAINER_NAME="cyberkit-toolkit"
DATA_DIR="./data"

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
    echo "Docker Deployment Script"
    echo -e "${RESET}"
}

# Logging functions
log_info() {
    echo -e "${BLUE}[*] $1${RESET}"
}

log_success() {
    echo -e "${GREEN}[+] $1${RESET}"
}

log_warning() {
    echo -e "${YELLOW}[!] $1${RESET}"
}

log_error() {
    echo -e "${RED}[!] $1${RESET}"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check if Docker is installed
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    # Check if Docker Compose is installed
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        log_error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi
    
    # Check if Docker is running
    if ! docker info &> /dev/null; then
        log_error "Docker is not running. Please start Docker first."
        exit 1
    fi
    
    log_success "Prerequisites check passed"
}

# Create necessary directories
create_directories() {
    log_info "Creating data directories..."
    
    mkdir -p "$DATA_DIR"/{engagements,reports,evidence,logs}
    mkdir -p config
    
    # Create sample user configuration
    if [ ! -f "config/user.conf" ]; then
        cat > config/user.conf << 'EOF'
# CyberKit User Configuration
# Override default settings here

# Default settings
DEBUG=false
VERBOSE=false
QUIET=false

# Custom tool paths (if different from defaults)
# CUSTOM_NMAP_PATH="/usr/local/bin/nmap"

# API Keys (use environment variables for security)
# SHODAN_API_KEY="${SHODAN_API_KEY}"
# VT_API_KEY="${VIRUSTOTAL_API_KEY}"
EOF
    fi
    
    log_success "Directories created"
}

# Build Docker image
build_image() {
    log_info "Building CyberKit Docker image..."
    
    # Build with build args for customization
    docker build \
        --tag "$DOCKER_IMAGE" \
        --build-arg BUILD_DATE="$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
        --build-arg VCS_REF="$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')" \
        .
    
    log_success "Docker image built successfully"
}

# Start container
start_container() {
    log_info "Starting CyberKit container..."
    
    # Stop existing container if running
    if docker ps -q -f name="$CONTAINER_NAME" | grep -q .; then
        log_warning "Stopping existing container..."
        docker stop "$CONTAINER_NAME"
    fi
    
    # Remove existing container if exists
    if docker ps -aq -f name="$CONTAINER_NAME" | grep -q .; then
        log_warning "Removing existing container..."
        docker rm "$CONTAINER_NAME"
    fi
    
    # Start container with docker-compose
    docker-compose up -d cyberkit
    
    log_success "CyberKit container started"
}

# Stop container
stop_container() {
    log_info "Stopping CyberKit container..."
    docker-compose down
    log_success "CyberKit container stopped"
}

# Access container shell
shell_access() {
    log_info "Connecting to CyberKit container shell..."
    docker exec -it "$CONTAINER_NAME" /bin/bash
}

# Show container status
show_status() {
    log_info "CyberKit container status:"
    echo ""
    
    if docker ps -q -f name="$CONTAINER_NAME" | grep -q .; then
        echo -e "${GREEN}Container is running${RESET}"
        docker ps -f name="$CONTAINER_NAME" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
    else
        echo -e "${YELLOW}Container is not running${RESET}"
    fi
    
    echo ""
    log_info "Data directory contents:"
    ls -la "$DATA_DIR" 2>/dev/null || echo "Data directory not found"
}

# Clean up Docker resources
cleanup() {
    log_info "Cleaning up Docker resources..."
    
    # Stop and remove container
    docker-compose down
    
    # Remove image if requested
    read -p "Remove Docker image? [y/N]: " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        docker rmi "$DOCKER_IMAGE" 2>/dev/null || true
        log_success "Docker image removed"
    fi
    
    # Clean up unused Docker resources
    docker system prune -f
    
    log_success "Cleanup completed"
}

# Show usage
show_usage() {
    echo "Usage: $0 [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  build       Build CyberKit Docker image"
    echo "  start       Start CyberKit container"
    echo "  stop        Stop CyberKit container"
    echo "  restart     Restart CyberKit container"
    echo "  shell       Access container shell"
    echo "  status      Show container status"
    echo "  cleanup     Clean up Docker resources"
    echo "  deploy      Full deployment (build + start)"
    echo ""
    echo "Examples:"
    echo "  $0 deploy       # Build image and start container"
    echo "  $0 shell        # Access running container"
    echo "  $0 status       # Check container status"
}

# Main function
main() {
    case "${1:-deploy}" in
        "build")
            print_banner
            check_prerequisites
            create_directories
            build_image
            ;;
        "start")
            print_banner
            check_prerequisites
            create_directories
            start_container
            ;;
        "stop")
            print_banner
            stop_container
            ;;
        "restart")
            print_banner
            check_prerequisites
            stop_container
            start_container
            ;;
        "shell")
            shell_access
            ;;
        "status")
            show_status
            ;;
        "cleanup")
            print_banner
            cleanup
            ;;
        "deploy")
            print_banner
            check_prerequisites
            create_directories
            build_image
            start_container
            echo ""
            log_success "CyberKit deployment completed!"
            echo ""
            echo "Next steps:"
            echo "  1. Configure API keys (if not done): Edit .env file"
            echo "  2. Access the container: $0 shell"
            echo "  3. Run a test: ./offensive/redteam-init.sh --test"
            echo "  4. Test with API keys: ./offensive/webapp-scan.sh -t example.com --shodan --virustotal"
            echo "  5. Check status: $0 status"
            ;;
        "-h"|"--help"|"help")
            show_usage
            ;;
        *)
            log_error "Unknown command: $1"
            show_usage
            exit 1
            ;;
    esac
}

# Run main function
main "$@"