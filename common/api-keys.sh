#!/bin/bash
# api-keys.sh - Secure API key management for CyberKit
# ====================================================
# This script provides secure API key management, allowing
# storage, retrieval, and usage of API keys without exposing
# them in scripts or including them in git repositories.

# Source common utilities
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$SCRIPT_DIR/utils.sh"

# API keys store location
API_KEYS_DIR="$HOME/.config/cyberkit/keys"
API_KEYS_FILE="$API_KEYS_DIR/api_keys.enc"
API_KEYS_SALT_FILE="$API_KEYS_DIR/salt"
DEFAULT_ENCRYPTION_METHOD="aes-256-cbc"

# Check if OpenSSL is available
if ! check_tool "openssl"; then
    log "ERROR" "OpenSSL is required for API key management but was not found."
    exit 1
fi

# Initialize the API keys directory and files
init_api_keys() {
    # Create directory if it doesn't exist
    ensure_dir "$API_KEYS_DIR"
    
    # Set secure permissions
    chmod 700 "$API_KEYS_DIR"
    
    # Generate salt if it doesn't exist
    if [ ! -f "$API_KEYS_SALT_FILE" ]; then
        openssl rand -hex 16 > "$API_KEYS_SALT_FILE"
        chmod 600 "$API_KEYS_SALT_FILE"
    fi
    
    # Create empty keys file if it doesn't exist
    if [ ! -f "$API_KEYS_FILE" ]; then
        echo "{}" | encrypt_data "" > "$API_KEYS_FILE"
        chmod 600 "$API_KEYS_FILE"
    fi
    
    log "SUCCESS" "API keys store initialized at $API_KEYS_DIR"
}

# Encrypt data with password
encrypt_data() {
    local password="$1"
    local salt=$(cat "$API_KEYS_SALT_FILE")
    
    # If no password provided, ask for it
    if [ -z "$password" ]; then
        read -s -p "Enter encryption password: " password
        echo
    fi
    
    # Use OpenSSL to encrypt with a key derived from password and salt
    openssl enc -$DEFAULT_ENCRYPTION_METHOD -md sha256 -salt -S "$salt" -pass pass:"$password"
}

# Decrypt data with password
decrypt_data() {
    local password="$1"
    local salt=$(cat "$API_KEYS_SALT_FILE")
    
    # If no password provided, ask for it
    if [ -z "$password" ]; then
        read -s -p "Enter decryption password: " password
        echo
    fi
    
    # Use OpenSSL to decrypt
    openssl enc -d -$DEFAULT_ENCRYPTION_METHOD -md sha256 -salt -S "$salt" -pass pass:"$password"
}

# Set an API key
set_api_key() {
    local service="$1"
    local key="$2"
    local password="$3"
    
    # Validate inputs
    if [ -z "$service" ] || [ -z "$key" ]; then
        log "ERROR" "Service name and API key are required."
        echo "Usage: set_api_key <service> <key> [password]"
        return 1
    fi
    
    # Initialize if needed
    if [ ! -f "$API_KEYS_FILE" ]; then
        init_api_keys
    fi
    
    # Get current keys
    local keys_json=""
    if [ -f "$API_KEYS_FILE" ]; then
        keys_json=$(cat "$API_KEYS_FILE" | decrypt_data "$password")
        if [ $? -ne 0 ]; then
            log "ERROR" "Failed to decrypt API keys. Check your password."
            return 1
        fi
    else
        keys_json="{}"
    fi
    
    # Add/update key
    keys_json=$(echo "$keys_json" | jq --arg service "$service" --arg key "$key" '. + {($service): $key}')
    
    # Save back encrypted
    echo "$keys_json" | encrypt_data "$password" > "$API_KEYS_FILE"
    chmod 600 "$API_KEYS_FILE"
    
    log "SUCCESS" "API key for $service has been set."
}

# Get an API key
get_api_key() {
    local service="$1"
    local password="$2"
    
    # Validate inputs
    if [ -z "$service" ]; then
        log "ERROR" "Service name is required."
        echo "Usage: get_api_key <service> [password]"
        return 1
    fi
    
    # Check if keys file exists
    if [ ! -f "$API_KEYS_FILE" ]; then
        log "ERROR" "API keys file not found. Initialize it first."
        return 1
    fi
    
    # Decrypt and get key
    local keys_json=$(cat "$API_KEYS_FILE" | decrypt_data "$password")
    if [ $? -ne 0 ]; then
        log "ERROR" "Failed to decrypt API keys. Check your password."
        return 1
    fi
    
    # Extract the key for the service
    local api_key=$(echo "$keys_json" | jq -r --arg service "$service" '.[$service] // empty')
    
    if [ -z "$api_key" ] || [ "$api_key" = "null" ]; then
        log "ERROR" "No API key found for service: $service"
        return 1
    fi
    
    echo "$api_key"
}

# List all stored service names
list_api_services() {
    local password="$1"
    
    # Check if keys file exists
    if [ ! -f "$API_KEYS_FILE" ]; then
        log "ERROR" "API keys file not found. Initialize it first."
        return 1
    fi
    
    # Decrypt and list services
    local keys_json=$(cat "$API_KEYS_FILE" | decrypt_data "$password")
    if [ $? -ne 0 ]; then
        log "ERROR" "Failed to decrypt API keys. Check your password."
        return 1
    fi
    
    # Extract and show service names only (not the keys)
    local services=$(echo "$keys_json" | jq -r 'keys[]')
    
    if [ -z "$services" ]; then
        echo "No API services configured."
    else
        echo "Configured API services:"
        echo "$services" | sed 's/^/- /'
    fi
}

# Delete an API key
delete_api_key() {
    local service="$1"
    local password="$2"
    
    # Validate inputs
    if [ -z "$service" ]; then
        log "ERROR" "Service name is required."
        echo "Usage: delete_api_key <service> [password]"
        return 1
    fi
    
    # Check if keys file exists
    if [ ! -f "$API_KEYS_FILE" ]; then
        log "ERROR" "API keys file not found. Initialize it first."
        return 1
    fi
    
    # Decrypt and get keys
    local keys_json=$(cat "$API_KEYS_FILE" | decrypt_data "$password")
    if [ $? -ne 0 ]; then
        log "ERROR" "Failed to decrypt API keys. Check your password."
        return 1
    fi
    
    # Remove the key
    keys_json=$(echo "$keys_json" | jq --arg service "$service" 'del(.[$service])')
    
    # Save back encrypted
    echo "$keys_json" | encrypt_data "$password" > "$API_KEYS_FILE"
    chmod 600 "$API_KEYS_FILE"
    
    log "SUCCESS" "API key for $service has been deleted."
}

# Change the encryption password
change_password() {
    local old_password="$1"
    local new_password="$2"
    
    # If passwords not provided, ask for them
    if [ -z "$old_password" ]; then
        read -s -p "Enter current password: " old_password
        echo
    fi
    
    if [ -z "$new_password" ]; then
        read -s -p "Enter new password: " new_password
        echo
        read -s -p "Confirm new password: " new_password_confirm
        echo
        
        if [ "$new_password" != "$new_password_confirm" ]; then
            log "ERROR" "Passwords do not match."
            return 1
        fi
    fi
    
    # Decrypt with old password
    local keys_json=$(cat "$API_KEYS_FILE" | decrypt_data "$old_password")
    if [ $? -ne 0 ]; then
        log "ERROR" "Failed to decrypt API keys. Check your old password."
        return 1
    fi
    
    # Encrypt with new password
    echo "$keys_json" | encrypt_data "$new_password" > "$API_KEYS_FILE"
    chmod 600 "$API_KEYS_FILE"
    
    log "SUCCESS" "Encryption password changed successfully."
}

# Export keys to a backup file
export_keys() {
    local backup_file="$1"
    local password="$2"
    
    # If no backup file specified, create one
    if [ -z "$backup_file" ]; then
        backup_file="$HOME/cyberkit_api_keys_backup_$(date +%Y%m%d).json"
    fi
    
    # Check if keys file exists
    if [ ! -f "$API_KEYS_FILE" ]; then
        log "ERROR" "API keys file not found. Initialize it first."
        return 1
    fi
    
    # Decrypt and export
    local keys_json=$(cat "$API_KEYS_FILE" | decrypt_data "$password")
    if [ $? -ne 0 ]; then
        log "ERROR" "Failed to decrypt API keys. Check your password."
        return 1
    fi
    
    echo "$keys_json" > "$backup_file"
    chmod 600 "$backup_file"
    
    log "SUCCESS" "API keys exported to $backup_file"
}

# Import keys from a backup file
import_keys() {
    local backup_file="$1"
    local password="$2"
    
    # Validate inputs
    if [ -z "$backup_file" ] || [ ! -f "$backup_file" ]; then
        log "ERROR" "Backup file not found: $backup_file"
        echo "Usage: import_keys <backup_file> [password]"
        return 1
    fi
    
    # Initialize if needed
    if [ ! -f "$API_KEYS_FILE" ]; then
        init_api_keys
    fi
    
    # Validate JSON format
    if ! jq empty "$backup_file" 2>/dev/null; then
        log "ERROR" "Invalid JSON format in backup file."
        return 1
    fi
    
    # Read backup and encrypt with password
    cat "$backup_file" | encrypt_data "$password" > "$API_KEYS_FILE"
    chmod 600 "$API_KEYS_FILE"
    
    log "SUCCESS" "API keys imported from $backup_file"
}

# Main function for CLI usage
api_keys_cli() {
    local action="$1"
    shift
    
    case "$action" in
        init)
            init_api_keys
            ;;
        set)
            set_api_key "$@"
            ;;
        get)
            get_api_key "$@"
            ;;
        list)
            list_api_services "$@"
            ;;
        delete)
            delete_api_key "$@"
            ;;
        change-password)
            change_password "$@"
            ;;
        export)
            export_keys "$@"
            ;;
        import)
            import_keys "$@"
            ;;
        help|--help|-h)
            echo "Usage: api-keys.sh <action> [options]"
            echo ""
            echo "Actions:"
            echo "  init                 Initialize the API keys store"
            echo "  set <service> <key>  Set an API key for a service"
            echo "  get <service>        Get an API key for a service"
            echo "  list                 List all configured services"
            echo "  delete <service>     Delete an API key"
            echo "  change-password      Change the encryption password"
            echo "  export [file]        Export keys to a backup file"
            echo "  import <file>        Import keys from a backup file"
            echo "  help                 Show this help message"
            ;;
        *)
            log "ERROR" "Unknown action: $action"
            echo "Use 'api-keys.sh help' for usage information"
            return 1
            ;;
    esac
}

# Execute main if script is run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    api_keys_cli "$@"
fi