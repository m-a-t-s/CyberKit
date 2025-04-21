API Keys Management
CyberKit provides a secure way to manage API keys for various services used in cybersecurity operations. This document explains how to use the API key management system to securely store and access your API keys without exposing them in scripts or committing them to git repositories.
Overview
The API key management system:

Uses strong encryption (AES-256-CBC) to protect your keys
Stores keys in a secure location outside your git repository
Provides a simple interface for adding, retrieving, and managing keys
Requires a password to decrypt keys, enhancing security

Services That May Require API Keys
Several tools and services used by CyberKit may require API keys:

Vulnerability Scanning Services

VirusTotal API
Shodan API
SecurityTrails API
Nuclei templates (some custom templates require API keys)


Domain Intelligence and Reconnaissance

Censys API
SpyOnWeb API
Hunter.io API
WhoisXML API


Cloud Service Providers

AWS Access Keys
Azure Service Principal Credentials
GCP Service Account Keys


Threat Intelligence Platforms

AlienVault OTX API
Recorded Future API
Mandiant API



Setting Up the API Key Store
Before using API keys, you need to initialize the secure store:
bash./common/api-keys.sh init
This will create the necessary encrypted storage in ~/.config/cyberkit/keys/.
Adding API Keys
To add a new API key:
bash./common/api-keys.sh set <service_name> <api_key>
For example:
bash./common/api-keys.sh set shodan ABC123DEF456GHI789JKL
You will be prompted for a password to encrypt the key. Remember this password as you'll need it to retrieve keys.
Retrieving API Keys in Scripts
To use an API key in your scripts:
bash# Example of how to use the API key in a script
SHODAN_API_KEY=$(./common/api-keys.sh get shodan)

# Check if we got a valid key
if [ $? -eq 0 ]; then
    # Use the key
    curl -s "https://api.shodan.io/shodan/host/search?key=$SHODAN_API_KEY&query=$TARGET"
else
    log "ERROR" "Failed to retrieve Shodan API key"
fi
Managing Your API Keys
List Available Services
To see what services you have configured:
bash./common/api-keys.sh list
Delete an API Key
To remove an API key:
bash./common/api-keys.sh delete shodan
Change Encryption Password
To change the password used for encryption:
bash./common/api-keys.sh change-password
Backup and Export
To export your keys (for backup or transfer to another system):
bash./common/api-keys.sh export ~/my_api_keys_backup.json
Import from Backup
To import keys from a backup:
bash./common/api-keys.sh import ~/my_api_keys_backup.json
Security Considerations

Never commit API keys to git - The system is designed to keep keys separate from your repository
Use strong passwords for the API key store
Backup your encrypted key store regularly
Rotate API keys periodically for better security
Use the minimum necessary privileges when creating API keys for services

Integration with CyberKit Tools
All CyberKit tools that need API keys are designed to use this system. For example, when running a web application scan that requires a Shodan API key, the tool will automatically attempt to retrieve it:
bash# Example from webapp-scan.sh
if [ "$USE_SHODAN" = true ]; then
    SHODAN_API_KEY=$(./common/api-keys.sh get shodan)
    if [ $? -eq 0 ]; then
        log "INFO" "Using Shodan API for additional reconnaissance..."
        # Use the key for scanning
    else
        log "WARNING" "Shodan API key not found. Skipping Shodan reconnaissance."
    fi
fi
This approach ensures that API keys are never hardcoded in scripts or committed to version control.