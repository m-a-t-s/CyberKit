#!/bin/bash
# engagement-setup.sh - Create standardized directory structure for engagements
# ====================================================================
# This utility creates a standardized folder structure for cybersecurity
# engagements, supporting both offensive and defensive operations.

# Source common utilities and configuration
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$SCRIPT_DIR/utils.sh"
source "$SCRIPT_DIR/config.sh"

# Display banner
print_banner "Engagement Directory Structure Setup"

# Global variables
CLIENT_NAME=""
ENGAGEMENT_NAME=""
ENGAGEMENT_TYPE="offensive" # offensive or defensive
BASE_DIR="$DEFAULT_ENGAGEMENTS_DIR"
INCLUDE_TEMPLATES=true
CREATE_GITIGNORE=true
CREATE_README=true
CUSTOM_STRUCTURE=""

# Function to parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -c|--client)
                CLIENT_NAME="$2"
                shift 2
                ;;
            -e|--engagement)
                ENGAGEMENT_NAME="$2"
                shift 2
                ;;
            -t|--type)
                if [[ "$2" == "offensive" || "$2" == "defensive" ]]; then
                    ENGAGEMENT_TYPE="$2"
                    shift 2
                else
                    log "ERROR" "Invalid engagement type: $2"
                    echo "Valid types: offensive, defensive"
                    exit 1
                fi
                ;;
            -d|--directory)
                BASE_DIR="$2"
                shift 2
                ;;
            -s|--structure)
                CUSTOM_STRUCTURE="$2"
                shift 2
                ;;
            --no-templates)
                INCLUDE_TEMPLATES=false
                shift
                ;;
            --no-gitignore)
                CREATE_GITIGNORE=false
                shift
                ;;
            --no-readme)
                CREATE_README=false
                shift
                ;;
            -h|--help)
                echo "Usage: $0 [options]"
                echo ""
                echo "Options:"
                echo "  -c, --client NAME        Client name (required)"
                echo "  -e, --engagement NAME    Engagement name (required)"
                echo "  -t, --type TYPE          Engagement type: offensive, defensive (default: offensive)"
                echo "  -d, --directory DIR      Base directory (default: $DEFAULT_ENGAGEMENTS_DIR)"
                echo "  -s, --structure FILE     Use custom structure from JSON file"
                echo "  --no-templates           Don't include template files"
                echo "  --no-gitignore           Don't create .gitignore"
                echo "  --no-readme              Don't create README.md"
                echo "  -h, --help               Show this help message"
                exit 0
                ;;
            *)
                log "ERROR" "Unknown option: $1"
                echo "Use -h or --help for usage information"
                exit 1
                ;;
        esac
    done
    
    # Check required arguments
    if [ -z "$CLIENT_NAME" ]; then
        log "ERROR" "Client name is required. Use -c or --client to specify."
        exit 1
    fi
    
    if [ -z "$ENGAGEMENT_NAME" ]; then
        log "ERROR" "Engagement name is required. Use -e or --engagement to specify."
        exit 1
    fi
    
    # Clean up input values
    CLIENT_NAME=$(sanitize_input "$CLIENT_NAME")
    ENGAGEMENT_NAME=$(sanitize_input "$ENGAGEMENT_NAME")
}

# Function to create standard offensive directory structure
create_offensive_structure() {
    local target_dir="$1"
    
    log "INFO" "Creating offensive engagement structure at $target_dir..."
    
    # Main directories
    ensure_dir "$target_dir"/{reconnaissance,scanning,enumeration,exploitation,post-exploitation,reporting,evidence,resources,logs}
    
    # Reconnaissance subdirectories
    ensure_dir "$target_dir"/reconnaissance/{passive,active,osint,network,web}
    
    # Scanning subdirectories
    ensure_dir "$target_dir"/scanning/{ports,services,vulnerabilities,web}
    
    # Enumeration subdirectories
    ensure_dir "$target_dir"/enumeration/{users,systems,services,applications}
    
    # Exploitation subdirectories
    ensure_dir "$target_dir"/exploitation/{webapps,network,social-engineering,persistence}
    
    # Post-exploitation subdirectories
    ensure_dir "$target_dir"/post-exploitation/{privilege-escalation,lateral-movement,data-exfiltration,cleanup}
    
    # Evidence subdirectories
    ensure_dir "$target_dir"/evidence/{screenshots,network-captures,credentials,files}
    
    # Reporting subdirectories
    ensure_dir "$target_dir"/reporting/{notes,findings,deliverables}
    
    log "SUCCESS" "Created offensive engagement directory structure."
}

# Function to create standard defensive directory structure
create_defensive_structure() {
    local target_dir="$1"
    
    log "INFO" "Creating defensive engagement structure at $target_dir..."
    
    # Main directories
    ensure_dir "$target_dir"/{assessment,monitoring,incident-response,hardening,reporting,evidence,resources,logs}
    
    # Assessment subdirectories
    ensure_dir "$target_dir"/assessment/{network,systems,applications,policies}
    
    # Monitoring subdirectories
    ensure_dir "$target_dir"/monitoring/{network,endpoints,logs,alerts}
    
    # Incident response subdirectories
    ensure_dir "$target_dir"/incident-response/{triage,analysis,containment,eradication,recovery}
    
    # Hardening subdirectories
    ensure_dir "$target_dir"/hardening/{network,systems,applications,policies}
    
    # Evidence subdirectories
    ensure_dir "$target_dir"/evidence/{network-captures,system-images,logs,timeline}
    
    # Reporting subdirectories
    ensure_dir "$target_dir"/reporting/{notes,findings,deliverables}
    
    log "SUCCESS" "Created defensive engagement directory structure."
}

# Function to create custom directory structure from JSON file
create_custom_structure() {
    local target_dir="$1"
    local structure_file="$2"
    
    log "INFO" "Creating custom directory structure from $structure_file..."
    
    if [ ! -f "$structure_file" ]; then
        log "ERROR" "Structure file not found: $structure_file"
        exit 1
    fi
    
    # Check if jq is available
    if ! check_tool "jq"; then
        log "ERROR" "jq is required for parsing custom structure files."
        exit 1
    fi
    
    # Parse the JSON file and create directories
    jq -r '.directories[] | .path' "$structure_file" | while read -r dir; do
        ensure_dir "$target_dir/$dir"
    done
    
    log "SUCCESS" "Created custom directory structure."
}

# Function to create template files
create_templates() {
    local target_dir="$1"
    
    log "INFO" "Creating template files..."
    
    # Create README.md if enabled
    if [ "$CREATE_README" = true ]; then
        log "INFO" "Creating README.md..."
        
        cat > "$target_dir/README.md" << EOF
# $CLIENT_NAME - $ENGAGEMENT_NAME

## Overview
- **Client:** $CLIENT_NAME
- **Engagement:** $ENGAGEMENT_NAME
- **Type:** $ENGAGEMENT_TYPE
- **Date Started:** $(date +"%Y-%m-%d")

## Scope


## Timeline
- Start Date: $(date +"%Y-%m-%d")
- End Date: 

## Team


## Contact Information


## Notes

EOF
    fi
    
    # Create .gitignore if enabled
    if [ "$CREATE_GITIGNORE" = true ]; then
        log "INFO" "Creating .gitignore..."
        
        cat > "$target_dir/.gitignore" << EOF
# Operating System Files
.DS_Store
Thumbs.db
desktop.ini

# Editor Files
*.swp
*.swo
*~
.vscode/
.idea/

# Log Files
*.log
logs/

# Sensitive Information
credentials/
*.key
*.pem
*.cer
*.pfx
*.p12

# Evidence Files
evidence/screenshots/
evidence/network-captures/
evidence/files/

# Node modules
node_modules/

# Python virtual environment
venv/
__pycache__/
*.pyc

# Temporary Files
tmp/
temp/
EOF
    fi
    
    # Create template files based on engagement type
    if [ "$INCLUDE_TEMPLATES" = true ]; then
        if [ "$ENGAGEMENT_TYPE" = "offensive" ]; then
            # Create scope.md
            cat > "$target_dir/scope.md" << EOF
# Engagement Scope

## In-Scope Assets
- 

## Out-of-Scope Assets
- 

## Rules of Engagement
- 

## Testing Windows
- 
EOF
            
            # Create findings template
            cat > "$target_dir/reporting/findings/template.md" << EOF
# Finding Template

## Overview
**Title:** 
**Severity:** (Critical, High, Medium, Low, Informational)
**Status:** (Open, Closed, In Progress)

## Description


## Evidence


## Impact


## Remediation


## References

EOF
            
            # Create report template
            cat > "$target_dir/reporting/deliverables/report-template.md" << EOF
# Security Assessment Report

## Executive Summary


## Scope and Methodology


## Key Findings
| # | Finding | Severity | Status |
|---|---------|----------|--------|
|   |         |          |        |

## Detailed Findings


## Recommendations


## Appendices

EOF
        else
            # Create defensive templates
            cat > "$target_dir/assessment/checklist.md" << EOF
# Security Assessment Checklist

## Network Security
- [ ] Firewall configurations reviewed
- [ ] Network segmentation assessed
- [ ] VPN configurations evaluated
- [ ] Wireless security reviewed

## System Security
- [ ] Operating system patch levels verified
- [ ] System hardening evaluated
- [ ] Administrative access controls reviewed
- [ ] Antivirus/EPP solutions assessed

## Application Security
- [ ] Web application security reviewed
- [ ] Database security assessed
- [ ] Authentication mechanisms evaluated
- [ ] Access control systems reviewed

## Policy & Compliance
- [ ] Security policies assessed
- [ ] Compliance requirements verified
- [ ] User awareness programs evaluated
- [ ] Incident response procedures reviewed
EOF
            
            # Create incident response template
            cat > "$target_dir/incident-response/template.md" << EOF
# Incident Response Template

## Incident Overview
**Date Detected:** 
**Date Contained:** 
**Type of Incident:** 
**Severity:** 
**Status:** 

## Detection
**How was the incident detected:**

**Initial indicators:**

## Analysis
**Affected systems:**

**Timeline of events:**

**Root cause:**

## Containment
**Actions taken:**

**Isolation measures:**

## Eradication
**Malware/threat removal:**

**Vulnerability patching:**

## Recovery
**System restoration:**

**Verification procedures:**

## Lessons Learned
**What went well:**

**What could be improved:**

**Preventive measures:**

EOF
        fi
    fi
    
    log "SUCCESS" "Template files created."
}

# Main function
main() {
    # Parse command line arguments
    parse_arguments "$@"
    
    # Create target directory name with date stamp
    local date_stamp=$(date +"%Y%m%d")
    local target_dir="$BASE_DIR/$CLIENT_NAME/$ENGAGEMENT_NAME-$date_stamp"
    
    # Ensure target directory exists
    ensure_dir "$target_dir"
    
    # Create directory structure based on type or custom structure
    if [ ! -z "$CUSTOM_STRUCTURE" ]; then
        create_custom_structure "$target_dir" "$CUSTOM_STRUCTURE"
    elif [ "$ENGAGEMENT_TYPE" = "offensive" ]; then
        create_offensive_structure "$target_dir"
    else
        create_defensive_structure "$target_dir"
    fi
    
    # Create template files
    create_templates "$target_dir"
    
    # Display completion message
    echo "${GREEN}${BOLD}"
    echo "============================================================"
    echo "Engagement directory structure created successfully!"
    echo "============================================================"
    echo "${RESET}"
    echo "Location: ${YELLOW}$target_dir${RESET}"
    echo ""
    echo "Quick access:"
    if [ "$ENGAGEMENT_TYPE" = "offensive" ]; then
        echo "1. Reconnaissance: ${YELLOW}cd $target_dir/reconnaissance${RESET}"
        echo "2. Scanning: ${YELLOW}cd $target_dir/scanning${RESET}"
        echo "3. Exploitation: ${YELLOW}cd $target_dir/exploitation${RESET}"
        echo "4. Reporting: ${YELLOW}cd $target_dir/reporting${RESET}"
    else
        echo "1. Assessment: ${YELLOW}cd $target_dir/assessment${RESET}"
        echo "2. Monitoring: ${YELLOW}cd $target_dir/monitoring${RESET}"
        echo "3. Incident Response: ${YELLOW}cd $target_dir/incident-response${RESET}"
        echo "4. Reporting: ${YELLOW}cd $target_dir/reporting${RESET}"
    fi
}

# Execute main if script is run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi