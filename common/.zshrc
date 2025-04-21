# Cybersecurity Toolkit .zshrc Configuration
# ----------------------------------------------------------------------

# General Configuration
# ----------------------------------------------------------------------
# History Configuration
HISTFILE=~/.zsh_history
HISTSIZE=10000
SAVEHIST=10000
setopt SHARE_HISTORY          # share history across terminals
setopt EXTENDED_HISTORY       # record timestamp of command
setopt HIST_EXPIRE_DUPS_FIRST # delete duplicates first when HISTFILE size exceeds HISTSIZE
setopt HIST_IGNORE_DUPS       # avoid storing duplicates
setopt HIST_VERIFY            # don't execute immediately upon history expansion

# Better directory navigation
setopt AUTO_CD           # cd by typing directory name
setopt AUTO_PUSHD        # pushd automatically on cd
setopt PUSHD_IGNORE_DUPS # don't push duplicates on stack

# Automatically use colored output
export CLICOLOR=1
export LSCOLORS=ExFxCxDxBxegedabagacad

# Better completion
autoload -Uz compinit
compinit
zstyle ':completion:*' menu select
zstyle ':completion:*' matcher-list 'm:{a-zA-Z}={A-Za-z}' # case-insensitive matching

# Security Tool Aliases
# ----------------------------------------------------------------------

# Reconnaissance
alias nmap-quick='nmap -T4 -F'
alias nmap-full='nmap -T4 -A -v'
alias nmap-vuln='nmap -T4 --script vuln'
alias nmap-top-ports='nmap -T4 --top-ports 1000'
alias nmap-stealth='sudo nmap -sS -T4'

# Web App Testing
alias zap-proxy='zaproxy'
alias burp='java -jar ~/tools/burpsuite/burpsuite_pro.jar'
alias dirb-common='dirb $1 /usr/share/dirb/wordlists/common.txt'
alias nikto-full='nikto -host $1 -port 80,443 -Tuning 1234567890abcde -C all'

# Exploitation
alias msf='msfconsole'
alias msfvenom-list='msfvenom --list formats'
alias msfvenom-windows='msfvenom -p windows/meterpreter/reverse_tcp'
alias msfvenom-linux='msfvenom -p linux/x86/meterpreter/reverse_tcp'
alias msfdb-update='sudo msfdb reinit'

# Port Forwarding/Proxies
alias socks5='ssh -D 8080 -f -C -q -N $1' # Create SOCKS proxy via SSH
alias chisel-server='chisel server -p 8080 --reverse'
alias chisel-client='chisel client $1 R:socks'

# Password Attacks
alias hashcat-md5='hashcat -m 0 -a 0 $1 /usr/share/wordlists/rockyou.txt'
alias hashcat-sha1='hashcat -m 100 -a 0 $1 /usr/share/wordlists/rockyou.txt'
alias hashcat-ntlm='hashcat -m 1000 -a 0 $1 /usr/share/wordlists/rockyou.txt'
alias hydra-ssh='hydra -l $1 -P /usr/share/wordlists/rockyou.txt ssh://$2'
alias hydra-web-form='hydra -l $1 -P /usr/share/wordlists/rockyou.txt $2 http-post-form "/login.php:username=^USER^&password=^PASS^:Login failed"'

# Defensive/Monitoring
alias tcpdump-basic='sudo tcpdump -i $1 -n'
alias tcpdump-http='sudo tcpdump -i $1 -n port 80 or port 443'
alias wireshark-quick='sudo wireshark -i $1 -k'
alias check-listening='sudo netstat -tulpn | grep LISTEN'
alias suricata-check='sudo suricata -T -c /etc/suricata/suricata.yaml'
alias wazuh-status='sudo systemctl status wazuh-manager'

# File Analysis/Forensics
alias binwalk-extract='binwalk -e $1'
alias volatility='python ~/tools/volatility/vol.py'
alias foremost-all='foremost -i $1 -o output'
alias strings-all='strings -a $1 | grep -i $2'
alias exiftool-all='exiftool $1'

# Information Gathering
alias whois-domain='whois $1'
alias dig-all='dig +nocmd $1 any +multiline +noall +answer'
alias traceroute-tcp='traceroute -T -p 80 $1'
alias harvester='theHarvester -d $1 -l 500 -b all'

# Project Management
alias create-project='function _create_project() { mkdir -p $1/{recon,enum,exploit,privesc,loot}; echo "Project created at $1"; }; _create_project'
alias create-report='function _create_report() { cp ~/templates/pentest-report.md $1/report-$(date +"%Y%m%d").md; }; _create_report'

# Documentation
alias screenshot='scrot -s ~/recon/%Y-%m-%d-%T-screenshot.png'
alias record-terminal='asciinema rec ~/documentation/terminal-session-$(date +"%Y%m%d-%H%M%S").cast'

# Helper Functions
# ----------------------------------------------------------------------

# Create a new engagement directory with standard subdirectories
function new-engagement() {
    if [ -z "$1" ]; then
        echo "Usage: new-engagement <client-name>"
        return 1
    fi
    
    local basedir="$HOME/engagements/$1-$(date +"%Y%m%d")"
    mkdir -p "$basedir"/{recon,scans,exploitation,evidence,report,logs}
    
    echo "# $1 Engagement Notes - $(date +"%Y-%m-%d")" > "$basedir/notes.md"
    echo "## Scope\n\n## Findings\n\n## Timeline\n\n" >> "$basedir/notes.md"
    
    echo "Engagement directory created at $basedir"
    cd "$basedir"
}

# Quick function to scan a target and output to a file
function quick-scan() {
    if [ -z "$1" ]; then
        echo "Usage: quick-scan <target>"
        return 1
    fi
    
    local outfile="nmap-quick-$(echo $1 | tr '/' '_' | tr ':' '_').txt"
    echo "Scanning $1, output to $outfile"
    nmap -T4 -F -oN "$outfile" "$1"
    echo "Scan complete."
}

# Function to start common Docker containers for security tools
function start-container() {
    case "$1" in
        kali)
            docker run --rm -it --name kali-instance kalilinux/kali-rolling
            ;;
        metasploit)
            docker run --rm -it --name msf -p 4444:4444 metasploitframework/metasploit-framework
            ;;
        openvas)
            docker run --rm -it --name openvas -p 443:443 -p 9390:9390 -p 9392:9392 -v openvas:/data greenbone/openvas
            ;;
        *)
            echo "Usage: start-container <kali|metasploit|openvas>"
            return 1
            ;;
    esac
}

# Function to extract IP addresses from a file
function extract-ips() {
    if [ -z "$1" ]; then
        echo "Usage: extract-ips <file>"
        return 1
    fi
    
    grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" "$1" | sort -u
}

# Function to convert Nmap XML output to HTML report
function nmap-report() {
    if [ -z "$1" ]; then
        echo "Usage: nmap-report <nmap-xml-file>"
        return 1
    fi
    
    local outfile="${1%.*}-report.html"
    xsltproc -o "$outfile" /usr/share/nmap/nmap.xsl "$1"
    echo "Report generated: $outfile"
}

# Additional Configuration
# ----------------------------------------------------------------------

# Source other custom scripts or configurations
if [ -f ~/.zsh_security_functions ]; then
    source ~/.zsh_security_functions
fi

# Add custom paths for security tools
export PATH=$PATH:$HOME/tools/bin:/usr/local/bin:/snap/bin

# Additional environment variables
export WORDLIST_PATH="/usr/share/wordlists"
export ROCKYOU_PATH="/usr/share/wordlists/rockyou.txt"
export SECLIST_PATH="/usr/share/seclists"

# Tools-specific configurations
export MSF_DATABASE_CONFIG=/opt/metasploit-framework/config/database.yml

# Optional: Integration with tmux for multi-pane security workflows
if [ -n "$1" ] && [ "$1" = "security-session" ]; then
    tmux new-session -s security -n 'scan' \; \
        split-window -v -p 50 \; \
        new-window -n 'exploit' \; \
        new-window -n 'monitor' \; \
        select-window -t 1 \;
fi

# End of configuration