#!/usr/bin/env bash

#####################################################################
# Bug Bounty Tools Installer for Kali Linux (WSL2 / Native)
# 
# Features:
# - Safe, idempotent installation
# - Proper user/sudo handling
# - Go and Python environment setup
# - Comprehensive verification
#####################################################################

set -euo pipefail

# Script metadata
SCRIPT_VERSION="1.0.0"
SCRIPT_NAME="$(basename "$0")"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"

# Determine actual user and home
ACTUAL_USER="${SUDO_USER:-$USER}"
if [[ "$ACTUAL_USER" == "root" ]]; then
    ACTUAL_USER="$(logname 2>/dev/null || echo "$USER")"
fi
ACTUAL_HOME="$(eval echo ~"$ACTUAL_USER")"

# Paths
TOOLS_DIR="/opt"
LOG_FILE="${ACTUAL_HOME}/install-log-${TIMESTAMP}.log"
GOPATH="${ACTUAL_HOME}/go"
GO_BIN="${GOPATH}/bin"

# Tool tracking
declare -A TOOL_STATUS
declare -A TOOL_PATH
declare -A TOOL_NOTES

# Logging functions
log_info() {
    echo -e "\e[34m[INFO]\e[0m $*" | tee -a "$LOG_FILE"
}

log_success() {
    echo -e "\e[32m[SUCCESS]\e[0m $*" | tee -a "$LOG_FILE"
}

log_warn() {
    echo -e "\e[33m[WARN]\e[0m $*" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "\e[31m[ERROR]\e[0m $*" | tee -a "$LOG_FILE"
}

log_section() {
    echo -e "\n\e[1m\e[35m=== $* ===\e[0m\n" | tee -a "$LOG_FILE"
}

# Error handler
error_handler() {
    local line_no=$1
    log_error "Script failed at line $line_no"
    log_error "Check log file: $LOG_FILE"
    exit 1
}

trap 'error_handler ${LINENO}' ERR

# Check if running with sudo
check_sudo() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run with sudo privileges"
        log_error "Usage: sudo ./$SCRIPT_NAME"
        exit 1
    fi
    log_success "Running with sudo privileges as user: $ACTUAL_USER"
}

# Detect WSL2
detect_wsl2() {
    if grep -qiE '(Microsoft|WSL)' /proc/version 2>/dev/null; then
        log_warn "WSL2 environment detected"
        return 0
    fi
    return 1
}

# Run command as actual user
run_as_user() {
    sudo -H -u "$ACTUAL_USER" bash -c "$*"
}

# Install system packages
install_system_deps() {
    log_section "Installing System Dependencies"
    
    local packages=(
        build-essential
        clang
        gcc
        pkg-config
        libssl-dev
        libxml2-dev
        libxslt1-dev
        libldns-dev
        libffi-dev
        python3-dev
        python3-venv
        python3-pip
        git
        curl
        wget
        ca-certificates
        apt-transport-https
        software-properties-common
    )
    
    log_info "Updating apt cache..."
    apt-get update -qq
    
    log_info "Installing build dependencies..."
    for pkg in "${packages[@]}"; do
        if ! dpkg -l | grep -q "^ii  $pkg "; then
            log_info "Installing $pkg..."
            apt-get install -y "$pkg" >> "$LOG_FILE" 2>&1
        else
            log_info "$pkg already installed"
        fi
    done
    
    log_success "System dependencies installed"
}

# Setup Go environment
setup_go() {
    log_section "Setting Up Go Environment"
    
    if ! command -v go &>/dev/null; then
        log_info "Installing Go from apt repository..."
        apt-get install -y golang >> "$LOG_FILE" 2>&1
    else
        log_info "Go already installed"
    fi
    
    local go_version=$(go version | awk '{print $3}')
    log_success "Go installed: $go_version"
    
    # Configure GOPATH
    export GOPATH="$GOPATH"
    export PATH="$GO_BIN:$PATH"
    
    log_info "Creating Go directories..."
    mkdir -p "$GOPATH"/{bin,src,pkg}
    chown -R "$ACTUAL_USER:$ACTUAL_USER" "$GOPATH"
    
    # Add to bashrc idempotently
    local bashrc="${ACTUAL_HOME}/.bashrc"
    if ! grep -q "export GOPATH=" "$bashrc" 2>/dev/null; then
        log_info "Adding GOPATH to $bashrc..."
        tee -a "$bashrc" > /dev/null << EOF

# Go environment (added by bug bounty tools installer)
export GOPATH="\$HOME/go"
export PATH="\$GOPATH/bin:\$PATH"
EOF
    fi
    
    log_success "Go environment configured"
}

# Setup pipx
setup_pipx() {
    log_section "Setting Up pipx"
    
    if ! command -v pipx &>/dev/null; then
        log_info "Installing pipx..."
        apt-get install -y python3-pipx >> "$LOG_FILE" 2>&1
    else
        log_info "pipx already installed"
    fi
    
    log_info "Ensuring pipx path..."
    run_as_user "pipx ensurepath" >> "$LOG_FILE" 2>&1 || true
    
    # Add to PATH for this script
    export PATH="${ACTUAL_HOME}/.local/bin:$PATH"
    
    # Add to bashrc idempotently
    local bashrc="${ACTUAL_HOME}/.bashrc"
    if ! grep -q ".local/bin" "$bashrc" 2>/dev/null; then
        log_info "Adding .local/bin to PATH in $bashrc..."
        tee -a "$bashrc" > /dev/null << 'EOF'

# Python local bin (added by bug bounty tools installer)
export PATH="$HOME/.local/bin:$PATH"
EOF
    fi
    
    log_success "pipx configured"
}

# Install Go tool
install_go_tool() {
    local tool_name="$1"
    local go_module="$2"
    local extra_env="$3"
    
    log_info "Installing $tool_name via go install..."
    
    local install_cmd="export GOPATH=$GOPATH && export PATH=$GO_BIN:\$PATH && $extra_env go install -v $go_module@latest"
    
    if run_as_user "$install_cmd" >> "$LOG_FILE" 2>&1; then
        local binary_name=$(basename "$go_module" | cut -d'/' -f1)
        local binary_path="$GO_BIN/$binary_name"
        
        if [[ -f "$binary_path" ]]; then
            TOOL_STATUS["$tool_name"]="OK"
            TOOL_PATH["$tool_name"]="$binary_path"
            log_success "$tool_name installed successfully"
        else
            TOOL_STATUS["$tool_name"]="FAIL"
            TOOL_NOTES["$tool_name"]="Binary not found after install"
            log_error "$tool_name installation failed - binary not found"
        fi
    else
        TOOL_STATUS["$tool_name"]="FAIL"
        TOOL_NOTES["$tool_name"]="go install failed (check log)"
        log_error "$tool_name installation failed"
    fi
}

# Install pipx tool
install_pipx_tool() {
    local tool_name="$1"
    local package="$2"
    
    log_info "Installing $tool_name via pipx..."
    
    if run_as_user "pipx install $package" >> "$LOG_FILE" 2>&1; then
        TOOL_STATUS["$tool_name"]="OK"
        TOOL_PATH["$tool_name"]="${ACTUAL_HOME}/.local/bin/$tool_name"
        log_success "$tool_name installed successfully"
    else
        TOOL_STATUS["$tool_name"]="FAIL"
        TOOL_NOTES["$tool_name"]="pipx install failed (check log)"
        log_error "$tool_name installation failed"
    fi
}

# Install apt tool
install_apt_tool() {
    local tool_name="$1"
    local package="${2:-$tool_name}"
    
    log_info "Installing $tool_name via apt..."
    
    if apt-get install -y "$package" >> "$LOG_FILE" 2>&1; then
        TOOL_STATUS["$tool_name"]="OK"
        local bin_path=$(command -v "$tool_name" 2>/dev/null || echo "N/A")
        TOOL_PATH["$tool_name"]="$bin_path"
        log_success "$tool_name installed successfully"
    else
        TOOL_STATUS["$tool_name"]="FAIL"
        TOOL_NOTES["$tool_name"]="apt install failed (check log)"
        log_error "$tool_name installation failed"
    fi
}

# Install git repo tool
install_git_tool() {
    local tool_name="$1"
    local repo_url="$2"
    local post_install="$3"
    
    local repo_dir="$TOOLS_DIR/$tool_name"
    
    log_info "Installing $tool_name from git..."
    
    if [[ -d "$repo_dir" ]]; then
        log_info "$tool_name already cloned, pulling latest..."
        cd "$repo_dir" && git pull >> "$LOG_FILE" 2>&1 || true
    else
        if git clone "$repo_url" "$repo_dir" >> "$LOG_FILE" 2>&1; then
            log_success "Cloned $tool_name"
        else
            TOOL_STATUS["$tool_name"]="FAIL"
            TOOL_NOTES["$tool_name"]="git clone failed"
            log_error "$tool_name clone failed"
            return 1
        fi
    fi
    
    chown -R "$ACTUAL_USER:$ACTUAL_USER" "$repo_dir"
    
    # Run post-install commands
    if [[ -n "$post_install" ]]; then
        log_info "Running post-install for $tool_name..."
        if run_as_user "cd $repo_dir && $post_install" >> "$LOG_FILE" 2>&1; then
            TOOL_STATUS["$tool_name"]="OK"
            TOOL_PATH["$tool_name"]="$repo_dir"
            log_success "$tool_name post-install completed"
        else
            TOOL_STATUS["$tool_name"]="FAIL"
            TOOL_NOTES["$tool_name"]="Post-install failed. Try: pip3 install --user -r requirements.txt"
            log_error "$tool_name post-install failed"
        fi
    else
        TOOL_STATUS["$tool_name"]="OK"
        TOOL_PATH["$tool_name"]="$repo_dir"
        log_success "$tool_name installed successfully"
    fi
}

# Install proxychains
install_proxychains() {
    log_section "Installing proxychains"
    
    if apt-get install -y proxychains4 >> "$LOG_FILE" 2>&1; then
        TOOL_STATUS["proxychains"]="OK"
        TOOL_PATH["proxychains"]=$(command -v proxychains4)
        log_success "proxychains4 installed successfully"
    elif apt-get install -y proxychains >> "$LOG_FILE" 2>&1; then
        TOOL_STATUS["proxychains"]="OK"
        TOOL_PATH["proxychains"]=$(command -v proxychains)
        log_success "proxychains installed successfully"
    else
        TOOL_STATUS["proxychains"]="FAIL"
        TOOL_NOTES["proxychains"]="apt install failed"
        log_error "proxychains installation failed"
    fi
}

# Note manual GUI tools
note_manual_tools() {
    log_section "GUI Tools - Manual Installation Required"
    
    log_warn "The following GUI tools must be installed manually:"
    echo ""
    echo "  - Chrome"
    echo "  - Firefox"
    echo "  - Burp Suite"
    echo "  - ZAP (OWASP ZAP)"
    echo "  - Caido"
    echo "  - Postman"
    echo ""
    log_info "These tools are not automatically installed by this script"
    
    # Mark them as manual in the report
    TOOL_STATUS["Chrome"]="MANUAL"
    TOOL_NOTES["Chrome"]="Install manually"
    
    TOOL_STATUS["Firefox"]="MANUAL"
    TOOL_NOTES["Firefox"]="Install manually"
    
    TOOL_STATUS["Burp Suite"]="MANUAL"
    TOOL_NOTES["Burp Suite"]="Install manually"
    
    TOOL_STATUS["ZAP"]="MANUAL"
    TOOL_NOTES["ZAP"]="Install manually"
    
    TOOL_STATUS["Caido"]="MANUAL"
    TOOL_NOTES["Caido"]="Install manually"
    
    TOOL_STATUS["Postman"]="MANUAL"
    TOOL_NOTES["Postman"]="Install manually"
}

# Main installation function
install_all_tools() {
    log_section "Installing Bug Bounty Tools"
    
    # Note manual tools
    note_manual_tools
    
    # Go-based tools
    log_section "Installing Go-based Tools"
    
    install_go_tool "httpx" "github.com/projectdiscovery/httpx/cmd/httpx" ""
    install_go_tool "shuffledns" "github.com/projectdiscovery/shuffledns/cmd/shuffledns" ""
    install_go_tool "subfinder" "github.com/projectdiscovery/subfinder/v2/cmd/subfinder" ""
    install_go_tool "chaos-client" "github.com/projectdiscovery/chaos-client/cmd/chaos" ""
    install_go_tool "ffuf" "github.com/ffuf/ffuf/v2" ""
    install_go_tool "waybackurls" "github.com/tomnomnom/waybackurls" ""
    install_go_tool "gau" "github.com/lc/gau/v2/cmd/gau" ""
    install_go_tool "hakrawler" "github.com/hakluke/hakrawler" ""
    install_go_tool "katana" "github.com/projectdiscovery/katana/cmd/katana" "CGO_ENABLED=1"
    install_go_tool "assetfinder" "github.com/tomnomnom/assetfinder" ""
    install_go_tool "prips" "github.com/imusabkhan/prips" ""
    install_go_tool "jsluice" "github.com/BishopFox/jsluice/cmd/jsluice" ""
    install_go_tool "gospider" "github.com/jaeles-project/gospider" "GO111MODULE=on"
    install_go_tool "shosubgo" "github.com/incogbyte/shosubgo" ""
    install_go_tool "wordlistgen" "github.com/ameenmaali/wordlistgen" ""
    install_go_tool "anew" "github.com/tomnomnom/anew" ""
    install_go_tool "cf-hero" "github.com/musana/cf-hero/cmd/cf-hero" ""
    
    # pipx-based tools
    log_section "Installing Python Tools (pipx)"
    
    install_pipx_tool "bbot" "bbot"
    install_pipx_tool "arjun" "arjun"
    install_pipx_tool "waymore" "git+https://github.com/xnl-h4ck3r/waymore.git"
    
    # apt-based tools
    log_section "Installing APT Tools"
    
    install_apt_tool "theHarvester" "theharvester"
    install_apt_tool "Amass" "amass"
    install_apt_tool "massdns" "massdns"
    install_apt_tool "cewl" "cewl"
    install_apt_tool "apktool" "apktool"
    
    # proxychains
    install_proxychains
    
    # Git-based tools
    log_section "Installing Git-based Tools"
    
    install_git_tool "trufflehog" "https://github.com/trufflesecurity/trufflehog.git" ""
    install_git_tool "GitDorker" "https://github.com/obheda12/GitDorker.git" "pip3 install --user -r requirements.txt"
    install_git_tool "github-search" "https://github.com/gwen001/github-search.git" "pip3 install --user -r requirements.txt"
    install_git_tool "Ghauri" "https://github.com/r0oth3x49/ghauri.git" "pip3 install --user -r requirements.txt"
    install_git_tool "CloakQuest3r" "https://github.com/spyboy-productions/CloakQuest3r.git" "pip3 install --user -r requirements.txt"
    install_git_tool "resolvers" "https://github.com/trickest/resolvers.git" ""
    
    log_success "Tool installation complete!"
}

# Verify installations
verify_tools() {
    log_section "Verifying Tool Installations"
    
    for tool in "${!TOOL_STATUS[@]}"; do
        if [[ "${TOOL_STATUS[$tool]}" == "OK" ]]; then
            local tool_path="${TOOL_PATH[$tool]}"
            
            # Try to run verification command
            case $tool in
                httpx|subfinder|ffuf|waybackurls|gau|hakrawler|katana|assetfinder|anew|shuffledns|chaos-client|prips|jsluice|gospider|shosubgo|wordlistgen|cf-hero)
                    if run_as_user "$tool_path -h" >> "$LOG_FILE" 2>&1; then
                        log_success "$tool verified: $tool_path"
                    else
                        TOOL_STATUS["$tool"]="WARN"
                        TOOL_NOTES["$tool"]="Installed but verification failed"
                        log_warn "$tool verification failed"
                    fi
                    ;;
                bbot|arjun|waymore)
                    if run_as_user "$tool_path --help" >> "$LOG_FILE" 2>&1; then
                        log_success "$tool verified: $tool_path"
                    else
                        TOOL_STATUS["$tool"]="WARN"
                        TOOL_NOTES["$tool"]="Installed but verification failed"
                        log_warn "$tool verification failed"
                    fi
                    ;;
                *)
                    log_info "$tool marked as OK (path: $tool_path)"
                    ;;
            esac
        fi
    done
}

# Generate final report
generate_report() {
    log_section "Installation Report"
    
    local report_file="${ACTUAL_HOME}/bugbounty-tools-report-${TIMESTAMP}.txt"
    
    {
        echo "========================================================================"
        echo "Bug Bounty Tools Installation Report"
        echo "========================================================================"
        echo "Date: $(date)"
        echo "User: $ACTUAL_USER"
        echo "Home: $ACTUAL_HOME"
        echo "Tools Directory: $TOOLS_DIR"
        echo "Go Path: $GOPATH"
        echo "Log File: $LOG_FILE"
        echo ""
        echo "========================================================================"
        echo "Tool Status Summary"
        echo "========================================================================"
        printf "%-25s %-12s %-40s %s\n" "TOOL NAME" "STATUS" "PATH" "NOTES"
        echo "------------------------------------------------------------------------"
        
        for tool in $(echo "${!TOOL_STATUS[@]}" | tr ' ' '\n' | sort); do
            local status="${TOOL_STATUS[$tool]}"
            local path="${TOOL_PATH[$tool]:-N/A}"
            local notes="${TOOL_NOTES[$tool]:-}"
            
            # Truncate long paths for display
            if [[ ${#path} -gt 40 ]]; then
                path="...${path: -37}"
            fi
            
            printf "%-25s %-12s %-40s %s\n" "$tool" "$status" "$path" "$notes"
        done
        
        echo ""
        echo "========================================================================"
        echo "Statistics"
        echo "========================================================================"
        
        local total=0
        local ok=0
        local fail=0
        local manual=0
        local warn=0
        
        for status in "${TOOL_STATUS[@]}"; do
            ((total++))
            case $status in
                OK) ((ok++)) ;;
                FAIL) ((fail++)) ;;
                MANUAL) ((manual++)) ;;
                WARN) ((warn++)) ;;
            esac
        done
        
        echo "Total Tools: $total"
        echo "Successful: $ok"
        echo "Failed: $fail"
        echo "Manual Install Required: $manual"
        echo "Warnings: $warn"
        
        echo ""
        echo "========================================================================"
        echo "Manual Installation Required"
        echo "========================================================================"
        echo ""
        echo "The following GUI tools must be installed manually:"
        echo ""
        
        for tool in "${!TOOL_STATUS[@]}"; do
            if [[ "${TOOL_STATUS[$tool]}" == "MANUAL" ]]; then
                echo "  - $tool"
            fi
        done
        
        echo ""
        echo "========================================================================"
        echo "Failed Installations"
        echo "========================================================================"
        
        local has_failures=0
        for tool in "${!TOOL_STATUS[@]}"; do
            if [[ "${TOOL_STATUS[$tool]}" == "FAIL" ]]; then
                has_failures=1
                echo ""
                echo "[$tool] - FAILED"
                if [[ -n "${TOOL_NOTES[$tool]}" ]]; then
                    echo "  ${TOOL_NOTES[$tool]}"
                fi
            fi
        done
        
        if [[ $has_failures -eq 0 ]]; then
            echo ""
            echo "No failures detected!"
        fi
        
        echo ""
        echo "========================================================================"
        echo "Verification Commands"
        echo "========================================================================"
        echo ""
        echo "# Test Go tools:"
        echo "httpx -h"
        echo "subfinder -h"
        echo "ffuf -h"
        echo "katana -h"
        echo ""
        echo "# Test Python tools:"
        echo "bbot --help"
        echo "arjun --help"
        echo "waymore --help"
        echo ""
        echo "# Test Git-based tools:"
        echo "python3 /opt/GitDorker/GitDorker.py -h"
        echo "python3 /opt/Ghauri/ghauri.py -h"
        echo ""
        echo "# Source your bashrc to update PATH:"
        echo "source ~/.bashrc"
        echo ""
        echo "========================================================================"
        echo "Important Notes"
        echo "========================================================================"
        echo ""
        echo "1. All Git repositories are cloned in: /opt"
        echo ""
        echo "2. API Keys: Some tools require API keys for full functionality:"
        echo "   - Subfinder: ~/.config/subfinder/config.yaml"
        echo "   - Amass: ~/.config/amass/config.ini"
        echo "   - Shosubgo: SHODAN_API_KEY environment variable"
        echo "   - Chaos: ~/.config/chaos/config.yaml"
        echo ""
        echo "3. Tool Updates: To update Go tools, re-run their install commands:"
        echo "   go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
        echo ""
        echo "4. Python Tools: For tools in /opt, pull latest with:"
        echo "   cd /opt/<tool-name> && git pull"
        echo ""
        echo "5. Wordlists: Consider downloading SecLists:"
        echo "   git clone https://github.com/danielmiessler/SecLists.git /opt/SecLists"
        echo ""
        echo "========================================================================"
        
    } | tee "$report_file"
    
    log_success "Report saved to: $report_file"
    
    # Print summary to console
    echo ""
    log_section "Quick Summary"
    echo "✓ Successful: $ok tools"
    if [[ $fail -gt 0 ]]; then
        echo "✗ Failed: $fail tools (see report for details)"
    fi
    if [[ $manual -gt 0 ]]; then
        echo "⊙ Manual Install Required: $manual tools"
    fi
    echo ""
    log_info "Full report: $report_file"
    log_info "Installation log: $LOG_FILE"
}

# Print final instructions
print_final_instructions() {
    log_section "Next Steps"
    
    cat << EOF

1. Reload your shell configuration:
   source ~/.bashrc

2. Verify tool installations:
   httpx -h
   subfinder -h
   bbot --help

3. Configure API keys for enhanced functionality:
   - Subfinder: ~/.config/subfinder/config.yaml
   - Amass: ~/.config/amass/config.ini
   - Shodan: export SHODAN_API_KEY="your-key"

4. Install GUI tools manually (if needed):
   - Chrome
   - Firefox
   - Burp Suite
   - ZAP
   - Caido
   - Postman

5. Download wordlists (optional):
   sudo git clone https://github.com/danielmiessler/SecLists.git /opt/SecLists

6. All Git-based tools are in /opt directory

Happy hunting! 🎯

EOF
}

# Main execution
main() {
    # Initialize log
    touch "$LOG_FILE"
    chown "$ACTUAL_USER:$ACTUAL_USER" "$LOG_FILE"
    
    log_section "Bug Bounty Tools Installer v${SCRIPT_VERSION}"
    log_info "Starting installation at $(date)"
    log_info "Running as: $(whoami)"
    log_info "Target user: $ACTUAL_USER"
    log_info "Target home: $ACTUAL_HOME"
    log_info "Tools directory: $TOOLS_DIR"
    
    # Check prerequisites
    check_sudo
    detect_wsl2
    
    # Setup environment
    install_system_deps
    setup_go
    setup_pipx
    
    # Install tools
    install_all_tools
    
    # Verify and report
    verify_tools
    generate_report
    print_final_instructions
    
    log_success "Installation completed successfully!"
    log_info "Please review the report and install GUI tools manually as needed."
}

# Run main function
main "$@"
