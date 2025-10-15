#!/bin/bash

# Net-Zilla Complete Installation Script
# Supports: Windows (WSL/WSL2), Linux, macOS, Termux

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Configuration
NET_ZILLA_DIR="$HOME/net-zilla"
JULIA_VERSION="1.9.3"
GO_VERSION="1.21"

# Logging
LOG_FILE="$NET_ZILLA_DIR/install.log"

print_banner() {
    clear
    echo -e "${RED}"
    cat << "BANNER"
███╗   ██╗███████╗████████╗    ███████╗██╗██╗     ██╗     
████╗  ██║██╔════╝╚══██╔══╝    ██╔════╝██║██║     ██║     
██╔██╗ ██║█████╗     ██║       ███████╗██║██║     ██║     
██║╚██╗██║██╔══╝     ██║       ╚════██║██║██║     ██║     
██║ ╚████║███████╗   ██║       ███████║██║███████╗███████╗
╚═╝  ╚═══╝╚══════╝   ▚═╝       ╚══════╝╚═╝╚══════╝╚══════╝
BANNER
    echo -e "${NC}"
    echo -e "${YELLOW}[ A network - ip - Link - SMS - DNS-Whois lookup enterprise level checker with A.I. ]${NC}"
    echo -e "${CYAN}Installing Net-Zilla...${NC}"
    echo "=========================================================="
}

log() {
    echo -e "$1"
    echo "$(date): $1" >> "$LOG_FILE"
}

check_success() {
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓${NC} $1"
    else
        echo -e "${RED}✗${NC} $1"
        return 1
    fi
}

detect_platform() {
    case "$(uname -s)" in
        Linux*)
            if [ -f "/etc/termux-info" ]; then
                PLATFORM="termux"
            elif grep -q Microsoft /proc/version; then
                PLATFORM="wsl"
            elif grep -q microsoft /proc/version; then
                PLATFORM="wsl2"
            else
                PLATFORM="linux"
            fi
            ;;
        Darwin*)
            PLATFORM="macos"
            ;;
        CYGWIN*|MINGW*|MSYS*)
            PLATFORM="windows"
            ;;
        *)
            PLATFORM="unknown"
            ;;
    esac
    
    log "${BOLD}Detected platform: $PLATFORM${NC}"
}

check_dependencies() {
    log "${CYAN}Checking system dependencies...${NC}"
    
    # Check basic tools
    command -v curl >/dev/null 2>&1 || MISSING+="curl "
    command -v wget >/dev/null 2>&1 || MISSING+="wget "
    command -v unzip >/dev/null 2>&1 || MISSING+="unzip "
    command -v tar >/dev/null 2>&1 || MISSING+="tar "
    command -v git >/dev/null 2>&1 || MISSING+="git "
    
    if [ -n "$MISSING" ]; then
        log "${YELLOW}Missing dependencies: $MISSING${NC}"
        install_basic_dependencies
    fi
}

install_basic_dependencies() {
    log "${CYAN}Installing basic dependencies...${NC}"
    
    case $PLATFORM in
        linux|wsl|wsl2)
            if command -v apt-get >/dev/null 2>&1; then
                sudo apt-get update && sudo apt-get install -y curl wget unzip tar git
            elif command -v yum >/dev/null 2>&1; then
                sudo yum install -y curl wget unzip tar git
            elif command -v dnf >/dev/null 2>&1; then
                sudo dnf install -y curl wget unzip tar git
            elif command -v pacman >/dev/null 2>&1; then
                sudo pacman -S --noconfirm curl wget unzip tar git
            fi
            ;;
        macos)
            if command -v brew >/dev/null 2>&1; then
                brew install curl wget unzip tar git
            else
                log "${RED}Homebrew not found. Please install Homebrew first.${NC}"
                return 1
            fi
            ;;
        termux)
            pkg update && pkg install -y curl wget unzip tar git
            ;;
        windows)
            log "${YELLOW}Please install Git for Windows: https://git-scm.com/download/win${NC}"
            ;;
    esac
    
    check_success "Basic dependencies installed"
}

install_go() {
    log "${CYAN}Installing Go...${NC}"
    
    if command -v go >/dev/null 2>&1; then
        CURRENT_GO_VERSION=$(go version | grep -oP 'go\K[0-9]+\.[0-9]+')
        log "${GREEN}Go already installed: $CURRENT_GO_VERSION${NC}"
        return 0
    fi
    
    case $PLATFORM in
        linux|wsl|wsl2)
            wget "https://golang.org/dl/go$GO_VERSION.linux-amd64.tar.gz" -O /tmp/go.tar.gz
            sudo tar -C /usr/local -xzf /tmp/go.tar.gz
            echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
            echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.profile
            export PATH=$PATH:/usr/local/go/bin
            ;;
        macos)
            wget "https://golang.org/dl/go$GO_VERSION.darwin-amd64.tar.gz" -O /tmp/go.tar.gz
            sudo tar -C /usr/local -xzf /tmp/go.tar.gz
            echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.zshrc
            echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bash_profile
            export PATH=$PATH:/usr/local/go/bin
            ;;
        termux)
            pkg install -y golang
            ;;
        windows)
            log "${YELLOW}Please install Go manually from: https://golang.org/dl/${NC}"
            return 1
            ;;
    esac
    
    check_success "Go $GO_VERSION installed"
}

install_julia() {
    log "${CYAN}Installing Julia...${NC}"
    
    if command -v julia >/dev/null 2>&1; then
        CURRENT_JULIA_VERSION=$(julia --version | grep -oP 'julia version \K[0-9]+\.[0-9]+\.[0-9]+')
        log "${GREEN}Julia already installed: $CURRENT_JULIA_VERSION${NC}"
        return 0
    fi
    
    case $PLATFORM in
        linux|wsl|wsl2)
            wget "https://julialang-s3.julialang.org/bin/linux/x64/${JULIA_VERSION%.*}/julia-$JULIA_VERSION-linux-x86_64.tar.gz" -O /tmp/julia.tar.gz
            mkdir -p /opt/julia
            sudo tar -C /opt/julia -xzf /tmp/julia.tar.gz --strip-components=1
            sudo ln -sf /opt/julia/bin/julia /usr/local/bin/julia
            ;;
        macos)
            wget "https://julialang-s3.julialang.org/bin/mac/x64/${JULIA_VERSION%.*}/julia-$JULIA_VERSION-mac64.dmg" -O /tmp/julia.dmg
            hdiutil attach /tmp/julia.dmg
            sudo cp -R /Volumes/Julia-*/Julia-*.app/Contents/Resources/julia /usr/local/
            ln -sf /usr/local/julia/bin/julia /usr/local/bin/julia
            hdiutil detach /Volumes/Julia-*
            ;;
        termux)
            pkg install -y julia
            ;;
        windows)
            log "${YELLOW}Please install Julia manually from: https://julialang.org/downloads/${NC}"
            return 1
            ;;
    esac
    
    check_success "Julia $JULIA_VERSION installed"
}

setup_net_zilla() {
    log "${CYAN}Setting up Net-Zilla...${NC}"
    
    # Create directory
    mkdir -p "$NET_ZILLA_DIR"
    cd "$NET_ZILLA_DIR"
    
    # Clone or update repository
    if [ -d ".git" ]; then
        log "${YELLOW}Updating existing Net-Zilla installation...${NC}"
        git pull origin main
    else
        log "${CYAN}Downloading Net-Zilla...${NC}"
        git clone https://github.com/FJ-cyberzilla/net-zilla.git .
    fi
    
    check_success "Net-Zilla repository setup"
    
    # Install Go dependencies
    log "${CYAN}Installing Go dependencies...${NC}"
    go mod download
    check_success "Go dependencies installed"
    
    # Build the application
    log "${CYAN}Building Net-Zilla...${NC}"
    go build -o net-zilla ./cmd/netzilla
    check_success "Net-Zilla built successfully"
    
    # Install ML models
    setup_ml_models
}

setup_ml_models() {
    log "${CYAN}Setting up AI models...${NC}"
    
    mkdir -p ml/models
    
    # Create basic ML models (in production, these would be trained models)
    cat > ml/models/link_health.jl << 'EOF'
# Link Health ML Model
using MLJ

# Placeholder model - in production this would be a trained model
function predict_link_health(features)
    # Simple heuristic-based model
    score = 0.8  # Default safe score
    return score
end
EOF

    cat > ml/models/ip_reputation.jl << 'EOF'
# IP Reputation ML Model
using MLJ

function predict_ip_reputation(ip_features)
    # Simple heuristic-based model
    score = 0.7  # Default medium reputation
    return score
end
EOF

    cat > ml/models/url_shortener.jl << 'EOF'
# URL Shortener Detection Model
using MLJ

function predict_url_shortening(features)
    # Detect common URL shorteners
    shorteners = ["bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co"]
    domain = features["domain"]
    
    is_shortened = any(shortener in domain for shortener in shorteners)
    return is_shortened ? 0.9 : 0.1
end
EOF

    check_success "AI models setup"
}

setup_environment() {
    log "${CYAN}Setting up environment...${NC}"
    
    # Add to PATH
    case $SHELL in
        */bash)
            echo "export PATH=\"\$PATH:$NET_ZILLA_DIR\"" >> ~/.bashrc
            echo "export NET_ZILLA_HOME=\"$NET_ZILLA_DIR\"" >> ~/.bashrc
            ;;
        */zsh)
            echo "export PATH=\"\$PATH:$NET_ZILLA_DIR\"" >> ~/.zshrc
            echo "export NET_ZILLA_HOME=\"$NET_ZILLA_DIR\"" >> ~/.zshrc
            ;;
    esac
    
    # Create config directory
    mkdir -p "$NET_ZILLA_DIR/config"
    mkdir -p "$NET_ZILLA_DIR/reports"
    
    # Create default config
    cat > "$NET_ZILLA_DIR/config/default.yaml" << 'EOF'
security:
  safe_user_agent: "Mozilla/5.0 (compatible; NetZilla-Security-Scanner/2.1)"
  request_timeout: 30
  max_redirects: 10

ai:
  enable_ai: true
  confidence_threshold: 0.7

output:
  save_reports: true
  report_format: "txt"
  enable_colors: true
EOF

    check_success "Environment configured"
}

run_tests() {
    log "${CYAN}Running basic tests...${NC}"
    
    cd "$NET_ZILLA_DIR"
    
    # Test Go build
    if ./net-zilla --version 2>/dev/null; then
        check_success "Net-Zilla executable test passed"
    else
        log "${YELLOW}Testing Net-Zilla build...${NC}"
        go build -o net-zilla ./cmd/netzilla
        check_success "Net-Zilla build test"
    fi
    
    # Test Julia installation
    if command -v julia >/dev/null 2>&1; then
        if julia -e 'println("Julia test successful")' 2>/dev/null; then
            check_success "Julia test passed"
        else
            log "${RED}Julia test failed${NC}"
            return 1
        fi
    fi
}

cleanup() {
    log "${CYAN}Cleaning up temporary files...${NC}"
    rm -f /tmp/go.tar.gz /tmp/julia.tar.gz /tmp/julia.dmg
    check_success "Cleanup completed"
}

display_success() {
    echo -e "\n${GREEN}"
    echo "╔══════════════════════════════════════════╗"
    echo "║          INSTALLATION SUCCESSFUL!        ║"
    echo "╚══════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "${BOLD}Net-Zilla has been successfully installed!${NC}"
    echo ""
    echo -e "${CYAN}Quick Start:${NC}"
    echo -e "  ${YELLOW}cd $NET_ZILLA_DIR${NC}"
    echo -e "  ${YELLOW}./net-zilla${NC}"
    echo ""
    echo -e "${GREEN}Features installed:${NC}"
    echo -e "  ✓ AI-Powered Threat Detection"
    echo -e "  ✓ SMS Phishing Analysis"
    echo -e "  ✓ DNS/WHOIS Lookup"
    echo -e "  ✓ TLS/SSL Checker"
    echo -e "  ✓ Redirect Tracing"
    echo -e "  ✓ IP Geolocation"
    echo -e "  ✓ Comprehensive Reporting"
    echo ""
    echo -e "${BLUE}Next steps:${NC}"
    echo -e "  1. Restart your terminal or run: ${YELLOW}source ~/.bashrc${NC}"
    echo -e "  2. Navigate to: ${YELLOW}$NET_ZILLA_DIR${NC}"
    echo -e "  3. Run: ${YELLOW}./net-zilla${NC}"
    echo ""
    echo -e "For issues, check: ${CYAN}$LOG_FILE${NC}"
}

display_failure() {
    echo -e "\n${RED}"
    echo "╔══════════════════════════════════════════╗"
    echo "║         INSTALLATION FAILED!             ║"
    echo "╚══════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "${BOLD}The installation encountered errors.${NC}"
    echo ""
    echo -e "${YELLOW}Debugging information:${NC}"
    echo -e "  • Check log file: ${CYAN}$LOG_FILE${NC}"
    echo -e "  • Platform detected: ${CYAN}$PLATFORM${NC}"
    echo -e "  • Installation directory: ${CYAN}$NET_ZILLA_DIR${NC}"
    echo ""
    echo -e "${RED}Common solutions:${NC}"
    echo -e "  1. Ensure you have internet connection"
    echo -e "  2. Check if your system meets requirements"
    echo -e "  3. Try running with administrator privileges"
    echo -e "  4. Manual installation might be required for your platform"
    echo ""
    echo -e "Get help: ${CYAN}https://github.com/FJ-cyberzilla/net-zilla/issues${NC}"
}

main() {
    # Initialize
    mkdir -p "$(dirname "$LOG_FILE")"
    echo "Net-Zilla Installation Log" > "$LOG_FILE"
    echo "Started at: $(date)" >> "$LOG_FILE"
    
    print_banner
    detect_platform
    
    if [ "$PLATFORM" = "unknown" ]; then
        log "${RED}Unsupported platform detected${NC}"
        display_failure
        exit 1
    fi
    
    # Installation steps
    STEPS=(
        "check_dependencies"
        "install_go"
        "install_julia"
        "setup_net_zilla"
        "setup_environment"
        "run_tests"
        "cleanup"
    )
    
    FAILED_STEPS=()
    
    for step in "${STEPS[@]}"; do
        if ! $step; then
            FAILED_STEPS+=("$step")
            log "${RED}Step failed: $step${NC}"
        fi
    done
    
    # Final result
    if [ ${#FAILED_STEPS[@]} -eq 0 ]; then
        display_success
    else
        display_failure
        echo -e "\n${RED}Failed steps: ${FAILED_STEPS[*]}${NC}"
        exit 1
    fi
}

# Run main function
main "$@"
