#!/bin/bash

# Exit on error, undefined variables, and pipe failures
set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Detect OS by checking ID and ID_LIKE
detect_os() {
    if [ ! -f /etc/os-release ]; then
        log_error "Cannot detect OS: /etc/os-release not found"
        exit 1
    fi
    
    . /etc/os-release
    
    # Check ID_LIKE first for derivatives, then fall back to ID
    if [ -n "${ID_LIKE:-}" ]; then
        if [[ "$ID_LIKE" =~ (^|[[:space:]])arch($|[[:space:]]) ]]; then
            OS="arch"
            log_info "Detected ($ID_LIKE) based OS"
        elif [[ "$ID_LIKE" =~ (^|[[:space:]])debian($|[[:space:]]) ]]; then
            OS="debian"
            log_info "Detected ($ID_LIKE) based OS"
        else
            # Fall back to ID if ID_LIKE doesn't match known values
            case $ID in
                debian|ubuntu|arch)
                    OS=$ID
                    log_info "Detected OS: $OS (from ID=$ID)"
                    ;;
                *)
                    log_error "Unsupported OS: ID=$ID, ID_LIKE=$ID_LIKE"
                    log_error "Only Debian-based or Arch-based distributions are supported"
                    exit 1
                    ;;
            esac
        fi
    else
        # No ID_LIKE, use ID directly
        case $ID in
            debian|ubuntu|arch)
                OS=$ID
                log_info "Detected OS: $OS"
                ;;
            *)
                log_error "Unsupported OS: $ID"
                log_error "Only Debian-based or Arch-based distributions are supported"
                exit 1
                ;;
        esac
    fi
}

# Check if running with sudo for certain operations
check_sudo() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This script requires sudo privileges. Please run with sudo."
        exit 1
    fi
}

# Install system dependencies based on OS
install_dependencies() {
    log_info "Installing system dependencies..."
    
    case $OS in
        debian|ubuntu)
            apt update
            apt install -y \
                build-essential \
                cmake \
                git \
                curl \
                gcc \
                g++ \
                libcurl4-openssl-dev \
                nlohmann-json3-dev \
                libpugixml-dev \
                pkg-config
            ;;
        arch)
            # Sync package databases
            pacman -Sy --noconfirm
            
            # Install base-devel group (includes gcc, make, etc.)
            # --needed flag avoids reinstalling already present packages
            pacman -S --needed --noconfirm base-devel cmake git curl pkg-config
            
            # Install individual libraries
            pacman -S --needed --noconfirm pugixml nlohmann-json
            # libcurl is part of curl package on Arch, already installed above
            ;;
        *)
            log_error "Unsupported OS: $OS. Only Debian/Ubuntu and Arch Linux are supported."
            exit 1
            ;;
    esac
    
    if [ $? -eq 0 ]; then
        log_info "System dependencies installed successfully"
    else
        log_error "Failed to install system dependencies"
        exit 1
    fi
}

# Build and install liburing from source
install_liburing() {
    log_info "Building and installing liburing from source..."
    
    # Clone if not exists, otherwise update
    if [ ! -d "liburing" ]; then
        git clone https://github.com/axboe/liburing.git
    else
        log_warn "liburing directory already exists, updating..."
        cd liburing
        git pull
        cd ..
    fi
    
    cd liburing
    
    # Configure with specified compilers
    log_info "Configuring liburing with gcc and g++..."
    ./configure --cc=gcc --cxx=g++
    
    # Build liburing
    log_info "Building liburing..."
    make -j$(nproc)
    
    # Build liburing.pc
    log_info "Building liburing.pc..."
    make liburing.pc
    
    # Install liburing (headers, shared/static libs, and manpage)
    log_info "Installing liburing..."
    make install
    
    # Verify installation
    if [ -f "/usr/include/liburing.h" ] && [ -d "/usr/include/liburing" ]; then
        log_info "liburing installed successfully"
        # Verify liburing.pc is installed
        if [ -f "/usr/lib/pkgconfig/liburing.pc" ] || [ -f "/usr/local/lib/pkgconfig/liburing.pc" ]; then
            log_info "liburing.pc installed successfully"
        fi
    else
        log_error "liburing installation verification failed"
        exit 1
    fi
    
    cd ..
}

# Install concurrentqueue
install_concurrentqueue() {
    log_info "Installing concurrentqueue..."
    
    # Clone if not exists, otherwise update
    if [ ! -d "concurrentqueue" ]; then
        git clone https://github.com/cameron314/concurrentqueue.git
    else
        log_warn "concurrentqueue directory already exists, updating..."
        cd concurrentqueue
        git pull
        cd ..
    fi
    
    # Copy header to both locations
    cp concurrentqueue/concurrentqueue.h /usr/include/
    cp concurrentqueue/concurrentqueue.h /usr/local/include/
    
    # Verify installation
    if [ -f "/usr/include/concurrentqueue.h" ] && [ -f "/usr/local/include/concurrentqueue.h" ]; then
        log_info "concurrentqueue installed successfully"
    else
        log_error "concurrentqueue installation failed"
        exit 1
    fi
}

# Setup data files
setup_data_files() {
    log_info "Setting up data files in /usr/share/shiv/"
    
    # Create directory
    mkdir -p /usr/share/shiv
    
    # Check if source files exist
    local missing_files=()
    for file in mac-vendor.txt ports.txt services; do
        if [ ! -f "$file" ]; then
            missing_files+=("$file")
        fi
    done
    
    if [ ${#missing_files[@]} -gt 0 ]; then
        log_error "Missing source files: ${missing_files[*]}"
        log_error "Please ensure these files are in the current directory"
        exit 1
    fi
    
    # Copy files
    cp mac-vendors.txt ports.txt services /usr/share/shiv/
    cp shiv_split.conf /usr/share/shiv/shiv_split.conf
    cp akamai.txt  aws.txt  azure_range.txt  cloudflare_range.txt  digitalocean_range.txt  google_range.txt alibaba.txt apple.txt anthropic.txt googlebot.txt linode.txt vultr.txt zscaler.txt tor.txt hetzner.txt fastly.txt /usr/share/shiv/
    
    # Set proper permissions
    chmod 644 /usr/share/shiv/*.txt /usr/share/shiv/services 2>/dev/null || true
    
    # Verify
    for file in mac-vendor.txt ports.txt services; do
        if [ -f "/usr/share/shiv/$file" ]; then
            log_info "Successfully copied $file"
        else
            log_error "Failed to copy $file"
            exit 1
        fi
    done
    
    log_info "Data files installed to /usr/share/shiv/"
}

# Build the project
build_project() {
    log_info "Building project..."
    
    # Clean previous builds
    if [ -f "Makefile" ]; then
        make clean || true
    fi
    
    # Build with all available cores
    make -j$(nproc)
    
    if [ $? -eq 0 ]; then
        log_info "Build completed successfully"
    else
        log_error "Build failed"
        exit 1
    fi
}

# Install the project
install_project() {
    log_info "Installing project..."
    
    make install
    
    if [ $? -eq 0 ]; then
        log_info "Installation completed successfully"
    else
        log_error "Installation failed"
        exit 1
    fi
}

# Verify final installation
verify_installation() {
    log_info "Verifying final installation..."
    
    # Check for installed components
    local checks=0
    local passed=0
    
    # Check liburing
    if [ -f "/usr/include/liburing.h" ]; then
        log_info "✓ liburing headers found"
        ((passed++))
    else
        log_warn "✗ liburing headers not found"
    fi
    ((checks++))
    
    # Check concurrentqueue
    if [ -f "/usr/include/concurrentqueue.h" ]; then
        log_info "✓ concurrentqueue found"
        ((passed++))
    else
        log_warn "✗ concurrentqueue not found"
    fi
    ((checks++))
    
    # Check data files
    if [ -f "/usr/share/shiv/mac-vendor.txt" ] && [ -f "/usr/share/shiv/ports.txt" ] && [ -f "/usr/share/shiv/services" ]; then
        log_info "✓ Data files found in /usr/share/shiv/"
        ((passed++))
    else
        log_warn "✗ Some data files missing in /usr/share/shiv/"
    fi
    ((checks++))
    
    log_info "Verification complete: $passed/$checks checks passed"
}

# Main execution
main() {
    log_info "Starting setup process..."
    
    # Detect OS first
    detect_os
    
    # Check for sudo
    check_sudo
    
    # Get script directory
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    cd "$SCRIPT_DIR"
    
    # Run setup steps
    install_dependencies
    install_liburing
    install_concurrentqueue
    setup_data_files
    build_project
    install_project
    verify_installation
    
    log_info "========================================="
    log_info "Setup completed successfully!"
    log_info "Project is now installed and ready to use"
    log_info "========================================="
}

# Run main function
main "$@"
