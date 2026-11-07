#!/bin/bash

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

detect_os() {
    if [ ! -f /etc/os-release ]; then
        log_error "Cannot detect OS: /etc/os-release not found"
        exit 1
    fi

    . /etc/os-release

    if [ -n "${ID_LIKE:-}" ]; then
        if [[ "$ID_LIKE" =~ (^|[[:space:]])arch($|[[:space:]]) ]]; then
            OS="arch"
            log_info "Detected ($ID_LIKE) based OS"
        elif [[ "$ID_LIKE" =~ (^|[[:space:]])debian($|[[:space:]]) ]]; then
            OS="debian"
            log_info "Detected ($ID_LIKE) based OS"
        else
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

check_sudo() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This script requires sudo privileges. Please run with sudo."
        exit 1
    fi
}

check_io_uring_support() {
    log_info "Checking kernel version..."

    local kver major minor
    kver="$(uname -r)"
    major="$(echo "$kver" | grep -oE '^[0-9]+')"
    minor="$(echo "$kver" | grep -oE '^[0-9]+\.[0-9]+' | cut -d. -f2)"

    if [ -z "$major" ] || [ -z "$minor" ]; then
        log_warn "Could not parse kernel version from '$kver' -- skipping kernel version check"
        return
    fi

    if [ "$major" -gt 6 ] || { [ "$major" -eq 6 ] && [ "$minor" -ge 12 ]; }; then
        log_info "Kernel $kver >= 6.12 -- OK"
    else
        log_error "Detected kernel: $kver"
        log_error "Shiv's minimum requirement kernel version is 6.12, please update the kernel and try again"
        exit 1
    fi
}

install_dependencies() {
    log_info "Installing system dependencies..."

    case $OS in
        debian|ubuntu)
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
                pkg-config \
                libpcre2-dev \
                libssl-dev \
                openssl \
                stunnel4 \
                zlib1g-dev 
            ;;
        arch)
            pacman -Sy --noconfirm

            pacman -S --needed --noconfirm base-devel cmake git curl pkg-config

            pacman -S --needed --noconfirm pugixml nlohmann-json openssl zlib stunnel
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

install_liburing() {
    log_info "Building and installing liburing from source..."

    if [ ! -d "liburing" ]; then
        git clone https://github.com/axboe/liburing.git
    else
        log_warn "liburing directory already exists, updating..."
        cd liburing
        git pull
        cd ..
    fi

    cd liburing

    log_info "Configuring liburing with gcc and g++..."
    ./configure --cc=gcc --cxx=g++

    log_info "Building liburing..."
    make -j$(nproc)

    log_info "Building liburing.pc..."
    make liburing.pc

    log_info "Installing liburing..."
    make install

    if [ -f "/usr/include/liburing.h" ] && [ -d "/usr/include/liburing" ]; then
        log_info "liburing installed successfully"
        if [ -f "/usr/lib/pkgconfig/liburing.pc" ] || [ -f "/usr/local/lib/pkgconfig/liburing.pc" ]; then
            log_info "liburing.pc installed successfully"
        fi
    else
        log_error "liburing installation verification failed"
        exit 1
    fi

    cd ..
}

install_concurrentqueue() {
    log_info "Installing concurrentqueue..."

    if [ ! -d "concurrentqueue" ]; then
        git clone https://github.com/cameron314/concurrentqueue.git
    else
        log_warn "concurrentqueue directory already exists, updating..."
        cd concurrentqueue
        git pull
        cd ..
    fi

    cp concurrentqueue/concurrentqueue.h /usr/include/
    cp concurrentqueue/concurrentqueue.h /usr/local/include/
    cp concurrentqueue/blockingconcurrentqueue.h /usr/include/
    cp concurrentqueue/blockingconcurrentqueue.h /usr/local/include/
    cp concurrentqueue/lightweightsemaphore.h /usr/include/
    cp concurrentqueue/lightweightsemaphore.h /usr/local/include/

    if [ -f "/usr/include/concurrentqueue.h" ] && [ -f "/usr/local/include/concurrentqueue.h" ]; then
        log_info "concurrentqueue installed successfully"
    else
        log_error "concurrentqueue installation failed"
        exit 1
    fi
}

setup_data_files() {
    log_info "Setting up data files in /usr/share/shiv/"

    mkdir -p /usr/share/shiv
    local root_files=(
        mac-vendors.txt
        ports.txt
        signatures.conf
        shiv_split.conf
    )
    local range_files=(
        akamai.txt
        aws.txt
        azure_range.txt
        cloudflare_range.txt
        digitalocean_range.txt
        google_range.txt
        alibaba.txt
        apple.txt
        anthropic.txt
        googlebot.txt
        linode.txt
        vultr.txt
        zscaler.txt
        tor.txt
        hetzner.txt
        fastly.txt
    )

    local missing_files=()
    for file in "${root_files[@]}"; do
        if [ ! -f "$file" ]; then
            missing_files+=("$file")
        fi
    done
    for file in "${range_files[@]}"; do
        if [ ! -f "ranges/$file" ]; then
            missing_files+=("ranges/$file")
        fi
    done

    if [ ${#missing_files[@]} -gt 0 ]; then
        log_error "Missing source files: ${missing_files[*]}"
        log_error "Please ensure these files are in the current directory"
        exit 1
    fi

    local copy_failed=()
    for file in "${root_files[@]}"; do
        if cp "$file" "/usr/share/shiv/$file"; then
            log_info "Copied $file -> /usr/share/shiv/$file"
        else
            log_error "Failed to copy $file to /usr/share/shiv/"
            copy_failed+=("$file")
        fi
    done
    for file in "${range_files[@]}"; do
        if cp "ranges/$file" "/usr/share/shiv/$file"; then
            log_info "Copied ranges/$file -> /usr/share/shiv/$file"
        else
            log_error "Failed to copy ranges/$file to /usr/share/shiv/"
            copy_failed+=("$file")
        fi
    done

    if [ ${#copy_failed[@]} -gt 0 ]; then
        log_error "cp reported failure for: ${copy_failed[*]}"
    fi

    chmod 644 /usr/share/shiv/*.txt /usr/share/shiv/services /usr/share/shiv/shiv_split.conf 2>/dev/null || true

    local missing_from_dest=()
    for file in "${root_files[@]}" "${range_files[@]}"; do
        if [ -f "/usr/share/shiv/$file" ]; then
            log_info "Verified $file is present in /usr/share/shiv/"
        else
            log_error "$file is missing from /usr/share/shiv/"
            missing_from_dest+=("$file")
        fi
    done

    if [ ${#missing_from_dest[@]} -gt 0 ]; then
        log_error "The following files are missing from /usr/share/shiv/: ${missing_from_dest[*]}"
        exit 1
    fi

    log_info "Data files installed to /usr/share/shiv/"
}

build_project() {
    log_info "Building project..."

    if [ -f "Makefile" ]; then
        make clean || true
    fi

    make -j$(nproc)

    if [ $? -eq 0 ]; then
        log_info "Build completed successfully"
    else
        log_error "Build failed"
        exit 1
    fi
}

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

verify_installation() {
    log_info "Verifying final installation..."

    local checks=0
    local passed=0

    if [ -f "/usr/include/liburing.h" ]; then
        log_info "✓ liburing headers found"
        ((passed++))
    else
        log_warn "✗ liburing headers not found"
    fi
    ((checks++))

    if [ -f "/usr/include/concurrentqueue.h" ]; then
        log_info "✓ concurrentqueue found"
        ((passed++))
    else
        log_warn "✗ concurrentqueue not found"
    fi
    ((checks++))

    if command -v stunnel >/dev/null 2>&1 || command -v stunnel4 >/dev/null 2>&1; then
        log_info "✓ stunnel found"
        ((passed++))
    else
        log_warn "✗ stunnel not found"
    fi
    ((checks++))

    if [ -f "/usr/share/shiv/mac-vendors.txt" ] && [ -f "/usr/share/shiv/ports.txt" ] && [ -f "/usr/share/shiv/services" ] && [ -f "/usr/share/shiv/signatures.conf" ] ; then
        log_info "✓ Data files found in /usr/share/shiv/"
        ((passed++))
    else
        log_warn "✗ Some data files missing in /usr/share/shiv/"
    fi
    ((checks++))

    log_info "Verification complete: $passed/$checks checks passed"
}

main() {
    log_info "Starting setup process..."

    detect_os

    check_io_uring_support

    check_sudo

    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    cd "$SCRIPT_DIR"

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

main "$@"
