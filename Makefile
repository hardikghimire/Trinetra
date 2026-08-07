# ============================================
# Makefile
# Secure + Optimized Compilation Only
# ============================================

# Show help if no target specified
.DEFAULT_GOAL := help

# Help target (what runs when user types just 'make')
help:
	@echo "Available commands:"
	@echo "  sudo make install     - Install the binary"
	@echo "  sudo make uninstall   - Remove installed binary"
	@echo "  make clean            - Remove build files"
	@echo "  make check-installed  - Check installation status"
# Compiler
CXX := g++

# Optimization flags
OPT_FLAGS := -std=c++20 -pthread -lssl -lcrypto -lz -lpcre2-8 -march=native -O3 -mavx2 -D__AVX2__ -static-libgcc -static-libstdc++

# Security hardening
SECURE_FLAGS := -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
                -Wformat -Wformat-security -fPIE -pie \
                -Wl,-z,relro,-z,now \
                -Wl,-z,noexecstack -fstack-clash-protection

# Include and library paths
INCLUDES := -I/usr/include/liburing
LIBS := -luring -lcurl -lpthread
LIB_DIRS := -L/usr/lib/x86_64-linux-gnu

# Source files and directories
SRCS := scan.cpp main.cpp utils.cpp public_db.cpp anomaly_analysis.cpp probe.cpp control.cpp async_io.cpp netns_split.cpp traceroute.cpp parser.cpp handler.cpp arp_handler.cpp debug.cpp dns_enum.cpp
OBJ_DIR := object
TARGET := shiv

# Get absolute path of current source directory
CURRENT_DIR := $(shell pwd)
BINARY_PATH := /usr/bin/$(TARGET)
INSTALL_RECORD := /usr/local/share/$(TARGET).install_path

# Object files in object directory
OBJS := $(addprefix $(OBJ_DIR)/, $(SRCS:.cpp=.o))

# Final compile flags
CXXFLAGS := $(SECURE_FLAGS) $(OPT_FLAGS) $(WARN_FLAGS) $(INCLUDES)
LDFLAGS := $(SECURE_FLAGS) $(OPT_FLAGS) $(LIB_DIRS)

# ============================================
# Build Rules
# ============================================

# Default: build optimized binary
all: $(TARGET)

# Quick check for installation conflicts (no compilation)
check-conflict:
	@echo "Checking for existing $(TARGET) installation..."
	@if [ -f $(BINARY_PATH) ]; then \
		SOURCE_DIR=$$(readlink -f $(BINARY_PATH) 2>/dev/null || echo ""); \
		RECORDED_DIR=$$(cat $(INSTALL_RECORD) 2>/dev/null || echo ""); \
		if [ -n "$$RECORDED_DIR" ] && [ "$$RECORDED_DIR" != "$(CURRENT_DIR)" ]; then \
			echo "ERROR: $(TARGET) is already installed from: $$RECORDED_DIR"; \
			echo "This binary was built from: $(CURRENT_DIR)"; \
			echo ""; \
			echo "To prevent conflicts, you must:"; \
			echo "  1. Uninstall the existing version first: 'sudo make uninstall' in $$RECORDED_DIR"; \
			echo "  2. Or use a different binary name by changing TARGET in Makefile"; \
			exit 1; \
		elif [ -n "$$SOURCE_DIR" ] && [ "$$SOURCE_DIR" != "$(CURRENT_DIR)/$(TARGET)" ]; then \
			echo "ERROR: $(TARGET) is already installed from a different location"; \
			echo "Installed binary points to: $$SOURCE_DIR"; \
			echo "Current directory: $(CURRENT_DIR)"; \
			echo ""; \
			echo "Please uninstall the existing version first or use a different binary name"; \
			exit 1; \
		else \
			echo "✓ No conflict detected. Proceeding with installation..."; \
		fi; \
	else \
		echo "✓ No existing installation found. Proceeding..."; \
	fi

# Create object directory if it doesn't exist
$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

# Link final binary
$(TARGET): $(OBJS)
	$(CXX) -o $@ $(OBJS) $(LIBS) $(LDFLAGS)

# Compile source files to object directory
$(OBJ_DIR)/%.o: %.cpp | $(OBJ_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Install binary with pre-check (no compilation if conflict exists)
install: check-conflict $(TARGET)
	@echo "Installing $(TARGET) to /usr/bin..."
	@sudo install -Dm755 $(TARGET) $(BINARY_PATH)
	@echo "$(CURRENT_DIR)" | sudo tee $(INSTALL_RECORD) > /dev/null 2>&1 || true
	@echo "✓ Done! You can now run '$(TARGET)' from anywhere"
	@echo "  Installation recorded from: $(CURRENT_DIR)"

# Force install (ignore conflicts, overwrite)
force-install: $(TARGET)
	@echo "WARNING: Force installing $(TARGET) - this will overwrite any existing installation"
	@sleep 1
	@sudo install -Dm755 $(TARGET) $(BINARY_PATH)
	@echo "$(CURRENT_DIR)" | sudo tee $(INSTALL_RECORD) > /dev/null 2>&1 || true
	@echo "✓ Force install complete from: $(CURRENT_DIR)"

# Remove binary with safety check
uninstall:
	@echo "Removing $(TARGET) from /usr/bin..."
	@if [ -f $(BINARY_PATH) ]; then \
		RECORDED_DIR=$$(cat $(INSTALL_RECORD) 2>/dev/null || echo ""); \
		if [ -n "$$RECORDED_DIR" ] && [ "$$RECORDED_DIR" != "$(CURRENT_DIR)" ]; then \
			echo "ERROR: This binary was installed from: $$RECORDED_DIR"; \
			echo "Current directory is: $(CURRENT_DIR)"; \
			echo "You are trying to uninstall from a different directory!"; \
			echo "Uninstall cancelled."; \
			exit 1; \
		else \
			sudo rm -f $(BINARY_PATH); \
			sudo rm -f $(INSTALL_RECORD); \
			echo "✓ Uninstalled!"; \
		fi; \
	else \
		echo "$(TARGET) is not installed in /usr/bin"; \
	fi

SHELL := /bin/bash

# Check installation status
check-installed:
	@if [ -f $(BINARY_PATH) ]; then \
		RECORDED_DIR=$$(cat $(INSTALL_RECORD) 2>/dev/null || echo "unknown"); \
		BIN_SOURCE=$$(readlink -f $(BINARY_PATH) 2>/dev/null || echo "unknown"); \
		echo "========================================="; \
		echo "$(TARGET) installation status:"; \
		echo "  Binary location: $(BINARY_PATH)"; \
		echo "  Binary source: $$BIN_SOURCE"; \
		echo "  Recorded directory: $$RECORDED_DIR"; \
		if [ "$$RECORDED_DIR" = "$(CURRENT_DIR)" ]; then \
			echo "  ✓ This is the current directory"; \
		else \
			echo "  ⚠ This is NOT the current directory"; \
		fi; \
		echo "========================================="; \
	else \
		echo "$(TARGET) is not installed"; \
	fi

# Clean build files
clean:
	rm -f $(TARGET)
	rm -rf $(OBJ_DIR)

# Clean everything including installed binary (use with caution!)
clean-all: clean
	@if [ -f $(BINARY_PATH) ]; then \
		echo "Removing installed binary as well..."; \
		sudo rm -f $(BINARY_PATH); \
		sudo rm -f $(INSTALL_RECORD); \
		echo "✓ Removed installed binary"; \
	fi

# ============================================
# Phony targets
# ============================================

.PHONY: all clean clean-all install force-install uninstall check-installed check-conflict
