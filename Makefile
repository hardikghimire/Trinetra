SHELL := /bin/bash

# Normal build output: one short line per step (CC / LD). V=1 shows full commands.
ifeq ($(V),1)
  Q :=
  say = @:
else
  Q := @
  say = @printf '  %-4s %s\n' '$(1)' '$(2)'
endif
.DEFAULT_GOAL := help

help:
	@echo "Available commands:"
	@echo "  sudo make -j\$$(nproc) all - Build and install the binary to /usr/bin"
	@echo "  sudo make install     - Same as all"
	@echo "  make build            - Build only, do not install"
	@echo "  sudo make force-install - Install, overwriting any existing binary"
	@echo "  sudo make uninstall   - Remove installed binary"
	@echo "  make clean            - Remove build files"
	@echo "  make check-installed  - Check installation status"
	@echo ""
	@echo "Build variants:"
	@echo "  make debug | san | tsan   - debug / ASan+UBSan / ThreadSanitizer builds"
	@echo "  make pgo-gen, pgo-use     - profile-guided optimization"
	@echo "  make pgo-clean            - discard collected PGO profile"
	@echo "  make checksec             - verify PIE/RELRO/NX/canary/fortify/CET on the binary"
	@echo "  make flags                - print the effective flags"
	@echo ""
	@echo "Overrides: ARCH=-march=x86-64-v3 OLEVEL=-O3 LTO=0 FORTIFY=0 ZEROINIT=1 STRICT=1 STRIP=1 PGO=none"

comma := ,
cc-option = $(shell echo 'int main(){}' | $(CXX) $(1) -x c++ -fsyntax-only - >/dev/null 2>&1 && echo $(1))
ld-option = $(shell echo 'int main(){}' | $(CXX) -x c++ - -o /dev/null $(1) >/dev/null 2>&1 && echo $(1))

CXX    ?= g++
BUILD  ?= release
ARCH   ?= -march=native
STRICT ?= 0
STRIP  ?= 0
ZEROINIT ?= 0
JOBS   ?= $(shell nproc 2>/dev/null || echo 2)
EXTRA_CXXFLAGS ?=
EXTRA_LDFLAGS  ?=

SAN_FLAGS :=

ifeq ($(BUILD),release)
  OLEVEL    ?= -O2
  LTO       ?= 1
  GC        ?= 1
  FORTIFY   ?= 1
  STATIC_RT ?= 1
else ifeq ($(BUILD),debug)
  OLEVEL    ?= -Og -g3 -fno-omit-frame-pointer
  LTO       ?= 0
  GC        ?= 0
  FORTIFY   ?= 1
  STATIC_RT ?= 1
else ifeq ($(BUILD),san)
  OLEVEL    ?= -O1 -g3 -fno-omit-frame-pointer
  SAN_FLAGS := -fsanitize=address,undefined -fno-sanitize-recover=all
  LTO       ?= 0
  GC        ?= 0
  FORTIFY   ?= 0
  STATIC_RT ?= 0
else ifeq ($(BUILD),tsan)
  OLEVEL    ?= -O1 -g3 -fno-omit-frame-pointer
  SAN_FLAGS := -fsanitize=thread
  LTO       ?= 0
  GC        ?= 0
  FORTIFY   ?= 0
  STATIC_RT ?= 0
else
  $(error Unknown BUILD '$(BUILD)' (use: release, debug, san, tsan))
endif

STD := -std=c++20 -pthread

GCC_MAJOR     := $(shell $(CXX) -dumpversion 2>/dev/null | cut -d. -f1)
FORTIFY_LEVEL := $(shell [ "$(GCC_MAJOR)" -ge 12 ] 2>/dev/null && echo 3 || echo 2)

OPT_FLAGS := -pipe -fno-plt -fno-math-errno \
             -fvisibility=hidden -fvisibility-inlines-hidden

ifeq ($(GC),1)
  OPT_FLAGS += -ffunction-sections -fdata-sections
endif

SAFE_FLAGS := -fno-strict-aliasing -fno-strict-overflow -fno-delete-null-pointer-checks

HARDEN := -fPIE -fstack-protector-strong \
          $(call cc-option,-fstack-clash-protection) \
          $(call cc-option,-fcf-protection=full) \
          $(call cc-option,-fzero-call-used-regs=used-gpr) \
          -D_GLIBCXX_ASSERTIONS

ifeq ($(FORTIFY),1)
  HARDEN += -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=$(FORTIFY_LEVEL)
endif
ifeq ($(ZEROINIT),1)
  HARDEN += $(call cc-option,-ftrivial-auto-var-init=zero)
endif

LTO_FLAGS :=
ifeq ($(LTO),1)
  LTO_FLAGS := $(call cc-option,-flto=auto)
endif

PGO_DIR   := $(CURDIR)/pgo-data
PGO_FLAGS :=
ifeq ($(origin PGO),undefined)
  ifneq ($(wildcard $(PGO_DIR)/*.gcda),)
    PGO := use
  endif
endif
ifeq ($(PGO),gen)
  PGO_FLAGS := -fprofile-generate -fprofile-update=atomic -fprofile-dir=$(PGO_DIR)
else ifeq ($(PGO),use)
  PGO_FLAGS := -fprofile-use -fprofile-dir=$(PGO_DIR) -fprofile-correction \
               $(call cc-option,-fprofile-partial-training) \
               -Wno-missing-profile -Wno-coverage-mismatch
endif

# No -Wall/-Wextra, so style noise (unused vars, enum/ternary mixes, dangling-ref
# heuristics, snprintf truncation...) stays silent. Only diagnostics that point at
# real memory-safety / format-string bugs are on. (Optimizer-based ones fire at -O1+.)
# V_WARN=1 restores the original full warning set.
WARN := -Wformat -Wformat-security -Wformat-overflow -Wno-format-truncation \
        -Warray-bounds -Wstringop-overflow -Wstringop-overread \
        -Wuse-after-free -Wfree-nonheap-object -Wreturn-local-addr \
        -Wnonnull -Wvla
ifeq ($(V_WARN),1)
  WARN := -Wall -Wextra -Wno-unused-parameter -Wformat -Wformat-security -Wvla
endif
ifeq ($(STRICT),1)
  WARN += -Werror
endif

CODEGEN := $(STD) $(OLEVEL) $(ARCH) $(OPT_FLAGS) $(SAFE_FLAGS) $(HARDEN) \
           $(LTO_FLAGS) $(PGO_FLAGS) $(SAN_FLAGS)

LD_HARDEN := -pie -Wl,-z,relro,-z,now,-z,noexecstack \
             $(call ld-option,-Wl$(comma)-z$(comma)separate-code)

LD_OPT := -Wl,--as-needed,-O1,--hash-style=gnu
ifeq ($(GC),1)
  LD_OPT += -Wl,--gc-sections
endif
ifeq ($(STATIC_RT),1)
  LD_OPT += -static-libgcc -static-libstdc++
endif
ifeq ($(STRIP),1)
  LD_OPT += -Wl,--strip-all
endif

INCLUDES := -I/usr/include/liburing
LIB_DIRS := -L/usr/lib/x86_64-linux-gnu

LIBS := -luring -lcurl -lssl -lcrypto -lz -lpcre2-8 -lpthread

CXXFLAGS := $(CODEGEN) $(WARN) -MMD -MP $(INCLUDES) $(EXTRA_CXXFLAGS)
LDFLAGS  := $(CODEGEN) $(LD_HARDEN) $(LD_OPT) $(LIB_DIRS) $(EXTRA_LDFLAGS)

SRCS := scan.cpp main.cpp utils.cpp public_db.cpp anomaly_analysis.cpp probe.cpp control.cpp async_io.cpp netns_split.cpp traceroute.cpp parser.cpp handler.cpp arp_handler.cpp debug.cpp dns_enum.cpp server.cpp ssl_enum.cpp simulations.cpp net_capture.cpp discover.cpp os_detect.cpp
OBJ_DIR := object
TARGET := shiv

CURRENT_DIR := $(CURDIR)
BINARY_PATH := /usr/bin/$(TARGET)
INSTALL_RECORD := /usr/local/share/$(TARGET).install_path

SUDO := $(if $(filter 0,$(shell id -u)),,sudo)

SUBJ = $(if $(findstring jobserver,$(MAKEFLAGS)),,-j$(JOBS))

OWNER_FIX := if [ -n "$$SUDO_UID" ]; then chown -R "$$SUDO_UID:$${SUDO_GID:-$$SUDO_UID}" $(OBJ_DIR) $(TARGET) 2>/dev/null || true; fi

OBJS := $(addprefix $(OBJ_DIR)/, $(SRCS:.cpp=.o))

all: install

build: $(TARGET)

FLAGS_STAMP := $(OBJ_DIR)/.build_flags

$(OBJ_DIR):
	$(Q)mkdir -p $(OBJ_DIR)

$(FLAGS_STAMP): FORCE | $(OBJ_DIR)
	@printf '%s\n' '$(CXX) $(CXXFLAGS) :: $(LDFLAGS) $(LIBS)' | cmp -s - $@ 2>/dev/null || \
		printf '%s\n' '$(CXX) $(CXXFLAGS) :: $(LDFLAGS) $(LIBS)' > $@

FORCE:

$(TARGET): $(OBJS) $(FLAGS_STAMP)
	$(call say,LD,$@)
	$(Q)$(CXX) -o $@ $(OBJS) $(LDFLAGS) $(LIBS)

$(OBJ_DIR)/%.o: %.cpp $(FLAGS_STAMP) | $(OBJ_DIR)
	$(call say,CXX,$<)
	$(Q)$(CXX) $(CXXFLAGS) -c $< -o $@

-include $(OBJS:.o=.d)

debug:
	@$(MAKE) --no-print-directory -j$(JOBS) BUILD=debug $(TARGET)

san:
	@$(MAKE) --no-print-directory -j$(JOBS) BUILD=san $(TARGET)

tsan:
	@$(MAKE) --no-print-directory -j$(JOBS) BUILD=tsan $(TARGET)

pgo-gen:
	@rm -rf $(PGO_DIR)
	@$(MAKE) --no-print-directory -j$(JOBS) BUILD=release PGO=gen $(TARGET)
	@echo "Instrumented build ready. Run ./$(TARGET) scans against a lab target,"
	@echo "let them finish, then run: make pgo-use"

pgo-use:
	@if ! ls $(PGO_DIR)/*.gcda >/dev/null 2>&1; then \
		echo "ERROR: no profile data in $(PGO_DIR). Run 'make pgo-gen' and exercise ./$(TARGET) first."; \
		exit 1; \
	fi
	@$(MAKE) --no-print-directory -j$(JOBS) BUILD=release PGO=use $(TARGET)

pgo-clean:
	rm -rf $(PGO_DIR)

flags:
	@echo "BUILD    = $(BUILD)   (LTO=$(LTO) GC=$(GC) FORTIFY=$(FORTIFY) PGO=$(PGO))"
	@echo "CXXFLAGS = $(CXXFLAGS)"
	@echo "LDFLAGS  = $(LDFLAGS)"
	@echo "LIBS     = $(LIBS)"

checksec: $(TARGET)
	@echo "== hardening report for $(TARGET) =="
	@readelf -h $(TARGET) | grep -qE 'Type:[[:space:]]*DYN' \
		&& echo "  PIE (ASLR)        : yes" || echo "  PIE (ASLR)        : NO"
	@readelf -lW $(TARGET) | grep -q GNU_RELRO \
		&& echo "  RELRO             : yes" || echo "  RELRO             : NO"
	@readelf -dW $(TARGET) | grep -qE 'BIND_NOW|FLAGS.*NOW' \
		&& echo "  BIND_NOW (full)   : yes" || echo "  BIND_NOW (full)   : NO"
	@readelf -lW $(TARGET) | grep GNU_STACK | grep -q RWE \
		&& echo "  NX stack          : NO" || echo "  NX stack          : yes"
	@echo "  stack canary refs : $$(readelf -sW $(TARGET) | grep -c '__stack_chk_fail@')  (>0 = yes)"
	@echo "  fortified calls   : $$(readelf -sW $(TARGET) | grep -cE '__[a-z0-9_]+_chk@')  (>0 = yes)"
	@readelf -nW $(TARGET) | grep -qE 'IBT|SHSTK' \
		&& echo "  CET (IBT/SHSTK)   : yes" || echo "  CET (IBT/SHSTK)   : NO"

check-conflict:
	@echo "Checking for existing $(TARGET) installation..."
	@if [ -e $(BINARY_PATH) ] || [ -L $(BINARY_PATH) ]; then \
		RECORDED_DIR=$$(cat $(INSTALL_RECORD) 2>/dev/null || echo ""); \
		LINK_TARGET=$$(readlink -f $(BINARY_PATH) 2>/dev/null || echo ""); \
		if [ -n "$$RECORDED_DIR" ] && [ "$$RECORDED_DIR" != "$(CURRENT_DIR)" ]; then \
			echo "ERROR: $(TARGET) is already installed from: $$RECORDED_DIR"; \
			echo "This binary was built from: $(CURRENT_DIR)"; \
			echo ""; \
			echo "To prevent conflicts, you must:"; \
			echo "  1. Uninstall the existing version first: 'sudo make uninstall' in $$RECORDED_DIR"; \
			echo "  2. Or run 'sudo make force-install' to overwrite it"; \
			echo "  3. Or use a different binary name by changing TARGET in Makefile"; \
			exit 1; \
		elif [ -z "$$RECORDED_DIR" ] && [ "$$LINK_TARGET" != "$(CURRENT_DIR)/$(TARGET)" ]; then \
			echo "ERROR: $(BINARY_PATH) already exists and was not installed by this Makefile"; \
			echo "Remove it first or run 'sudo make force-install' to overwrite it"; \
			exit 1; \
		else \
			echo "✓ Existing installation is from this directory. It will be updated."; \
		fi; \
	else \
		echo "✓ No existing installation found. Proceeding..."; \
	fi

install:
	@$(MAKE) --no-print-directory check-conflict
	@$(MAKE) --no-print-directory $(SUBJ) $(TARGET)
	@$(OWNER_FIX)
	@echo "Installing $(TARGET) to $(BINARY_PATH)..."
	@$(SUDO) install -Dm755 $(TARGET) $(BINARY_PATH)
	@$(SUDO) mkdir -p $(dir $(INSTALL_RECORD))
	@echo "$(CURRENT_DIR)" | $(SUDO) tee $(INSTALL_RECORD) > /dev/null
	@echo "✓ Done! You can now run '$(TARGET)' from anywhere"
	@echo "  Installation recorded from: $(CURRENT_DIR)"

force-install:
	@$(MAKE) --no-print-directory $(SUBJ) $(TARGET)
	@$(OWNER_FIX)
	@echo "WARNING: Force installing $(TARGET) - this will overwrite any existing installation"
	@sleep 1
	@$(SUDO) install -Dm755 $(TARGET) $(BINARY_PATH)
	@$(SUDO) mkdir -p $(dir $(INSTALL_RECORD))
	@echo "$(CURRENT_DIR)" | $(SUDO) tee $(INSTALL_RECORD) > /dev/null
	@echo "✓ Force install complete from: $(CURRENT_DIR)"

uninstall:
	@echo "Removing $(TARGET) from $(BINARY_PATH)..."
	@if [ -e $(BINARY_PATH) ] || [ -L $(BINARY_PATH) ]; then \
		RECORDED_DIR=$$(cat $(INSTALL_RECORD) 2>/dev/null || echo ""); \
		if [ -n "$$RECORDED_DIR" ] && [ "$$RECORDED_DIR" != "$(CURRENT_DIR)" ]; then \
			echo "ERROR: This binary was installed from: $$RECORDED_DIR"; \
			echo "Current directory is: $(CURRENT_DIR)"; \
			echo "You are trying to uninstall from a different directory!"; \
			echo "Uninstall cancelled."; \
			exit 1; \
		else \
			$(SUDO) rm -f $(BINARY_PATH); \
			$(SUDO) rm -f $(INSTALL_RECORD); \
			echo "✓ Uninstalled!"; \
		fi; \
	else \
		echo "$(TARGET) is not installed in $(BINARY_PATH)"; \
	fi

check-installed:
	@if [ -e $(BINARY_PATH) ] || [ -L $(BINARY_PATH) ]; then \
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

clean:
	rm -f $(TARGET)
	rm -rf $(OBJ_DIR)

clean-all: clean pgo-clean
	@if [ -e $(BINARY_PATH) ] || [ -L $(BINARY_PATH) ]; then \
		echo "Removing installed binary as well..."; \
		$(SUDO) rm -f $(BINARY_PATH); \
		$(SUDO) rm -f $(INSTALL_RECORD); \
		echo "✓ Removed installed binary"; \
	fi

.PHONY: all build help FORCE debug san tsan pgo-gen pgo-use pgo-clean flags checksec \
        clean clean-all install force-install uninstall check-installed check-conflict
