# XOmB Exokernel Makefile
#
# Targets:
#   make build         - Build both UEFI and multiboot2 kernels
#   make build-uefi    - Build UEFI kernel only
#   make build-mb2     - Build multiboot2 kernel only (for Bochs)
#   make qemu          - Run UEFI kernel in QEMU
#   make bochs         - Run multiboot2 kernel in Bochs
#   make qemu-gdb      - Run in QEMU with GDB server
#   make test          - Run unit tests on host
#   make clippy        - Run clippy lints
#   make fmt           - Format code
#   make clean         - Clean build artifacts

# Targets
TARGET_UEFI := x86_64-unknown-uefi
TARGET_MB2 := x86_64-xomb.json

# Build directories
BUILD_DIR_UEFI := target/$(TARGET_UEFI)
BUILD_DIR_MB2 := target/x86_64-xomb

# Output files
DEBUG_EFI := $(BUILD_DIR_UEFI)/debug/xomb-uefi.efi
RELEASE_EFI := $(BUILD_DIR_UEFI)/release/xomb-uefi.efi
DEBUG_ELF := $(BUILD_DIR_MB2)/debug/xomb-multiboot2
RELEASE_ELF := $(BUILD_DIR_MB2)/release/xomb-multiboot2

# OVMF firmware paths (adjust for your system)
# Ubuntu/Debian: /usr/share/OVMF/
# Fedora: /usr/share/edk2/ovmf/
# Arch: /usr/share/ovmf/x64/
OVMF_DIR ?= /usr/share/OVMF
OVMF_CODE ?= $(OVMF_DIR)/OVMF_CODE_4M.fd
OVMF_VARS ?= $(OVMF_DIR)/OVMF_VARS_4M.fd

# ESP (EFI System Partition) image
ESP_DIR := esp
ESP_IMG := esp.img

# QEMU settings
QEMU := qemu-system-x86_64
QEMU_MEMORY := 512M
QEMU_UEFI := \
	-machine q35 \
	-m $(QEMU_MEMORY) \
	-drive if=pflash,format=raw,readonly=on,file=$(OVMF_CODE) \
	-drive if=pflash,format=raw,file=OVMF_VARS.fd \
	-drive format=raw,file=$(ESP_IMG) \
	-serial stdio \
	-no-reboot

QEMU_MB2 := \
	-machine q35 \
	-m $(QEMU_MEMORY) \
	-kernel $(DEBUG_ELF) \
	-serial stdio \
	-no-reboot

# Bochs settings
BOCHS := /home/$(USER)/Bochs/usr/bin/bochs
BOCHSRC := bochsrc.txt

# Build-std flags
BUILD_STD := -Z build-std=core,compiler_builtins,alloc -Z build-std-features=compiler-builtins-mem
BUILD_STD_NO_ALLOC := -Z build-std=core,compiler_builtins -Z build-std-features=compiler-builtins-mem

.PHONY: all build build-uefi build-mb2 release qemu bochs qemu-gdb qemu-mb2 test clippy fmt clean setup help

all: build

# Build both kernels
build: build-uefi build-mb2

# Build UEFI kernel
build-uefi:
	cargo build --bin xomb-uefi --features uefi --target $(TARGET_UEFI) $(BUILD_STD)

# Build multiboot2 kernel
build-mb2:
	cargo build --bin xomb-multiboot2 --features multiboot2 --target $(TARGET_MB2) $(BUILD_STD_NO_ALLOC)

# Release builds
release: release-uefi release-mb2

release-uefi:
	cargo build --release --bin xomb-uefi --features uefi --target $(TARGET_UEFI) $(BUILD_STD)

release-mb2:
	cargo build --release --bin xomb-multiboot2 --features multiboot2 --target $(TARGET_MB2) $(BUILD_STD_NO_ALLOC)

# Create ESP filesystem image
esp: build-uefi
	@echo "Creating EFI System Partition image..."
	@mkdir -p $(ESP_DIR)/EFI/BOOT
	@cp $(DEBUG_EFI) $(ESP_DIR)/EFI/BOOT/BOOTX64.EFI
	@dd if=/dev/zero of=$(ESP_IMG) bs=1M count=64 2>/dev/null
	@mkfs.fat -F 32 $(ESP_IMG) >/dev/null
	@mcopy -i $(ESP_IMG) -s $(ESP_DIR)/EFI ::

esp-release: release-uefi
	@echo "Creating EFI System Partition image (release)..."
	@mkdir -p $(ESP_DIR)/EFI/BOOT
	@cp $(RELEASE_EFI) $(ESP_DIR)/EFI/BOOT/BOOTX64.EFI
	@dd if=/dev/zero of=$(ESP_IMG) bs=1M count=64 2>/dev/null
	@mkfs.fat -F 32 $(ESP_IMG) >/dev/null
	@mcopy -i $(ESP_IMG) -s $(ESP_DIR)/EFI ::

# Copy OVMF_VARS to local directory (needed for writable vars)
OVMF_VARS.fd:
	@if [ -f "$(OVMF_VARS)" ]; then \
		cp "$(OVMF_VARS)" OVMF_VARS.fd; \
	else \
		echo "Error: OVMF_VARS not found at $(OVMF_VARS)"; \
		echo "Please install OVMF or set OVMF_DIR"; \
		exit 1; \
	fi

# Run targets
run: qemu

# QEMU with UEFI
qemu: esp OVMF_VARS.fd
	@echo "Starting QEMU (UEFI)..."
	$(QEMU) $(QEMU_UEFI)

qemu-release: esp-release OVMF_VARS.fd
	@echo "Starting QEMU (UEFI, release build)..."
	$(QEMU) $(QEMU_UEFI)

qemu-gdb: esp OVMF_VARS.fd
	@echo "Starting QEMU with GDB server on :1234..."
	@echo "Connect with: rust-gdb -ex 'target remote :1234'"
	$(QEMU) $(QEMU_UEFI) -s -S

# QEMU with multiboot2 (boots from GRUB ISO)
qemu-mb2: $(BOOT_ISO)
	@echo "Starting QEMU (multiboot2 via GRUB ISO)..."
	$(QEMU) -machine q35 -m $(QEMU_MEMORY) -cdrom $(BOOT_ISO) -serial stdio -no-reboot

# Bootable ISO for Bochs (GRUB + multiboot2 kernel)
BOOT_ISO := xomb.iso
ISO_DIR := iso_staging

$(BOOT_ISO): build-mb2
	@echo "Creating GRUB bootable ISO..."
	@mkdir -p $(ISO_DIR)/boot/grub
	@cp $(DEBUG_ELF) $(ISO_DIR)/boot/xomb-multiboot2
	@cp boot/grub/grub.cfg $(ISO_DIR)/boot/grub/
	@grub-mkrescue -o $(BOOT_ISO) $(ISO_DIR) 2>/dev/null || \
		(echo "Error: grub-mkrescue failed. Install grub-pc-bin and xorriso." && exit 1)
	@rm -rf $(ISO_DIR)
	@echo "Bootable ISO created: $(BOOT_ISO)"

# Bochs with multiboot2 (boots from ISO)
bochs: $(BOOT_ISO)
	@echo "Starting Bochs (multiboot2 via GRUB ISO)..."
	@if [ ! -f "$(BOCHSRC)" ]; then \
		echo "Error: $(BOCHSRC) not found"; \
		exit 1; \
	fi
	$(BOCHS) -f $(BOCHSRC) -q

# Alternative: QEMU with ISO (useful for testing GRUB boot)
qemu-iso: $(BOOT_ISO)
	@echo "Starting QEMU with GRUB ISO..."
	$(QEMU) -machine q35 -m $(QEMU_MEMORY) -cdrom $(BOOT_ISO) -serial stdio -no-reboot

# Testing
test:
	cargo test --lib --target x86_64-unknown-linux-gnu

test-verbose:
	cargo test --lib --target x86_64-unknown-linux-gnu -- --nocapture

# Linting and formatting
clippy:
	cargo clippy --lib --target x86_64-unknown-linux-gnu -- -D warnings
	cargo clippy --bin xomb-uefi --features uefi --target $(TARGET_UEFI) $(BUILD_STD) -- -D warnings

fmt:
	cargo fmt

fmt-check:
	cargo fmt -- --check

# Clean
clean:
	cargo clean
	rm -rf $(ESP_DIR) $(ESP_IMG) $(BOOT_ISO) $(ISO_DIR) OVMF_VARS.fd bochs.log debugger.log serial.log

# Setup helper - checks dependencies
setup:
	@echo "Checking dependencies..."
	@echo ""
	@echo "Rust toolchain:"
	@rustc --version || echo "  ERROR: rustc not found"
	@cargo --version || echo "  ERROR: cargo not found"
	@echo ""
	@echo "Required components:"
	@rustup component list --installed | grep -E "(rust-src|llvm-tools)" || echo "  Run: rustup component add rust-src llvm-tools-preview"
	@echo ""
	@echo "Targets:"
	@rustup target list --installed | grep -E "($(TARGET_UEFI)|$(TARGET_MB2))" || echo "  Run: rustup target add $(TARGET_UEFI) $(TARGET_MB2)"
	@echo ""
	@echo "OVMF firmware:"
	@if [ -f "$(OVMF_CODE)" ]; then echo "  Found: $(OVMF_CODE)"; else echo "  NOT FOUND: $(OVMF_CODE)"; fi
	@if [ -f "$(OVMF_VARS)" ]; then echo "  Found: $(OVMF_VARS)"; else echo "  NOT FOUND: $(OVMF_VARS)"; fi
	@echo ""
	@echo "Emulators:"
	@which qemu-system-x86_64 >/dev/null 2>&1 && echo "  QEMU: $$(which qemu-system-x86_64)" || echo "  QEMU: NOT FOUND"
	@which bochs >/dev/null 2>&1 && echo "  Bochs: $$(which bochs)" || echo "  Bochs: NOT FOUND"
	@echo ""
	@echo "Disk tools:"
	@which mkfs.fat >/dev/null 2>&1 && echo "  mkfs.fat: OK" || echo "  mkfs.fat: NOT FOUND (install dosfstools)"
	@which mcopy >/dev/null 2>&1 && echo "  mcopy: OK" || echo "  mcopy: NOT FOUND (install mtools)"
	@echo ""
	@echo "Assembler:"
	@which as >/dev/null 2>&1 && echo "  as (GNU assembler): OK" || echo "  as: NOT FOUND (install binutils)"
	@echo ""
	@echo "ISO creation:"
	@which grub-mkrescue >/dev/null 2>&1 && echo "  grub-mkrescue: OK" || echo "  grub-mkrescue: NOT FOUND (install grub-common)"
	@which xorriso >/dev/null 2>&1 && echo "  xorriso: OK" || echo "  xorriso: NOT FOUND (install xorriso)"

# Help
help:
	@echo "XOmB Exokernel Build System"
	@echo ""
	@echo "Build commands:"
	@echo "  make build        Build both UEFI and multiboot2 kernels"
	@echo "  make build-uefi   Build UEFI kernel only"
	@echo "  make build-mb2    Build multiboot2 kernel only"
	@echo "  make release      Build both in release mode"
	@echo ""
	@echo "Run commands:"
	@echo "  make qemu         Run UEFI kernel in QEMU"
	@echo "  make qemu-mb2     Run multiboot2 kernel in QEMU"
	@echo "  make bochs        Run multiboot2 kernel in Bochs"
	@echo "  make qemu-gdb     Run UEFI kernel with GDB server"
	@echo ""
	@echo "Test commands:"
	@echo "  make test         Run unit tests on host"
	@echo "  make clippy       Run clippy lints"
	@echo "  make fmt          Format code"
	@echo ""
	@echo "Other:"
	@echo "  make setup        Check development dependencies"
	@echo "  make clean        Remove build artifacts"
