#!/bin/bash

set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}Building FCM Push Listener universal library${NC}"

# Save current directory
PROJECT_DIR=$(pwd)

# Complete clean
echo -e "${BLUE}Cleaning previous builds...${NC}"
cargo clean
rm -rf target/

# Force dynamic OpenSSL
export OPENSSL_NO_VENDOR=1
export OPENSSL_STATIC=0
export OPENSSL_DYNAMIC=1

# Create cargo config for dynamic linking
mkdir -p .cargo
cat > .cargo/config.toml << 'EOF'
[env]
OPENSSL_NO_VENDOR = "1"
OPENSSL_STATIC = "0"

[target.x86_64-apple-darwin]
rustflags = ["-C", "link-arg=-undefined", "-C", "link-arg=dynamic_lookup"]

[target.aarch64-apple-darwin]
rustflags = ["-C", "link-arg=-undefined", "-C", "link-arg=dynamic_lookup"]
EOF

# Install cbindgen if needed (only if using FFI feature)
if [ -f "cbindgen.toml" ]; then
    if ! command -v cbindgen &> /dev/null; then
        echo -e "${BLUE}Installing cbindgen...${NC}"
        cargo install cbindgen
    fi
    
    # Generate headers
    mkdir -p include
    echo -e "${BLUE}Generating C/C++ headers...${NC}"
    
    # Generate C++ header
    cbindgen --config cbindgen.toml --lang c++ --output include/fcm_push_listener.hpp || {
        echo -e "${RED}Warning: Failed to generate C++ header${NC}"
    }
    
    # Generate C header
    cbindgen --config cbindgen.toml --lang c --output include/fcm_push_listener.h || {
        echo -e "${RED}Warning: Failed to generate C header${NC}"
    }
fi

# Build for each architecture
echo -e "${BLUE}Building for x86_64-apple-darwin...${NC}"
if ! cargo build --release --features ffi --lib --target x86_64-apple-darwin; then
    echo -e "${RED}Failed to build x86_64 library${NC}"
    exit 1
fi

echo -e "${BLUE}Building for aarch64-apple-darwin...${NC}"
if ! cargo build --release --features ffi --lib --target aarch64-apple-darwin; then
    echo -e "${RED}Failed to build arm64 library${NC}"
    exit 1
fi

# Verify libraries exist
if [ ! -f "target/x86_64-apple-darwin/release/libfcm_push_listener.a" ]; then
    echo -e "${RED}ERROR: x86_64 library not found${NC}"
    exit 1
fi

if [ ! -f "target/aarch64-apple-darwin/release/libfcm_push_listener.a" ]; then
    echo -e "${RED}ERROR: arm64 library not found${NC}"
    exit 1
fi

# Create universal library directory
mkdir -p target/universal/release

# Function to clean archive
clean_archive() {
    local input_arch=$1
    local output_name=$2
    local expected_arch=$3
    
    echo "Cleaning $input_arch archive..."
    
    local tmpdir=$(mktemp -d)
    cd "$tmpdir"
    
    # Extract all objects
    ar x "$PROJECT_DIR/target/$input_arch/release/libfcm_push_listener.a"
    
    local total_objects=$(ls -1 *.o 2>/dev/null | wc -l | tr -d ' ')
    echo "  Total objects: $total_objects"
    
    # Remove OpenSSL objects
    local removed_count=0
    for pattern in "lib*ssl*.o" "lib*crypto*.o" "libcommon*.o" "libdefault*.o" "liblegacy*.o"; do
        local files_to_remove=$(ls $pattern 2>/dev/null || true)
        if [ -n "$files_to_remove" ]; then
            rm -f $pattern
            removed_count=$((removed_count + $(echo "$files_to_remove" | wc -w)))
        fi
    done
    echo "  Removed $removed_count OpenSSL objects"
    
    # Remove objects with wrong architecture
    local wrong_arch_count=0
    for obj in *.o; do
        if [ -f "$obj" ]; then
            if file "$obj" | grep -q "$expected_arch"; then
                : # Correct architecture, keep it
            else
                rm -f "$obj"
                ((wrong_arch_count++))
            fi
        fi
    done
    echo "  Removed $wrong_arch_count wrong architecture objects"
    
    # Create cleaned archive
    local remaining=$(ls -1 *.o 2>/dev/null | wc -l | tr -d ' ')
    echo "  Remaining objects: $remaining"
    
    if [ "$remaining" -gt 0 ]; then
        ar rcs "$PROJECT_DIR/target/universal/release/$output_name" *.o
    else
        echo -e "${RED}  ERROR: No objects left after cleaning!${NC}"
        cd "$PROJECT_DIR"
        rm -rf "$tmpdir"
        return 1
    fi
    
    cd "$PROJECT_DIR"
    rm -rf "$tmpdir"
}

# Clean both architectures
echo -e "${BLUE}Cleaning archives from OpenSSL objects...${NC}"
clean_archive "x86_64-apple-darwin" "libfcm_push_listener_x86_64.a" "x86_64"
clean_archive "aarch64-apple-darwin" "libfcm_push_listener_arm64.a" "arm64"

# Create universal library
echo -e "${BLUE}Creating universal library...${NC}"
lipo -create \
    target/universal/release/libfcm_push_listener_x86_64.a \
    target/universal/release/libfcm_push_listener_arm64.a \
    -output target/universal/release/libfcm_push_listener.a

# Clean up temporary files
rm -f target/universal/release/libfcm_push_listener_x86_64.a
rm -f target/universal/release/libfcm_push_listener_arm64.a

# Verify the result
echo -e "${GREEN}Build complete!${NC}"
echo ""
echo "Files created:"
echo "  Library: target/universal/release/libfcm_push_listener.a"
if [ -f "include/fcm_push_listener.h" ]; then
    echo "  C header: include/fcm_push_listener.h"
fi
if [ -f "include/fcm_push_listener.hpp" ]; then
    echo "  C++ header: include/fcm_push_listener.hpp"
fi

echo ""
echo "Library info:"
lipo -info target/universal/release/libfcm_push_listener.a
ls -lh target/universal/release/libfcm_push_listener.a

# Quick symbol check
echo ""
echo -e "${BLUE}Quick symbol check:${NC}"
echo "OpenSSL symbols (should NOT be defined in library):"
nm target/universal/release/libfcm_push_listener.a 2>/dev/null | grep -E "T _SSL_|T _CRYPTO_" | head -5 || echo "  Good: No OpenSSL symbols found"

echo ""
echo "Undefined aws-lc/ring symbols (expected):"
nm -u target/universal/release/libfcm_push_listener.a 2>/dev/null | grep -E "_aws_lc|_ring" | head -5

echo ""
echo -e "${GREEN}Ready for integration with your C++ project!${NC}"