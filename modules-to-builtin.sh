#!/bin/bash

# Script to convert all kernel modules to built-in
# This eliminates the need for initrd by building everything into the kernel

set -e

CONFIG_FILE=".config"
BACKUP_FILE=".config.backup.$(date +%Y%m%d_%H%M%S)"

if [ ! -f "$CONFIG_FILE" ]; then
    echo "Error: $CONFIG_FILE not found. Please run this from the kernel source directory."
    exit 1
fi

echo "Converting all modules to built-in..."
echo "Original config backed up to: $BACKUP_FILE"

# Backup original config
cp "$CONFIG_FILE" "$BACKUP_FILE"

# Count modules before conversion
MODULES_BEFORE=$(grep -c "=m$" "$CONFIG_FILE" || true)
echo "Modules before conversion: $MODULES_BEFORE"

# Convert all =m to =y
sed -i 's/=m$/=y/g' "$CONFIG_FILE"

# Optionally disable module support entirely since we're building everything in
echo ""
read -p "Disable module support entirely? This will prevent loading any modules later. (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Disabling module support..."
    sed -i 's/^CONFIG_MODULES=y$/# CONFIG_MODULES is not set/' "$CONFIG_FILE"
    # Also disable module-related options that become irrelevant
    sed -i 's/^CONFIG_MODULE_UNLOAD=y$/# CONFIG_MODULE_UNLOAD is not set/' "$CONFIG_FILE"
    sed -i 's/^CONFIG_STRICT_MODULE_RWX=y$/# CONFIG_STRICT_MODULE_RWX is not set/' "$CONFIG_FILE"
fi

# Count modules after conversion
MODULES_AFTER=$(grep -c "=m$" "$CONFIG_FILE" || true)
echo "Modules after conversion: $MODULES_AFTER"

# Show what changed
CONVERTED=$((MODULES_BEFORE - MODULES_AFTER))
echo "Converted $CONVERTED modules to built-in"

echo ""
echo "Next steps:"
echo "1. Run 'make oldconfig' to resolve any dependency conflicts"
echo "2. Run 'make -j$(nproc)' to build the kernel with everything built-in"
echo "3. The resulting kernel will not need initrd/initramfs"

echo ""
echo "To restore original config: cp $BACKUP_FILE $CONFIG_FILE"