#!/bin/bash

# This script configures the vbox-adapter-check file to run automatically. It performs setup of a cron task.

# --- Configuration ---
INSTALL_DIR="$HOME/vbox"

set -e

echo_step() {
  echo -e "\n\033[1;34m==> $1\033[0m"
}

echo_info() {
  echo "$1"
}

echo_success() {
  echo -e "\033[1;32m✅ $1\033[0m"
}

echo_error() {
  echo -e "\n\033[1;31m❌ ERROR: $1\033[0m" >&2
  exit 1
}

# Step 1: Create installation directory and copy files
echo_step "Setting up installation directory..."
mkdir -p "$INSTALL_DIR"
SCRIPT_DIR=$(dirname "$0")
if [ -f "$SCRIPT_DIR/vbox-adapter-check" -a -f "$SCRIPT_DIR/vbox-clean-snapshots" ]; then
    cp "$SCRIPT_DIR/vbox-adapter-check" "$INSTALL_DIR/"
    cp "$SCRIPT_DIR/vbox-clean-snapshots" "$INSTALL_DIR/"
elif [ -f "vbox-adapter-check" -a -f "vbox-clean-snapshots" ]; then
    cp "vbox-adapter-check" "$INSTALL_DIR/"
    cp "vbox-clean-snapshots" "$INSTALL_DIR/"
else
    echo_error "The 'vbox-adapter-check' and 'vbox-clean-snapshots' binaries are not in the directory of the script or the current directory."
fi
echo_info "Copied 'vbox-adapter-check' and 'vbox-clean-snapshots' to $INSTALL_DIR"

# Step 2: Make files executable
echo_step "Making tools in $INSTALL_DIR executable..."
if ! chmod +x "$INSTALL_DIR"/*; then
  echo_error "Failed to set execute permissions on files in $INSTALL_DIR."
fi
echo_info "File permissions updated."

# Step 3: Run vbox-adapter-check
echo_step "Running vbox-adapter-check"
$INSTALL_DIR/vbox-adapter-check

# Step 4: Schedule the cron job if it doesn't exist
echo_step "Scheduling background task..."
CRON_JOB="*/5 * * * * (echo \"# \$(date)\"; $INSTALL_DIR/vbox-adapter-check) >> \"$INSTALL_DIR/vbox-adapter-check.log\" 2>&1"

# Check if the job already exists
if crontab -l 2>/dev/null | grep -Fq "vbox-adapter-check"; then
    echo_info "Cron job for vbox-adapter-check already exists. Skipping."
else
    echo_info "Adding cron job..."
    (crontab -l 2>/dev/null; echo "$CRON_JOB") | crontab -
    echo_info "Cron job scheduled."
fi

echo_success "Installation Successful!"
echo_info "The vbox tools are installed in: $INSTALL_DIR"
echo_info "vbox-adapter-check writes logging information every 5 minutes to: $INSTALL_DIR/vbox-adapter-check.log"

echo_step "MANUAL ACTION REQUIRED: Add to PATH"
echo_info "To run the 'vbox' commands easily, you must add the installation directory to your shell's PATH."
echo_info "Choose the command for your shell and add it to your startup file (e.g., ~/.bashrc, ~/.zshrc):"
echo ""
echo "    # For bash or zsh shells:"
echo "    echo 'export PATH=\"\$HOME/vbox:\$PATH\"' >> ~/.bashrc  # Or ~/.zshrc"
echo ""
echo "    # For fish shell:"
echo "    echo 'set -U fish_user_paths \$HOME/vbox \$fish_user_paths' >> ~/.config/fish/config.fish"
echo ""
echo_info "After updating your config file, restart your shell or run 'source ~/.bashrc' (or equivalent) to apply the changes."
