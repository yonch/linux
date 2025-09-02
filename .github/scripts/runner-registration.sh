#!/bin/bash
set -euo pipefail

# GitHub Runner Registration Helper Script
# This script handles registration of a new GitHub Actions runner
# Usage: ./runner-registration.sh <action> <args...>

ACTION="${1:-}"
REPO_OWNER="${GITHUB_REPOSITORY_OWNER:-}"
REPO_NAME="${GITHUB_REPOSITORY##*/}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $*" >&2
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR:${NC} $*" >&2
}

warning() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING:${NC} $*" >&2
}

# Function to get registration token from GitHub
get_registration_token() {
    local github_token="$1"
    
    log "Requesting GitHub registration token..."
    
    RESPONSE=$(curl -s -X POST \
        -H "Accept: application/vnd.github.v3+json" \
        -H "Authorization: token ${github_token}" \
        "https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/actions/runners/registration-token")
    
    TOKEN=$(echo "$RESPONSE" | jq -r '.token')
    
    if [[ -z "$TOKEN" || "$TOKEN" == "null" ]]; then
        error "Failed to get registration token"
        echo "Response: $RESPONSE" >&2
        return 1
    fi
    
    echo "$TOKEN"
}

# Function to register a runner
register_runner() {
    local runner_dir="$1"
    local runner_name="$2"
    local runner_labels="$3"
    local registration_token="$4"
    local work_dir="${5:-_work}"
    
    log "Registering runner: $runner_name"
    log "Labels: $runner_labels"
    log "Runner directory: $runner_dir"
    
    cd "$runner_dir"
    
    # Configure the runner
    export RUNNER_ALLOW_RUNASROOT=1
    
    ./config.sh \
        --url "https://github.com/${REPO_OWNER}/${REPO_NAME}" \
        --token "$registration_token" \
        --name "$runner_name" \
        --labels "$runner_labels" \
        --work "$work_dir" \
        --unattended \
        --replace
    
    if [[ $? -eq 0 ]]; then
        log "✅ Runner registered successfully: $runner_name"
        return 0
    else
        error "Failed to register runner"
        return 1
    fi
}

# Function to start a runner
start_runner() {
    local runner_dir="$1"
    local run_as_service="${2:-false}"
    
    log "Starting runner in directory: $runner_dir"
    
    cd "$runner_dir"
    
    export RUNNER_ALLOW_RUNASROOT=1
    
    if [[ "$run_as_service" == "true" ]]; then
        log "Installing and starting runner as systemd service..."
        
        # Create systemd service
        cat > /etc/systemd/system/github-runner-custom.service << EOF
[Unit]
Description=GitHub Actions Runner (Custom Kernel)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=$runner_dir
ExecStart=$runner_dir/run.sh
Restart=on-failure
RestartSec=10
StartLimitBurst=5
Environment="RUNNER_ALLOW_RUNASROOT=1"
StandardOutput=journal+console
StandardError=journal+console

[Install]
WantedBy=multi-user.target
EOF
        
        systemctl daemon-reload
        systemctl enable github-runner-custom.service
        systemctl start github-runner-custom.service
        
        log "✅ Runner service started"
    else
        log "Starting runner in foreground..."
        ./run.sh &
        RUNNER_PID=$!
        log "✅ Runner started with PID: $RUNNER_PID"
        echo "$RUNNER_PID"
    fi
}

# Function to check if a runner is online
check_runner_status() {
    local github_token="$1"
    local runner_label="$2"
    
    RESPONSE=$(curl -s \
        -H "Accept: application/vnd.github.v3+json" \
        -H "Authorization: token ${github_token}" \
        "https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/actions/runners")
    
    # Check if any runner with the label exists and is online
    RUNNER_STATUS=$(echo "$RESPONSE" | jq -r \
        --arg label "$runner_label" \
        '.runners[] | select(.labels[].name == $label) | .status' | head -1)
    
    if [[ "$RUNNER_STATUS" == "online" ]]; then
        echo "online"
        return 0
    elif [[ -n "$RUNNER_STATUS" ]]; then
        echo "$RUNNER_STATUS"
        return 1
    else
        echo "not_found"
        return 1
    fi
}

# Function to wait for runner to become online
wait_for_runner() {
    local github_token="$1"
    local runner_label="$2"
    local timeout_seconds="${3:-300}"  # Default 5 minutes
    local check_interval="${4:-10}"    # Check every 10 seconds
    
    log "Waiting for runner with label '$runner_label' to become online..."
    log "Timeout: ${timeout_seconds}s, Check interval: ${check_interval}s"
    
    local elapsed=0
    
    while [[ $elapsed -lt $timeout_seconds ]]; do
        STATUS=$(check_runner_status "$github_token" "$runner_label")
        
        if [[ "$STATUS" == "online" ]]; then
            log "✅ Runner is online!"
            return 0
        elif [[ "$STATUS" == "not_found" ]]; then
            warning "Runner not found yet..."
        else
            warning "Runner status: $STATUS"
        fi
        
        sleep "$check_interval"
        elapsed=$((elapsed + check_interval))
        log "Waiting... (${elapsed}s/${timeout_seconds}s)"
    done
    
    error "Timeout waiting for runner to become online"
    return 1
}

# Function to remove a runner
remove_runner() {
    local github_token="$1"
    local runner_label="$2"
    
    log "Removing runner with label: $runner_label"
    
    # Get runner ID
    RESPONSE=$(curl -s \
        -H "Accept: application/vnd.github.v3+json" \
        -H "Authorization: token ${github_token}" \
        "https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/actions/runners")
    
    RUNNER_ID=$(echo "$RESPONSE" | jq -r \
        --arg label "$runner_label" \
        '.runners[] | select(.labels[].name == $label) | .id' | head -1)
    
    if [[ -z "$RUNNER_ID" || "$RUNNER_ID" == "null" ]]; then
        warning "Runner with label '$runner_label' not found"
        return 0
    fi
    
    log "Found runner ID: $RUNNER_ID"
    
    # Remove the runner
    RESPONSE=$(curl -s -X DELETE \
        -H "Accept: application/vnd.github.v3+json" \
        -H "Authorization: token ${github_token}" \
        "https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/actions/runners/${RUNNER_ID}")
    
    if [[ $? -eq 0 ]]; then
        log "✅ Runner removed successfully"
        return 0
    else
        error "Failed to remove runner"
        return 1
    fi
}

# Main execution
case "$ACTION" in
    get-token)
        GITHUB_TOKEN="${2:-$GITHUB_TOKEN}"
        get_registration_token "$GITHUB_TOKEN"
        ;;
    
    register)
        RUNNER_DIR="${2:-/tmp/actions-runner}"
        RUNNER_NAME="${3:-github-runner-$$}"
        RUNNER_LABELS="${4:-self-hosted,Linux,X64}"
        REGISTRATION_TOKEN="${5:-}"
        WORK_DIR="${6:-_work}"
        
        if [[ -z "$REGISTRATION_TOKEN" ]]; then
            error "Registration token is required"
            exit 1
        fi
        
        register_runner "$RUNNER_DIR" "$RUNNER_NAME" "$RUNNER_LABELS" "$REGISTRATION_TOKEN" "$WORK_DIR"
        ;;
    
    start)
        RUNNER_DIR="${2:-/tmp/actions-runner}"
        RUN_AS_SERVICE="${3:-false}"
        start_runner "$RUNNER_DIR" "$RUN_AS_SERVICE"
        ;;
    
    check-status)
        GITHUB_TOKEN="${2:-$GITHUB_TOKEN}"
        RUNNER_LABEL="${3:-}"
        
        if [[ -z "$RUNNER_LABEL" ]]; then
            error "Runner label is required"
            exit 1
        fi
        
        check_runner_status "$GITHUB_TOKEN" "$RUNNER_LABEL"
        ;;
    
    wait)
        GITHUB_TOKEN="${2:-$GITHUB_TOKEN}"
        RUNNER_LABEL="${3:-}"
        TIMEOUT="${4:-300}"
        CHECK_INTERVAL="${5:-10}"
        
        if [[ -z "$RUNNER_LABEL" ]]; then
            error "Runner label is required"
            exit 1
        fi
        
        wait_for_runner "$GITHUB_TOKEN" "$RUNNER_LABEL" "$TIMEOUT" "$CHECK_INTERVAL"
        ;;
    
    remove)
        GITHUB_TOKEN="${2:-$GITHUB_TOKEN}"
        RUNNER_LABEL="${3:-}"
        
        if [[ -z "$RUNNER_LABEL" ]]; then
            error "Runner label is required"
            exit 1
        fi
        
        remove_runner "$GITHUB_TOKEN" "$RUNNER_LABEL"
        ;;
    
    *)
        echo "Usage: $0 <action> [args...]"
        echo ""
        echo "Actions:"
        echo "  get-token <github_token>"
        echo "    Get a registration token from GitHub"
        echo ""
        echo "  register <runner_dir> <runner_name> <runner_labels> <registration_token> [work_dir]"
        echo "    Register a new runner"
        echo ""
        echo "  start <runner_dir> [run_as_service]"
        echo "    Start a registered runner"
        echo ""
        echo "  check-status <github_token> <runner_label>"
        echo "    Check if a runner is online"
        echo ""
        echo "  wait <github_token> <runner_label> [timeout_seconds] [check_interval]"
        echo "    Wait for a runner to become online"
        echo ""
        echo "  remove <github_token> <runner_label>"
        echo "    Remove a runner from GitHub"
        exit 1
        ;;
esac