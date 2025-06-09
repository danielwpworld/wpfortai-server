#!/bin/bash
set -e # Exit immediately if a command exits with a non-zero status.

# --- Script must be run as root ---
if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root. Please use: sudo $0" >&2
  exit 1
fi
echo "Running as user: $(whoami)" # Should output 'root'

# --- Configuration ---
SERVER_DIR="/wpfort-server"
REPO_URL="https://github.com/danielwpworld/wpfortai-server.git" # Plain HTTPS URL
SERVICE_NAME="wpfort"
GIT_BRANCH="main" # Or your desired production branch

# Location of the environment file to be copied
# Assuming this script is run from a directory that contains 'env_files' subdirectory
SOURCE_ENV_FILE_DIR="$(pwd)/env_files" # Directory where this script is located, then /env_files
SOURCE_ENV_FILE_NAME=".env.local_server"
TARGET_ENV_FILE_NAME=".env.local"

# --- GitHub CLI Setup ---
echo "--- GitHub CLI Setup ---"
# Check if GitHub CLI (gh) is installed
if ! command -v gh &> /dev/null; then
    echo "ERROR: GitHub CLI (gh) is not installed. Please install it first."
    echo "Installation instructions: https://github.com/cli/cli#installation"
    exit 1
fi

# Check GitHub CLI authentication status for the current user (root)
echo "Checking GitHub CLI authentication status for github.com..."
if ! gh auth status --hostname github.com &>/dev/null; then
    echo "GitHub CLI is not authenticated for github.com."
    echo "Attempting to authenticate GitHub CLI interactively..."
    if gh auth login --hostname github.com; then
        echo "GitHub CLI authentication successful."
    else
        echo "ERROR: GitHub CLI authentication failed."
        echo "If this script needs to be non-interactive, ensure gh is pre-authenticated for root"
        echo "or run this script with 'sudo GITHUB_TOKEN=your_token ./your_script.sh' and modify the"
        echo "script to use 'gh auth login --with-token <<< \"\$GITHUB_TOKEN\"' inside the if block for first-time auth."
        exit 1
    fi
else
    echo "GitHub CLI is already authenticated for github.com."
fi

echo "Ensuring Git is configured to use GitHub CLI for authentication..."
gh auth setup-git --hostname github.com
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to configure Git with GitHub CLI."
    exit 1
fi
echo "--- GitHub CLI Setup Complete ---"
echo ""

# --- Deployment Steps ---
echo "--- Starting WPFort Server Deployment ---"

echo "Stopping $SERVICE_NAME server..."
systemctl stop "$SERVICE_NAME" || echo "Warning: Failed to stop $SERVICE_NAME (it might not have been running)."

# Navigate to server directory or clone/initialize if it doesn't exist or isn't a git repo
if [ ! -d "$SERVER_DIR/.git" ]; then
    if [ -d "$SERVER_DIR" ]; then
        echo "$SERVER_DIR exists but is not a git repository. Removing for fresh clone."
        rm -rf "$SERVER_DIR"
    else
        echo "$SERVER_DIR does not exist."
    fi
    echo "Cloning $REPO_URL into $SERVER_DIR..."
    parent_dir=$(dirname "$SERVER_DIR")
    if [ ! -d "$parent_dir" ]; then
        echo "Creating parent directory: $parent_dir"
        mkdir -p "$parent_dir"
    fi

    if git clone "$REPO_URL" "$SERVER_DIR"; then
        cd "$SERVER_DIR"
    else
        echo "ERROR: Failed to clone repository $REPO_URL into $SERVER_DIR."
        exit 1
    fi
else
    echo "Navigating to existing git repository: $SERVER_DIR..."
    cd "$SERVER_DIR"

    if git remote | grep -q "^origin$"; then
        echo "Remote 'origin' exists."
        current_url=$(git remote get-url origin 2>/dev/null || echo "failed_to_get_url")
        if [ "$current_url" != "$REPO_URL" ]; then
            echo "Updating remote URL 'origin' from '$current_url' to '$REPO_URL'"
            git remote set-url origin "$REPO_URL"
        else
            echo "Remote 'origin' URL is already correct: $REPO_URL"
        fi
    else
        echo "Remote 'origin' does not exist. Adding it with URL: $REPO_URL"
        git remote add origin "$REPO_URL"
    fi
fi

echo "Configuring safe directory for Git: $SERVER_DIR"
git config --global --add safe.directory "$SERVER_DIR"

echo "Pulling latest changes from origin/$GIT_BRANCH..."
git fetch origin
if [ $? -ne 0 ]; then
    echo "ERROR: git fetch failed. Check authentication, repository access, and network."
    exit 1
fi

echo "Resetting to origin/$GIT_BRANCH (will overwrite local changes)..."
echo "Stashing any local changes (if any)..."
git stash push -u -m "Pre-deployment stash $(date +%Y-%m-%d_%H-%M-%S)" || true
echo "Cleaning working directory..."
git clean -fdx
echo "Resetting to remote branch..."
git reset --hard "origin/$GIT_BRANCH"
if [ $? -ne 0 ]; then
    echo "ERROR: git reset --hard failed."
    exit 1
fi

# --- Copy Environment File ---
FULL_SOURCE_ENV_FILE_PATH="${SOURCE_ENV_FILE_DIR}/${SOURCE_ENV_FILE_NAME}"
TARGET_ENV_FILE_PATH="${SERVER_DIR}/${TARGET_ENV_FILE_NAME}"

echo "Attempting to copy environment file..."
if [ -f "$FULL_SOURCE_ENV_FILE_PATH" ]; then
    echo "Copying $FULL_SOURCE_ENV_FILE_PATH to $TARGET_ENV_FILE_PATH"
    cp "$FULL_SOURCE_ENV_FILE_PATH" "$TARGET_ENV_FILE_PATH"
    # Optional: Set permissions for the .env.local file if needed
    # chmod 600 "$TARGET_ENV_FILE_PATH" # Example: restrict read/write to owner
    echo "Environment file copied successfully."
else
    echo "ERROR: Source environment file not found at $FULL_SOURCE_ENV_FILE_PATH"
    echo "Please ensure the env_files directory and $SOURCE_ENV_FILE_NAME exist in the same directory as this script, or adjust SOURCE_ENV_FILE_DIR."
    exit 1
fi
# --- End Copy Environment File ---

echo "Installing dependencies..."
if [ -f "package-lock.json" ]; then
    echo "Using npm ci for dependency installation."
    npm ci
else
    echo "Using npm install for dependency installation."
    npm install
fi
if [ $? -ne 0 ]; then
    echo "ERROR: npm install/ci failed."
    exit 1
fi

echo "Building project..."
if npm run build; then
    echo "Build successful."
else
    echo "ERROR: npm run build failed."
    exit 1
fi

echo "Starting $SERVICE_NAME server..."
if systemctl start "$SERVICE_NAME"; then
    echo "$SERVICE_NAME started successfully."
else
    echo "ERROR: Failed to start $SERVICE_NAME. Check service logs with 'journalctl -u $SERVICE_NAME -n 100'."
    exit 1
fi

echo ""
echo "--- Deployment Complete! ---"
echo "Checking recent logs for $SERVICE_NAME (last 20 lines, following):"
journalctl -u "$SERVICE_NAME" -n 20 -f