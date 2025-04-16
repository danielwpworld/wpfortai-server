#!/bin/bash

# Exit on any error
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}Starting WPFort Server Installation...${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
  echo -e "${RED}Please run as root${NC}"
  exit 1
fi

# Create wpfort-server directory
echo -e "${YELLOW}Creating server directory...${NC}"
mkdir -p /wpfort-server
cd /wpfort-server

# Install system dependencies
echo -e "${YELLOW}Installing system dependencies...${NC}"
apt-get update
apt-get install -y curl git redis-server build-essential

# Install Node.js 18.x
echo -e "${YELLOW}Installing Node.js...${NC}"
curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
apt-get install -y nodejs

# Check if GITHUB_TOKEN is provided
if [ -z "$GITHUB_TOKEN" ]; then
    echo -e "${RED}Error: GITHUB_TOKEN environment variable is not set${NC}"
    echo -e "${YELLOW}Please run the script with:${NC}"
    echo -e "GITHUB_TOKEN=your_token ./install.sh"
    exit 1
fi

# Clone the repository using token
echo -e "${YELLOW}Cloning WPFort server repository...${NC}"
git clone https://oauth2:${GITHUB_TOKEN}@github.com/danielwpworld/wpfortai-server.git .

# Install npm dependencies
echo -e "${YELLOW}Installing npm dependencies...${NC}"
npm install

# Install TypeScript globally
echo -e "${YELLOW}Installing TypeScript globally...${NC}"
npm install -g typescript

# Setup environment file
echo -e "${YELLOW}Setting up environment configuration...${NC}"
cat > .env.local << EOL
# Database Configuration (Neon)
DATABASE_URL=your-neon-connection-string
REDIS_SERVER=localhost:6379
REDIS_USERNAME=
REDIS_PASSWORD=

# Grafana Loki Configuration
GRAFANA_LOKI_HOST=your-loki-host
GRAFANA_LOKI_USER=your-loki-user
GRAFANA_LOKI_TOKEN=your-loki-token

# Server Configuration
PORT=3000
NODE_ENV=production

# Webhook Configuration
WEBHOOK_SECRET_KEY=
WEBHOOK_SIGNATURE_HEADER=x-wpfort-signature
WEBHOOK_TIMESTAMP_HEADER=x-wpfort-timestamp
EOL

# Generate a random webhook secret key
WEBHOOK_SECRET=$(openssl rand -hex 32)
sed -i "s/WEBHOOK_SECRET_KEY=/WEBHOOK_SECRET_KEY=${WEBHOOK_SECRET}/" .env.local

# Build the TypeScript code
echo -e "${YELLOW}Building TypeScript code...${NC}"
npm run build

# Verify the build output exists
if [ ! -f "dist/index.js" ]; then
    echo -e "${RED}Error: Build failed - dist/index.js not found${NC}"
    echo -e "${YELLOW}Build output:${NC}"
    ls -la dist/
    exit 1
fi

# Set correct permissions
chown -R root:root /wpfort-server
chmod -R 755 /wpfort-server

# Setup systemd service
echo -e "${YELLOW}Creating systemd service...${NC}"
cat > /etc/systemd/system/wpfort.service << EOL
[Unit]
Description=WPFort Server
After=network.target redis-server.service

[Service]
Type=simple
User=root
WorkingDirectory=/wpfort-server
Environment=NODE_ENV=production
ExecStart=/usr/bin/node /wpfort-server/dist/index.js
Restart=always
RestartSec=3
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
EOL

# Configure Redis for production
echo -e "${YELLOW}Configuring Redis...${NC}"
sed -i 's/bind 127.0.0.1/bind 127.0.0.1/g' /etc/redis/redis.conf
systemctl restart redis-server

# Note: Database migrations should be run through Neon's interface

# Reload systemd and enable service
systemctl daemon-reload
systemctl enable wpfort

# Start the service
systemctl start wpfort

echo -e "${GREEN}Installation complete!${NC}"
echo -e "${GREEN}WPFort server is now running on port 3000${NC}"
echo -e "${YELLOW}Important: Please update the following in .env.local:${NC}"
echo -e "${YELLOW}1. Grafana Loki configuration${NC}"
echo -e "${YELLOW}2. Your Neon database connection string${NC}"
echo -e "\nWebhook secret key has been automatically generated."
echo -e "Server logs can be viewed with: journalctl -u wpfort -f"
