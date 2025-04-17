#!/bin/bash

echo "Stopping WPFort server..."
sudo systemctl stop wpfort

echo "Pulling latest changes..."
cd /wpfort-server && git pull origin main

echo "Installing dependencies..."
npm install

echo "Building project..."
npm run build

echo "Starting WPFort server..."
sudo systemctl start wpfort

echo "Deployment complete!"
echo "Checking logs..."
sudo journalctl -u wpfort -n 20 -f
