# WPFort Server Installation Guide

This guide explains how to install and run the WPFort server on Ubuntu Linux.

## Prerequisites

- Ubuntu 20.04 or later
- Root access to the server
- Git installed
- Internet connection

## Installation Steps

1. Copy both `install.sh` and this `INSTALL.md` to your Ubuntu server

2. Make the installation script executable:
   ```bash
   chmod +x install.sh
   ```

3. Run the installation script as root:
   ```bash
   sudo ./install.sh
   ```

4. After installation, update the environment configuration in `/wpfort-server/.env.local`:
   ```bash
   sudo nano /wpfort-server/.env.local
   ```
   Update the following values:
   - `DATABASE_URL`: Your PostgreSQL connection string
   - `GRAFANA_LOKI_HOST`: Your Grafana Loki host
   - `GRAFANA_LOKI_USER`: Your Grafana Loki user
   - `GRAFANA_LOKI_TOKEN`: Your Grafana Loki token

5. Start the WPFort server:
   ```bash
   sudo systemctl start wpfort
   ```

6. Check the server status:
   ```bash
   sudo systemctl status wpfort
   ```

## Service Management

- Start the server: `sudo systemctl start wpfort`
- Stop the server: `sudo systemctl stop wpfort`
- Restart the server: `sudo systemctl restart wpfort`
- View logs: `sudo journalctl -u wpfort -f`

## Verification

1. Check if the server is running:
   ```bash
   curl http://localhost:3000/api/health
   ```

2. Monitor the logs:
   ```bash
   sudo journalctl -u wpfort -f
   ```

## Troubleshooting

1. If the service fails to start, check the logs:
   ```bash
   sudo journalctl -u wpfort -n 50
   ```

2. Verify Redis is running:
   ```bash
   sudo systemctl status redis-server
   ```

3. Verify PostgreSQL is running:
   ```bash
   sudo systemctl status postgresql
   ```

4. Check the Node.js version:
   ```bash
   node --version
   ```
   It should be 18.x or later.

For additional support, please refer to the project documentation or contact support.
