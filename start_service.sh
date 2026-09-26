#!/bin/bash
# AEraLogin Server Startup Script
# This script handles spaces in paths for systemd

cd "/var/local/aeralogin+imp. backup-07.12.2025/aeralogin+implement/aeralogin"

# Activate virtual environment
source "./venv/bin/activate"

# Start the server
exec python server.py
