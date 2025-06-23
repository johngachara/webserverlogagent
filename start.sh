#!/bin/bash

# Log Security Agent Deployment Script

echo "Starting Log Security Agent deployment..."

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "Node.js is not installed. Please install Node.js 16+ first."
    exit 1
fi

# Check if npm is installed
if ! command -v npm &> /dev/null; then
    echo "npm is not installed. Please install npm first."
    exit 1
fi

# Create necessary directories
mkdir -p rules
mkdir -p logs

# Install dependencies
echo "Installing dependencies..."
npm install

# Create config file if it doesn't exist
if [ ! -f "config.yaml" ]; then
    echo "Creating default config.yaml..."
    cat > config.yaml << 'EOF'
# Log Security Agent Configuration

logs:
  - "/var/log/apache2/access.log"
  - "/var/log/nginx/access.log"

thresholds:
  minimum_score: 5
  alert_threshold: 7
  llm_analysis: 6
  brute_force_attempts: 10
  brute_force_score: 7

apis:
  openai_key: "your_openai_api_key_here"
  virustotal_key: "your_virustotal_api_key_here"
  abuseipdb_key: "your_abuseipdb_api_key_here"
  telegram_token: "your_telegram_bot_token_here"

telegram:
  chat_id: "your_telegram_chat_id_here"
  alert_frequency: "immediate"
  max_alerts_per_hour: 50

llm:
  provider: "openai"
  model: "gpt-4"
  max_tokens: 300
  temperature: 0.1

logging:
  level: "info"
  file: "agent.log"
  max_size: "10MB"
  max_files: 5
EOF
    echo "Please edit config.yaml with your API keys and settings."
fi

# Create patterns.json if it doesn't exist
if [ ! -f "rules/patterns.json" ]; then
    echo "Creating threat detection patterns..."
    # The patterns.json content would be created here
    echo "Patterns file created."
fi

# Create whitelist if it doesn't exist
if [ ! -f "rules/whitelist.txt" ]; then
    echo "Creating IP whitelist..."
    cat > rules/whitelist.txt << 'EOF'
# Known good IPs (one per line)
192.168.1.0/24
10.0.0.0/8
172.16.0.0/12
127.0.0.1
EOF
fi

# Create systemd service file
if [ -f "/etc/systemd/system/log-security-agent.service" ]; then
    echo "Systemd service already exists"
else
    echo "Creating systemd service..."
    sudo tee /etc/systemd/system/log-security-agent.service > /dev/null << EOF
[Unit]
Description=Log Security Agent
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$(pwd)
ExecStart=$(which node) main.js
Restart=always
RestartSec=10
Environment=NODE_ENV=production

# Output to journal
StandardOutput=journal
StandardError=journal
SyslogIdentifier=log-security-agent

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd and enable service
    sudo systemctl daemon-reload
    sudo systemctl enable log-security-agent
    echo "Systemd service created and enabled."
fi

echo "Deployment complete!"
echo ""
echo "Next steps:"
echo "1. Edit config.yaml with your API keys"
echo "2. Test with: npm start"
echo "3. Start service: sudo systemctl start log-security-agent"
echo "4. Check status: sudo systemctl status log-security-agent"
echo "5. View logs: sudo journalctl -u log-security-agent -f"