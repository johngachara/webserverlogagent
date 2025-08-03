#!/bin/bash
echo "Checking whether nodejs is installed"
if ! command -v node ; then
echo "node not installed"
# Download and install nvm:
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh | bash

# in lieu of restarting the shell
\. "$HOME/.nvm/nvm.sh"

# Download and install Node.js:
nvm install 24
nvm alias default 24
node -v && npm -v && echo "node successfully installed"
else
echo "node is installed"
fi

echo "Checking whether docker is installed"
if  ! command -v docker; then
echo "Installing docker"
# Add Docker's official GPG key:
sudo apt-get update
sudo apt-get install ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

# Add the repository to Apt sources:
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo docker run hello-world && echo "Docker successfully installed"
else
echo "Docker is already installed"
fi
echo "Creating agent directory and config files"
if [ -d "/logagent" ]; then
cd /logagent
else
mkdir -p "$HOME/logagent" && cd "$HOME/logagent"
fi
if [ ! -f "config.yaml" ]; then
cat > config.yaml << 'EOF'
  # Log Security Agent Configuration

  # Log files to monitor
  logs:
   # - "/logagent/logs/test.log"
   # - "/var/log/nginx/access.log"
   # - "/var/log/httpd/access_log"

  # Detection thresholds (1-10 scale)
  thresholds:
    minimum_score: 5          # Minimum score to consider a threat
    alert_threshold: 9        # Score required to send alert
    llm_analysis: 7          # Score to trigger LLM analysis
    brute_force_attempts: 10  # Failed attempts in time window
    brute_force_score: 7     # Score for brute force detection
    block_ip_threshold : 8 # Score required to drop an ip address connection


  # LLM Provider settings
  llm:
    provider: "groq"  # openai, groq, local
    model: "openai/gpt4.1"     # gpt-4, mixtral-8x7b-32768
    max_tokens: 300
    temperature: 0.1

  # System URLs configuration
  # URLs that match these patterns will be skipped during threat detection
  # unless they contain malicious content
  system_urls:
    # Regex patterns for system URLs (e.g., "/api" will match all URLs starting with "/api")
    # Format: each entry should be a valid JavaScript regex pattern without the leading and trailing '/'
    # Examples:
    #   - "^/api" - matches all URLs starting with "/api"
    #   - "^/admin" - matches all URLs starting with "/admin"
    #   - "^/home$" - matches exactly "/home" URL
    #   - "^/(home|about|contact)$" - matches exactly "/home", "/about", or "/contact" URLs
    patterns:
      - ""
      - ""
    # Specific URLs to be considered as system URLs
    # Format: exact URL paths without query parameters
    # Examples:
    #   - "/login"
    #   - "/dashboard"
    specific:


  # Logging configuration
  logging:
    level: "info"
    file: "agent.log"
    max_size: "10MB"
    max_files: 5
EOF
echo "config file created"
fi
if [ ! -f ".env" ]; then
echo "Creating .env file"
cat > .env << 'EOF'
OPENAIKEY=
GROQKEY=
VIRUSTOTALKEY=
ABUSEIPDBKEY=
PUSHOVERUSERKEY=
PUSHOVERAPPTOKEN=
SUPABASE_KEY=
SUPABASE_URL=
UPSTASH_REDIS_REST_URL=
UPSTASH_REDIS_REST_TOKEN=
CEREBRAS_API_KEY=
EOF
echo ".env file created successfully"
fi
