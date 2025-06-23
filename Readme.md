# Log Security Agent - Node.js Edition

A real-time log analysis and threat detection system that monitors web server logs, detects security threats using pattern matching and AI-powered final decision making, automatically blocks malicious IPs via iptables, and sends alerts to your Android/Apple device via Pushover.

## 🛡️ How It Works

The Log Security Agent operates as an intelligent multi-layered security system:

1. **Pattern Detection Engine**: Monitors web server logs in real-time using regex patterns to identify potential threats (SQL injection, XSS, path traversal, command injection, SSRF, etc.)

2. **LLM-Powered Final Decision**: When threats are detected, the system forwards them to **Groq's Llama-3.3-70b-versatile model** for intelligent analysis to reduce false positives and make the final threat determination

3. **Automated IP Blocking**: IPs with threat scores ≥8/10 are automatically blocked using iptables rules to protect your server infrastructure

4. **Smart Alerting**: Pushover notifications are sent directly to your Mobile device for immediate threat awareness

5. **Threat Intelligence**: Integrates with VirusTotal and AbuseIPDB for IP reputation checking and enhanced context

## 🚀 Features

### 🔍 **Advanced Threat Detection**
- **Regex Pattern Matching**: Detects SQL injection, XSS, path traversal, command injection, SSRF, NoSQL injection, LDAP injection, and brute force attacks
- **LLM Final Decision**: Groq Llama-3.3-70b-versatile model makes intelligent final threat assessments
- **Configurable Thresholds**:
    - LLM Analysis: ≥7/10 threat score
    - Alert Notifications: ≥9/10 threat score
    - Automatic IP Blocking: ≥8/10 threat score
- **Custom Pattern Engine**: Easily extensible with custom threat patterns

### 🤖 **AI-Powered Intelligence**
- **Primary**: Groq API with Llama-3.3-70b-versatile (fast and efficient)
- **Secondary**: OpenAI models via GitHub free model inferences (fallback option)
- **False Positive Reduction**: AI context analysis prevents unnecessary blocking
- **Threat Reasoning**: Detailed explanations for each threat decision
- **Adaptive Learning**: Contextual understanding of legitimate vs malicious requests

### 🛡️ **Automated Protection**
- **iptables Integration**: Automatic IP blocking for high-risk threats
- **Linux Server Protection**: Designed specifically for Linux server environments
- **Web Server Compatibility**: Optimized for Nginx and Apache logs (works with any web server)
- **Real-time Response**: Immediate threat mitigation within seconds

### 📱 **Smart Notifications**
- **Pushover Integration**: Direct notifications to your Mobile device
- **Rich Alert Content**: IP details, threat type, confidence score, and reasoning
- **Rate Limiting**: Prevents notification spam while ensuring critical alerts
- **Threat Intelligence**: Includes IP reputation and geolocation data

### 🔗 **Threat Intelligence**
- **VirusTotal Integration**: IP reputation and malware analysis
- **AbuseIPDB Integration**: Abuse confidence scoring and reporting history
- **CVE Lookups**: Known vulnerability pattern matching
- **Geolocation Data**: IP origin tracking and ASN information

## 📋 Sample Log Analysis

Based on sample logs, here's how the system processes threats:

```json
{
  "ip": "196.251.85.193",
  "threat_type": "sensitive_file_access",
  "url": "/.env HTTP/1.1",
  "confidence": 5,
  "llm_decision": "MALICIOUS",
  "final_confidence": 8,
  "reasoning": "Attempting to access sensitive .env file with bad IP reputation",
  "action": "BLOCKED"
}
```

The agent detected a `.env` file access attempt, forwarded it to Groq for analysis, received a MALICIOUS verdict with confidence 8/10, and automatically blocked the IP via iptables.

## 🚀 Quick Start

### 1. Docker Installation (Recommended)

#### Pull the Docker Image
```bash
# Pull the latest image (once public)
docker pull gachar4/logagent:latest
```

#### Create Configuration Files

**Create `config.yaml`:**
```yaml
# Log files to monitor
logs:
  - "${LOG_PATH_1:-/var/log/nginx/access.log}"
  - "${LOG_PATH_2:-/var/log/apache2/access.log}"
  - "${LOG_PATH_3:-/var/log/httpd/access_log}"

# Detection thresholds (1-10 scale)
thresholds:
  minimum_score: ${MIN_SCORE:-5}          # Minimum score to consider a threat
  alert_threshold: ${ALERT_THRESHOLD:-9}  # Score required to send alert
  llm_analysis: ${LLM_ANALYSIS:-7}        # Score to trigger LLM analysis
  brute_force_attempts: ${BRUTE_FORCE_ATTEMPTS:-10}  # Failed attempts in time window
  brute_force_score: ${BRUTE_FORCE_SCORE:-7}     # Score for brute force detection
  block_ip_threshold: ${BLOCK_IP_THRESHOLD:-8}   # Score required to drop an ip address connection

# LLM Provider settings
llm:
  provider: "${LLM_PROVIDER:-groq}"  # openai, groq, local
  model: "${LLM_MODEL:-llama-3.3-70b-versatile}"     # llama-3.3-70b-versatile, gpt-4o-mini
  max_tokens: ${MAX_TOKENS:-300}
  temperature: ${TEMPERATURE:-0.1}

# Logging configuration
logging:
  level: "${LOG_LEVEL:-info}"
  file: "${LOG_FILE:-agent.log}"
  max_size: "${MAX_SIZE:-10MB}"
  max_files: ${MAX_FILES:-5}
```

**Create `.env` file with your API keys:**
```bash
# .env
GROQ_API_KEY=gsk_your_groq_api_key_here
OPENAIKEY=your_openai_or_github_token
VIRUSTOTALKEY=your_virustotal_api_key
ABUSEIPDBKEY=your_abuseipdb_api_key
PUSHOVER_APP_TOKEN=your_pushover_app_token
PUSHOVER_USER_KEY=your_pushover_user_key

# Log paths (optional - can be set in config.yaml)
LOG_PATH_1=/var/log/nginx/access.log
LOG_PATH_2=/var/log/apache2/access.log
MIN_SCORE=5
ALERT_THRESHOLD=9
```

#### Run with Docker
```bash
# Basic run command
docker run -d \
  --name logagent \
  --env-file .env \
  -v ./config.yaml:/logagent/config.yaml:ro \
  -v /var/log:/var/log:ro \
  --cap-add NET_ADMIN \
  --restart unless-stopped \
  gachar4/logagent:latest
```

#### Run with Docker Compose
```yaml
# docker-compose.yml
version: '3.8'
services:
  logagent:
    image: gachar4/logagent:latest
    container_name: logagent
    env_file:
      - .env
    volumes:
      - ./config.yaml:/logagent/config.yaml:ro
      - /var/log:/var/log:ro
      # Mount additional log directories as needed
      - ./app/logs:/app/logs:ro
    cap_add:
      - NET_ADMIN  # Required for iptables blocking
    restart: unless-stopped
    network_mode: host  # Required for iptables integration
```

```bash
# Start with Docker Compose
docker-compose up -d

# View logs
docker-compose logs -f logagent

# Stop the service
docker-compose down
```

### 2. Native Installation

```bash
# Clone the repository
git clone <repo-url>
cd log-security-agent

# Install dependencies
npm install

# Run the deployment script
chmod +x start.sh
./start.sh
```

## 🔧 API Keys Setup

### Groq API Key (Primary LLM)
1. Visit https://console.groq.com/
2. Create account and generate API key
3. Add to .env: `GROQ_API_KEY=gsk-...`
4. Model: `llama-3.3-70b-versatile` (default)

### GitHub Models (OpenAI Fallback)
1. Generate GitHub Personal Access Token
2. Enable GitHub Models beta access
3. Add to .env: `OPENAIKEY=ghp_...`
4. Free tier includes GPT-4o-mini access

### Pushover Notifications
1. Create account at https://pushover.net/
2. Create new application to get App Token
3. Get your User Key from dashboard
4. Install Pushover app on your mobile device
5. Add to .env:
   ```bash
   PUSHOVER_APP_TOKEN=your-app-token
   PUSHOVER_USER_KEY=your-user-key
   ```

### VirusTotal API Key (v3)
1. Register at https://www.virustotal.com/
2. Navigate to profile → API Key
3. Add to .env: `VIRUSTOTALKEY=your-key`

### AbuseIPDB API Key
1. Register at https://www.abuseipdb.com/
2. Navigate to account → API
3. Add to .env: `ABUSEIPDBKEY=your-key`

## 🐳 Docker Usage Examples

### Monitor Different Log Files
```bash
# For Nginx logs
docker run -d \
  --name logagent-nginx \
  --env-file .env \
  -e LOG_PATH_1=/var/log/nginx/access.log \
  -e LOG_PATH_2=/var/log/nginx/error.log \
  -v ./config.yaml:/logagent/config.yaml:ro \
  -v /var/log/nginx:/var/log/nginx:ro \
  --cap-add NET_ADMIN \
  gachar4/logagent:latest

# For Apache logs
docker run -d \
  --name logagent-apache \
  --env-file .env \
  -e LOG_PATH_1=/var/log/apache2/access.log \
  -e LOG_PATH_2=/var/log/apache2/error.log \
  -v ./config.yaml:/logagent/config.yaml:ro \
  -v /var/log/apache2:/var/log/apache2:ro \
  --cap-add NET_ADMIN \
  gachar4/logagent:latest
```

### Use in Other Docker Compose Projects
```yaml
# your-project/docker-compose.yml
version: '3.8'
services:
  your-app:
    image: your-app:latest
    volumes:
      - app_logs:/app/logs

  nginx:
    image: nginx:latest
    volumes:
      - nginx_logs:/var/log/nginx

  logagent:
    image: gachar4/logagent:latest
    env_file:
      - .env
    environment:
      - LOG_PATH_1=/app/logs/application.log
      - LOG_PATH_2=/var/log/nginx/access.log
    volumes:
      - ./logagent-config.yaml:/logagent/config.yaml:ro
      - app_logs:/app/logs:ro
      - nginx_logs:/var/log/nginx:ro
    cap_add:
      - NET_ADMIN
    network_mode: host
    depends_on:
      - your-app
      - nginx

volumes:
  app_logs:
  nginx_logs:
```

### Development and Testing
```bash
# Run in development mode (with shell access)
docker run -it \
  --name logagent-dev \
  --env-file .env \
  -v ./config.yaml:/logagent/config.yaml:ro \
  -v /var/log:/var/log:ro \
  gachar4/logagent:latest \
  /bin/bash

# Test with custom log files
docker run --rm \
  --env-file .env \
  -v ./test-logs:/test-logs:ro \
  -v ./config.yaml:/logagent/config.yaml:ro \
  -e LOG_PATH_1=/test-logs/sample.log \
  gachar4/logagent:latest
```

## 🏗️ Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Web Server    │───▶│   Log Parser     │───▶│ Pattern Matcher │
│ Nginx/Apache    │    │  (chokidar)      │    │ (Regex Engine)  │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                                        │
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│ iptables Block  │◀───│ Main Orchestrator│◀───│ Groq LLM Judge  │
│ (Auto Protect)  │    │   (main.js)      │    │ (Final Decision)│
└─────────────────┘    └──────────────────┘    └─────────────────┘
        │                       │                        │
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│ Pushover Alert  │    │ Threat Intel     │    │ Threat Queue    │
│ (Mobile Phone) │    │ (VT/AbuseIPDB)   │    │ (Rate Limited)  │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

## ⚙️ Configuration Options

### Threat Thresholds
```yaml
thresholds:
  minimum_score: 3        # Log threshold
  llm_analysis: 7         # LLM analysis trigger
  alert_threshold: 9      # Pushover notification  
  block_threshold: 8      # iptables blocking
  brute_force_attempts: 5 # Login attempt limit
  block_ip_threshold: 8
```

### Supported Log Formats
- **Apache Common Log Format**
- **Apache Combined Log Format**
- **Nginx Access Logs**
- **Custom Formats** (modify `log_parser.js`)

### LLM Configuration
```yaml
llm:
  provider: "groq"                    # groq or openai
  model: "llama-3.3-70b-versatile"   # Groq model
  fallback_model: "gpt-4o-mini"      # GitHub model
  max_tokens: 1000
  temperature: 0.1
```

## 📊 Monitoring and Maintenance

### Docker Monitoring
```bash
# View container logs
docker logs -f logagent

# Check container status
docker ps | grep logagent

# Container resource usage
docker stats logagent

# Access container shell
docker exec -it logagent /bin/bash
```

### Host System Monitoring
```bash
# Blocked IPs
sudo iptables -L INPUT -n | grep DROP

# System logs
sudo journalctl -f

# Application logs (if mounted)
tail -f ./logs/agent.log
```

### Performance Tuning
- **Threshold Adjustment**: Modify scores based on your environment
- **Pattern Customization**: Add/remove threat patterns in `rules/patterns.json`
- **Rate Limiting**: Adjust API call intervals for your usage limits
- **Whitelist Management**: Update `rules/whitelist.txt` for legitimate traffic

## 🔧 Customization

### Add Custom Threat Patterns
Edit `rules/patterns.json`:
```json
{
  "custom_backdoor": {
    "patterns": ["(?i)(backdoor|shell|webshell)"],
    "score": 9,
    "description": "Potential backdoor access attempt"
  }
}
```

### Docker Environment Variables
All configuration can be overridden via environment variables:
```bash
# In .env file or docker run command
LOG_PATH_1=/custom/path/app.log
MIN_SCORE=6
LLM_PROVIDER=openai
ALERT_THRESHOLD=8
```

### iptables Integration
The system automatically manages iptables rules:
```bash
# View blocked IPs
sudo iptables -L INPUT -n

# Manual IP block
sudo iptables -I INPUT -s 192.168.1.100 -j DROP

# Unblock IP
sudo iptables -D INPUT -s 192.168.1.100 -j DROP
```

## 🚀 Production Deployment

### Security Considerations
- **API Key Security**: Use `.env` files and never commit secrets to version control
- **Log Rotation**: Implement logrotate for agent logs
- **Firewall Rules**: Ensure iptables persistence across reboots
- **Resource Monitoring**: Monitor CPU/memory usage under load
- **Container Updates**: Regularly update the Docker image

### Docker Production Setup
```bash
# Production docker-compose.yml with health checks
version: '3.8'
services:
  logagent:
    image: gachar4/logagent:latest
    container_name: logagent
    env_file:
      - .env
    volumes:
      - ./config.yaml:/logagent/config.yaml:ro
      - /var/log:/var/log:ro
      - ./logs:/logagent/logs  # Persistent logs
    cap_add:
      - NET_ADMIN
    restart: unless-stopped
    network_mode: host
    healthcheck:
      test: ["CMD", "pgrep", "node"]
      interval: 30s
      timeout: 10s
      retries: 3
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
```

## 🐛 Troubleshooting

### Common Docker Issues
1. **Permission Denied on .env**: Check file ownership and permissions
   ```bash
   sudo chown $USER:$USER .env
   chmod 644 .env
   ```

2. **iptables Errors**: Ensure container has NET_ADMIN capability
   ```bash
   docker run --cap-add NET_ADMIN ...
   ```

3. **Log Files Not Found**: Verify volume mounts and file paths
   ```bash
   docker exec -it logagent ls -la /var/log/
   ```

4. **API Connection Issues**: Check environment variables
   ```bash
   docker exec -it logagent printenv | grep -i groq
   ```

5. **Container Won't Start**: Check logs for errors
   ```bash
   docker logs logagent
   ```

### Debug Mode
```bash
# Enable verbose logging
docker run -e DEBUG=* ... gachar4/logagent:latest

# Test configuration
docker run --rm -it \
  --env-file .env \
  -v ./config.yaml:/logagent/config.yaml:ro \
  gachar4/logagent:latest \
  node test-config.js
```

## 📈 System Requirements

### Host System
- **Docker**: v20.10+
- **Linux**: Ubuntu 20.04+, CentOS 8+, Debian 11+
- **Memory**: 512MB minimum, 2GB recommended for high traffic
- **Storage**: 10GB for logs and threat database
- **Network**: Stable internet for API calls (Groq, threat intelligence)
- **Permissions**: Docker access and sudo for iptables (NET_ADMIN capability)

### Container Resources
- **CPU**: 0.5 cores minimum, 1+ core recommended
- **Memory**: 256MB minimum, 1GB recommended
- **Storage**: 1GB for application and logs

## 🔒 License

MIT License - see LICENSE file for details.

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/enhancement`)
3. Commit changes (`git commit -am 'Add new feature'`)
4. Push to branch (`git push origin feature/enhancement`)
5. Create Pull Request

Please follow existing code style and include tests for new features.

## 📞 Support

For issues, questions, and feature requests:
- **GitHub Issues**: Technical problems and bug reports
- **Docker Hub**: https://hub.docker.com/r/gachar4/logagent

---

**Note**: This project is actively being developed and tested in production Linux server environments. The Docker containerization makes deployment simple and consistent across different infrastructures. The LLM-powered decision making significantly reduces false positives while maintaining strong security protection for web applications and server infrastructure.