# 🧠 Log Security Agent

The Log Security Agent is a real-time, intelligent log monitoring and threat response system designed for Linux servers. It runs as a containerized solution that monitors host logs through volume mounts, using both traditional pattern-matching techniques and modern LLMs to analyze access logs, detect malicious behavior, and take automated defensive actions.

### Core Components

#### 1. **Log Parser**
- **Purpose**: Identifies and parses various log formats from mounted host directories
- **Capabilities**:
    - Multi-format support (Nginx, Apache, custom formats)
    - Regex-based pattern recognition for different log structures
    - Real-time log tailing and processing
    - Structured data extraction from raw log entries

#### 2. **Threat Detection Engine**
- **Pattern Matching**: Uses regex rules to detect common attack patterns:
    - SQL Injection (SQLi)
    - Cross-Site Scripting (XSS)
    - Path Traversal
    - NoSQL Injection (NoSQLi)
    - Server-Side Request Forgery (SSRF)
    - Command Injection
    - Sensitive File Access
- **Rule Configuration**: Patterns stored in `rules/patterns.json`
- **Initial Scoring**: Assigns preliminary threat scores based on pattern matches

#### 3. **Request Cache (Map)**
- **Purpose**: Prevents redundant LLM analysis and reduces API costs
- **Functionality**:
    - Caches IPs that have been flagged as malicious
    - Automatically marks subsequent requests from flagged IPs as malicious
    - Avoids unnecessary LLM calls for known bad actors
    - Temporary in-memory storage with configurable TTL

#### 4. **LLM Analysis Engine**
- **Provider**: Cerebras
- **Models**: Currently testing GPT OSS and LLaMA 3.3
- **Intelligence Tools**:
    - `checkAbuseIPDB`: Queries IP reputation and abuse reports
    - `checkVirusTotal`: Analyzes IP through multiple AV engines
    - `storeMonitoringLog`: Caches borderline suspicious requests and retrieves historical malicious activity.
- **Decision Process**:
    - Evaluates threat context using external intelligence
    - Assigns confidence scores (1-10 scale)
    - Provides reasoning for decisions
    - Only processes requests above configured threshold

#### 5. **Smart Brain (Upstash Redis)**
- **Purpose**: Short-term memory for ambiguous threats
- **Storage Duration**: 1 hour cache
- **Use Cases**:
    - Monitoring IPs with borderline suspicious activity
    - Correlating multiple low-confidence events from same source
    - Building behavioral patterns over time
    - Preventing false positives through temporal analysis

#### 6. **Action Pipeline**
- **Blocking Mechanism**: Currently uses iptables (customizable per infrastructure)
- **Threshold**: Confidence score ≥ 8 triggers IP blocking
- **Customization**: Blocking mechanism can be adapted to:
    - Cloud WAF rules
    - Load balancer configurations
    - Firewall appliances
    - CDN blocking lists

#### 7. **Data Persistence (Supabase)**
- **Comprehensive Logging**: Stores all analyzed requests (malicious and benign)
- **Schema Fields**:
    - `ip_address`, `method`, `url`, `user_agent`, `status`
    - `threat_type`, `confidence`, `llm_decision`, `reasoning`
    - `is_blocked`, `timestamp`, `created_at`
- **Benefits**:
    - Historical threat analysis
    - False positive investigation
    - Traffic pattern visualization
    - Forensic capabilities

## ⚙️ How It Works

### Processing Flow

```
Log Entry → Log Parser → Threat Regex → Cache Check → LLM Analysis → Action Decision
     │           │            │            │             │              │
     │           │            │            │             │              └── Block IP
     │           │            │            │             │              └── Monitor
     │           │            │            │             │              └── Allow
     │           │            │            │             │
     │           │            │            │             └── External Intel
     │           │            │            │                  (VirusTotal, AbuseIPDB)
     │           │            │            │
     │           │            │            └── Known Malicious IP?
     │           │            │                 └── Auto-flag as malicious
     │           │            │
     │           │            └── Pattern Match Score ≥ Threshold?
     │           │                 └── Queue for LLM
     │           │
     │           └── Extract: IP, Method, URL, User-Agent, etc.
     │
     └── Raw log line from mounted volume
```

### Decision Matrix

| Confidence Score | Action | Cache Duration | Notification |
|-----------------|---------|----------------|--------------|
| 8-10 | Block IP with iptables | Permanent cache | Log to Supabase |
| 5-7 | Monitor in Redis Brain | 1 hour | Log to Supabase |
| 1-4 | Allow with logging | No cache | Log to Supabase |

## 🔍 LLM Tools: Internal Intelligence System

The LLM (via Cerebras) has access to specialized tools it uses during request evaluation:

### `checkVirusTotal`
Makes a direct call to VirusTotal for a given IP. Returns antivirus engine verdicts, malicious score, and historical context.

### `checkAbuseIPDB`
Queries AbuseIPDB's database to get:
- Abuse confidence percentage
- Total reports
- ISP and usage type (residential, hosting, etc.)

### `storeMonitoringLog`
If a request looks weird but not clearly malicious, it's cached in Upstash Redis for 1 hour with metadata like:
- Confidence score (0–10)
- LLM-generated explanation
- Request details (IP, URL, user-agent)
- The system checks if there's a recent entry for the same IP to prevent spam and correlate actions over time.
