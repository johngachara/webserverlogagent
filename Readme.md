# 🧠 Log Security Agent

The Log Security Agent is a real-time, intelligent log monitoring and threat response system designed for Linux servers. Built as a lightweight containerized solution, it monitors host logs through volume mounts and employs a hybrid two-tier LLM architecture to analyze access logs, detect malicious behavior, and take automated defensive actions. This project automates network security monitoring, acting as your personal AI security analyst team.

## 🎯 Project Vision

This is a fun project designed to create a minimal-resource security agent that automates the continuous monitoring of network applications. Instead of manually reviewing logs and monitoring for threats, two AI models work together as security analysts - a lightweight local model for initial screening and a powerful cloud model for complex decision-making.

### Why This Architecture?

- **Cost-Effective**: Primary analysis runs locally, reducing cloud API costs
- **Low Latency**: Local model provides fast initial response
- **Intelligent Escalation**: Only uncertain cases hit the cloud model
- **Minimal Hardware**: Runs efficiently on modest hardware with Tailscale networking
- **Automated Security**: Eliminates the need for constant manual log monitoring

## 🏗️ Core Architecture

### Hybrid LLM Intelligence System

#### **Tier 1: Local Primary Analysis (Phi-3.5:3.8B)**
- **Purpose**: Fast, local threat classification and initial screening
- **Deployment**: Runs via Ollama on local VM or computer
- **Network**: Connected through Tailscale private network for secure API access
- **Capabilities**:
    - Rapid pattern recognition and classification
    - Initial confidence scoring (1-10 scale)
    - Handles majority of clear-cut cases (obvious attacks or benign traffic)
#### **Tier 2: Cloud Expert Analysis (Qwen-3:32B via Cerebras)**
- **Purpose**: Complex decision-making for uncertain cases
- **Trigger**: When Phi-3.5 confidence score is below threshold or explicitly uncertain
- **Benefits**:
    - Reduces Cerebras API rate limit pressure
    - Handles nuanced, contextual threat analysis
    - Access to advanced reasoning capabilities
    - Cost optimization through intelligent routing

### Decision Flow
```
Log Entry → Pattern Match → Phi-3.5 Analysis
                                    │
                               Confident? ─── YES ──→ Take Action
                                    │
                                   NO
                                    │
                                    ▼
                            Qwen-3 Analysis ──→ Final Decision
```

## ⚙️ Core Components

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
- **Purpose**: Prevents redundant analysis and reduces processing overhead
- **Functionality**:
    - Caches IPs that have been flagged as malicious
    - Automatically marks subsequent requests from flagged IPs as malicious
    - Avoids unnecessary LLM calls for known bad actors
    - Temporary in-memory storage with configurable TTL

#### 4. **Hybrid LLM Analysis Pipeline**

**Local Tier (Phi-3.5:3.8B via Ollama)**
- **Network**: Tailscale-secured private connection
- **Role**: Primary security analyst for rapid classification
- **Decision Logic**:
    - High confidence (≥8): Direct action recommendation
    - Medium confidence (4-7): Monitor and potentially escalate
    - Low confidence or uncertainty: Escalate to Tier 2

**Cloud Tier (Qwen-3:32B via Cerebras)**
- **Role**: Expert security analyst for complex cases
- **Intelligence Tools**:
    - `checkAbuseIPDB`: Queries IP reputation and abuse reports
    - `checkVirusTotal`: Analyzes IP through multiple AV engines
    - `storeMonitoringLog`: Caches borderline suspicious requests
- **Advanced Capabilities**:
    - Contextual threat assessment
    - Historical pattern correlation
    - Sophisticated reasoning with external intelligence

#### 5. **Smart Brain (Upstash Redis)**
- **Purpose**: Short-term memory for ambiguous threats and cross-tier communication
- **Storage Duration**: 1 hour cache
- **Use Cases**:
    - Monitoring IPs with borderline suspicious activity
    - Correlating multiple low-confidence events from same source
    - Building behavioral patterns over time
    - Caching escalation decisions between tiers

#### 6. **Azure-Based Action Pipeline**
- **Blocking Mechanism**: Azure SDK integration for cloud-native IP restriction (meant for this branch alone,uses iptables in main branch)
- **Capabilities**:
    - Azure Firewall IP blocking
- **Threshold**: Combined confidence score ≥ 8 triggers IP blocking
- **Benefits**: Cloud-native, scalable, and centrally managed security actions

#### 7. **Data Persistence (Supabase)**
- **Comprehensive Logging**: Stores all analyzed requests with tier information
- **Schema Fields**:
    - Standard fields: `ip_address`, `method`, `url`, `user_agent`, `status`
    - Analysis fields: `threat_type`, `confidence`, `reasoning`
## 🔍 How It Works

### Enhanced Processing Flow

```
Log Entry → Log Parser → Threat Regex → Cache Check → Phi-3.5 Analysis
     │           │            │            │              │
     │           │            │            │              ├── Confident → Action
     │           │            │            │              │
     │           │            │            │              └── Uncertain → Qwen-3
     │           │            │            │                              │
     │           │            │            │                              ├── External Intel
     │           │            │            │                              │   (VirusTotal, AbuseIPDB)
     │           │            │            │                              │
     │           │            │            │                              └── Azure Blocking
     │           │            │            │
     │           │            │            └── Known Malicious IP?
     │           │            │                 └── Auto-flag as malicious
     │           │            │
     │           │            └── Pattern Match Score ≥ Threshold?
     │           │                 └── Queue for LLM Analysis
     │           │
     │           └── Extract: IP, Method, URL, User-Agent, etc.
     │
     └── Raw log line from mounted volume
```

## 🛠️ Technology Stack

### **Core Services**
- **Ollama**: Local LLM inference server for Phi-3.5
- **Tailscale**: Zero-config private networking between components
- **Cerebras Cloud**: High-performance inference for Qwen-3 model
- **Azure SDK**: Cloud-native security action implementation
- **Upstash Redis**: Serverless Redis for temporary threat intelligence
- **Supabase**: PostgreSQL-based persistent storage and analytics


## 🚀 Key Benefits

1. **Cost Optimization**: ~80% of requests handled locally at zero API cost
2. **Low Latency**: Sub-second response for most threat classifications
3. **Intelligent Scaling**: Only complex cases utilize expensive cloud resources
4. **Minimal Infrastructure**: Runs on modest hardware with private networking
5. **Automated Security**: Eliminates manual log monitoring and threat hunting
6. **Cloud Integration**: Native Azure security service integration
7. **Learning System**: Continuous improvement through dual-model feedback


---

*This project transforms traditional log monitoring from a manual, reactive process into an automated, intelligent security system. The dual AI analysts work 24/7 to protect your network infrastructure while you focus on building great applications.*