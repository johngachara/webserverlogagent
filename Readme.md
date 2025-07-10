# 🛡️ Log Security Agent - Node.js Edition

> ⚠️ **Documentation Notice**  
> This README is still under active development. Some internals and architectural details may be incomplete or undergoing revision. Please refer to the source code if something is unclear — improvements to documentation are ongoing.

---

## 🧠 Project Summary

The Log Security Agent is a **real-time, intelligent log monitoring and threat response system** designed for Linux servers. It uses both traditional pattern-matching techniques and modern LLMs (like LLaMA 3.3 70B) to analyze HTTP access logs, detect malicious behavior, and take automated action such as blocking IPs with `iptables`.

It supports integration with **VirusTotal**, **AbuseIPDB**, **Supabase**, **Redis (via Upstash)**, and **Pushover**.

---

## 🆕 Key Updates (as of latest release)

### ✅ 1. Documentation WIP
This documentation isn't final — expect improvements. If you're confused about a feature, check the implementation files directly for now (e.g. `main.js`, `llm.js`, `supabase.js`).

---

### 📨 2. Pushover Now Only for Lifecycle Notifications

Pushover is no longer used for sending **threat alerts** to avoid overwhelming users with noise. Instead, it's now reserved for:
- Startup complete messages
- Critical internal failures (e.g. can't connect to Groq)
- Restarts or shutdowns

This change helps keep your phone quiet unless something important happens.

---

### 🧾 3. All Logs Stored to Supabase — Even Benign Ones

Every request analyzed (malicious or not) is saved to **Supabase** under the `logs` table. This lets you:
- Investigate false positives or ambiguous requests later
- Visualize traffic patterns over time
- Analyze IP trends (even if they don’t cross the threat threshold)

Why? Because even a benign-looking request may be part of a **slow, stealthy attack**. By logging everything, we don't miss those patterns.

---

### 🖼️ 4. Web Frontend for Logs (Separate Repo)

A modern React-based frontend interface is being built in a **separate repository**. It connects to Supabase and provides:
- Realtime table/grid of requests
- Filters by IP, method, threat type, confidence score
- Visual indicators for malicious vs benign logs
- LLM-generated reasoning per request

This dashboard allows server admins or SOC teams to get visibility into the data without tailing logs manually.

---

### 🔍 5. LLM Tools: Internal Intelligence System

The LLM (via Groq) has access to specialized tools it uses during request evaluation. These tools are not directly exposed to users but are used inside `llm.js` and `upstash.js` to make smarter decisions.

#### The available tools:

- **checkIPIntelligence**  
  Aggregates results from VirusTotal and AbuseIPDB to determine if an IP is suspicious, using reputation scores, report counts, and more.

- **checkVirusTotal**  
  Makes a direct call to VirusTotal for a given IP. Returns antivirus engine verdicts, malicious score, and historical context.

- **checkAbuseIPDB**  
  Queries AbuseIPDB’s database to get:
    - Abuse confidence percentage
    - Total reports
    - ISP and usage type (residential, hosting, etc.)

- **storeMonitoringLog**  
  If a request looks weird but not clearly malicious, it’s cached in **Upstash Redis** for 1 hour with metadata like:
    - Confidence score (0–10)
    - LLM-generated explanation
    - Request details (IP, URL, user-agent)

  This allows tracking of repeated behavior from the same IP over time — like multiple low-suspicion attempts that eventually escalate.

- **checkStoredLogs**  
  Before logging a new suspicious request to Redis, the system checks if there’s a recent entry for the same IP. This prevents spamming the cache and also allows correlating actions over time.

---

## ⚙️ How It Works

1. **Pattern Matching Engine**
    - Regex rules detect common attacks:
        - SQLi, XSS, Path traversal, NoSQLi, SSRF, Command injection
    - Found in `rules/patterns.json`

2. **AI Decision Layer**
    - Matched requests are passed to Groq (LLaMA 3.3 70B)
    - The model:
        - Assesses maliciousness
        - Gives confidence score (1–10)
        - Explains why it flagged something
    - Only runs if initial match score is ≥ configured threshold

3. **Action Pipeline**
    - If confidence ≥ block threshold:
        - IP is dropped using `iptables`
        - Supabase is updated
    - If confidence is borderline:
        - Redis monitoring is used to observe future behavior

4. **Supabase Logging**
    - All malicious logs saved regardless of LLM verdict
    - Fields include:
        - `ip_address`, `method`, `url`, `user_agent`, `status`, `threat_type`, `confidence`, `llm_decision`, `reasoning`, `is_blocked`, and timestamps

---

## 📋 Sample Log Analysis

```json
{
  "ip": "196.251.85.193",
  "method": "GET",
  "url": "/.env",
  "threat_type": "sensitive_file_access",
  "llm_decision": "MALICIOUS",
  "confidence": 8,
  "reasoning": "Attempting to access a known sensitive file (.env), commonly used to steal secrets. IP has poor reputation from VirusTotal.",
  "is_blocked": true
}
