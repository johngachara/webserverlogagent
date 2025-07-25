import OpenAI from 'openai';
import Groq from 'groq-sdk';
import Anthropic from '@anthropic-ai/sdk';
import Cerebras from '@cerebras/cerebras_cloud_sdk';
import { checkAbuseIPDB,  checkVirusTotal } from "./llmtools.js";
import { checkStoredLogs, storeMonitoringLog } from "./upstash.js";

class LLMAnalyzer {
    constructor(apiKey, provider = 'cerebras' ) {
        this.apiKey = apiKey;
        this.provider = provider;
        this.client = this.initializeClient();
        this.analysisCache = new Map();
    }

    initializeClient() {
        switch (this.provider) {
            case 'openai':
                return new OpenAI({
                    apiKey: this.apiKey,
                    baseURL: 'https://models.github.ai/inference'
                });

            case 'groq':
                return new Groq({
                    apiKey: this.apiKey
                });
            case 'cerebras':
                return  new Cerebras({
                    apiKey: this.apiKey,
                });
            case 'anthropic':
                return new Anthropic({
                    apiKey: this.apiKey
                });

            default:
                throw new Error(`Unsupported provider: ${this.provider}`);
        }
    }

    getModelName() {
        switch (this.provider) {
            case 'openai':
                return 'gpt-4o';
            case 'groq':
                return 'llama3-70b-8192';
            case 'anthropic':
                return 'claude-3-sonnet-20240229';
             case 'cerebras':
                 return 'llama3.3-70b'
            default:
                return 'gpt-4o';
        }
    }

    createCacheKey(logEntry) {
        return `${logEntry.ip}_${logEntry.method}_${logEntry.url}_${JSON.stringify(logEntry.payload || {})}`;
    }

    async analyze(logEntry, threatResult) {
        try {
            const cacheKey = this.createCacheKey(logEntry);
            if (this.analysisCache.has(cacheKey)) {
                console.log('Using cached LLM analysis for similar request');
                return this.analysisCache.get(cacheKey);
            }

            const prompt = this.buildEnhancedAnalysisPrompt(logEntry, threatResult);
            let response;

            switch (this.provider) {
                case 'openai':
                case 'groq':
                case 'cerebras':
                    response = await this.analyzeWithOpenAIFormat(prompt);
                    break;

                case 'anthropic':
                    response = await this.analyzeWithAnthropic(prompt);
                    break;

                default:
                    throw new Error(`Unsupported provider: ${this.provider}`);
            }

            const result = this.parseResponse(response);
            this.analysisCache.set(cacheKey, result);

            if (this.analysisCache.size > 1000) {
                const firstKey = this.analysisCache.keys().next().value;
                this.analysisCache.delete(firstKey);
            }

            return result;

        } catch (error) {
            console.error(`${this.provider} Analysis error:`, error.message);
            return {
                isMalicious: null,
                confidence: 0,
                explanation: 'Analysis failed due to API error - manual review recommended',
                error: error.message,
                requiresManualReview: true,
                shouldBlock: false,
                impact: 'UNKNOWN',
                attackType: null
            };
        }
    }

    getFunctionTools() {
        return [
            {
                type: "function",
                function: {
                    name: "checkVirusTotal",
                    description: "Check an IP address specifically against VirusTotal's database. Returns detailed analysis from multiple antivirus engines including malicious/suspicious counts and engine-specific results.",
                    parameters: {
                        type: "object",
                        properties: {
                            ip: {
                                type: "string",
                                description: "The IPv4 or IPv6 address to check against VirusTotal (e.g., 192.168.1.100)"
                            }
                        },
                        required: ["ip"],
                        additionalProperties: false
                    }
                }
            },
            {
                type: "function",
                function: {
                    name: "checkAbuseIPDB",
                    description: "Check an IP address against AbuseIPDB's database of reported malicious IPs. Returns abuse confidence percentage, total reports, and usage type information.",
                    parameters: {
                        type: "object",
                        properties: {
                            ip: {
                                type: "string",
                                description: "The IPv4 or IPv6 address to check against AbuseIPDB (e.g., 192.168.1.100)"
                            }
                        },
                        required: ["ip"],
                        additionalProperties: false
                    }
                }
            },
            {
                type: "function",
                function: {
                    name: "storeMonitoringLog",
                    description: "Store a request log entry in Redis for monitoring purposes. Use this for requests that you want to monitor but are not clearly malicious. The data will be stored for 1 hour for pattern analysis.",
                    parameters: {
                        type: "object",
                        properties: {
                            logEntry: {
                                type: "object",
                                description: "The log entry object containing request details",
                                properties: {
                                    ip: {
                                        type: "string",
                                        description: "IP address of the request"
                                    },
                                    method: {
                                        type: "string",
                                        description: "HTTP method (GET, POST, etc.)"
                                    },
                                    queryString: {
                                        type: "string",
                                        description: "Query string from the request"
                                    },
                                    userAgent: {
                                        type: "string",
                                        description: "User agent string"
                                    },
                                    url: {
                                        type: "string",
                                        description: "Requested URL"
                                    },
                                    status: {
                                        type: "number",
                                        description: "HTTP status code"
                                    }
                                },
                                required: ["ip", "method", "queryString", "userAgent", "url", "status"]
                            },
                            confidenceScore: {
                                type: "number",
                                description: "Your confidence score (0-10) for this being suspicious"
                            },
                            explanation: {
                                type: "string",
                                description: "Your explanation for this being suspicious"
                            }
                        },
                        required: ["logEntry", "confidenceScore", "explanation"],
                        additionalProperties: false
                    }
                }
            },
            {
                type: "function",
                function: {
                    name: "checkStoredLogs",
                    description: "Check if there are existing monitoring logs for a specific IP address. Use this before storing new logs to see if the IP is already being monitored.",
                    parameters: {
                        type: "object",
                        properties: {
                            ipAddress: {
                                type: "string",
                                description: "The IP address to check for existing monitoring logs"
                            }
                        },
                        required: ["ipAddress"],
                        additionalProperties: false
                    }
                }
            }
        ];
    }

    getAvailableFunctions() {
        return {
            "checkVirusTotal": checkVirusTotal,
            "checkAbuseIPDB": checkAbuseIPDB,
            "checkStoredLogs": checkStoredLogs,
            "storeMonitoringLog": storeMonitoringLog
        };
    }

    async executeFunctionCall(functionName, functionArgs) {
        const availableFunctions = this.getAvailableFunctions();
        const functionToCall = availableFunctions[functionName];

        if (!functionToCall) {
            throw new Error(`Function ${functionName} not found`);
        }

        console.log(`Executing function: ${functionName} with args:`, functionArgs);

        try {
            let result;

            switch (functionName) {
                case 'checkVirusTotal':
                case 'checkAbuseIPDB':
                    result = await functionToCall(functionArgs.ip);
                    break;

                case 'checkStoredLogs':
                    result = await functionToCall(functionArgs.ipAddress);
                    break;

                case 'storeMonitoringLog':
                    result = await storeMonitoringLog(
                        functionArgs.logEntry,
                        functionArgs.confidenceScore,
                        functionArgs.explanation
                    );
                    break;

                default:
                    throw new Error(`Unknown function: ${functionName}`);
            }

            console.log(`Function ${functionName} result:`, result);
            return result;

        } catch (error) {
            console.error(`Error executing ${functionName}:`, error);
            throw error;
        }
    }

    async analyzeWithOpenAIFormat(prompt) {
        const tools = this.getFunctionTools();

        const messages = [
            {
                role: "system",
                content: this.getSystemPrompt()
            },
            {
                role: "user",
                content: prompt,
            }
        ];

        try {
            console.log('Making single API call with tool support');

            const completion = await this.client.chat.completions.create({
                model: this.getModelName(),
                messages: messages,
                temperature: 0.1,
                max_tokens: 800,
                stream: false,
                tools: tools,
                tool_choice: "auto"
            });

            const responseMessage = completion.choices[0].message;
            const toolCalls = responseMessage.tool_calls;

            if (toolCalls && toolCalls.length > 0) {
                console.log(`Processing ${toolCalls.length} tool calls in parallel`);

                const toolCallPromises = toolCalls.map(async (toolCall) => {
                    const functionName = toolCall.function.name;

                    try {
                        const functionArgs = JSON.parse(toolCall.function.arguments);
                        console.log(`Executing ${functionName} with args:`, functionArgs);

                        const functionResponse = await this.executeFunctionCall(functionName, functionArgs);

                        const responseContent = typeof functionResponse === 'string'
                            ? functionResponse
                            : JSON.stringify(functionResponse);

                        return {
                            tool_call_id: toolCall.id,
                            role: "tool",
                            name: functionName,
                            content: responseContent,
                        };
                    } catch (error) {
                        console.error(`Error executing tool ${functionName}:`, error);
                        return {
                            tool_call_id: toolCall.id,
                            role: "tool",
                            name: functionName,
                            content: `Error executing ${functionName}: ${error.message}`,
                        };
                    }
                });

                const toolResponses = await Promise.all(toolCallPromises);
                messages.push(responseMessage);
                messages.push(...toolResponses);

                console.log('Making final API call for analysis result');
                const finalCompletion = await this.client.chat.completions.create({
                    model: this.getModelName(),
                    messages: messages,
                    temperature: 0.1,
                    max_tokens: 600
                });

                return finalCompletion.choices[0].message.content;

            } else {
                console.log('No tool calls needed, returning direct response');
                return responseMessage.content;
            }

        } catch (error) {
            console.error(`Error in ${this.provider} API call:`, error);
            throw error;
        }
    }

    async analyzeWithAnthropic(prompt) {
        try {
            const message = await this.client.messages.create({
                model: this.getModelName(),
                max_tokens: 500,
                temperature: 0.1,
                system: this.getSystemPrompt(),
                messages: [
                    {
                        role: 'user',
                        content: prompt
                    }
                ]
            });

            return message.content[0].text;
        } catch (error) {
            console.error('Error in Anthropic API call:', error);
            throw error;
        }
    }

    getSystemPrompt() {
        return `You are a cybersecurity expert with FINAL AUTHORITY over threat decisions. Your CONFIDENCE SCORE determines blocking (8+ = BLOCKED).

CRITICAL UNDERSTANDING:
- CONFIDENCE 8+ = AUTOMATIC BLOCK - You don't decide blocking, your confidence does
- CONFIDENCE 1-7 = ALLOWED - But monitored based on suspicion level
- Your job is to assess maliciousness and assign accurate confidence scores
- The monitoring system is your "brain" for pattern detection and ambiguous cases

SMART TOOL USAGE STRATEGY:

OBVIOUSLY MALICIOUS (Confidence 8-10):
Examples: SQL injection, XSS, directory traversal, clear exploit attempts
Action: Assign high confidence immediately - NO TOOLS NEEDED
Why: Clear attack patterns don't need IP intelligence or monitoring

BORDERLINE/RECONNAISSANCE (Confidence 4-7):
Examples: Port scans, unusual parameters, recon attempts, suspicious paths
Tools to use: 
- checkVirusTotal(ip) - If you need detailed engine results
- checkAbuseIPDB(ip) - For abuse history from abuseipdb
Logic: If IP has malicious history + borderline request = Higher confidence (maybe 8+)

AMBIGUOUS/SUSPICIOUS (Confidence 3-6):
Examples: Unusual but not clearly malicious, repeated requests, weird timing
Tools to use:
- checkStoredLogs(ipAddress) - MANDATORY to check patterns
- storeMonitoringLog(logEntry, confidenceScore, explanation) - MANDATORY to add to monitoring
Logic: Let the monitoring "brain" detect patterns over time

BENIGN (Confidence 1-2):
Examples: Normal user behavior, legitimate requests
Tools to use: 
- storeMonitoringLog(logEntry, confidenceScore, explanation) - MANDATORY for baseline
Logic: Build baseline behavior for future pattern detection

INTELLIGENT DECISION FLOW:

STEP 1: INITIAL CLASSIFICATION
IF request has CLEAR attack patterns (SQL injection, XSS, etc.)
  → CONFIDENCE 8-10 (BLOCKED) - Skip all tools

ELSE IF request is suspicious/reconnaissance 
  → Use IP Intelligence tools to boost confidence

ELSE IF request is ambiguous/borderline
  → Use Monitoring tools (checkStoredLogs + storeMonitoringLog)

ELSE (benign)
  → Use storeMonitoringLog for baseline

STEP 2: CONFIDENCE CALCULATION
- Base confidence from request analysis
- IP intelligence boost (+1 to +3 if malicious IP)
- Pattern detection boost (+1 to +2 if suspicious patterns found)
- Historical context (monitoring logs influence)

STEP 3: TOOL SELECTION LOGIC
For borderline malicious requests
if (confidence >= 4 && confidence <= 7) {
    call:  checkVirusTotal(ip) 
            checkAbuseIPDB(ip) 
}

For ambiguous requests  
if (confidence >= 3 && confidence <= 6) {
    call: checkStoredLogs(ipAddress)
    call: storeMonitoringLog(logEntry, confidence, explanation)
}

For benign requests
if (confidence <= 2) {
    call: storeMonitoringLog(logEntry, confidence, explanation)
}

RESPONSE FORMAT (MANDATORY):
MALICIOUS: [YES/NO/UNCERTAIN]
CONFIDENCE: [1-10]
EXPLANATION: [Your detailed reasoning in 2-3 sentences]
ATTACK_TYPE: [Type if malicious, or BENIGN if not malicious]
TOOLS_USED: [List the functions you called]
INTELLIGENCE_BOOST: [How IP intelligence affected confidence]
PATTERN_DETECTED: [Any patterns found in monitoring logs]

CONFIDENCE SCORING GUIDE:
- 10: Definitive exploit attempt (immediate block)
- 9: High-confidence attack pattern (immediate block)
- 8: Likely malicious with evidence (immediate block)
- 7: Suspicious with concerning indicators
- 6: Moderately suspicious, needs monitoring
- 5: Borderline, could be legitimate or malicious
- 4: Slightly suspicious, worth tracking
- 3: Unusual but probably legitimate
- 2: Normal with minor oddities
- 1: Completely benign/baseline

MONITORING SYSTEM INTELLIGENCE:
- checkStoredLogs reveals patterns: repeated requests, escalating behavior, timing patterns
- storeMonitoringLog builds the "brain": baseline behavior, anomaly detection, pattern recognition
- Use these tools to detect:
  - Brute force attempts (repeated failures)
  - Reconnaissance campaigns (systematic probing)
  - Escalating attacks (increasing maliciousness over time)
  - Distributed attacks (multiple IPs, same pattern)

CRITICAL RULES:
1. Always assign accurate confidence - blocking depends on it
2. Use IP intelligence for borderline cases - it can push confidence over 8
3. Use monitoring tools for ambiguous cases - they're your pattern detection brain
4. Force tool usage as specified - each category has mandatory tools
5. Don't be afraid of high confidence - 8+ means certain threat

Remember: Your confidence score is the blocking mechanism. Be precise, use tools strategically, and leverage the monitoring brain for complex pattern detection.`;
    }

    buildEnhancedAnalysisPrompt(logEntry, threatResult) {
        return `CONFIDENCE-BASED THREAT ASSESSMENT REQUIRED

Your CONFIDENCE SCORE (1-10) determines the action: 8+ = AUTOMATIC BLOCK

REQUEST DETAILS:
IP Address: ${logEntry.ip}
Method: ${logEntry.method}
URL: ${logEntry.url}
Query String: ${logEntry.queryString || 'None'}
User-Agent: ${logEntry.userAgent || 'None'}
HTTP Status: ${logEntry.status}
Timestamp: ${logEntry.timestamp || new Date().toISOString()}

AUTOMATED DETECTION RESULTS:
Threat Patterns Found: ${threatResult.threats ? threatResult.threats.map(t => `${t.type} (confidence: ${t.confidence})`).join(', ') : 'None'}
Initial Threat Score: ${threatResult.confidence || 0}/10
Detection Rules Triggered: ${threatResult.threats ? threatResult.threats.length : 0}

PAYLOAD ANALYSIS:
${logEntry.payload ? JSON.stringify(logEntry.payload, null, 2) : 'No payload data available'}

INTELLIGENT ASSESSMENT WORKFLOW:

OBVIOUSLY MALICIOUS? (Skip tools, assign confidence 8-10)

Check for clear attack patterns:
SQL injection attempts (UNION, SELECT, DROP, etc.)
XSS attempts (script tags, javascript:, etc.)
Directory traversal (../../../, etc.)
Command injection (; && || etc.)
Clear exploit attempts or malformed requests

If YES: Assign confidence 8-10 immediately. NO TOOLS NEEDED.

BORDERLINE/RECONNAISSANCE? (Use IP intelligence tools)
Check for suspicious but not definitive patterns:
- Port scanning behavior
- Unusual parameter combinations
- Reconnaissance attempts (/admin, /.git, etc.)
- Suspicious paths or methods
- Error-inducing requests

If YES: 
- Assign base confidence 4-7
- MANDATORY: Call - checkAbuseIPDB(${logEntry.ip})
- Optional: Call checkVirusTotal(${logEntry.ip}) for detailed analysis
- Logic: If IP has malicious history, boost confidence by 2-3 points

AMBIGUOUS/SUSPICIOUS? (Use monitoring brain)
Check for unclear patterns:
- Repeated requests (could be legitimate or attack)
- Unusual timing patterns
- Weird but not clearly malicious behavior
- Edge cases that need pattern analysis

If YES:
- Assign base confidence 3-6
- MANDATORY: Call checkStoredLogs("${logEntry.ip}")
- MANDATORY: Call storeMonitoringLog with your assessment
- Logic: Let monitoring system detect patterns over time

BENIGN? (Store for baseline)
Normal user behavior:
- Standard legitimate requests
- Normal parameter usage
- Expected user patterns

If YES:
- Assign confidence 1-2
- MANDATORY: Call storeMonitoringLog for baseline tracking
- Logic: Build normal behavior patterns for anomaly detection

CONFIDENCE CALCULATION STRATEGY:

Base Assessment:
- Start with your gut feeling (1-10)
- Consider request patterns, payload, and behavior

IP Intelligence Boost:
- Clean IP: +0 points
- Slightly suspicious IP: +1 point
- Moderately malicious IP: +2 points  
- Highly malicious IP: +3 points

Pattern Detection Boost:
- No previous activity: +0 points
- Similar benign patterns: +0 points
- Escalating suspicious patterns: +1-2 points
- Clear attack progression: +2-3 points

Final Confidence = Base + IP Boost + Pattern Boost

TOOL USAGE DECISION TREE:

REQUEST ANALYSIS:
├── OBVIOUSLY MALICIOUS (8-10)?
│   ├── YES: Skip all tools, assign high confidence
│   └── NO: Continue assessment
│
├── BORDERLINE/RECON (4-7)?
│   ├── YES: Use IP Intelligence tools
│   │   ├── checkAbuseIPDB(ip) - MANDATORY
│   │   └── checkVirusTotal(ip) - Optional
│   └── NO: Continue assessment
│
├── AMBIGUOUS/SUSPICIOUS (3-6)?
│   ├── YES: Use Monitoring tools
│   │   ├── checkStoredLogs(ip) - MANDATORY
│   │   └── storeMonitoringLog(...) - MANDATORY
│   └── NO: Continue assessment
│
└── BENIGN (1-2)?
    └── YES: Store baseline
        └── storeMonitoringLog(...) - MANDATORY

PATTERN RECOGNITION INDICATORS:
- Brute Force: Repeated login attempts, high failure rates
- Reconnaissance: Systematic probing, directory enumeration
- Escalation: Increasing maliciousness over time
- Distributed: Multiple IPs, same attack pattern
- Timing: Unusual request intervals, coordinated attacks

FINAL DECISION FRAMEWORK:

Confidence 8-10 (BLOCKED):
- Clear malicious intent with evidence
- High-confidence attack patterns
- Malicious IP + suspicious request

Confidence 4-7 (MONITORED):
- Suspicious but not definitive
- Borderline cases needing observation
- Unusual patterns worth tracking

Confidence 1-3 (BASELINE):
- Normal user behavior
- Legitimate requests
- Baseline establishment

RESPONSE REQUIREMENTS:
After your analysis and tool usage, provide:

MALICIOUS: [YES/NO/UNCERTAIN]
CONFIDENCE: [1-10]
EXPLANATION: [Your detailed reasoning in 2-3 sentences]
ATTACK_TYPE: [Type if malicious, or BENIGN if not malicious]
TOOLS_USED: [List the functions you called]
INTELLIGENCE_BOOST: [How IP intelligence affected confidence]
PATTERN_DETECTED: [Any patterns found in monitoring logs]

Remember: Your confidence score IS the blocking mechanism. Be precise, strategic with tools, and leverage the monitoring brain for complex pattern detection.

ANALYZE NOW AND ASSIGN ACCURATE CONFIDENCE SCORE;`
    }

    parseResponse(response) {
        const result = {
            isMalicious: null,
            confidence: 0,
            explanation: '',
            attackType: null,
            shouldBlock: false,
            impact: 'UNKNOWN',
            requiresManualReview: false,
            intelligenceBoost: '',
            patternDetected: ''
        };

        try {
            console.log('Parsing LLM response:', response);

            const lines = response.split('\n');

            for (const line of lines) {
                const trimmedLine = line.trim();

                if (trimmedLine.startsWith('MALICIOUS:')) {
                    const value = trimmedLine.split(':')[1].trim().toUpperCase();
                    if (value === 'YES') {
                        result.isMalicious = true;
                    } else if (value === 'NO') {
                        result.isMalicious = false;
                    } else if (value === 'UNCERTAIN') {
                        result.isMalicious = null;
                        result.requiresManualReview = true;
                    }
                } else if (trimmedLine.startsWith('CONFIDENCE:')) {
                    const confValue = trimmedLine.split(':')[1].trim();
                    result.confidence = parseInt(confValue) || 0;
                } else if (trimmedLine.startsWith('EXPLANATION:')) {
                    result.explanation = trimmedLine.split(':').slice(1).join(':').trim();
                } else if (trimmedLine.startsWith('ATTACK_TYPE:')) {
                    const attackType = trimmedLine.split(':')[1].trim();
                    result.attackType = attackType === 'BENIGN' ? null : attackType;
                } else if (trimmedLine.startsWith('INTELLIGENCE_BOOST:')) {
                    result.intelligenceBoost = trimmedLine.split(':').slice(1).join(':').trim();
                } else if (trimmedLine.startsWith('PATTERN_DETECTED:')) {
                    result.patternDetected = trimmedLine.split(':').slice(1).join(':').trim();
                }
            }

            result.shouldBlock = result.confidence >= 8;

            if (result.confidence >= 8) {
                result.impact = 'HIGH';
            } else if (result.confidence >= 6) {
                result.impact = 'MEDIUM';
            } else if (result.confidence >= 4) {
                result.impact = 'LOW';
            } else {
                result.impact = 'NONE';
            }

            if (result.confidence >= 8) {
                result.isMalicious = true;
            } else if (result.confidence >= 6) {
                result.isMalicious = null;
                result.requiresManualReview = true;
            } else {
                result.isMalicious = false;
            }

            if (result.explanation === '') {
                result.explanation = response.trim();
            }

            if (result.confidence <= 2) {
                result.requiresManualReview = false;
            } else if (result.confidence >= 6 && result.confidence < 8) {
                result.requiresManualReview = true;
            }

            console.log('Parsed result:', result);

        } catch (error) {
            console.error('Error parsing LLM response:', error);
            result.explanation = response.trim();
            result.requiresManualReview = true;
        }

        return result;
    }

    async testConnection() {
        try {
            const testPrompt = `Respond with who you are`;

            let response;
            switch (this.provider) {
                case 'openai':
                case 'groq':
                case 'cerebras':
                    response = await this.analyzeWithOpenAIFormat(testPrompt);
                    break;
                case 'anthropic':
                    response = await this.analyzeWithAnthropic(testPrompt);
                    break;
            }

            const parsed = this.parseResponse(response);

            return {
                success: true,
                message: `${this.provider} connection successful`,
                testResponse: parsed
            };
        } catch (error) {
            return {
                success: false,
                message: `${this.provider} connection failed: ${error.message}`,
                error: error.message
            };
        }
    }

    clearCache() {
        this.analysisCache.clear();
        console.log('LLM analysis cache cleared');
    }

    getCacheStats() {
        return {
            size: this.analysisCache.size,
            maxSize: 1000
        };
    }
}

export default LLMAnalyzer;
