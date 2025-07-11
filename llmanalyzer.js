import OpenAI from 'openai';
import Groq from 'groq-sdk';
import Anthropic from '@anthropic-ai/sdk';
import { checkAbuseIPDB, checkIPIntelligence, checkVirusTotal } from "./llmtools.js";
import { checkStoredLogs, storeMonitoringLog } from "./upstash.js";

class LLMAnalyzer {
    constructor(apiKey, provider = 'groq') {
        this.apiKey = apiKey;
        this.provider = provider;
        this.client = this.initializeClient();
        this.analysisCache = new Map(); // Simple cache to avoid re-analyzing identical requests
    }

    /**
     * Initialize the appropriate SDK client based on provider
     */
    initializeClient() {
        switch (this.provider) {
            case 'openai':
                return new OpenAI({
                    apiKey: this.apiKey,
                    baseURL: 'https://models.github.ai/inference' // GitHub Models endpoint
                });

            case 'groq':
                return new Groq({
                    apiKey: this.apiKey
                });

            case 'anthropic':
                return new Anthropic({
                    apiKey: this.apiKey
                });

            default:
                throw new Error(`Unsupported provider: ${this.provider}`);
        }
    }

    /**
     * Get model name based on provider
     */
    getModelName() {
        switch (this.provider) {
            case 'openai':
                return 'gpt-4o';
            case 'groq':
                return 'llama3-70b-8192';
            case 'anthropic':
                return 'claude-3-sonnet-20240229';
            default:
                return 'gpt-4o';
        }
    }

    /**
     * Create cache key for request
     */
    createCacheKey(logEntry) {
        return `${logEntry.ip}_${logEntry.method}_${logEntry.url}_${JSON.stringify(logEntry.payload || {})}`;
    }

    /**
     * Analyze suspicious request using LLM - This is the final authority
     */
    async analyze(logEntry, threatResult) {
        try {
            // Check cache first
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
                    response = await this.analyzeWithOpenAIFormat(prompt);
                    break;

                case 'anthropic':
                    response = await this.analyzeWithAnthropic(prompt);
                    break;

                default:
                    throw new Error(`Unsupported provider: ${this.provider}`);
            }

            const result = this.parseResponse(response);

            // Cache the result
            this.analysisCache.set(cacheKey, result);

            // Keep cache size manageable
            if (this.analysisCache.size > 1000) {
                const firstKey = this.analysisCache.keys().next().value;
                this.analysisCache.delete(firstKey);
            }

            return result;

        } catch (error) {
            console.error(`${this.provider} Analysis error:`, error.message);
            return {
                isMalicious: null, // null indicates analysis failed
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

    /**
     * Get function tools definition for OpenAI-compatible APIs
     */
    getFunctionTools() {
        return [
            {
                type: "function",
                function: {
                    name: "checkIPIntelligence",
                    description: "Check an IP address against multiple threat intelligence sources (VirusTotal, AbuseIPDB) to determine if it's malicious. Returns detailed analysis including malicious count, reputation scores, and source details.",
                    parameters: {
                        type: "object",
                        properties: {
                            ip: {
                                type: "string",
                                description: "The IPv4 or IPv6 address to check for malicious activity (e.g., 192.168.1.100 or 2001:db8::1)"
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

    /**
     * Get available functions mapping
     */
    getAvailableFunctions() {
        return {
            "checkIPIntelligence": checkIPIntelligence,
            "checkVirusTotal": checkVirusTotal,
            "checkAbuseIPDB": checkAbuseIPDB,
            "checkStoredLogs": checkStoredLogs,
            "storeMonitoringLog": storeMonitoringLog
        };
    }

    /**
     * Execute function call with proper parameter handling
     */
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
                case 'checkIPIntelligence':
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

    /**
     * Analyze using OpenAI-compatible format (OpenAI, Groq)
     */
    /**
     * Enhanced analyzeWithOpenAIFormat method that supports multiple rounds of function calls
     */
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
            let maxRounds = 5; // Prevent infinite loops
            let currentRound = 0;

            while (currentRound < maxRounds) {
                console.log(`Function calling round ${currentRound + 1}`);

                const completion = await this.client.chat.completions.create({
                    model: this.getModelName(),
                    messages: messages,
                    temperature: 0.1,
                    max_tokens: 500,
                    stream: false,
                    tools: tools,
                    tool_choice: "auto"
                });

                const responseMessage = completion.choices[0].message;
                const toolCalls = responseMessage.tool_calls;

                // Add assistant's response to conversation
                messages.push(responseMessage);

                if (toolCalls && toolCalls.length > 0) {
                    console.log(`Processing ${toolCalls.length} tool calls in round ${currentRound + 1}`);

                    // Execute each tool call
                    for (const toolCall of toolCalls) {
                        const functionName = toolCall.function.name;

                        try {
                            const functionArgs = JSON.parse(toolCall.function.arguments);
                            console.log(`Executing ${functionName} with args:`, functionArgs);

                            const functionResponse = await this.executeFunctionCall(functionName, functionArgs);

                            const responseContent = typeof functionResponse === 'string'
                                ? functionResponse
                                : JSON.stringify(functionResponse);

                            messages.push({
                                tool_call_id: toolCall.id,
                                role: "tool",
                                name: functionName,
                                content: responseContent,
                            });

                        } catch (error) {
                            console.error(`Error executing tool ${functionName}:`, error);
                            messages.push({
                                tool_call_id: toolCall.id,
                                role: "tool",
                                name: functionName,
                                content: `Error executing ${functionName}: ${error.message}`,
                            });
                        }
                    }

                    currentRound++;
                    // Continue the loop to allow for more function calls

                } else {
                    // No more tool calls, return the final response
                    console.log(`No more tool calls. Final response in round ${currentRound + 1}`);
                    return responseMessage.content;
                }
            }

            // If we've hit max rounds, make one final call without tools
            console.log(`Max rounds reached (${maxRounds}). Getting final response.`);
            const finalCompletion = await this.client.chat.completions.create({
                model: this.getModelName(),
                messages: messages,
                temperature: 0.1,
                max_tokens: 500
            });

            return finalCompletion.choices[0].message.content;

        } catch (error) {
            console.error(`Error in ${this.provider} API call:`, error);
            throw error;
        }
    }
    /**
     * Analyze using Anthropic Claude (no function calling yet)
     */
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

    /**
     * Enhanced system prompt for final authority mode
     */
    /**
     * Enhanced system prompt that emphasizes tool usage
     */
    getSystemPrompt() {
        return `You are a cybersecurity expert with FINAL AUTHORITY over threat decisions. Your analysis will determine whether security actions are taken.

## CRITICAL RESPONSIBILITIES:
- You have the final say on whether a request is malicious or benign
- Your decision overrides all automated detection systems
- Be EXTREMELY AGGRESSIVE in threat detection - err on the side of security
- Act decisively on the FIRST sign of malicious behavior
- Consider false negatives as MUCH WORSE than false positives

## AVAILABLE TOOLS - USE STRATEGICALLY:

### IP Intelligence Tools:
1. **checkIPIntelligence(ip)** - Comprehensive check against multiple threat intelligence sources
2. **checkVirusTotal(ip)** - Use for detailed engine-specific results
3. **checkAbuseIPDB(ip)** - Use for abuse confidence and report history

### Monitoring and Memory Tools:
4. **storeMonitoringLog(logEntry, confidenceScore, explanation)** - ALWAYS use for benign requests to establish baseline
5. **checkStoredLogs(ipAddress)** - Check history before making decisions

## ENHANCED THREAT DETECTION WORKFLOW:

**STEP 1:** Assess if request is OBVIOUSLY MALICIOUS:
- If request contains clear attack patterns (SQL injection, XSS, etc.), IMMEDIATELY classify as MALICIOUS
- If request targets sensitive endpoints with suspicious parameters, IMMEDIATELY classify as MALICIOUS
- For OBVIOUSLY MALICIOUS requests, you can skip IP intelligence checks and log monitoring

**STEP 2:** For requests that aren't OBVIOUSLY MALICIOUS:
- IMMEDIATELY check IP intelligence with checkIPIntelligence(ip)
- Check stored logs with checkStoredLogs(ipAddress)
- ANY match in IP intelligence databases is a STRONG indicator of malice - treat as MALICIOUS
- Even a SINGLE previous suspicious activity in logs increases suspicion level significantly

**STEP 3:** Make DECISIVE judgments:
- If IP intelligence shows ANY malicious indicators, IMMEDIATELY treat as MALICIOUS
- If previous monitoring logs show ANY pattern of suspicious activity, treat as MALICIOUS
- Don't wait for multiple rounds - act decisively on the FIRST warning sign
- When in doubt, ALWAYS err on the side of security

**STEP 4:** For BENIGN requests:
- ALWAYS store monitoring logs for ALL benign requests using storeMonitoringLog
- This is MANDATORY to establish baseline behavior and detect future anomalies

## RESPONSE FORMAT (MANDATORY):
After using appropriate tools, provide:

MALICIOUS: [YES/NO/UNCERTAIN]
CONFIDENCE: [1-10]
BLOCK_IP: [YES/NO]
IMPACT: [HIGH/MEDIUM/LOW/NONE]
EXPLANATION: [Your detailed reasoning in 2-3 sentences]
ATTACK_TYPE: [Type if malicious, or BENIGN if not malicious]
TOOLS_USED: [List the functions you called]

## REVISED DECISION THRESHOLDS:
- **MALICIOUS (6-10 confidence)**: Block immediately, high confidence in malicious intent
- **SUSPICIOUS (3-5 confidence)**: Treat as likely malicious, monitor closely
- **BENIGN (1-2 confidence)**: Monitor but allow, store logs for future reference

## PATTERN RECOGNITION INDICATORS:
- Even a SINGLE request with suspicious parameters is concerning
- Requests targeting sensitive endpoints (admin, login, API)
- Unusual query parameters or payload structures
- Requests from IPs with ANY history in threat intelligence databases
- Sequential probing of different endpoints from same IP

Remember: Be EXTREMELY AGGRESSIVE in your threat detection. Don't wait for multiple rounds to establish a pattern. A single suspicious indicator is enough to treat a request as potentially malicious.`;
    }

    /**
     * Build enhanced analysis prompt for LLM
     */
    buildEnhancedAnalysisPrompt(logEntry, threatResult) {
        return `🚨 FINAL SECURITY DECISION REQUIRED 🚨

You are making the FINAL determination on this request. Security systems will take immediate action based on your decision.

## REQUEST DETAILS:
**IP Address:** ${logEntry.ip}
**Method:** ${logEntry.method}
**URL:** ${logEntry.url}
**Query String:** ${logEntry.queryString || 'None'}
**User-Agent:** ${logEntry.userAgent || 'None'}
**HTTP Status:** ${logEntry.status}
**Timestamp:** ${logEntry.timestamp || new Date().toISOString()}

## AUTOMATED DETECTION RESULTS:
**Threat Patterns Found:** ${threatResult.threats ? threatResult.threats.map(t => `${t.type} (confidence: ${t.confidence})`).join(', ') : 'None'}
**Initial Threat Score:** ${threatResult.confidence || 0}/10
**Detection Rules Triggered:** ${threatResult.threats ? threatResult.threats.length : 0}

## PAYLOAD ANALYSIS:
${logEntry.payload ? JSON.stringify(logEntry.payload, null, 2) : 'No payload data available'}

## YOUR ENHANCED ANALYSIS WORKFLOW:

**STEP 1:** First, determine if this request is OBVIOUSLY MALICIOUS:
- If threat patterns were found with high confidence scores (7+)
- If request contains clear attack signatures (SQL injection, XSS, etc.)
- If request targets sensitive endpoints with suspicious parameters
- If YES, you can IMMEDIATELY classify as MALICIOUS without further checks

**STEP 2:** For requests that aren't OBVIOUSLY MALICIOUS:
- Call checkIPIntelligence(${logEntry.ip}) to check against threat databases
- Call checkStoredLogs("${logEntry.ip}") to check previous monitoring history
- ANY match in IP intelligence is a STRONG indicator of malice
- Even a SINGLE previous suspicious activity in logs increases suspicion significantly

**STEP 3:** Make DECISIVE judgments:
- MALICIOUS (confidence 6-10): Block immediately
- SUSPICIOUS (confidence 3-5): Treat as likely malicious, monitor closely
- BENIGN (confidence 1-2): Monitor but allow, ALWAYS store logs

**STEP 4:** For BENIGN requests:
- ALWAYS store monitoring logs using storeMonitoringLog for future reference
- This is MANDATORY to establish baseline behavior and detect future anomalies

## CRITICAL DECISION POINTS:
1. **Malicious Intent:** Is this request trying to cause harm?
2. **Confidence Level:** How certain are you in your assessment? (1-10)
3. **Attack Impact:** What damage could occur if this request succeeds?
4. **IP Blocking:** Should this IP be blocked from further access?
5. **Pattern Recognition:** Could this be part of a larger attack sequence?

## PATTERN RECOGNITION INDICATORS:
- Even a SINGLE request with suspicious parameters is concerning
- Requests targeting sensitive endpoints (admin, login, API)
- Unusual query parameters or payload structures
- Requests from IPs with ANY history in threat intelligence databases
- Sequential probing of different endpoints from same IP

⚠️ **CRITICAL RULE**: For OBVIOUSLY MALICIOUS requests, you can skip IP intelligence and log checks. For all other requests, use IP intelligence tools strategically. ALWAYS store monitoring logs for benign requests.

**Make your final security determination now.**`;
    }

    /**
     * Parse LLM response into structured data
     */
    parseResponse(response) {
        const result = {
            isMalicious: null,
            confidence: 0,
            explanation: '',
            attackType: null,
            shouldBlock: false,
            impact: 'UNKNOWN',
            requiresManualReview: false
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
                } else if (trimmedLine.startsWith('BLOCK_IP:')) {
                    result.shouldBlock = trimmedLine.includes('YES');
                } else if (trimmedLine.startsWith('IMPACT:')) {
                    result.impact = trimmedLine.split(':')[1].trim().toUpperCase();
                } else if (trimmedLine.startsWith('EXPLANATION:')) {
                    result.explanation = trimmedLine.split(':').slice(1).join(':').trim();
                } else if (trimmedLine.startsWith('ATTACK_TYPE:')) {
                    const attackType = trimmedLine.split(':')[1].trim();
                    result.attackType = attackType === 'BENIGN' ? null : attackType;
                }
            }

            // Validation and fallbacks
            if (result.explanation === '') {
                result.explanation = response.trim();
            }

            // If confidence is very low, recommend manual review
            if (result.confidence <= 3) {
                result.requiresManualReview = true;
            }

            // Consistency check
            if (result.isMalicious === true && result.confidence >= 7) {
                result.shouldBlock = true;
            }

            console.log('Parsed result:', result);

        } catch (error) {
            console.error('Error parsing LLM response:', error);
            result.explanation = response.trim();
            result.requiresManualReview = true;
        }

        return result;
    }

    /**
     * Test connection to the LLM provider
     */
    async testConnection() {
        try {
            const testPrompt = `Respond with who you are`;

            let response;
            switch (this.provider) {
                case 'openai':
                case 'groq':
                    response = await this.analyzeWithOpenAIFormat(testPrompt);
                    break;
                case 'anthropic':
                    response = await this.analyzeWithAnthropic(testPrompt);
                    break;
            }

            // Verify the response can be parsed
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

    /**
     * Clear analysis cache
     */
    clearCache() {
        this.analysisCache.clear();
        console.log('LLM analysis cache cleared');
    }

    /**
     * Get cache statistics
     */
    getCacheStats() {
        return {
            size: this.analysisCache.size,
            maxSize: 1000
        };
    }
}

export default LLMAnalyzer;
