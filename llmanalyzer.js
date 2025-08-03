import OpenAI from 'openai';
import Groq from 'groq-sdk';
import Anthropic from '@anthropic-ai/sdk';
import Cerebras from '@cerebras/cerebras_cloud_sdk';
import { checkAbuseIPDB, checkVirusTotal } from "./llmtools.js";
import { checkStoredLogs, storeMonitoringLog } from "./upstash.js";

class LLMAnalyzer {
    constructor(apiKey, provider = 'cerebras') {
        this.apiKey = apiKey;
        this.provider = provider;
        this.client = this.initializeClient();

        // Cache structure: Map<ipAddress, analysisResult>
        // This allows us to quickly check if an IP is already marked as malicious
        this.ipCache = new Map();

        // Queue tracking: Map<ipAddress, Set<requestKeys>>
        // Tracks all pending requests per IP so we can clean them up
        this.ipRequestQueue = new Map();

        // Request cache for detailed caching: Map<requestKey, analysisResult>
        this.requestCache = new Map();
    }

    initializeClient() {
        switch (this.provider) {
            case 'openai':
                return new OpenAI({
                    apiKey: this.apiKey,
                    baseURL: 'https://models.github.ai/inference'
                });
            case 'groq':
                return new Groq({ apiKey: this.apiKey });
            case 'cerebras':
                return new Cerebras({ apiKey: this.apiKey });
            case 'anthropic':
                return new Anthropic({ apiKey: this.apiKey });
            default:
                throw new Error(`Unsupported provider: ${this.provider}`);
        }
    }

    getModelName() {
        const models = {
            'openai': 'gpt-4o',
            'groq': 'llama3-70b-8192',
            'anthropic': 'claude-3-sonnet-20240229',
            'cerebras': 'llama3.3-70b'
        };
        return models[this.provider] || 'llama3.3-70b';
    }

    /**
     * Creates a unique key for caching individual requests
     */
    createRequestKey(logEntry) {
        return `${logEntry.ip}_${logEntry.method}_${logEntry.url}_${JSON.stringify(logEntry.payload || {})}`;
    }

    /**
     * Adds a request to the IP's queue for tracking
     */
    addToQueue(ip, requestKey) {
        if (!this.ipRequestQueue.has(ip)) {
            this.ipRequestQueue.set(ip, new Set());
        }
        this.ipRequestQueue.get(ip).add(requestKey);
    }

    /**
     * Removes all pending requests from a malicious IP
     */
    cleanupMaliciousIP(ip) {
        const requests = this.ipRequestQueue.get(ip);
        if (requests) {
            // Remove all cached requests for this IP
            requests.forEach(requestKey => {
                this.requestCache.delete(requestKey);
            });

            // Clear the queue for this IP
            this.ipRequestQueue.delete(ip);

            console.log(`Cleaned up ${requests.size} pending requests from malicious IP: ${ip}`);
        }
    }

    /**
     * Main analysis method with optimized caching and queue management
     */
    async analyze(logEntry, threatResult) {
        const ip = logEntry.ip;
        const requestKey = this.createRequestKey(logEntry);

        try {
            // Check if IP is already marked as malicious
            if (this.ipCache.has(ip)) {
                const cachedResult = this.ipCache.get(ip);
                if (cachedResult.confidence >= 8) {
                    console.log(`IP ${ip} already marked as malicious - blocking immediately`);
                    return {
                        ...cachedResult,
                        explanation: 'IP previously identified as malicious - auto-blocked'
                    };
                }
            }

            // Check for exact request match
            if (this.requestCache.has(requestKey)) {
                console.log('Using cached analysis for identical request');
                return this.requestCache.get(requestKey);
            }

            // Add to queue for potential cleanup
            this.addToQueue(ip, requestKey);

            // Perform analysis
            const prompt = this.buildAnalysisPrompt(logEntry, threatResult);
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

            // Handle system URL attribute from threatResult
            if (!result.is_system_url && threatResult.is_system_url) {
                result.is_system_url = true;
            }

            // Cache the result
            this.requestCache.set(requestKey, result);

            // If malicious (confidence >= 8), cache IP and cleanup queue
            if (result.confidence >= 8) {
                this.ipCache.set(ip, result);
                this.cleanupMaliciousIP(ip);
                console.log(`IP ${ip} marked as malicious with confidence ${result.confidence}`);
            }

            // Cache cleanup to prevent memory bloat
            this.maintainCacheSize();

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

    /**
     * Maintains cache size limits
     */
    maintainCacheSize() {
        // Limit IP cache to 500 entries
        if (this.ipCache.size > 500) {
            const firstKey = this.ipCache.keys().next().value;
            this.ipCache.delete(firstKey);
        }

        // Limit request cache to 1000 entries
        if (this.requestCache.size > 1000) {
            const firstKey = this.requestCache.keys().next().value;
            this.requestCache.delete(firstKey);
        }
    }

    /**
     * Function tools definition for LLM
     */
    getFunctionTools() {
        return [
            {
                type: "function",
                function: {
                    name: "checkVirusTotal",
                    description: "Check IP against VirusTotal database for malicious activity",
                    parameters: {
                        type: "object",
                        properties: {
                            ip: {
                                type: "string",
                                description: "IPv4 or IPv6 address to check"
                            }
                        },
                        required: ["ip"]
                    }
                }
            },
            {
                type: "function",
                function: {
                    name: "checkAbuseIPDB",
                    description: "Check IP against AbuseIPDB for abuse reports",
                    parameters: {
                        type: "object",
                        properties: {
                            ip: {
                                type: "string",
                                description: "IPv4 or IPv6 address to check"
                            }
                        },
                        required: ["ip"]
                    }
                }
            },
            {
                type: "function",
                function: {
                    name: "storeMonitoringLog",
                    description: "Store suspicious request for pattern monitoring",
                    parameters: {
                        type: "object",
                        properties: {
                            logEntry: {
                                type: "object",
                                description: "Request log entry",
                                properties: {
                                    ip: { type: "string" },
                                    method: { type: "string" },
                                    queryString: { type: "string" },
                                    userAgent: { type: "string" },
                                    url: { type: "string" },
                                    status: { type: "number" }
                                },
                                required: ["ip", "method", "queryString", "userAgent", "url", "status"]
                            },
                            confidenceScore: {
                                type: "number",
                                description: "Confidence score (0-10)"
                            },
                            explanation: {
                                type: "string",
                                description: "Explanation for suspicion"
                            }
                        },
                        required: ["logEntry", "confidenceScore", "explanation"]
                    }
                }
            },
            {
                type: "function",
                function: {
                    name: "checkStoredLogs",
                    description: "Check existing monitoring logs for IP patterns",
                    parameters: {
                        type: "object",
                        properties: {
                            ipAddress: {
                                type: "string",
                                description: "IP address to check for existing logs"
                            }
                        },
                        required: ["ipAddress"]
                    }
                }
            }
        ];
    }

    /**
     * Available function mappings
     */
    getAvailableFunctions() {
        return {
            "checkVirusTotal": checkVirusTotal,
            "checkAbuseIPDB": checkAbuseIPDB,
            "checkStoredLogs": checkStoredLogs,
            "storeMonitoringLog": storeMonitoringLog
        };
    }

    /**
     * Execute function calls from LLM
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
     * OpenAI-format API analysis with tool support
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
                content: prompt
            }
        ];

        try {
            console.log('Making API call with tool support');

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
                console.log(`Processing ${toolCalls.length} tool calls`);

                // Execute all tool calls in parallel
                const toolCallPromises = toolCalls.map(async (toolCall) => {
                    const functionName = toolCall.function.name;

                    try {
                        const functionArgs = JSON.parse(toolCall.function.arguments);
                        const functionResponse = await this.executeFunctionCall(functionName, functionArgs);

                        return {
                            tool_call_id: toolCall.id,
                            role: "tool",
                            name: functionName,
                            content: typeof functionResponse === 'string'
                                ? functionResponse
                                : JSON.stringify(functionResponse)
                        };
                    } catch (error) {
                        console.error(`Error executing tool ${functionName}:`, error);
                        return {
                            tool_call_id: toolCall.id,
                            role: "tool",
                            name: functionName,
                            content: `Error: ${error.message}`
                        };
                    }
                });

                const toolResponses = await Promise.all(toolCallPromises);
                messages.push(responseMessage);
                messages.push(...toolResponses);

                // Get final analysis
                const finalCompletion = await this.client.chat.completions.create({
                    model: this.getModelName(),
                    messages: messages,
                    temperature: 0.1,
                    max_tokens: 600
                });

                return finalCompletion.choices[0].message.content;
            } else {
                return responseMessage.content;
            }

        } catch (error) {
            console.error(`Error in ${this.provider} API call:`, error);
            throw error;
        }
    }

    /**
     * Anthropic API analysis
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
     * Concise system prompt focused on core decision making
     */
    getSystemPrompt() {
        return `You are a cybersecurity expert. Your CONFIDENCE SCORE (1-10) determines blocking: 8+ = BLOCKED.

ANALYSIS PRIORITY:
1. OBVIOUS ATTACKS (8-10 confidence): SQL injection, XSS, directory traversal, command injection etc
   → Assign high confidence immediately, NO TOOLS NEEDED

2. SUSPICIOUS REQUESTS (4-7 confidence): Recon attempts, unusual patterns, port scans etc
   → Use checkAbuseIPDB() or checkVirusTotal() to boost confidence if needed

3. AMBIGUOUS REQUESTS (3-6 confidence): Unclear intent, repeated requests
   → Use checkStoredLogs() and storeMonitoringLog() for pattern detection

4. BENIGN REQUESTS (1-2 confidence): Normal user behavior
   → Optionally use storeMonitoringLog() for baseline

TOOL USAGE RULES:
- Clear attacks: Skip tools, assign 8-10 confidence
- Borderline cases: Use IP intelligence tools (checkAbuseIPDB/checkVirusTotal)
- Ambiguous cases: Use monitoring tools (checkStoredLogs/storeMonitoringLog)
- Avoid unnecessary tool calls for obvious cases

SYSTEM URLS:
- System URLs are admin-configured trusted URLs
- Be lenient unless payload contains clear attacks
- Include "is_system_url: true" in response when applicable

RESPONSE FORMAT:
MALICIOUS: [YES/NO/UNCERTAIN]
CONFIDENCE: [1-10]
EXPLANATION: [Brief reasoning]
ATTACK_TYPE: [Type or BENIGN]

CONFIDENCE GUIDE:
10-9: Definitive attacks
8: Likely malicious 
7-4: Suspicious, needs monitoring
3-1: Benign/baseline`;
    }

    /**
     * Build analysis prompt with request details
     */
    buildAnalysisPrompt(logEntry, threatResult) {
        return `THREAT ASSESSMENT REQUEST

REQUEST DETAILS:
IP: ${logEntry.ip}
Method: ${logEntry.method}
URL: ${logEntry.url}
Query: ${logEntry.queryString || 'None'}
User-Agent: ${logEntry.userAgent || 'None'}
Status: ${logEntry.status}
System URL: ${threatResult.is_system_url ? 'YES' : 'NO'}

AUTOMATED DETECTION:
Threats Found: ${threatResult.threats ? threatResult.threats.map(t => `${t.type} (${t.confidence})`).join(', ') : 'None'}
Initial Score: ${threatResult.confidence || 0}/10

PAYLOAD:
${logEntry.payload ? JSON.stringify(logEntry.payload, null, 2) : 'No payload'}

ANALYSIS STEPS:
1. Check for obvious attack patterns (assign 8-10 if found)
2. If suspicious but unclear, use appropriate tools
3. Assign final confidence score
4. Provide assessment in required format

Your confidence score determines blocking (8+ = blocked). Analyze and respond.`;
    }

    /**
     * Parse LLM response into structured result
     */
    parseResponse(response) {
        const result = {
            isMalicious: null,
            confidence: 0,
            explanation: '',
            attackType: null,
            shouldBlock: false,
            impact: 'UNKNOWN',
            requiresManualReview: false,
            is_system_url: false
        };

        try {
            console.log('Parsing LLM response:', response);

            const lines = response.split('\n');

            for (const line of lines) {
                const trimmed = line.trim();

                if (trimmed.startsWith('MALICIOUS:')) {
                    const value = trimmed.split(':')[1].trim().toUpperCase();
                    result.isMalicious = value === 'YES' ? true : value === 'NO' ? false : null;
                    if (value === 'UNCERTAIN') result.requiresManualReview = true;
                }
                else if (trimmed.startsWith('CONFIDENCE:')) {
                    result.confidence = parseInt(trimmed.split(':')[1].trim()) || 0;
                }
                else if (trimmed.startsWith('EXPLANATION:')) {
                    result.explanation = trimmed.split(':').slice(1).join(':').trim();
                }
                else if (trimmed.startsWith('ATTACK_TYPE:')) {
                    const attackType = trimmed.split(':')[1].trim();
                    result.attackType = attackType === 'BENIGN' ? null : attackType;
                }
                else if (trimmed.includes('is_system_url: true')) {
                    result.is_system_url = true;
                }
            }

            // Set derived properties
            result.shouldBlock = result.confidence >= 8;

            // Set impact level
            if (result.confidence >= 8) result.impact = 'HIGH';
            else if (result.confidence >= 6) result.impact = 'MEDIUM';
            else if (result.confidence >= 4) result.impact = 'LOW';
            else result.impact = 'NONE';

            // Set malicious status based on confidence
            if (result.confidence >= 8) {
                result.isMalicious = true;
            } else if (result.confidence >= 6) {
                result.isMalicious = null;
                result.requiresManualReview = true;
            } else {
                result.isMalicious = false;
            }

            // Fallback explanation
            if (!result.explanation) {
                result.explanation = response.trim();
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
     * Test connection to LLM provider
     */
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

            return {
                success: true,
                message: `${this.provider} connection successful`,
                testResponse: this.parseResponse(response)
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
     * Clear all caches
     */
    clearCache() {
        this.ipCache.clear();
        this.requestCache.clear();
        this.ipRequestQueue.clear();
        console.log('All caches cleared');
    }

    /**
     * Get cache statistics
     */
    getCacheStats() {
        return {
            ipCache: this.ipCache.size,
            requestCache: this.requestCache.size,
            queuedIPs: this.ipRequestQueue.size,
            maxIpCache: 500,
            maxRequestCache: 1000
        };
    }

    /**
     * Get malicious IPs from cache
     */
    getMaliciousIPs() {
        const maliciousIPs = [];
        for (const [ip, result] of this.ipCache.entries()) {
            if (result.confidence >= 8) {
                maliciousIPs.push({
                    ip,
                    confidence: result.confidence,
                    attackType: result.attackType
                });
            }
        }
        return maliciousIPs;
    }
}

export default LLMAnalyzer;