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

            if (toolCalls && toolCalls.length > 0) {
                console.log(`Processing ${toolCalls.length} tool calls`);

                // Add the assistant's response to messages
                messages.push(responseMessage);

                // Execute each tool call
                for (const toolCall of toolCalls) {
                    const functionName = toolCall.function.name;

                    try {
                        // Parse function arguments
                        const functionArgs = JSON.parse(toolCall.function.arguments);
                        console.log(`Parsed function args for ${functionName}:`, functionArgs);

                        // Execute the function
                        const functionResponse = await this.executeFunctionCall(functionName, functionArgs);

                        // Ensure response is a string
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
                        // Handle tool execution errors gracefully
                        messages.push({
                            tool_call_id: toolCall.id,
                            role: "tool",
                            name: functionName,
                            content: `Error executing ${functionName}: ${error.message}`,
                        });
                    }
                }

                // Get the final response after tool calls
                const secondResponse = await this.client.chat.completions.create({
                    model: this.getModelName(),
                    messages: messages,
                    temperature: 0.1,
                    max_tokens: 500
                });

                return secondResponse.choices[0].message.content;
            }

            return responseMessage.content;

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
    getSystemPrompt() {
        return `You are a cybersecurity expert with FINAL AUTHORITY over threat decisions. Your analysis will determine whether security actions are taken.

## CRITICAL RESPONSIBILITIES:
- You have the final say on whether a request is malicious or benign
- Your decision overrides all automated detection systems
- Be thorough but decisive - systems depend on your judgment
- Consider false positives carefully as they can disrupt legitimate users
- Consider false negatives carefully as they can allow attacks through

## AVAILABLE TOOLS:

### IP Intelligence Tools:
1. **checkIPIntelligence(ip)** - Comprehensive IP reputation check against multiple threat intelligence sources
2. **checkVirusTotal(ip)** - Specific check against VirusTotal's database
3. **checkAbuseIPDB(ip)** - Check against AbuseIPDB's database of reported malicious IPs

### Monitoring and Memory Tools:
4. **storeMonitoringLog(logEntry, confidenceScore, explanation)** - Store a request log for monitoring
5. **checkStoredLogs(ipAddress)** - Check if there are existing monitoring logs for an IP

## MONITORING WORKFLOW:
1. **First check if the IP is already being monitored** using checkStoredLogs(ipAddress)
2. **If NOT already monitored and the request is suspicious**, store it using storeMonitoringLog()
3. **If the IP is already being monitored**, you can see the pattern history
4. **For clearly malicious requests**, proceed directly to blocking

## TOOL USAGE GUIDELINES:
- Use IP intelligence tools ONLY when you need reputation data to make a decision
- Do NOT check IPs for obviously malicious requests
- Use monitoring tools for suspicious but ambiguous cases
- Always check existing monitoring logs before storing new ones

## RESPONSE FORMAT (MANDATORY):
MALICIOUS: [YES/NO/UNCERTAIN]
CONFIDENCE: [1-10]
BLOCK_IP: [YES/NO]
IMPACT: [HIGH/MEDIUM/LOW/NONE]
EXPLANATION: [Your detailed reasoning in 2-3 sentences]
ATTACK_TYPE: [Type if malicious, or BENIGN if not malicious]

Remember: Your decision has immediate consequences. Be thorough but decisive.`;
    }

    /**
     * Build enhanced analysis prompt for LLM
     */
    buildEnhancedAnalysisPrompt(logEntry, threatResult) {
        return `🚨 FINAL SECURITY DECISION REQUIRED 🚨

You are making the FINAL determination on this request. Security systems will take action based on your decision.

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
Raw Detection Rules Triggered: ${threatResult.threats ? threatResult.threats.length : 0}

PAYLOAD ANALYSIS:
${logEntry.payload ? JSON.stringify(logEntry.payload, null, 2) : 'No payload data'}

YOUR FINAL DECISION MUST ADDRESS:
1. Is this request actually malicious and dangerous?
2. What is your confidence in this decision? (1-10)
3. What would happen if this request succeeded?
4. Should this IP be blocked?
5. Brief explanation of your reasoning

DECISION GUIDANCE:
- If OBVIOUSLY malicious, decide without checking IP reputation
- If POTENTIALLY malicious but need context, use IP intelligence tools
- If appears benign, no need to check IP reputation unless suspicious

Use the available tools strategically when additional context is needed.`;
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
            const testPrompt = `Test connection. Respond with a simple security analysis of IP 8.8.8.8 making a GET request to /test`;

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