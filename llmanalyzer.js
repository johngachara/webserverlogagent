const OpenAI = require('openai');
const Groq = require('groq-sdk');
const Anthropic = require('@anthropic-ai/sdk');

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
                return 'openai/gpt-4.1';
            case 'groq':
                return 'llama-3.3-70b-versatile';
            case 'anthropic':
                return 'claude-3-sonnet-20240229';
            default:
                return 'openai/gpt-4.1';
        }
    }

    /**
     * Create cache key for request
     */
    createCacheKey(logEntry) {
        return `${logEntry.ip}_${logEntry.method}_${logEntry.url}_${JSON.stringify(logEntry.payload)}`;
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
                requiresManualReview: true
            };
        }
    }

    /**
     * Analyze using OpenAI-compatible format (OpenAI, Groq)
     */
    async analyzeWithOpenAIFormat(prompt) {
        const completion = await this.client.chat.completions.create({
            model: this.getModelName(),
            messages: [
                {
                    role: 'system',
                    content: this.getSystemPrompt()
                },
                {
                    role: 'user',
                    content: prompt
                }
            ],
            temperature: 0.1,
            max_tokens: 400
        });

        return completion.choices[0].message.content;
    }

    /**
     * Analyze using Anthropic Claude
     */
    async analyzeWithAnthropic(prompt) {
        const message = await this.client.messages.create({
            model: this.getModelName(),
            max_tokens: 400,
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
    }

    /**
     * Enhanced system prompt for final authority mode
     */
    getSystemPrompt() {
        return `You are a cybersecurity expert with FINAL AUTHORITY over threat decisions. Your analysis will determine whether security actions are taken.

CRITICAL RESPONSIBILITIES:
- You have the final say on whether a request is malicious or benign
- Your decision overrides all automated detection systems
- Be thorough but decisive - systems depend on your judgment
- Consider false positives carefully as they can disrupt legitimate users
- Consider false negatives carefully as they can allow attacks through

DECISION CRITERIA:
- Analyze the actual intent and potential impact
- Consider if the request could cause real harm
- Distinguish between unusual but legitimate traffic vs actual attacks
- Factor in context, patterns, and sophistication level

Respond with structured analysis that security systems can act upon immediately.`;
    }

    /**
     * Build enhanced analysis prompt for LLM with final authority context
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
Timestamp: ${logEntry.timestamp}

AUTOMATED DETECTION RESULTS:
Threat Patterns Found: ${threatResult.threats.map(t => `${t.type} (confidence: ${t.confidence})`).join(', ')}
Initial Threat Score: ${threatResult.confidence}/10
Raw Detection Rules Triggered: ${threatResult.threats.length}

PAYLOAD ANALYSIS:
${JSON.stringify(logEntry.payload, null, 2)}

THREAT INTELLIGENCE:
${threatResult.intelData ? `IP Reputation: ${threatResult.intelData.maliciousCount > 0 ? 'BAD' : 'CLEAN'} (${threatResult.intelData.maliciousCount} reports)` : 'No intel data available'}

YOUR FINAL DECISION MUST ADDRESS:
1. Is this request actually malicious and dangerous? (YES/NO/UNCERTAIN)
2. What is your confidence in this decision? (1-10, where 10 = absolutely certain)
3. What would happen if this request succeeded? (Impact assessment)
4. Should this IP be blocked? (YES/NO)
5. Brief explanation of your reasoning

RESPONSE FORMAT (MANDATORY):
MALICIOUS: [YES/NO/UNCERTAIN]
CONFIDENCE: [1-10]
BLOCK_IP: [YES/NO]
IMPACT: [HIGH/MEDIUM/LOW/NONE]
EXPLANATION: [Your detailed reasoning in 2-3 sentences]
ATTACK_TYPE: [Type if malicious, or BENIGN if not malicious]

Remember: Your decision has immediate consequences. Be thorough but decisive.`;
    }

    /**
     * Parse LLM response into structured data with enhanced fields
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
                    result.confidence = parseInt(trimmedLine.split(':')[1].trim()) || 0;
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
                result.shouldBlock = true; // Override if high confidence malicious
            }

        } catch (error) {
            result.explanation = response.trim();
            result.requiresManualReview = true;
        }

        return result;
    }

    /**
     * Test connection to the LLM provider with enhanced testing
     */
    async testConnection() {
        try {
            const testPrompt = `Test connection: Analyze this benign request:
IP: 192.168.1.100
Method: GET
URL: /test
User-Agent: TestBot/1.0

Respond with: MALICIOUS: NO, CONFIDENCE: 10, EXPLANATION: Test successful`;

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

module.exports = LLMAnalyzer;