import OpenAI from 'openai';
import Groq from 'groq-sdk';
import Anthropic from '@anthropic-ai/sdk';
import Cerebras from '@cerebras/cerebras_cloud_sdk';
import TransformersLLM from './transformersLLM.js';
import { checkAbuseIPDB, checkVirusTotal } from "./llmtools.js";
import { storeMonitoringLog } from "./upstash.js";

/**
 * LLMAnalyzer - Advanced Two-Tier Threat Analysis System
 *
 * A sophisticated security analysis system that uses a two-tier approach:
 * 1. Primary Tier: Fast Transformers.js model (Llama-3.2-1B) for 80% of decisions
 * 2. Secondary Tier: Advanced cloud models with tool calling for complex cases
 *
 * Architecture Benefits:
 * - Fast response times for obvious cases
 * - Resource efficiency through intelligent routing
 * - Advanced analysis only when needed
 * - Comprehensive caching across both tiers
 * - Seamless fallback mechanisms
 *
 * Decision Flow:
 * Request → Primary Model → [BENIGN/MALICIOUS: Return] → [UNCERTAIN: Escalate] → Secondary Model → Final Decision
 *
 * @class LLMAnalyzer
 */
class LLMAnalyzer {
    /**
     * Initialize the two-tier LLM analyzer system
     *
     * @param {string} apiKey - API key for the secondary LLM provider
     * @param {string} provider - Secondary LLM provider ('cerebras', 'openai', 'groq', 'anthropic')
     * @param {Object} options - Additional configuration options
     * @param {boolean} options.enablePrimaryModel - Enable primary Transformers model (default: true)
     * @param {string} options.primaryModelId - Primary model identifier (default: meta-llama/Llama-3.2-1B)
     * @throws {Error} If API key is missing or initialization fails
     */
    constructor(apiKey, provider = 'cerebras', options = {}) {
        console.log('Initializing two-tier LLMAnalyzer system...');

        // Validate required API key for secondary model
        if (!apiKey) {
            throw new Error('API key is required for secondary LLM initialization');
        }

        // Store configuration
        this.apiKey = apiKey;
        this.provider = provider.toLowerCase();
        this.options = {
            enablePrimaryModel: true,
            primaryModelId: 'meta-llama/Llama-3.2-1B',
            primaryDevice: 'cpu',
            ...options
        };

        // Initialize secondary (advanced) LLM client
        try {
            this.secondaryClient = this.initializeSecondaryClient();
            console.log(`Secondary model initialized: ${this.provider} (${this.getSecondaryModelName()})`);
        } catch (error) {
            console.error('Failed to initialize secondary LLM client:', error.message);
            throw new Error(`Secondary LLM client initialization failed: ${error.message}`);
        }

        // Initialize primary (fast) model if enabled
        this.primaryModel = null;
        if (this.options.enablePrimaryModel) {
            try {
                this.primaryModel = new TransformersLLM({
                    modelId: this.options.primaryModelId,
                    device: this.options.primaryDevice
                });
                console.log(`Primary model configured: ${this.options.primaryModelId}`);
            } catch (error) {
                console.warn('Primary model initialization failed, continuing with secondary only:', error.message);
                this.options.enablePrimaryModel = false;
            }
        }

        // Set up caching systems
        this.initializeCaches();

        // Define system configuration constants
        this.config = {
            // Cache size limits
            maxIpCacheSize: 500,
            maxRequestCacheSize: 1000,

            // Threat detection thresholds
            maliciousConfidenceThreshold: 8,

            // Two-tier system settings
            primaryTimeoutMs: 15000,                 // Primary model timeout
            maxPrimaryRetries: 1,                   // Primary model retry attempts
            escalationThreshold: 5,                 // Confidence level that triggers escalation

            // Maintenance settings
            cacheCleanupInterval: 3600000,
        };

        // Performance tracking for two-tier system
        this.tierStats = {
            totalRequests: 0,
            primaryResolved: 0,
            secondaryEscalated: 0,
            primaryErrors: 0,
            averagePrimaryTime: 0,
            averageSecondaryTime: 0,
            escalationRate: 0
        };

        // Start automatic cache maintenance
        this.startCacheMaintenance();

        console.log('Two-tier LLMAnalyzer initialization complete');
        console.log(`Primary tier: ${this.options.enablePrimaryModel ? 'ENABLED' : 'DISABLED'}`);
        console.log(`Secondary tier: ${this.provider} (${this.getSecondaryModelName()})`);
    }

    /**
     * Initialize all cache data structures (same as before)
     */
    initializeCaches() {
        this.ipCache = new Map();
        this.ipRequestQueue = new Map();
        this.requestCache = new Map();

        this.cacheMetadata = {
            lastCleanup: Date.now(),
            totalAnalyzed: 0,
            cacheHits: 0,
            cacheMisses: 0
        };

        console.log('Cache systems initialized for two-tier analysis');
    }

    /**
     * Initialize the secondary (advanced) LLM client
     */
    initializeSecondaryClient() {
        const providerConfigs = {
            'openai': () => new OpenAI({
                apiKey: this.apiKey,
                baseURL: 'https://models.github.ai/inference'
            }),
            'groq': () => new Groq({
                apiKey: this.apiKey
            }),
            'cerebras': () => new Cerebras({
                apiKey: this.apiKey
            }),
            'anthropic': () => new Anthropic({
                apiKey: this.apiKey
            })
        };

        const clientFactory = providerConfigs[this.provider];
        if (!clientFactory) {
            const supportedProviders = Object.keys(providerConfigs).join(', ');
            throw new Error(`Unsupported secondary provider: ${this.provider}. Supported: ${supportedProviders}`);
        }

        return clientFactory();
    }

    /**
     * Get the secondary model name for the current provider
     */
    getSecondaryModelName() {
        const modelMap = {
            'openai': 'gpt-4o',
            'groq': 'llama3-70b-8192',
            'anthropic': 'claude-3-sonnet-20240229',
            'cerebras': 'llama-3.3-70b'
        };

        return modelMap[this.provider] || 'llama-3.3-70b';
    }

    /**
     * Create request key for caching (same as before)
     */
    createRequestKey(logEntry) {
        if (!logEntry || !logEntry.ip) {
            throw new Error('Invalid log entry: IP address is required for cache key generation');
        }

        const keyComponents = [
            logEntry.ip,
            logEntry.method || 'UNKNOWN',
            logEntry.url || '',
            JSON.stringify(logEntry.payload || {})
        ];

        return keyComponents.join('_');
    }

    /**
     * Add request to IP processing queue (same as before)
     */
    addToQueue(ip, requestKey) {
        if (!this.ipRequestQueue.has(ip)) {
            this.ipRequestQueue.set(ip, new Set());
        }
        this.ipRequestQueue.get(ip).add(requestKey);
    }

    /**
     * Clean up cached data for malicious IP (same as before)
     */
    cleanupMaliciousIP(ip) {
        const requests = this.ipRequestQueue.get(ip);
        if (!requests) return;

        let cleanedCount = 0;
        requests.forEach(requestKey => {
            if (this.requestCache.delete(requestKey)) {
                cleanedCount++;
            }
        });

        this.ipRequestQueue.delete(ip);
        console.log(`[CLEANUP] Removed ${cleanedCount} cached requests from malicious IP: ${ip}`);
    }

    /**
     * Main two-tier analysis method with intelligent routing
     *
     * Two-Tier Analysis Flow:
     * 1. Check caches for existing results
     * 2. Try primary model first (fast decision)
     * 3. If primary returns UNCERTAIN, escalate to secondary model
     * 4. Cache and return final result
     *
     * @param {Object} logEntry - Request log entry to analyze
     * @param {Object} threatResult - Initial automated threat detection results
     * @returns {Promise<Object>} Comprehensive analysis result
     */
    async analyze(logEntry, threatResult) {
        if (!logEntry || !logEntry.ip) {
            throw new Error('Invalid log entry: IP address is required for analysis');
        }

        const ip = logEntry.ip;
        const analysisId = `${ip}-${Date.now()}`;
        let requestKey;

        console.log(`[${analysisId}] Starting two-tier analysis for IP: ${ip}`);

        try {
            requestKey = this.createRequestKey(logEntry);
        } catch (error) {
            console.error(`[${analysisId}] Error creating request key:`, error.message);
            return this.createErrorResult('Invalid request format', error.message);
        }

        try {
            // Update total request counter
            this.tierStats.totalRequests++;
            this.cacheMetadata.totalAnalyzed++;

            // STEP 1: Check IP-level cache for known malicious IPs
            if (this.ipCache.has(ip)) {
                const cachedResult = this.ipCache.get(ip);
                if (cachedResult.confidence >= this.config.maliciousConfidenceThreshold) {
                    console.log(`[${analysisId}] IP already marked as malicious (confidence: ${cachedResult.confidence}) - blocking immediately`);
                    this.cacheMetadata.cacheHits++;
                    return {
                        ...cachedResult,
                        explanation: `IP previously identified as malicious with confidence ${cachedResult.confidence} - auto-blocked`,
                        fromCache: true,
                        tier: 'cache'
                    };
                }
            }

            // STEP 2: Check request-level cache
            if (this.requestCache.has(requestKey)) {
                console.log(`[${analysisId}] Using cached analysis for identical request`);
                this.cacheMetadata.cacheHits++;
                const cachedResult = this.requestCache.get(requestKey);
                return { ...cachedResult, fromCache: true };
            }

            // STEP 3: Cache miss - perform two-tier analysis
            this.cacheMetadata.cacheMisses++;
            console.log(`[${analysisId}] Cache miss - starting two-tier analysis`);

            this.addToQueue(ip, requestKey);

            // Try primary model first (if enabled)
            let finalResult;
            if (this.options.enablePrimaryModel && this.primaryModel) {
                finalResult = await this.performTwoTierAnalysis(logEntry, threatResult, analysisId);
            } else {
                // Fallback to secondary model only
                console.log(`[${analysisId}] Primary model disabled - using secondary model directly`);
                finalResult = await this.performSecondaryAnalysis(logEntry, threatResult, analysisId);
                finalResult.tier = 'secondary-direct';
            }

            // Preserve system URL attribute
            if (!finalResult.is_system_url && threatResult?.is_system_url) {
                finalResult.is_system_url = true;
            }

            // Cache successful results
            if (finalResult.confidence > 0 && !finalResult.error) {
                this.requestCache.set(requestKey, finalResult);
                console.log(`[${analysisId}] Cached analysis result (confidence: ${finalResult.confidence})`);
            }

            // Handle malicious IP detection
            if (finalResult.confidence >= this.config.maliciousConfidenceThreshold) {
                this.ipCache.set(ip, finalResult);
                this.cleanupMaliciousIP(ip);
                console.log(`[${analysisId}] IP marked as malicious with confidence ${finalResult.confidence}`);
            }

            // Update tier statistics
            this.updateTierStats();

            // Perform cache maintenance
            this.maintainCacheSize();

            return finalResult;

        } catch (error) {
            console.error(`[${analysisId}] Analysis error:`, error.message);
            return this.createErrorResult('Two-tier analysis failed', error.message);
        }
    }

    /**
     * Perform complete two-tier analysis with primary → secondary escalation
     *
     * @private
     * @param {Object} logEntry - Request log entry
     * @param {Object} threatResult - Initial threat detection results
     * @param {string} analysisId - Unique analysis identifier for logging
     * @returns {Promise<Object>} Final analysis result
     */
    async performTwoTierAnalysis(logEntry, threatResult, analysisId) {
        console.log(`[${analysisId}] Starting primary tier analysis...`);

        try {
            // Initialize primary model if not already done
            if (!this.primaryModel.isInitialized) {
                console.log(`[${analysisId}] Initializing primary model...`);
                await this.primaryModel.initialize();
            }

            // TIER 1: Primary model analysis
            const primaryStartTime = Date.now();
            const primaryResult = await Promise.race([
                this.primaryModel.analyze(logEntry),
                new Promise((_, reject) =>
                    setTimeout(() => reject(new Error('Primary model timeout')), this.config.primaryTimeoutMs)
                )
            ]);
            const primaryTime = Date.now() - primaryStartTime;

            console.log(`[${analysisId}] Primary tier decision: ${primaryResult.decision} (${primaryTime}ms)`);

            // Update primary timing stats
            this.updatePrimaryStats(primaryTime);

            // Check if primary model resolved the request
            if (primaryResult.decision !== 'UNCERTAIN' && !primaryResult.error) {
                this.tierStats.primaryResolved++;

                // Convert primary result to final format
                const finalResult = this.convertPrimaryResult(primaryResult, analysisId);
                finalResult.analysisTime = primaryTime;

                console.log(`[${analysisId}] Request resolved by primary tier (confidence: ${finalResult.confidence})`);
                return finalResult;
            }

            // TIER 2: Escalate to secondary model
            console.log(`[${analysisId}] Escalating to secondary tier - reason: ${primaryResult.explanation}`);
            this.tierStats.secondaryEscalated++;

            const secondaryResult = await this.performSecondaryAnalysis(
                logEntry,
                threatResult,
                analysisId,
                primaryResult  // Pass primary result as context
            );

            // Combine timing information
            secondaryResult.analysisTime = primaryTime + (secondaryResult.analysisTime || 0);
            secondaryResult.primaryTime = primaryTime;
            secondaryResult.escalationReason = primaryResult.explanation;

            return secondaryResult;

        } catch (error) {
            console.error(`[${analysisId}] Primary tier analysis failed:`, error.message);
            this.tierStats.primaryErrors++;

            // Fallback to secondary model
            console.log(`[${analysisId}] Falling back to secondary tier due to primary error`);
            const fallbackResult = await this.performSecondaryAnalysis(logEntry, threatResult, analysisId);
            fallbackResult.primaryError = error.message;
            fallbackResult.tier = 'secondary-fallback';

            return fallbackResult;
        }
    }

    /**
     * Convert primary model result to final analysis format
     *
     * @private
     * @param {Object} primaryResult - Primary model result
     * @param {string} analysisId - Analysis identifier
     * @returns {Object} Converted final result
     */
    convertPrimaryResult(primaryResult, analysisId) {
        let isMalicious, shouldBlock, impact;

        // Map primary decision to final format
        switch (primaryResult.decision) {
            case 'MALICIOUS':
                isMalicious = true;
                shouldBlock = true;
                impact = 'HIGH';
                break;
            case 'BENIGN':
                isMalicious = false;
                shouldBlock = false;
                impact = 'NONE';
                break;
            default:
                // This shouldn't happen if primary model works correctly
                isMalicious = null;
                shouldBlock = false;
                impact = 'UNKNOWN';
                break;
        }

        return {
            isMalicious,
            confidence: primaryResult.confidence,
            explanation: `[PRIMARY] ${primaryResult.explanation}`,
            attackType: isMalicious ? 'DETECTED_BY_PRIMARY' : null,
            shouldBlock,
            impact,
            requiresManualReview: false,
            is_system_url: false,
            toolsUsed: [],  // Primary model doesn't use tools
            intelligenceBoost: 'N/A - primary model decision',
            patternDetected: 'Fast pattern recognition',
            tier: 'primary',
            model: primaryResult.model,
            fromCache: false,
            responseTime: primaryResult.responseTime || 0
        };
    }

    /**
     * Perform secondary (advanced) analysis with full tool calling support
     *
     * @private
     * @param {Object} logEntry - Request log entry
     * @param {Object} threatResult - Initial threat detection
     * @param {string} analysisId - Analysis identifier
     * @param {Object} primaryResult - Optional primary model result for context
     * @returns {Promise<Object>} Secondary analysis result
     */
    async performSecondaryAnalysis(logEntry, threatResult, analysisId, primaryResult = null) {
        console.log(`[${analysisId}] Starting secondary tier analysis...`);

        const secondaryStartTime = Date.now();

        try {
            // Build enhanced prompt with primary context if available
            const prompt = this.buildSecondaryPrompt(logEntry, threatResult, primaryResult);

            let response;
            switch (this.provider) {
                case 'openai':
                case 'groq':
                case 'cerebras':
                    response = await this.analyzeWithOpenAIFormat(prompt, analysisId);
                    break;
                case 'anthropic':
                    response = await this.analyzeWithAnthropic(prompt, analysisId);
                    break;
                default:
                    throw new Error(`Unsupported secondary provider: ${this.provider}`);
            }

            const secondaryTime = Date.now() - secondaryStartTime;
            this.updateSecondaryStats(secondaryTime);

            // Parse response into final format
            const result = this.parseResponse(response);

            if (this.validateAnalysisResult(result)) {
                result.tier = 'secondary';
                result.analysisTime = secondaryTime;
                result.model = this.getSecondaryModelName();
                result.fromCache = false;

                console.log(`[${analysisId}] Secondary analysis completed (confidence: ${result.confidence}, time: ${secondaryTime}ms)`);
                return result;
            } else {
                throw new Error('Invalid analysis result format from secondary model');
            }

        } catch (error) {
            console.error(`[${analysisId}] Secondary analysis failed:`, error.message);
            return this.createErrorResult('Secondary model analysis failed', error.message);
        }
    }

    /**
     * Build enhanced prompt for secondary model with primary context
     *
     * @private
     * @param {Object} logEntry - Request log entry
     * @param {Object} threatResult - Initial threat detection
     * @param {Object} primaryResult - Primary model result (if available)
     * @returns {string} Enhanced analysis prompt
     */
    buildSecondaryPrompt(logEntry, threatResult, primaryResult = null) {
        let prompt = `ADVANCED THREAT ASSESSMENT REQUEST

REQUEST DETAILS:
IP: ${logEntry.ip}
Method: ${logEntry.method || 'UNKNOWN'}
URL: ${logEntry.url || 'Not specified'}
Query: ${logEntry.queryString || 'None'}
User-Agent: ${logEntry.userAgent || 'None'}
Status: ${logEntry.status || 'Unknown'}
System URL: ${threatResult?.is_system_url ? 'YES' : 'NO'}

AUTOMATED DETECTION:
Threats Found: ${threatResult?.threats ? threatResult.threats.map(t => `${t.type} (${t.confidence})`).join(', ') : 'None'}
Initial Score: ${threatResult?.confidence || 0}/10`;

        // Add primary model context if available
        if (primaryResult) {
            prompt += `

PRIMARY MODEL ASSESSMENT:
Decision: ${primaryResult.decision}
Confidence: ${primaryResult.confidence}
Reasoning: ${primaryResult.explanation}
Model: ${primaryResult.model}
Response Time: ${primaryResult.responseTime}ms

NOTE: Primary model was uncertain about this request. As the advanced secondary model with tool access, 
provide a definitive assessment using available intelligence tools when helpful.`;
        }

        prompt += `

PAYLOAD:
${logEntry.payload ? JSON.stringify(logEntry.payload, null, 2) : 'No payload'}

ADVANCED ANALYSIS INSTRUCTIONS:
As the secondary (advanced) model, you have access to external intelligence tools and should provide 
a definitive assessment. Use tools strategically when they add value to your decision.

Your confidence score determines blocking (8+ = blocked). Analyze comprehensively and respond.`;

        return prompt;
    }

    /**
     * Update primary tier performance statistics
     */
    updatePrimaryStats(responseTime) {
        const totalPrimary = this.tierStats.primaryResolved + this.tierStats.primaryErrors;
        this.tierStats.averagePrimaryTime = totalPrimary > 0
            ? (this.tierStats.averagePrimaryTime * (totalPrimary - 1) + responseTime) / totalPrimary
            : responseTime;
    }

    /**
     * Update secondary tier performance statistics
     */
    updateSecondaryStats(responseTime) {
        const totalSecondary = this.tierStats.secondaryEscalated;
        this.tierStats.averageSecondaryTime = totalSecondary > 0
            ? (this.tierStats.averageSecondaryTime * (totalSecondary - 1) + responseTime) / totalSecondary
            : responseTime;
    }

    /**
     * Update overall tier statistics
     */
    updateTierStats() {
        if (this.tierStats.totalRequests > 0) {
            this.tierStats.escalationRate =
                (this.tierStats.secondaryEscalated / this.tierStats.totalRequests * 100).toFixed(1);
        }
    }

    /**
     * Create standardized error result (same as before but with tier info)
     */
    createErrorResult(message, details = '') {
        return {
            isMalicious: null,
            confidence: 0,
            explanation: `${message}${details ? ` - ${details}` : ''} - manual review recommended`,
            error: details,
            requiresManualReview: true,
            shouldBlock: false,
            impact: 'UNKNOWN',
            attackType: null,
            fromCache: false,
            tier: 'error'
        };
    }



    validateAnalysisResult(result) {
        if (!result || typeof result !== 'object') {
            console.error('Analysis result is not a valid object');
            return false;
        }

        const requiredFields = ['confidence', 'explanation'];
        for (const field of requiredFields) {
            if (!(field in result)) {
                console.error(`Missing required field in analysis result: ${field}`);
                return false;
            }
        }

        if (typeof result.confidence !== 'number' || result.confidence < 0 || result.confidence > 10) {
            console.error(`Invalid confidence score: ${result.confidence} (must be number between 0-10)`);
            return false;
        }

        return true;
    }

    maintainCacheSize() {
        if (this.ipCache.size > this.config.maxIpCacheSize) {
            const excessCount = this.ipCache.size - this.config.maxIpCacheSize;
            const keysToRemove = Array.from(this.ipCache.keys()).slice(0, excessCount);
            keysToRemove.forEach(key => this.ipCache.delete(key));
            console.log(`Cache maintenance: Cleaned up ${excessCount} entries from IP cache`);
        }

        if (this.requestCache.size > this.config.maxRequestCacheSize) {
            const excessCount = this.requestCache.size - this.config.maxRequestCacheSize;
            const keysToRemove = Array.from(this.requestCache.keys()).slice(0, excessCount);
            keysToRemove.forEach(key => this.requestCache.delete(key));
            console.log(`Cache maintenance: Cleaned up ${excessCount} entries from request cache`);
        }
    }

    startCacheMaintenance() {
        setInterval(() => {
            console.log('Starting periodic cache maintenance...');
            this.maintainCacheSize();
            this.cacheMetadata.lastCleanup = Date.now();

            const stats = this.getCacheStats();
            console.log(`Cache maintenance completed - IP Cache: ${stats.ipCache}, Request Cache: ${stats.requestCache}, Hit Rate: ${stats.hitRate}`);
        }, this.config.cacheCleanupInterval);

        console.log(`Periodic cache maintenance scheduled every ${this.config.cacheCleanupInterval / 1000 / 60} minutes`);
    }

    // [Continue with tool-related methods - same as original]
    getFunctionTools() {
        return [
            {
                type: "function",
                function: {
                    name: "checkVirusTotal",
                    description: "Check IP against VirusTotal database for malicious activity reports and reputation data",
                    parameters: {
                        type: "object",
                        properties: {
                            ip: {
                                type: "string",
                                description: "IPv4 or IPv6 address to check against VirusTotal threat databases"
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
                    description: "Check IP against AbuseIPDB for historical abuse reports, confidence scores, and reputation data",
                    parameters: {
                        type: "object",
                        properties: {
                            ip: {
                                type: "string",
                                description: "IPv4 or IPv6 address to check for historical abuse patterns"
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
                    description: "Store suspicious request for pattern analysis, monitoring, and automatic recurrence detection",
                    parameters: {
                        type: "object",
                        properties: {
                            logEntry: {
                                type: "object",
                                description: "Complete request log entry with all traffic details",
                                properties: {
                                    ip: { type: "string", description: "Source IP address" },
                                    method: { type: "string", description: "HTTP method (GET, POST, etc.)" },
                                    queryString: { type: "string", description: "URL query parameters" },
                                    userAgent: { type: "string", description: "Client user agent string" },
                                    url: { type: "string", description: "Requested URL path" },
                                    status: { type: "number", description: "HTTP response status code" }
                                },
                                required: ["ip", "method", "queryString", "userAgent", "url", "status"]
                            },
                            confidenceScore: {
                                type: "number",
                                description: "Threat confidence score from 0-10"
                            },
                            explanation: {
                                type: "string",
                                description: "Detailed explanation of the threat assessment reasoning"
                            }
                        },
                        required: ["logEntry", "confidenceScore", "explanation"]
                    }
                }
            }
        ];
    }

    getAvailableFunctions() {
        return {
            "checkVirusTotal": checkVirusTotal,
            "checkAbuseIPDB": checkAbuseIPDB,
            "storeMonitoringLog": storeMonitoringLog
        };
    }

    async executeFunctionCall(functionName, functionArgs) {
        const availableFunctions = this.getAvailableFunctions();
        const functionToCall = availableFunctions[functionName];

        if (!functionToCall) {
            throw new Error(`Function ${functionName} not found in available functions`);
        }

        console.log(`Executing tool function: ${functionName} with arguments:`, functionArgs);

        try {
            let result;

            switch (functionName) {
                case 'checkVirusTotal':
                case 'checkAbuseIPDB':
                    if (!functionArgs.ip) {
                        throw new Error(`IP address is required for ${functionName}`);
                    }
                    result = await functionToCall(functionArgs.ip);
                    break;

                case 'storeMonitoringLog':
                    const { logEntry, confidenceScore, explanation } = functionArgs;
                    if (!logEntry || confidenceScore === undefined || !explanation) {
                        throw new Error('Missing required arguments for storeMonitoringLog (logEntry, confidenceScore, explanation)');
                    }
                    result = await functionToCall(logEntry, confidenceScore, explanation);
                    break;

                default:
                    throw new Error(`Unknown function execution pattern: ${functionName}`);
            }

            console.log(`Function ${functionName} executed successfully`);
            return result;

        } catch (error) {
            console.error(`Error executing function ${functionName}:`, error.message);
            throw new Error(`Function execution failed: ${error.message}`);
        }
    }

    async analyzeWithOpenAIFormat(prompt, analysisId = 'unknown') {
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

        const maxToolRounds = 3;
        let currentRound = 0;
        const executedTools = new Set();

        try {
            console.log(`[${analysisId}] Making ${this.provider} API call with advanced tool support enabled`);

            let completion = await this.secondaryClient.chat.completions.create({
                model: this.getSecondaryModelName(),
                messages: messages,
                temperature: 0.1,
                max_tokens: 800,
                stream: false,
                tools: tools,
                tool_choice: "auto",
            });

            if (!completion.choices || completion.choices.length === 0) {
                console.error(`[${analysisId}] API Response:`, JSON.stringify(completion, null, 2));
                throw new Error('No response choices returned from LLM API');
            }

            let responseMessage = completion.choices[0].message;
            if (!responseMessage) {
                throw new Error('Empty response message from LLM API');
            }

            // Tool calling loop with intelligent termination
            while (responseMessage.tool_calls && responseMessage.tool_calls.length > 0 && currentRound < maxToolRounds) {
                currentRound++;
                console.log(`[${analysisId}] === Tool Calling Round ${currentRound}/${maxToolRounds} ===`);

                const toolCalls = responseMessage.tool_calls;
                console.log(`[${analysisId}] Processing ${toolCalls.length} tool call(s) in round ${currentRound}`);

                messages.push(responseMessage);

                const executionStrategy = this.determineExecutionStrategy(toolCalls, this.provider);
                console.log(`[${analysisId}] Using execution strategy: ${executionStrategy}`);

                if (executionStrategy === 'parallel') {
                    await this.executeToolCallsParallel(toolCalls, messages, executedTools, analysisId);
                } else {
                    await this.executeToolCallsSequential(toolCalls, messages, executedTools, analysisId);
                }

                console.log(`[${analysisId}] Requesting completion after tool round ${currentRound}`);

                const nextCompletionConfig = {
                    model: this.getSecondaryModelName(),
                    messages: messages,
                    temperature: 0.1,
                    max_tokens: 600,
                    tools: tools,
                    tool_choice: "auto",
                };

                if (this.provider === 'cerebras') {
                    messages.push({
                        role: "user",
                        content: `Round ${currentRound} complete. If you have all needed information, provide your final assessment in the required format. If you need more tools, call them now.`
                    });
                    nextCompletionConfig.max_tokens = 500;
                }

                completion = await this.secondaryClient.chat.completions.create(nextCompletionConfig);

                if (!completion.choices || completion.choices.length === 0) {
                    throw new Error(`No response choices returned in tool round ${currentRound}`);
                }

                responseMessage = completion.choices[0].message;
                if (!responseMessage) {
                    throw new Error(`Empty response message in tool round ${currentRound}`);
                }

                if (this.hasAnalysisContent(responseMessage)) {
                    console.log(`[${analysisId}] Analysis content detected in round ${currentRound} - completing`);
                    break;
                }

                if (this.detectToolLoop(responseMessage.tool_calls, executedTools)) {
                    console.warn(`[${analysisId}] Tool loop detected in round ${currentRound} - forcing completion`);
                    return this.forceCompletionWithContext(messages, executedTools, analysisId);
                }
            }

            if (responseMessage.tool_calls && responseMessage.tool_calls.length > 0) {
                console.warn(`[${analysisId}] Maximum tool rounds (${maxToolRounds}) reached with pending tool calls`);
                return this.forceCompletionWithContext(messages, executedTools, analysisId);
            }

            if (!responseMessage.content || responseMessage.content.trim() === '') {
                console.warn(`[${analysisId}] Empty content in final response after tool execution`);
                return this.forceCompletionWithContext(messages, executedTools, analysisId);
            }

            console.log(`[${analysisId}] Analysis completed successfully after ${currentRound} tool rounds`);
            return responseMessage.content;

        } catch (error) {
            console.error(`[${analysisId}] Error in ${this.provider} API call:`, error.message);
            throw new Error(`${this.provider} API error: ${error.message}`);
        }
    }

    determineExecutionStrategy(toolCalls, provider) {
        if (toolCalls.length === 1) {
            return 'sequential';
        }

        const toolTypes = toolCalls.map(call => call.function.name);
        const hasStorageTools = toolTypes.includes('storeMonitoringLog');
        const hasIPChecks = toolTypes.includes('checkAbuseIPDB') || toolTypes.includes('checkVirusTotal');

        if (hasStorageTools && hasIPChecks) {
            console.log('Mixed tool types detected - using sequential execution for data consistency');
            return 'sequential';
        }

        if (toolTypes.every(tool => ['checkAbuseIPDB', 'checkVirusTotal'].includes(tool))) {
            console.log('Multiple IP reputation checks - using parallel execution');
            return 'parallel';
        }

        if (provider === 'cerebras') {
            return 'sequential';
        }

        return 'parallel';
    }

    async executeToolCallsParallel(toolCalls, messages, executedTools, analysisId) {
        console.log(`[${analysisId}] Executing ${toolCalls.length} tools in parallel`);

        const toolPromises = toolCalls.map(async (toolCall) => {
            const functionName = this.normalizeToolName(toolCall.function.name);
            const toolSignature = `${functionName}:${toolCall.function.arguments}`;

            try {
                console.log(`[${analysisId}][Parallel] Executing: ${functionName}`);

                if (executedTools.has(toolSignature)) {
                    console.log(`[${analysisId}][Parallel] Skipping duplicate tool: ${functionName}`);
                    return {
                        toolCall,
                        result: 'Tool already executed in previous round',
                        skipped: true
                    };
                }

                executedTools.add(toolSignature);
                const functionArgs = JSON.parse(toolCall.function.arguments);
                const functionResponse = await this.executeFunctionCall(functionName, functionArgs);

                return {
                    toolCall,
                    result: functionResponse,
                    skipped: false
                };

            } catch (error) {
                console.error(`[${analysisId}][Parallel] Error executing ${functionName}:`, error.message);
                return {
                    toolCall,
                    error: error.message,
                    skipped: false
                };
            }
        });

        const results = await Promise.all(toolPromises);

        results.forEach(({ toolCall, result, error, skipped }) => {
            const toolResponse = {
                tool_call_id: toolCall.id,
                role: "tool",
                name: this.normalizeToolName(toolCall.function.name),
                content: error
                    ? `Error: ${error}`
                    : (skipped
                        ? result
                        : (typeof result === 'string' ? result : JSON.stringify(result, null, 2)))
            };

            messages.push(toolResponse);
        });

        console.log(`[${analysisId}] Parallel execution completed - ${results.length} tools processed`);
    }

    async executeToolCallsSequential(toolCalls, messages, executedTools, analysisId) {
        console.log(`[${analysisId}] Executing ${toolCalls.length} tools sequentially`);

        for (const toolCall of toolCalls) {
            const functionName = this.normalizeToolName(toolCall.function.name);
            const toolSignature = `${functionName}:${toolCall.function.arguments}`;

            try {
                console.log(`[${analysisId}][Sequential] Executing: ${functionName}`);

                if (executedTools.has(toolSignature)) {
                    console.log(`[${analysisId}][Sequential] Skipping duplicate tool: ${functionName}`);

                    const skipResponse = {
                        tool_call_id: toolCall.id,
                        role: "tool",
                        name: functionName,
                        content: 'Tool already executed in previous round'
                    };
                    messages.push(skipResponse);
                    continue;
                }

                executedTools.add(toolSignature);
                const functionArgs = JSON.parse(toolCall.function.arguments);
                const functionResponse = await this.executeFunctionCall(functionName, functionArgs);

                const toolResponse = {
                    tool_call_id: toolCall.id,
                    role: "tool",
                    name: functionName,
                    content: typeof functionResponse === 'string'
                        ? functionResponse
                        : JSON.stringify(functionResponse, null, 2)
                };

                messages.push(toolResponse);

            } catch (error) {
                console.error(`[${analysisId}][Sequential] Error executing ${functionName}:`, error.message);

                const errorResponse = {
                    tool_call_id: toolCall.id,
                    role: "tool",
                    name: functionName,
                    content: `Error executing ${functionName}: ${error.message}`
                };

                messages.push(errorResponse);
            }
        }

        console.log(`[${analysisId}] Sequential execution completed`);
    }

    normalizeToolName(toolName) {
        if (toolName.startsWith('functions.')) {
            return toolName.replace('functions.', '');
        }

        if (toolName.includes('.')) {
            const parts = toolName.split('.');
            return parts[parts.length - 1];
        }

        return toolName;
    }

    hasAnalysisContent(message) {
        if (!message.content) return false;

        const content = message.content.toUpperCase();
        const indicators = [
            'MALICIOUS:',
            'CONFIDENCE:',
            'EXPLANATION:',
            'ATTACK_TYPE:'
        ];

        const foundIndicators = indicators.filter(indicator => content.includes(indicator));
        return foundIndicators.length >= 2;
    }

    detectToolLoop(newToolCalls, executedTools) {
        if (!newToolCalls || newToolCalls.length === 0) return false;

        const allAlreadyExecuted = newToolCalls.every(toolCall => {
            const functionName = this.normalizeToolName(toolCall.function.name);
            const toolSignature = `${functionName}:${toolCall.function.arguments}`;
            return executedTools.has(toolSignature);
        });

        if (allAlreadyExecuted) {
            console.warn('Tool loop detected: All requested tools already executed');
            return true;
        }

        const currentTools = newToolCalls.map(call => ({
            name: this.normalizeToolName(call.function.name),
            args: call.function.arguments
        }));

        const duplicates = currentTools.filter((tool, index) =>
            currentTools.findIndex(t => t.name === tool.name && t.args === tool.args) !== index
        );

        if (duplicates.length > 0) {
            console.warn('Tool loop detected: Duplicate tools in same request');
            return true;
        }

        return false;
    }

    async forceCompletionWithContext(messages, executedTools, analysisId) {
        console.log(`[${analysisId}] Forcing completion with available context`);

        const forceMessages = [...messages, {
            role: "user",
            content: `Please provide your final security assessment now based on all the tool results above. Use the required format:

MALICIOUS: [YES/NO/UNCERTAIN]
CONFIDENCE: [1-10]
EXPLANATION: [Your reasoning]
ATTACK_TYPE: [Type or BENIGN]
TOOLS_USED: [Tools that were called]
INTELLIGENCE_BOOST: [How tools influenced your decision]
PATTERN_DETECTED: [Any patterns found]

Do not call any more tools - just analyze and respond.`
        }];

        try {
            const forcedCompletion = await this.secondaryClient.chat.completions.create({
                model: this.getSecondaryModelName(),
                messages: forceMessages,
                temperature: 0.1,
                max_tokens: 500,
                tool_choice: "none"
            });

            if (!forcedCompletion.choices?.[0]?.message?.content) {
                console.warn(`[${analysisId}] Forced completion also failed - creating manual fallback`);
                return this.createManualFallback(messages, executedTools);
            }

            console.log(`[${analysisId}] Forced completion successful`);
            return forcedCompletion.choices[0].message.content;

        } catch (error) {
            console.error(`[${analysisId}] Forced completion failed:`, error.message);
            return this.createManualFallback(messages, executedTools);
        }
    }

    createManualFallback(messages, executedTools) {
        const toolsUsedList = Array.from(executedTools).map(sig => sig.split(':')[0]).join(', ');

        return `MALICIOUS: UNCERTAIN
CONFIDENCE: 5
EXPLANATION: Secondary model tool execution incomplete - manual review recommended due to system limitations
ATTACK_TYPE: UNKNOWN
TOOLS_USED: ${toolsUsedList || 'NONE'}
INTELLIGENCE_BOOST: Partial tool data available but incomplete analysis
PATTERN_DETECTED: System limitation - incomplete tool chain execution`;
    }

    /**
     * Perform the actual LLM analysis without retry logic (from original)
     *
     * @private
     * @param {Object} logEntry - Request log entry
     * @param {Object} threatResult - Initial automated threat detection results
     * @returns {Promise<Object>} Analysis result
     */
    async performAnalysis(logEntry, threatResult) {
        const prompt = this.buildAnalysisPrompt(logEntry, threatResult);

        try {
            console.log(`Starting LLM analysis for IP ${logEntry.ip}`);

            let response;

            // Route to appropriate provider method
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

            // Parse the LLM response into structured format
            const result = this.parseResponse(response);

            // Validate the parsed result structure
            if (this.validateAnalysisResult(result)) {
                console.log(`Analysis completed successfully for IP ${logEntry.ip} (confidence: ${result.confidence})`);
                return result;
            } else {
                throw new Error('Invalid analysis result format returned by LLM');
            }

        } catch (error) {
            console.error(`Analysis failed for IP ${logEntry.ip}:`, error.message);

            // Return structured error result instead of throwing
            return this.createErrorResult('LLM analysis failed', error?.message || 'Unknown error');
        }
    }

    /**
     * Build comprehensive analysis prompt with request details and context (from original)
     *
     * @private
     * @param {Object} logEntry - Request log entry with all details
     * @param {Object} threatResult - Initial automated threat detection results
     * @returns {string} Formatted analysis prompt for LLM
     */
    buildAnalysisPrompt(logEntry, threatResult) {
        return `THREAT ASSESSMENT REQUEST

REQUEST DETAILS:
IP: ${logEntry.ip}
Method: ${logEntry.method || 'UNKNOWN'}
URL: ${logEntry.url || 'Not specified'}
Query: ${logEntry.queryString || 'None'}
User-Agent: ${logEntry.userAgent || 'None'}
Status: ${logEntry.status || 'Unknown'}
System URL: ${threatResult?.is_system_url ? 'YES' : 'NO'}

AUTOMATED DETECTION:
Threats Found: ${threatResult?.threats ? threatResult.threats.map(t => `${t.type} (${t.confidence})`).join(', ') : 'None'}
Initial Score: ${threatResult?.confidence || 0}/10

PAYLOAD:
${logEntry.payload ? JSON.stringify(logEntry.payload, null, 2) : 'No payload'}

ANALYSIS STEPS:
1. Check for obvious attack patterns (assign 8-10 if found)
2. If suspicious but unclear, use appropriate tools
3. Assign final confidence score
4. Provide assessment in required format

Your confidence score determines blocking (8+ = blocked). Analyze and respond.`;
    }

    async analyzeWithAnthropic(prompt, analysisId = 'unknown') {
        try {
            console.log(`[${analysisId}] Making Anthropic Claude API call`);

            const message = await this.secondaryClient.messages.create({
                model: this.getSecondaryModelName(),
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

            if (!message.content || message.content.length === 0) {
                throw new Error('Empty response from Anthropic API');
            }

            const responseText = message.content[0]?.text;

            if (!responseText) {
                throw new Error('No text content in Anthropic response');
            }

            console.log(`[${analysisId}] Anthropic analysis completed successfully`);
            return responseText;

        } catch (error) {
            console.error(`[${analysisId}] Error in Anthropic API call:`, error.message);
            throw new Error(`Anthropic API error: ${error.message}`);
        }
    }

    getSystemPrompt() {
        return `
## Role Definition
You are a cybersecurity expert with final authority over threat decisions. You analyze requests using a systematic approach and assign confidence scores that determine security actions.

## Core Decision Framework
Your **confidence score (1-10) is the primary decision mechanism**:
- **Confidence 8+ = Automatic block**
- **Confidence 1-7 = Allowed with monitoring**

## CRITICAL: Chain of Thought Tool Usage Strategy

### Step 1: Content Analysis (Always First)
Before using ANY tools, systematically evaluate:

1. **Request Content Assessment**:
   - Analyze URL, payload, headers, and parameters
   - Look for obvious attack patterns or legitimate use cases
   - Determine if content alone provides sufficient verdict

2. **IP Context Evaluation**:
   - Check if IP is internal (127.x.x.x, 10.x.x.x, 192.168.x.x, 172.16-31.x.x)
   - Consider if external reputation would change assessment

3. **Uncertainty Calibration**:
   - Ask: "Will external intelligence actually change my confidence score?"
   - Ask: "Is this genuinely uncertain or am I overcomplicating?"

### Step 2: Tool Usage Decision Tree

**NO TOOLS REQUIRED - Confidence 1-3 (Obviously Benign):**
Examples:
- Standard requests: \`/favicon.ico\`, \`/robots.txt\`, \`/sitemap.xml\`
- CDN resources: \`cdn.example.com/script.js\`
- Normal API calls with valid authentication
- Well-formed requests to expected endpoints
- Internal IP traffic

**NO TOOLS REQUIRED - Confidence 8-10 (Obviously Malicious):**
Examples:
- SQL injection: \`' OR 1=1--\`, \`UNION SELECT\`
- XSS: \`javascript:void(0)\`
- Command injection: \`; rm -rf /\`, \`| whoami\`, \`&& curl malicious.com\`
- Directory traversal: \`../../../etc/passwd\`
- Buffer overflow attempts, null bytes, format strings

**SELECTIVE TOOL USAGE - Confidence 4-7 (Uncertain Cases):**

#### MANDATORY: Monitoring (Always for uncertain cases)
\`\`\`
storeMonitoringLog(entry, confidence, explanation)
\`\`\`
**Why monitoring is essential:**
- Builds comprehensive historical context
- Tracks behavioral patterns across requests
- Enables repeat offender detection
- Provides local intelligence that's often more valuable than external reputation
- Creates learning dataset for future decisions

**Monitoring must include:**
- Detailed explanation of why case is uncertain
- Specific behavioral patterns observed
- Context for future pattern matching

#### SELECTIVE: External Intelligence (Only when valuable)

**Use checkAbuseIPDB(ip) when:**
- External IP showing reconnaissance patterns (\`/admin\`, \`/.env\`, \`/.well-known/\`)
- Multiple failed authentication attempts from single IP
- Scanning behavior that's suspicious but not obviously malicious
- Geographic access anomalies requiring reputation context

**Use checkVirusTotal(ip) when:**
- Borderline malicious behavior needs reputation validation
- IP reputation could significantly shift confidence score
- Advanced persistent threat indicators present
- Sophisticated attack patterns that benefit from threat intelligence

**NEVER use external APIs for:**
- Internal/private IP addresses
- Cases where content provides clear verdict (confidence 1-3 or 8-10)
- Obviously automated scanning with clear malicious intent
- Rate limit conservation when content analysis suffices

### Step 3: Historical Context Integration
- Review monitoring logs for repeat patterns
- Consider IP behavioral history
- Integrate historical context with current assessment
- Adjust confidence based on accumulated intelligence

### Step 4: Final Decision
Synthesize all intelligence sources and provide structured assessment.

## Structured Response Format
You must respond in this exact format:

\`\`\`
MALICIOUS: [YES/NO/UNCERTAIN]
CONFIDENCE: [1-10]
EXPLANATION: [Your reasoning in 2-3 clear sentences, including why tools were/weren't used]
ATTACK_TYPE: [Specific threat type or BENIGN]
TOOLS_USED: [Functions called during analysis or "NONE - obvious case"]
INTELLIGENCE_BOOST: [How external data influenced confidence or "N/A - content-based decision"]
PATTERN_DETECTED: [Relevant behavioral patterns identified]
\`\`\`

## Key Efficiency Principles

1. **Content-First Analysis**: Most verdicts come from request content, not IP reputation
2. **Monitoring-Heavy Strategy**: Build local intelligence aggressively for uncertain cases
3. **Selective External Queries**: Use external APIs only when reputation significantly impacts decision
4. **Pattern Recognition**: Let historical data guide future assessments
5. **Resource Conservation**: Treat external APIs as rate-limited resources

Your goal: Maximum threat detection accuracy with intelligent tool usage that builds comprehensive local intelligence while conserving external API resources.
        `;
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
            is_system_url: false,
            toolsUsed: [],
            intelligenceBoost: '',
            patternDetected: '',
        };

        try {
            if (!response || typeof response !== 'string') {
                console.error('Invalid response type received from LLM:', typeof response);
                result.explanation = 'LLM returned invalid or empty response format';
                result.requiresManualReview = true;
                return result;
            }

            const responseText = response.trim();
            if (responseText.length === 0) {
                console.error('Empty response received from LLM');
                result.explanation = 'LLM returned completely empty response';
                result.requiresManualReview = true;
                return result;
            }

            console.log('Parsing LLM response (first 200 chars):', responseText.substring(0, 200) + '...');

            const lines = responseText.split('\n')
                .map(line => line.trim())
                .filter(line => line.length > 0);

            for (const line of lines) {
                try {
                    this.parseResponseLine(line, result);
                } catch (lineError) {
                    console.warn('Error parsing response line:', line, '-', lineError.message);
                }
            }

            this.finalizeParseResult(result, responseText);

            console.log('Successfully parsed LLM response:', {
                confidence: result.confidence,
                isMalicious: result.isMalicious,
                shouldBlock: result.shouldBlock,
                attackType: result.attackType,
            });

        } catch (error) {
            console.error('Critical error parsing LLM response:', error.message);
            console.error('Response content:', response);

            result.explanation = `Response parsing failed: ${error.message}. Raw response: ${response}`;
            result.requiresManualReview = true;
            result.confidence = 0;
        }

        return result;
    }

    parseResponseLine(line, result) {
        const upperLine = line.toUpperCase();

        if (upperLine.startsWith('MALICIOUS:')) {
            const value = line.split(':')[1]?.trim().toUpperCase();
            if (value === 'YES') {
                result.isMalicious = true;
            } else if (value === 'NO') {
                result.isMalicious = false;
            } else if (value === 'UNCERTAIN') {
                result.isMalicious = null;
                result.requiresManualReview = true;
            }
        }
        else if (upperLine.startsWith('CONFIDENCE:')) {
            const confidenceStr = line.split(':')[1]?.trim();
            const confidenceNum = parseInt(confidenceStr);

            if (!isNaN(confidenceNum) && confidenceNum >= 0 && confidenceNum <= 10) {
                result.confidence = confidenceNum;
            } else {
                console.warn(`Invalid confidence value detected: ${confidenceStr}, using default 0`);
            }
        }
        else if (upperLine.startsWith('EXPLANATION:')) {
            result.explanation = line.split(':').slice(1).join(':').trim();
        }
        else if (upperLine.startsWith('ATTACK_TYPE:')) {
            const attackType = line.split(':')[1]?.trim();
            result.attackType = (attackType && attackType.toUpperCase() !== 'BENIGN') ? attackType : null;
        }
        else if (upperLine.startsWith('TOOLS_USED:')) {
            const toolsStr = line.split(':')[1]?.trim();
            if (toolsStr && toolsStr !== 'None' && toolsStr !== 'N/A') {
                result.toolsUsed = toolsStr.split(',').map(tool => tool.trim());
            }
        }
        else if (upperLine.startsWith('INTELLIGENCE_BOOST:')) {
            result.intelligenceBoost = line.split(':').slice(1).join(':').trim();
        }
        else if (upperLine.startsWith('PATTERN_DETECTED:')) {
            result.patternDetected = line.split(':').slice(1).join(':').trim();
        }
        else if (line.includes('is_system_url: true') || upperLine.includes('SYSTEM URL: YES')) {
            result.is_system_url = true;
        }
    }

    finalizeParseResult(result, originalResponse) {
        result.shouldBlock = result.confidence >= this.config.maliciousConfidenceThreshold;

        if (result.confidence >= 8) {
            result.impact = 'HIGH';
        } else if (result.confidence >= 6) {
            result.impact = 'MEDIUM';
        } else if (result.confidence >= 4) {
            result.impact = 'LOW';
        } else {
            result.impact = 'NONE';
        }

        if (result.isMalicious === null) {
            if (result.confidence >= 8) {
                result.isMalicious = true;
            } else if (result.confidence >= 6) {
                result.requiresManualReview = true;
            } else {
                result.isMalicious = false;
            }
        }

        if (!result.explanation || result.explanation.trim().length === 0) {
            if (originalResponse.length > 0) {
                result.explanation = `Analysis completed with confidence ${result.confidence}/10. ${originalResponse.substring(0, 200)}`;
            } else {
                result.explanation = `Analysis completed with confidence ${result.confidence}/10 - no detailed explanation provided by LLM`;
            }
        }

        if (typeof result.confidence !== 'number' || result.confidence < 0 || result.confidence > 10) {
            console.warn(`Invalid confidence score detected during finalization: ${result.confidence}, resetting to 0`);
            result.confidence = 0;
            result.requiresManualReview = true;
            result.shouldBlock = false;
        }
    }

    /**
     * Test connection for both primary and secondary models
     */
    async testConnection() {
        const results = {
            primary: { success: false, message: 'Not tested' },
            secondary: { success: false, message: 'Not tested' },
            overall: false
        };

        // Test primary model if enabled
        if (this.options.enablePrimaryModel && this.primaryModel) {
            try {
                console.log('Testing primary model connection...');
                results.primary = await this.primaryModel.testConnection();
            } catch (error) {
                results.primary = {
                    success: false,
                    message: `Primary model test failed: ${error.message}`,
                    error: error.message
                };
            }
        } else {
            results.primary = {
                success: false,
                message: 'Primary model disabled or not initialized'
            };
        }

        // Test secondary model
        try {
            console.log('Testing secondary model connection...');

            const testLogEntry = {
                ip: '127.0.0.1',
                method: 'GET',
                url: '/',
                queryString: '',
                userAgent: 'Test-Agent',
                status: 200
            };

            const testThreatResult = {
                confidence: 1,
                threats: [],
                is_system_url: false
            };

            const testPrompt = this.buildSecondaryPrompt(testLogEntry, testThreatResult);
            let response;

            switch (this.provider) {
                case 'openai':
                case 'groq':
                case 'cerebras':
                    response = await this.analyzeWithOpenAIFormat(testPrompt, 'connection-test');
                    break;
                case 'anthropic':
                    response = await this.analyzeWithAnthropic(testPrompt, 'connection-test');
                    break;
                default:
                    throw new Error(`Unsupported provider: ${this.provider}`);
            }

            const parsedResponse = this.parseResponse(response);

            results.secondary = {
                success: true,
                message: `${this.provider} connection successful`,
                model: this.getSecondaryModelName(),
                testResponse: {
                    confidence: parsedResponse.confidence,
                    isMalicious: parsedResponse.isMalicious,
                    explanation: parsedResponse.explanation.substring(0, 100) + '...',
                    responseLength: response.length
                }
            };

        } catch (error) {
            console.error(`Secondary model connection test failed:`, error.message);
            results.secondary = {
                success: false,
                message: `${this.provider} connection failed: ${error.message}`,
                error: error.message,
                model: this.getSecondaryModelName()
            };
        }

        // Determine overall success
        results.overall = results.secondary.success &&
            (!this.options.enablePrimaryModel || results.primary.success);

        return {
            success: results.overall,
            message: results.overall ? 'Two-tier system operational' : 'System issues detected',
            primary: results.primary,
            secondary: results.secondary,
            configuration: {
                primaryEnabled: this.options.enablePrimaryModel,
                secondaryProvider: this.provider,
                timestamp: new Date().toISOString()
            }
        };
    }

    /**
     * Get comprehensive statistics for the two-tier system
     */
    getCacheStats() {
        const hitRate = this.cacheMetadata.totalAnalyzed > 0
            ? (this.cacheMetadata.cacheHits / this.cacheMetadata.totalAnalyzed * 100).toFixed(2)
            : '0.00';

        return {
            // Cache statistics
            ipCache: this.ipCache.size,
            requestCache: this.requestCache.size,
            queuedIPs: this.ipRequestQueue.size,
            maxIpCache: this.config.maxIpCacheSize,
            maxRequestCache: this.config.maxRequestCacheSize,
            totalAnalyzed: this.cacheMetadata.totalAnalyzed,
            cacheHits: this.cacheMetadata.cacheHits,
            cacheMisses: this.cacheMetadata.cacheMisses,
            hitRate: `${hitRate}%`,
            lastCleanup: new Date(this.cacheMetadata.lastCleanup).toISOString(),
            estimatedMemoryKB: Math.round((this.ipCache.size + this.requestCache.size) * 0.5),

            // Two-tier system statistics
            tierStats: {
                totalRequests: this.tierStats.totalRequests,
                primaryResolved: this.tierStats.primaryResolved,
                secondaryEscalated: this.tierStats.secondaryEscalated,
                primaryErrors: this.tierStats.primaryErrors,
                escalationRate: `${this.tierStats.escalationRate}%`,
                averagePrimaryTime: Math.round(this.tierStats.averagePrimaryTime),
                averageSecondaryTime: Math.round(this.tierStats.averageSecondaryTime)
            },

            // Primary model statistics (if enabled)
            primaryStats: this.options.enablePrimaryModel && this.primaryModel
                ? this.primaryModel.getStats()
                : { message: 'Primary model not enabled or not initialized' }
        };
    }

    /**
     * Get list of currently cached malicious IPs with details
     */
    getMaliciousIPs() {
        const maliciousIPs = [];

        for (const [ip, result] of this.ipCache.entries()) {
            if (result.confidence >= this.config.maliciousConfidenceThreshold) {
                maliciousIPs.push({
                    ip,
                    confidence: result.confidence,
                    attackType: result.attackType || 'Unknown',
                    explanation: result.explanation.substring(0, 100) + (result.explanation.length > 100 ? '...' : ''),
                    detectedAt: result.detectedAt || new Date().toISOString(),
                    tier: result.tier || 'unknown'
                });
            }
        }

        return maliciousIPs.sort((a, b) => b.confidence - a.confidence);
    }

    /**
     * Get current configuration settings for two-tier system
     */
    getConfiguration() {
        return {
            // Secondary model configuration
            secondaryProvider: this.provider,
            secondaryModel: this.getSecondaryModelName(),

            // Primary model configuration
            primaryEnabled: this.options.enablePrimaryModel,
            primaryModel: this.options.primaryModelId,
            primaryDevice: this.options.primaryDevice,

            // System configuration
            config: { ...this.config },
            cacheEnabled: true,
            toolsEnabled: true,

            // Two-tier specific features
            features: {
                twoTierAnalysis: true,
                intelligentEscalation: true,
                primaryModelFallback: true,
                sequentialToolExecution: true,
                noRetryLogic: true,
                intelligentCaching: true,
                maliciousIPTracking: true
            },

            // Performance settings
            primaryTimeoutMs: this.config.primaryTimeoutMs,
            escalationThreshold: this.config.escalationThreshold
        };
    }

    /**
     * Update configuration settings with validation
     */
    updateConfiguration(newConfig) {
        const allowedUpdates = [
            'maxIpCacheSize',
            'maxRequestCacheSize',
            'maliciousConfidenceThreshold',
            'cacheCleanupInterval',
            'primaryTimeoutMs',
            'escalationThreshold'
        ];

        for (const [key, value] of Object.entries(newConfig)) {
            if (allowedUpdates.includes(key) && typeof value === 'number' && value > 0) {
                const oldValue = this.config[key];
                this.config[key] = value;
                console.log(`Configuration updated: ${key} changed from ${oldValue} to ${value}`);
            } else {
                console.warn(`Invalid configuration update attempted: ${key} = ${value} (rejected)`);
            }
        }
    }

    /**
     * Clear all caches and reset analyzer state
     */
    clearCache() {
        const stats = this.getCacheStats();

        this.ipCache.clear();
        this.requestCache.clear();
        this.ipRequestQueue.clear();

        this.cacheMetadata = {
            ...this.cacheMetadata,
            lastCleanup: Date.now(),
            cacheHits: 0,
            cacheMisses: 0
        };

        // Reset tier statistics
        this.tierStats = {
            totalRequests: 0,
            primaryResolved: 0,
            secondaryEscalated: 0,
            primaryErrors: 0,
            averagePrimaryTime: 0,
            averageSecondaryTime: 0,
            escalationRate: 0
        };

        console.log('All caches and tier statistics cleared successfully. Previous statistics:', stats);
    }

    /**
     * Comprehensive health check for the two-tier analyzer system
     */
    async healthCheck() {
        const stats = this.getCacheStats();
        const maliciousCount = this.getMaliciousIPs().length;

        // Test both tier connections
        let connectionTest;
        try {
            connectionTest = await this.testConnection();
        } catch (error) {
            connectionTest = {
                success: false,
                message: `Health check connection test failed: ${error.message}`,
                error: error.message,
                primary: { success: false, message: 'Test failed' },
                secondary: { success: false, message: 'Test failed' }
            };
        }

        // Determine overall system health
        const isHealthy = connectionTest.success && stats.totalAnalyzed >= 0;

        // Calculate efficiency metrics
        const primaryEfficiency = this.tierStats.totalRequests > 0
            ? ((this.tierStats.primaryResolved / this.tierStats.totalRequests) * 100).toFixed(1)
            : '0.0';

        return {
            status: isHealthy ? 'healthy' : 'unhealthy',

            // Model status
            models: {
                primary: {
                    enabled: this.options.enablePrimaryModel,
                    model: this.options.primaryModelId,
                    status: connectionTest.primary.success ? 'operational' : 'error',
                    message: connectionTest.primary.message
                },
                secondary: {
                    provider: this.provider,
                    model: this.getSecondaryModelName(),
                    status: connectionTest.secondary.success ? 'operational' : 'error',
                    message: connectionTest.secondary.message
                }
            },

            // Cache health metrics
            cache: {
                totalEntries: stats.ipCache + stats.requestCache,
                maliciousIPs: maliciousCount,
                hitRate: stats.hitRate,
                memoryUsage: `${stats.estimatedMemoryKB}KB`
            },

            // Two-tier performance metrics
            performance: {
                totalAnalyzed: stats.totalAnalyzed,
                primaryResolution: `${primaryEfficiency}%`,
                escalationRate: stats.tierStats.escalationRate + '%',
                averagePrimaryTime: `${stats.tierStats.averagePrimaryTime}ms`,
                averageSecondaryTime: `${stats.tierStats.averageSecondaryTime}ms`,
                systemEfficiency: primaryEfficiency > 70 ? 'excellent' : primaryEfficiency > 50 ? 'good' : 'needs improvement'
            },

            // System information
            system: {
                uptime: Date.now() - this.cacheMetadata.lastCleanup,
                architecture: 'two-tier',
                features: {
                    primaryTier: this.options.enablePrimaryModel,
                    intelligentEscalation: true,
                    toolCalling: true,
                    maliciousTracking: true,
                    caching: true
                }
            },

            // Test results
            connectionTest: connectionTest.success ? 'passed' : 'failed',
            lastCheck: new Date().toISOString()
        };
    }

    /**
     * Get detailed tier performance report
     */
    getTierPerformanceReport() {
        const totalRequests = this.tierStats.totalRequests;
        const primaryResolved = this.tierStats.primaryResolved;
        const secondaryEscalated = this.tierStats.secondaryEscalated;
        const primaryErrors = this.tierStats.primaryErrors;

        return {
            summary: {
                totalRequests,
                primaryResolved,
                secondaryEscalated,
                primaryErrors,
                escalationRate: totalRequests > 0 ? ((secondaryEscalated / totalRequests) * 100).toFixed(1) + '%' : '0.0%',
                primarySuccessRate: totalRequests > 0 ? ((primaryResolved / totalRequests) * 100).toFixed(1) + '%' : '0.0%',
                errorRate: totalRequests > 0 ? ((primaryErrors / totalRequests) * 100).toFixed(1) + '%' : '0.0%'
            },

            performance: {
                averagePrimaryTime: Math.round(this.tierStats.averagePrimaryTime),
                averageSecondaryTime: Math.round(this.tierStats.averageSecondaryTime),
                timeEfficiencyGain: this.tierStats.averageSecondaryTime > 0 && this.tierStats.averagePrimaryTime > 0
                    ? `${(((this.tierStats.averageSecondaryTime - this.tierStats.averagePrimaryTime) / this.tierStats.averageSecondaryTime) * 100).toFixed(1)}%`
                    : 'N/A'
            },

            recommendations: this.generatePerformanceRecommendations(),

            primaryModelStats: this.options.enablePrimaryModel && this.primaryModel
                ? this.primaryModel.getStats()
                : null,

            generatedAt: new Date().toISOString()
        };
    }

    /**
     * Generate performance recommendations based on tier statistics
     */
    generatePerformanceRecommendations() {
        const recommendations = [];
        const escalationRate = parseFloat(this.tierStats.escalationRate);
        const errorRate = this.tierStats.totalRequests > 0
            ? (this.tierStats.primaryErrors / this.tierStats.totalRequests) * 100
            : 0;

        if (escalationRate > 30) {
            recommendations.push({
                type: 'optimization',
                priority: 'medium',
                message: `High escalation rate (${escalationRate.toFixed(1)}%) - consider tuning primary model or improving training data`
            });
        }

        if (escalationRate < 10) {
            recommendations.push({
                type: 'efficiency',
                priority: 'low',
                message: `Excellent escalation rate (${escalationRate.toFixed(1)}%) - primary model performing well`
            });
        }

        if (errorRate > 5) {
            recommendations.push({
                type: 'stability',
                priority: 'high',
                message: `Primary model error rate is high (${errorRate.toFixed(1)}%) - investigate primary model stability`
            });
        }

        if (this.tierStats.averagePrimaryTime > 3000) {
            recommendations.push({
                type: 'performance',
                priority: 'medium',
                message: `Primary model response time is slow (${this.tierStats.averagePrimaryTime.toFixed(0)}ms) - consider optimization`
            });
        }

        if (recommendations.length === 0) {
            recommendations.push({
                type: 'status',
                priority: 'info',
                message: 'Two-tier system performing within expected parameters'
            });
        }

        return recommendations;
    }

    /**
     * Force escalation to secondary model (for testing/debugging)
     */
    async forceSecondaryAnalysis(logEntry, threatResult) {
        console.log(`[FORCE-SECONDARY] Forcing analysis to secondary tier for IP: ${logEntry.ip}`);

        const analysisId = `force-${logEntry.ip}-${Date.now()}`;
        return await this.performSecondaryAnalysis(logEntry, threatResult, analysisId);
    }

    /**
     * Initialize primary model manually (if auto-initialization failed)
     */
    async initializePrimaryModel() {
        if (!this.options.enablePrimaryModel) {
            throw new Error('Primary model is disabled in configuration');
        }

        if (!this.primaryModel) {
            this.primaryModel = new TransformersLLM();
        }

        if (!this.primaryModel.isInitialized) {
            console.log('Manually initializing primary model...');
            await this.primaryModel.initialize();
            console.log('Primary model manual initialization completed');
        } else {
            console.log('Primary model already initialized');
        }

        return this.primaryModel.getStats();
    }

    /**
     * Dispose of resources for both models
     */
    async dispose() {
        console.log('Disposing two-tier LLMAnalyzer resources...');

        try {
            // Dispose primary model if it exists
            if (this.primaryModel) {
                await this.primaryModel.dispose();
                console.log('Primary model disposed');
            }

            // Clear all caches
            this.clearCache();

            // Clear intervals
            if (this.cacheMaintenanceInterval ) {
                clearInterval(this.cacheMaintenanceInterval);
            }

            console.log('Two-tier LLMAnalyzer disposed successfully');

        } catch (error) {
            console.warn('Error during disposal:', error.message);
        }
    }
}

export default LLMAnalyzer;