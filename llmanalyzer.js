import OpenAI from 'openai';
import Groq from 'groq-sdk';
import Anthropic from '@anthropic-ai/sdk';
import Cerebras from '@cerebras/cerebras_cloud_sdk';
import { checkAbuseIPDB, checkVirusTotal } from "./llmtools.js";
import { storeMonitoringLog } from "./upstash.js";

/**
 * LLMAnalyzer - Advanced Threat Analysis Using Large Language Models
 *
 * A  security analysis system that leverages multiple LLM providers
 * to intelligently analyze network traffic and identify potential threats.
 *
 * Core Capabilities:
 * - Multi-provider LLM support (OpenAI, Groq, Cerebras, Anthropic)
 * - Intelligent caching system with IP and request-level storage
 * - External threat intelligence integration via function calling
 * - Automated malicious IP reputation management
 * - Comprehensive request pattern analysis and monitoring
 * - Sequential tool execution to prevent race conditions
 * - Robust error handling without retry logic
 *
 * Architecture:
 * - IP Cache: Fast blocking of known malicious IPs
 * - Request Cache: Detailed analysis results for specific requests
 * - Queue Tracking: Manages pending requests per IP for cleanup
 * - Tool Integration: External APIs for enhanced threat intelligence
 *
 * @class LLMAnalyzer
 */
class LLMAnalyzer {
    /**
     * Initialize the LLM Analyzer with provider-specific configuration
     *
     * @param {string} apiKey - API key for the chosen LLM provider
     * @param {string} provider - LLM provider name ('openai', 'groq', 'cerebras', 'anthropic')
     * @throws {Error} If API key is missing or provider initialization fails
     */
    constructor(apiKey, provider = 'cerebras') {
        // Validate required API key
        if (!apiKey) {
            throw new Error('API key is required for LLM initialization');
        }

        // Store configuration
        this.apiKey = apiKey;
        this.provider = provider.toLowerCase();

        // Initialize the appropriate LLM client
        try {
            this.client = this.initializeClient();
        } catch (error) {
            console.error('Failed to initialize LLM client:', error.message);
            throw new Error(`LLM client initialization failed: ${error.message}`);
        }

        // Set up all caching systems
        this.initializeCaches();

        // Define system configuration constants
        this.config = {
            // Cache size limits
            maxIpCacheSize: 500,                    // Maximum IPs to cache
            maxRequestCacheSize: 1000,              // Maximum individual requests to cache

            // Threat detection thresholds
            maliciousConfidenceThreshold: 8,        // Confidence level (8+) that triggers automatic blocking

            // Maintenance settings
            cacheCleanupInterval: 3600000,          // Cache cleanup every hour (ms)
        };

        // Start automatic cache maintenance
        this.startCacheMaintenance();

        console.log(`LLMAnalyzer initialized with provider: ${this.provider}, model: ${this.getModelName()}`);
    }

    /**
     * Initialize all cache data structures
     *
     * Cache Architecture:
     * - IP Cache: Stores high-confidence malicious IPs for immediate blocking
     * - Request Cache: Stores detailed analysis results for specific requests
     * - Queue Tracking: Manages cleanup of cached data when IPs become malicious
     * - Metadata: Tracks performance metrics and maintenance schedules
     *
     * @private
     */
    initializeCaches() {
        // IP-level cache for fast malicious IP blocking
        // Structure: Map<ipAddress, analysisResult>
        // Purpose: Immediate blocking of known threats without re-analysis
        this.ipCache = new Map();

        // Request-level tracking for cleanup management
        // Structure: Map<ipAddress, Set<requestKeys>>
        // Purpose: Track all cached requests per IP for bulk cleanup when IP becomes malicious
        this.ipRequestQueue = new Map();

        // Detailed request cache for specific request patterns
        // Structure: Map<requestKey, analysisResult>
        // Purpose: Cache individual request analysis to avoid duplicate processing
        this.requestCache = new Map();

        // Cache performance and maintenance metadata
        this.cacheMetadata = {
            lastCleanup: Date.now(),        // Timestamp of last maintenance cycle
            totalAnalyzed: 0,               // Total requests processed
            cacheHits: 0,                   // Requests served from cache
            cacheMisses: 0                  // Requests requiring fresh analysis
        };

        console.log('Cache systems initialized');
    }

    /**
     * Initialize the appropriate LLM client based on provider selection
     *
     * @private
     * @returns {Object} Configured LLM client instance
     * @throws {Error} If provider is unsupported or client creation fails
     */
    initializeClient() {
        // Define provider-specific client factories
        const providerConfigs = {
            'openai': () => new OpenAI({
                apiKey: this.apiKey,
                baseURL: 'https://models.github.ai/inference'    // GitHub Models endpoint
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

        // Get the appropriate factory function
        const clientFactory = providerConfigs[this.provider];
        if (!clientFactory) {
            const supportedProviders = Object.keys(providerConfigs).join(', ');
            throw new Error(`Unsupported provider: ${this.provider}. Supported providers: ${supportedProviders}`);
        }

        // Create and return the client instance
        return clientFactory();
    }

    /**
     * Get the appropriate model name for the current provider
     *
     * @private
     * @returns {string} Model identifier for API calls
     */
    getModelName() {
        const modelMap = {
            'openai': 'gpt-4o',                          // Latest GPT-4 optimized model
            'groq': 'llama3-70b-8192',                   // Llama 3 70B with 8K context
            'anthropic': 'claude-3-sonnet-20240229',     // Claude 3 Sonnet
            'cerebras': 'llama-3.3-70b'                   // llama 3
        };

        return modelMap[this.provider] || 'llama3.3-70b';  // Default fallback
    }

    /**
     * Create a unique cache key for individual requests
     *
     * Cache Key Strategy:
     * - Combines IP, method, URL, and payload for uniqueness
     * - Ensures different requests from same IP are cached separately
     * - Deterministic key generation for consistent lookup
     *
     * @private
     * @param {Object} logEntry - Request log entry containing request details
     * @returns {string} Unique request identifier for caching
     * @throws {Error} If log entry is invalid or missing required fields
     */
    createRequestKey(logEntry) {
        // Validate required fields
        if (!logEntry || !logEntry.ip) {
            throw new Error('Invalid log entry: IP address is required for cache key generation');
        }

        // Build deterministic key from request components
        const keyComponents = [
            logEntry.ip,                                    // Source IP address
            logEntry.method || 'UNKNOWN',                   // HTTP method (GET, POST, etc.)
            logEntry.url || '',                             // Requested URL path
            JSON.stringify(logEntry.payload || {})          // Request payload/body
        ];

        return keyComponents.join('_');
    }

    /**
     * Add a request to the IP's processing queue for cleanup tracking
     *
     * Queue Management:
     * - Tracks which requests belong to which IP
     * - Enables bulk cleanup when IP becomes malicious
     * - Maintains referential integrity between caches
     *
     * @private
     * @param {string} ip - IP address
     * @param {string} requestKey - Unique request identifier
     */
    addToQueue(ip, requestKey) {
        // Initialize queue for new IPs
        if (!this.ipRequestQueue.has(ip)) {
            this.ipRequestQueue.set(ip, new Set());
        }

        // Add request to IP's queue
        this.ipRequestQueue.get(ip).add(requestKey);
    }

    /**
     * Clean up all cached data for a malicious IP
     *
     * Cleanup Strategy:
     * - Remove all individual request cache entries for the malicious IP
     * - Clear the IP from queue tracking
     * - Preserve the IP-level malicious marking for future blocking
     * - Log cleanup statistics for monitoring
     *
     * @private
     * @param {string} ip - IP address to clean up
     */
    cleanupMaliciousIP(ip) {
        const requests = this.ipRequestQueue.get(ip);
        if (!requests) {
            return; // No cleanup needed if IP has no tracked requests
        }

        // Remove all cached requests for this malicious IP
        let cleanedCount = 0;
        requests.forEach(requestKey => {
            if (this.requestCache.delete(requestKey)) {
                cleanedCount++;
            }
        });

        // Clear the IP's request queue
        this.ipRequestQueue.delete(ip);

        console.log(`Cleaned up ${cleanedCount} cached requests from malicious IP: ${ip}`);
    }

    /**
     * Main analysis method with comprehensive caching and error handling
     *
     * Analysis Flow:
     * 1. Validate input and create request key
     * 2. Check IP-level cache for known malicious IPs (immediate blocking)
     * 3. Check request-level cache for identical previous requests
     * 4. Perform fresh LLM analysis if no cache hit
     * 5. Cache results and handle malicious IP detection
     * 6. Return structured analysis result
     *
     * @param {Object} logEntry - Request log entry to analyze
     * @param {Object} threatResult - Initial automated threat detection results
     * @returns {Promise<Object>} Comprehensive analysis result with confidence scoring
     */
    async analyze(logEntry, threatResult) {
        // Input validation
        if (!logEntry || !logEntry.ip) {
            throw new Error('Invalid log entry: IP address is required for analysis');
        }

        const ip = logEntry.ip;
        let requestKey;

        // Generate unique request identifier
        try {
            requestKey = this.createRequestKey(logEntry);
        } catch (error) {
            console.error('Error creating request key:', error.message);
            return this.createErrorResult('Invalid request format', error.message);
        }

        try {
            // Track total analysis requests for metrics
            this.cacheMetadata.totalAnalyzed++;

            // FIRST PRIORITY: Check if IP is already marked as malicious
            // This provides immediate blocking for known threats
            if (this.ipCache.has(ip)) {
                const cachedResult = this.ipCache.get(ip);

                // If IP has high confidence malicious rating, block immediately
                if (cachedResult.confidence >= this.config.maliciousConfidenceThreshold) {
                    console.log(`IP ${ip} already marked as malicious (confidence: ${cachedResult.confidence}) - blocking immediately`);
                    this.cacheMetadata.cacheHits++;

                    return {
                        ...cachedResult,
                        explanation: `IP previously identified as malicious with confidence ${cachedResult.confidence} - auto-blocked`,
                        fromCache: true
                    };
                }
            }

            // SECOND PRIORITY: Check for exact request match in cache
            // This avoids re-analyzing identical requests
            if (this.requestCache.has(requestKey)) {
                console.log('Using cached analysis for identical request');
                this.cacheMetadata.cacheHits++;

                const cachedResult = this.requestCache.get(requestKey);
                return { ...cachedResult, fromCache: true };
            }

            // CACHE MISS: Perform fresh analysis
            this.cacheMetadata.cacheMisses++;
            console.log(`Cache miss - performing fresh analysis for IP ${ip}`);

            // Add to processing queue for potential cleanup
            this.addToQueue(ip, requestKey);

            // Perform the actual LLM analysis
            const analysisResult = await this.performAnalysis(logEntry, threatResult);

            // Preserve system URL attribute from initial threat detection
            if (!analysisResult.is_system_url && threatResult?.is_system_url) {
                analysisResult.is_system_url = true;
            }

            // Cache the fresh analysis result (only if successful)
            // Don't cache error results to prevent serving stale failures
            if (analysisResult.confidence > 0 && !analysisResult.error) {
                this.requestCache.set(requestKey, analysisResult);
                console.log(`Cached successful analysis result for IP ${ip} (confidence: ${analysisResult.confidence})`);
            } else {
                console.log(`Skipping cache storage for failed analysis (confidence: ${analysisResult.confidence}, error: ${!!analysisResult.error})`);
            }

            // MALICIOUS IP HANDLING: If analysis indicates high-confidence threat
            if (analysisResult.confidence >= this.config.maliciousConfidenceThreshold) {
                // Mark IP as malicious for future immediate blocking
                this.ipCache.set(ip, analysisResult);

                // Clean up all other cached requests from this IP
                this.cleanupMaliciousIP(ip);

                console.log(`IP ${ip} marked as malicious with confidence ${analysisResult.confidence}`);
            }

            // Perform periodic cache maintenance
            this.maintainCacheSize();

            return analysisResult;

        } catch (error) {
            console.error(`Analysis error for IP ${ip}:`, error.message);
            console.error('Stack trace:', error.stack);

            // Return structured error result for graceful degradation
            return this.createErrorResult('Analysis failed due to system error', error.message);
        }
    }

    /**
     * Perform the actual LLM analysis without retry logic
     *
     * Analysis Process:
     * 1. Build comprehensive analysis prompt
     * 2. Route to appropriate provider-specific method
     * 3. Parse and validate LLM response
     * 4. Return structured result or error
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
     * Create a standardized error result for graceful failure handling
     *
     * Error Result Structure:
     * - Sets safe defaults that won't trigger false blocks
     * - Includes error details for debugging
     * - Flags result for manual review
     * - Maintains consistent result structure
     *
     * @private
     * @param {string} message - Primary error message
     * @param {string} details - Detailed error information
     * @returns {Object} Structured error result
     */
    createErrorResult(message, details = '') {
        return {
            isMalicious: null,                          // Uncertain status
            confidence: 0,                              // No confidence in result
            explanation: `${message}${details ? ` - ${details}` : ''} - manual review recommended`,
            error: details,                             // Technical error details
            requiresManualReview: true,                 // Flag for human review
            shouldBlock: false,                         // Don't auto-block on errors
            impact: 'UNKNOWN',                          // Unknown impact level
            attackType: null,                           // No attack type identified
            fromCache: false,                           // Fresh (failed) analysis
            reasoningEffort: 'error'                    // Special reasoning effort marker
        };
    }

    /**
     * Validate analysis result structure and required fields
     *
     * Validation Checks:
     * - Ensures result is a valid object
     * - Verifies all required fields are present
     * - Validates confidence score range (0-10)
     * - Logs specific validation failures for debugging
     *
     * @private
     * @param {Object} result - Analysis result to validate
     * @returns {boolean} Whether result passes validation
     */
    validateAnalysisResult(result) {
        // Basic type checking
        if (!result || typeof result !== 'object') {
            console.error('Analysis result is not a valid object');
            return false;
        }

        // Required field validation
        const requiredFields = ['confidence', 'explanation'];
        for (const field of requiredFields) {
            if (!(field in result)) {
                console.error(`Missing required field in analysis result: ${field}`);
                return false;
            }
        }

        // Confidence score validation
        if (typeof result.confidence !== 'number' || result.confidence < 0 || result.confidence > 10) {
            console.error(`Invalid confidence score: ${result.confidence} (must be number between 0-10)`);
            return false;
        }

        return true;
    }

    /**
     * Maintain cache size limits and perform cleanup
     *
     * Cache Maintenance Strategy:
     * - Remove oldest entries when limits are exceeded
     * - Prioritize keeping high-value malicious IP entries
     * - Log cleanup operations for monitoring
     * - Use FIFO (First In, First Out) eviction policy
     *
     * @private
     */
    maintainCacheSize() {
        // Clean up IP cache if it exceeds configured limit
        if (this.ipCache.size > this.config.maxIpCacheSize) {
            const excessCount = this.ipCache.size - this.config.maxIpCacheSize;

            // Get oldest entries for removal (FIFO eviction)
            const keysToRemove = Array.from(this.ipCache.keys()).slice(0, excessCount);

            // Remove excess entries
            keysToRemove.forEach(key => this.ipCache.delete(key));
            console.log(`Cache maintenance: Cleaned up ${excessCount} entries from IP cache`);
        }

        // Clean up request cache if it exceeds configured limit
        if (this.requestCache.size > this.config.maxRequestCacheSize) {
            const excessCount = this.requestCache.size - this.config.maxRequestCacheSize;

            // Get oldest entries for removal (FIFO eviction)
            const keysToRemove = Array.from(this.requestCache.keys()).slice(0, excessCount);

            // Remove excess entries
            keysToRemove.forEach(key => this.requestCache.delete(key));
            console.log(`Cache maintenance: Cleaned up ${excessCount} entries from request cache`);
        }
    }

    /**
     * Start periodic cache maintenance operations
     *
     * Maintenance Operations:
     * - Runs on configured interval (default: hourly)
     * - Maintains cache size limits
     * - Updates maintenance metadata
     * - Logs completion for monitoring
     *
     * @private
     */
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

    /**
     * Get function tool definitions for LLM function calling
     *
     * Available Tools:
     * - checkVirusTotal: IP reputation checking via VirusTotal API
     * - checkAbuseIPDB: Historical abuse data from AbuseIPDB
     * - storeMonitoringLog: Pattern analysis and monitoring storage
     *
     * @private
     * @returns {Array} OpenAI-compatible function tool definitions
     */
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

    /**
     * Get function name to implementation mapping for execution
     *
     * @private
     * @returns {Object} Function name to implementation mapping
     */
    getAvailableFunctions() {
        return {
            "checkVirusTotal": checkVirusTotal,         // VirusTotal IP reputation checking
            "checkAbuseIPDB": checkAbuseIPDB,           // AbuseIPDB historical data
            "storeMonitoringLog": storeMonitoringLog    // Pattern monitoring and storage
        };
    }

    /**
     * Execute a function call requested by the LLM
     *
     * Function Execution:
     * - Validates function exists and arguments are correct
     * - Provides function-specific argument handling
     * - Returns structured results for LLM consumption
     * - Handles errors gracefully without breaking analysis
     *
     * @private
     * @param {string} functionName - Name of function to execute
     * @param {Object} functionArgs - Arguments for the function call
     * @returns {Promise<*>} Function execution result
     */
    async executeFunctionCall(functionName, functionArgs) {
        const availableFunctions = this.getAvailableFunctions();
        const functionToCall = availableFunctions[functionName];

        // Validate function exists
        if (!functionToCall) {
            throw new Error(`Function ${functionName} not found in available functions`);
        }

        console.log(`Executing tool function: ${functionName} with arguments:`, functionArgs);

        try {
            let result;

            // Handle function-specific argument patterns
            switch (functionName) {
                case 'checkVirusTotal':
                case 'checkAbuseIPDB':
                    // IP reputation checking functions
                    if (!functionArgs.ip) {
                        throw new Error(`IP address is required for ${functionName}`);
                    }
                    result = await functionToCall(functionArgs.ip);
                    break;

                case 'storeMonitoringLog':
                    // Pattern monitoring function
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

            // Re-throw with more context for LLM
            throw new Error(`Function execution failed: ${error.message}`);
        }
    }

    /**
     * Analyze request using OpenAI-compatible API format with tool support
     *
     * OpenAI Analysis Flow:
     * 1. Send initial request with available tools
     * 2. Process any tool calls sequentially (prevents race conditions)
     * 3. Send tool results back to LLM for final analysis
     * 4. Return final analysis incorporating tool intelligence
     *
     * @private
     * @param {string} prompt - Analysis prompt for the LLM
     * @returns {Promise<string>} Final analysis response from LLM
     */
    /**
     * Analyze request using OpenAI-compatible API format with intelligent tool support
     * Supports multiple tool calling rounds, parallel execution, and loop prevention
     *
     * @private
     * @param {string} prompt - Analysis prompt for the LLM
     * @returns {Promise<string>} Final analysis response from LLM
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

        const maxToolRounds = 3; // Prevent infinite loops
        let currentRound = 0;
        const executedTools = new Set(); // Track executed tools to prevent duplicates

        try {
            console.log(`Making ${this.provider} API call with advanced tool support enabled`);

            // Initial completion request with tools available
            let completion = await this.client.chat.completions.create({
                model: this.getModelName(),
                messages: messages,
                temperature: 0.1,
                max_tokens: 800,
                stream: false,
                tools: tools,
                tool_choice: "auto",
            });

            if (!completion.choices || completion.choices.length === 0) {
                console.error('API Response:', JSON.stringify(completion, null, 2));
                throw new Error('No response choices returned from LLM API');
            }

            let responseMessage = completion.choices[0].message;
            if (!responseMessage) {
                throw new Error('Empty response message from LLM API');
            }

            // Tool calling loop with intelligent termination
            while (responseMessage.tool_calls && responseMessage.tool_calls.length > 0 && currentRound < maxToolRounds) {
                currentRound++;
                console.log(`=== Tool Calling Round ${currentRound}/${maxToolRounds} ===`);

                const toolCalls = responseMessage.tool_calls;
                console.log(`Processing ${toolCalls.length} tool call(s) in round ${currentRound}`);

                // Add the assistant's response with tool calls to message history
                messages.push(responseMessage);

                // Determine execution strategy based on provider and tool types
                const executionStrategy = this.determineExecutionStrategy(toolCalls, this.provider);
                console.log(`Using execution strategy: ${executionStrategy}`);

                if (executionStrategy === 'parallel') {
                    await this.executeToolCallsParallel(toolCalls, messages, executedTools);
                } else {
                    await this.executeToolCallsSequential(toolCalls, messages, executedTools);
                }

                // Request next completion with updated context
                console.log(`Requesting completion after tool round ${currentRound}`);

                const nextCompletionConfig = {
                    model: this.getModelName(),
                    messages: messages,
                    temperature: 0.1,
                    max_tokens: 600,
                    tools: tools,
                    tool_choice: "auto",
                };

                // Cerebras-specific adjustments for better tool handling
                if (this.provider === 'cerebras') {
                    // Add explicit guidance for Cerebras
                    messages.push({
                        role: "user",
                        content: `Round ${currentRound} complete. If you have all needed information, provide your final assessment in the required format. If you need more tools, call them now.`
                    });

                    // Slightly reduce max tokens to encourage completion
                    nextCompletionConfig.max_tokens = 500;
                }

                completion = await this.client.chat.completions.create(nextCompletionConfig);

                if (!completion.choices || completion.choices.length === 0) {
                    throw new Error(`No response choices returned in tool round ${currentRound}`);
                }

                responseMessage = completion.choices[0].message;
                if (!responseMessage) {
                    throw new Error(`Empty response message in tool round ${currentRound}`);
                }

                // Check for completion indicators
                if (this.hasAnalysisContent(responseMessage)) {
                    console.log(`Analysis content detected in round ${currentRound} - completing`);
                    break;
                }

                // Detect potential loops
                if (this.detectToolLoop(responseMessage.tool_calls, executedTools)) {
                    console.warn(`Tool loop detected in round ${currentRound} - forcing completion`);
                    return this.forceCompletionWithContext(messages, executedTools);
                }
            }

            // Handle final response
            if (responseMessage.tool_calls && responseMessage.tool_calls.length > 0) {
                // Hit max rounds with pending tool calls
                console.warn(`Maximum tool rounds (${maxToolRounds}) reached with pending tool calls`);
                return this.forceCompletionWithContext(messages, executedTools);
            }

            // Final analysis content
            if (!responseMessage.content || responseMessage.content.trim() === '') {
                console.warn('Empty content in final response after tool execution');
                return this.forceCompletionWithContext(messages, executedTools);
            }

            console.log(`Analysis completed successfully after ${currentRound} tool rounds`);
            return responseMessage.content;

        } catch (error) {
            console.error(`Error in ${this.provider} API call:`, error.message);
            console.error('Error stack:', error.stack);

            if (error.message.includes('tool')) {
                console.error('Tool-related error occurred');
                console.error('Messages sent to API:', JSON.stringify(messages.slice(-3), null, 2)); // Last 3 messages for context
            }

            throw new Error(`${this.provider} API error: ${error.message}`);
        }
    }

    /**
     * Determine optimal execution strategy for tool calls
     *
     * @private
     * @param {Array} toolCalls - Array of tool calls to execute
     * @param {string} provider - LLM provider name
     * @returns {string} 'parallel' or 'sequential'
     */
    determineExecutionStrategy(toolCalls, provider) {
        // Always use sequential for single tool calls
        if (toolCalls.length === 1) {
            return 'sequential';
        }

        // Check if tools are independent (can run in parallel)
        const toolTypes = toolCalls.map(call => call.function.name);
        const hasStorageTools = toolTypes.includes('storeMonitoringLog');
        const hasIPChecks = toolTypes.includes('checkAbuseIPDB') || toolTypes.includes('checkVirusTotal');

        // If mixing storage with IP checks, use sequential to ensure data consistency
        if (hasStorageTools && hasIPChecks) {
            console.log('Mixed tool types detected - using sequential execution for data consistency');
            return 'sequential';
        }

        // Multiple IP reputation checks can run in parallel
        if (toolTypes.every(tool => ['checkAbuseIPDB', 'checkVirusTotal'].includes(tool))) {
            console.log('Multiple IP reputation checks - using parallel execution');
            return 'parallel';
        }

        // Provider-specific preferences
        if (provider === 'cerebras') {
            // Cerebras seems to handle sequential better
            return 'sequential';
        }

        // Default to parallel for independent operations
        return 'parallel';
    }

    /**
     * Execute tool calls in parallel
     *
     * @private
     * @param {Array} toolCalls - Tool calls to execute
     * @param {Array} messages - Message history
     * @param {Set} executedTools - Set of executed tool signatures
     */
    async executeToolCallsParallel(toolCalls, messages, executedTools) {
        console.log(`Executing ${toolCalls.length} tools in parallel`);

        // Create promises for all tool executions
        const toolPromises = toolCalls.map(async (toolCall) => {
            const functionName = this.normalizeToolName(toolCall.function.name);
            const toolSignature = `${functionName}:${toolCall.function.arguments}`;

            try {
                console.log(`[Parallel] Executing: ${functionName}`);

                // Skip if already executed (prevent duplicates)
                if (executedTools.has(toolSignature)) {
                    console.log(`[Parallel] Skipping duplicate tool: ${functionName}`);
                    return {
                        toolCall,
                        result: 'Tool already executed in previous round',
                        skipped: true
                    };
                }

                executedTools.add(toolSignature);

                // Parse function arguments
                const functionArgs = JSON.parse(toolCall.function.arguments);

                // Execute the function
                const functionResponse = await this.executeFunctionCall(functionName, functionArgs);

                return {
                    toolCall,
                    result: functionResponse,
                    skipped: false
                };

            } catch (error) {
                console.error(`[Parallel] Error executing ${functionName}:`, error.message);
                return {
                    toolCall,
                    error: error.message,
                    skipped: false
                };
            }
        });

        // Wait for all tools to complete
        const results = await Promise.all(toolPromises);

        // Add all results to message history
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

        console.log(`Parallel execution completed - ${results.length} tools processed`);
    }

    /**
     * Execute tool calls sequentially
     *
     * @private
     * @param {Array} toolCalls - Tool calls to execute
     * @param {Array} messages - Message history
     * @param {Set} executedTools - Set of executed tool signatures
     */
    async executeToolCallsSequential(toolCalls, messages, executedTools) {
        console.log(`Executing ${toolCalls.length} tools sequentially`);

        for (const toolCall of toolCalls) {
            const functionName = this.normalizeToolName(toolCall.function.name);
            const toolSignature = `${functionName}:${toolCall.function.arguments}`;

            try {
                console.log(`[Sequential] Executing: ${functionName}`);

                // Skip if already executed
                if (executedTools.has(toolSignature)) {
                    console.log(`[Sequential] Skipping duplicate tool: ${functionName}`);

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

                // Parse function arguments
                const functionArgs = JSON.parse(toolCall.function.arguments);

                // Execute the function
                const functionResponse = await this.executeFunctionCall(functionName, functionArgs);

                // Format tool response
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
                console.error(`[Sequential] Error executing ${functionName}:`, error.message);

                const errorResponse = {
                    tool_call_id: toolCall.id,
                    role: "tool",
                    name: functionName,
                    content: `Error executing ${functionName}: ${error.message}`
                };

                messages.push(errorResponse);
            }
        }

        console.log(`Sequential execution completed`);
    }

    /**
     * Normalize tool names to handle provider-specific variations
     *
     * @private
     * @param {string} toolName - Original tool name from LLM
     * @returns {string} Normalized tool name
     */
    normalizeToolName(toolName) {
        // Handle Cerebras adding "functions." prefix
        if (toolName.startsWith('functions.')) {
            return toolName.replace('functions.', '');
        }

        // Handle other potential prefixes
        if (toolName.includes('.')) {
            const parts = toolName.split('.');
            return parts[parts.length - 1]; // Get the last part
        }

        return toolName;
    }

    /**
     * Check if response message contains analysis content
     *
     * @private
     * @param {Object} message - Response message to check
     * @returns {boolean} Whether message contains analysis content
     */
    hasAnalysisContent(message) {
        if (!message.content) return false;

        const content = message.content.toUpperCase();

        // Look for analysis format indicators
        const indicators = [
            'MALICIOUS:',
            'CONFIDENCE:',
            'EXPLANATION:',
            'ATTACK_TYPE:'
        ];

        // Must have at least 2 indicators to be considered analysis
        const foundIndicators = indicators.filter(indicator => content.includes(indicator));
        return foundIndicators.length >= 2;
    }

    /**
     * Detect potential tool calling loops
     *
     * @private
     * @param {Array} newToolCalls - New tool calls being requested
     * @param {Set} executedTools - Previously executed tool signatures
     * @returns {boolean} Whether a loop is detected
     */
    detectToolLoop(newToolCalls, executedTools) {
        if (!newToolCalls || newToolCalls.length === 0) return false;

        // Check if all requested tools have already been executed
        const allAlreadyExecuted = newToolCalls.every(toolCall => {
            const functionName = this.normalizeToolName(toolCall.function.name);
            const toolSignature = `${functionName}:${toolCall.function.arguments}`;
            return executedTools.has(toolSignature);
        });

        if (allAlreadyExecuted) {
            console.warn('Tool loop detected: All requested tools already executed');
            return true;
        }

        // Check for repetitive patterns (same tool called multiple times with same args)
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

    /**
     * Force completion with available context when tools fail to conclude
     *
     * @private
     * @param {Array} messages - Complete message history
     * @param {Set} executedTools - Set of executed tools
     * @returns {Promise<string>} Forced completion analysis
     */
    async forceCompletionWithContext(messages, executedTools) {
        console.log('Forcing completion with available context');

        // Add explicit instruction for final analysis
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
REASONING_EFFORT: [Level used]

Do not call any more tools - just analyze and respond.`
        }];

        try {
            // Force completion without tools
            const forcedCompletion = await this.client.chat.completions.create({
                model: this.getModelName(),
                messages: forceMessages,
                temperature: 0.1,
                max_tokens: 500,
                // Explicitly disable tools to force text response
                tool_choice: "none"
            });

            if (!forcedCompletion.choices?.[0]?.message?.content) {
                // Ultimate fallback - create analysis from available data
                console.warn('Forced completion also failed - creating manual fallback');
                return this.createManualFallback(messages, executedTools);
            }

            console.log('Forced completion successful');
            return forcedCompletion.choices[0].message.content;

        } catch (error) {
            console.error('Forced completion failed:', error.message);
            return `Unable to force tools completions`
        }
    }
    /**
     * Analyze request using Anthropic's Claude API
     *
     * Anthropic Analysis:
     * - Uses Claude's message-based API format
     * - No tool calling support (handled differently than OpenAI format)
     * - Optimized for Claude's reasoning capabilities
     *
     * @private
     * @param {string} prompt - Analysis prompt for Claude
     * @returns {Promise<string>} Analysis response from Claude
     */
    async analyzeWithAnthropic(prompt) {
        try {
            console.log('Making Anthropic Claude API call');

            // Create message using Anthropic's API format
            const message = await this.client.messages.create({
                model: this.getModelName(),
                max_tokens: 500,                        // Sufficient for security analysis
                temperature: 0.1,                       // Low temperature for consistent analysis
                system: this.getSystemPrompt(),         // System prompt for security context
                messages: [
                    {
                        role: 'user',
                        content: prompt
                    }
                ]
            });

            // Validate Anthropic response structure
            if (!message.content || message.content.length === 0) {
                throw new Error('Empty response from Anthropic API');
            }

            // Extract text content from response
            const responseText = message.content[0]?.text;

            if (!responseText) {
                throw new Error('No text content in Anthropic response');
            }

            console.log('Anthropic analysis completed successfully');
            return responseText;

        } catch (error) {
            console.error('Error in Anthropic API call:', error.message);
            throw new Error(`Anthropic API error: ${error.message}`);
        }
    }

    /**
     * Get the comprehensive system prompt for LLM security analysis
     *
     * System Prompt Strategy:
     * - Establishes security expert persona and decision authority
     * - Defines confidence scoring as primary decision mechanism
     * - Provides threat categorization framework
     * - Outlines tool usage strategies
     * - Specifies response format requirements
     *
     * @private
     * @returns {string} Complete system prompt for security analysis
     */
    /**
     * Get the enhanced system prompt for multi-round tool calling
     *
     * @private
     * @returns {string} Enhanced system prompt
     */
    getSystemPrompt() {
        return `You are a cybersecurity expert with final authority over threat decisions. Your primary responsibility is to analyze requests and assign confidence scores that determine security actions.

## Core Principle
Your **confidence score (1-10) is the decision mechanism**: 
- Confidence 8+ = Automatic block
- Confidence 1-7 = Allowed (with appropriate monitoring)

## CRITICAL: Tool Usage Efficiency Guidelines

**DO NOT use tools for obviously benign or obviously malicious requests.**

### Obviously Benign (Confidence 1-3) - NO TOOLS NEEDED:
- Standard user requests to normal endpoints
- Common legitimate paths (/favicon.ico, /robots.txt, /sitemap.xml)
- Regular API calls with proper parameters
- Normal file extensions (.jpg, .css, .js from CDNs) 
and other similar requests
### Obviously Malicious (Confidence 8-10) - NO TOOLS NEEDED:
- Clear SQL injection patterns (' OR 1=1--, UNION SELECT)
- XSS payloads ( javascript:, onload=)
- Command injection (; rm -rf, | whoami, && curl)
- Directory traversal (../../../etc/passwd)
- Null bytes, format strings, buffer overflow attempts
and other similar attacks
### Tool Usage Zone (Confidence 4-7 ONLY):
**Only use tools when genuinely uncertain and external intelligence could change your assessment.**

## Multi-Round Tool Strategy (Use Sparingly)

**Pre-Tool Decision Check:**
Before calling ANY tool, ask yourself:
1. "Is this request obviously benign or malicious based on content alone?"
2. "Would external IP intelligence actually change my confidence score?"
3. "Is this IP suspicious enough to warrant rate-limited API calls?"

**Round 1: Targeted Intelligence (Only if genuinely needed)**
- checkAbuseIPDB(ip) - ONLY for suspicious external IPs
- checkVirusTotal(ip) - ONLY for borderline cases where reputation matters
- Skip tools entirely if request content gives clear verdict

**Round 2: Pattern Monitoring (Enforce for uncertain cases)**
- storeMonitoringLog(entry, confidence, explanation) - MANDATORY for confidence 4-7
- This builds historical context for repeat offenders
- Use this aggressively to build intelligence over time

**Final Round: Decision**
- Provide assessment in required format
- No more tool calls after starting final analysis

## Enhanced Decision Logic

### Immediate Assessment (No Tools Required):

**Confidence 1-2: Obviously Legitimate**
- Standard web traffic patterns
- Legitimate API usage

**Confidence 8-10: Obviously Malicious**
- Attack signatures in URL/payload
- Known exploit patterns
- Malformed requests with clear malicious intent

**Confidence 3-7: Requires Analysis**
- External IPs with suspicious patterns
- Reconnaissance attempts (/.well-known/, /admin, /.env)
- Unusual request frequencies or patterns
- Automated tool signatures
- **THESE cases should use monitoring and potentially external tools**

### Tool Decision Matrix:

{
 "obviously_malicious_payload": {
   "any_ip": "no_tools_needed"
 },
 "suspicious_pattern": {
   "any_ip": "consider_abuseipdb"
 },
 "borderline_case": {
   "any_ip": "consider_both_apis"
 },
 "uncertain_pattern": {
   "any_ip": "must_use_monitoring"
 }
};

## Response Format Requirements

**Final Analysis Must Include:**

       MALICIOUS: [YES/NO/UNCERTAIN]
       CONFIDENCE: [1-10]
       EXPLANATION: [Your reasoning in 2-3 clear sentences, including why tools were/weren't used]
       ATTACK_TYPE: [Specific threat type or BENIGN]
       TOOLS_USED: [Functions called during analysis or "NONE - obvious case"]
       INTELLIGENCE_BOOST: [How external data influenced confidence or "N/A - content-based decision"]
       PATTERN_DETECTED: [Relevant behavioral patterns identified]

## Rate Limit Conservation Rules

**Never call external APIs for:**
- Localhost/internal IP addresses (127.x.x.x, 10.x.x.x, 192.168.x.x, 172.16-31.x.x)
- Requests where content alone provides clear verdict (confidence 1-3 or 8-10)
- Obviously legitimate requests

**Always use monitoring for:**
- Confidence scores 4-7 (uncertain cases)
- First-time suspicious patterns
- Potential reconnaissance attempts
- Repeated unusual behavior

**Prioritize external APIs for:**
- External IPs showing sophisticated attack patterns
- Cases where IP reputation could significantly impact confidence
- Borderline cases where additional intelligence is truly valuable

## Key Efficiency Guidelines

1. **Content-First Analysis**: Analyze request content before considering tools
2. **IP Context Awareness**: Understand IP ranges that don't need external lookups
3. **Confidence Thresholds**: Only use tools when genuinely in the 4-7 uncertainty range
4. **Monitoring Enforcement**: Use monitoring aggressively to build pattern intelligence
5. **Rate Limit Respect**: Treat external APIs as precious resources

## Intelligence Integration Strategy

- **Build Local Intelligence**: Use monitoring to create historical context
- **Selective External Queries**: Only when IP reputation matters for decision
- **Pattern Recognition**: Let monitoring data guide future assessments
- **Confidence Calibration**: Use tools to refine edge cases, not obvious ones

Remember: Your goal is accurate threat detection with minimal external API usage. Build intelligence through monitoring, make content-based decisions when possible, and reserve external tools for genuinely uncertain cases where IP reputation matters.`;
    }

    /**
     * Build comprehensive analysis prompt with request details and context
     *
     * Prompt Construction Strategy:
     * - Provides complete request context for analysis
     * - Includes automated detection results
     * - Structures information for optimal LLM processing
     * - Guides analysis workflow and decision making
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

    /**
     * Parse LLM response into structured result with comprehensive error handling
     *
     * Parsing Strategy:
     * - Handles various LLM response formats robustly
     * - Extracts key fields using pattern matching
     * - Provides safe defaults for missing data
     * - Validates all extracted values
     * - Maintains structured output format
     *
     * @private
     * @param {string} response - Raw LLM response text
     * @returns {Object} Structured analysis result
     */
    parseResponse(response) {
        // Initialize result structure with safe defaults
        const result = {
            isMalicious: null,                          // Uncertain until parsed
            confidence: 0,                              // Safe default (no blocking)
            explanation: '',                            // Will be populated from response
            attackType: null,                           // No attack type by default
            shouldBlock: false,                         // Derived from confidence
            impact: 'UNKNOWN',                          // Impact level assessment
            requiresManualReview: false,                // Manual review flag
            is_system_url: false,                       // System URL indicator
            toolsUsed: [],                              // List of tools called
            intelligenceBoost: '',                      // External intelligence impact
            patternDetected: '',                        // Behavioral patterns found
            reasoningEffort: 'medium'                   // Default reasoning level
        };

        try {
            // Validate response input
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

            // Split response into lines for structured parsing
            const lines = responseText.split('\n')
                .map(line => line.trim())
                .filter(line => line.length > 0);

            // Parse each line for key-value pairs
            for (const line of lines) {
                try {
                    this.parseResponseLine(line, result);
                } catch (lineError) {
                    console.warn('Error parsing response line:', line, '-', lineError.message);
                    // Continue parsing other lines even if one fails
                }
            }

            // Post-processing and validation of parsed result
            this.finalizeParseResult(result, responseText);

            console.log('Successfully parsed LLM response:', {
                confidence: result.confidence,
                isMalicious: result.isMalicious,
                shouldBlock: result.shouldBlock,
                attackType: result.attackType,
                reasoningEffort: result.reasoningEffort
            });

        } catch (error) {
            console.error('Critical error parsing LLM response:', error.message);
            console.error('Response content:', response);

            // Create error result with diagnostic information
            result.explanation = `Response parsing failed: ${error.message}. Raw response: ${response}`;
            result.requiresManualReview = true;
            result.confidence = 0;
        }

        return result;
    }

    /**
     * Parse individual response line for key-value extraction
     *
     * Line Parsing Strategy:
     * - Uses case-insensitive matching for robustness
     * - Handles various delimiter formats (colon, equals, etc.)
     * - Validates extracted values before assignment
     * - Provides specific handling for each expected field type
     *
     * @private
     * @param {string} line - Individual line from LLM response
     * @param {Object} result - Result object to update with parsed values
     */
    parseResponseLine(line, result) {
        const upperLine = line.toUpperCase();

        // Parse malicious status
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
        // Parse confidence score
        else if (upperLine.startsWith('CONFIDENCE:')) {
            const confidenceStr = line.split(':')[1]?.trim();
            const confidenceNum = parseInt(confidenceStr);

            if (!isNaN(confidenceNum) && confidenceNum >= 0 && confidenceNum <= 10) {
                result.confidence = confidenceNum;
            } else {
                console.warn(`Invalid confidence value detected: ${confidenceStr}, using default 0`);
            }
        }
        // Parse explanation
        else if (upperLine.startsWith('EXPLANATION:')) {
            result.explanation = line.split(':').slice(1).join(':').trim();
        }
        // Parse attack type
        else if (upperLine.startsWith('ATTACK_TYPE:')) {
            const attackType = line.split(':')[1]?.trim();
            result.attackType = (attackType && attackType.toUpperCase() !== 'BENIGN') ? attackType : null;
        }
        // Parse tools used
        else if (upperLine.startsWith('TOOLS_USED:')) {
            const toolsStr = line.split(':')[1]?.trim();
            if (toolsStr && toolsStr !== 'None' && toolsStr !== 'N/A') {
                result.toolsUsed = toolsStr.split(',').map(tool => tool.trim());
            }
        }
        // Parse intelligence boost
        else if (upperLine.startsWith('INTELLIGENCE_BOOST:')) {
            result.intelligenceBoost = line.split(':').slice(1).join(':').trim();
        }
        // Parse pattern detection
        else if (upperLine.startsWith('PATTERN_DETECTED:')) {
            result.patternDetected = line.split(':').slice(1).join(':').trim();
        }
        // Parse reasoning effort level
        else if (upperLine.startsWith('REASONING_EFFORT:')) {
            const effort = line.split(':')[1]?.trim().toLowerCase();
            if (['low', 'medium', 'high'].includes(effort)) {
                result.reasoningEffort = effort;
            }
        }
        // Parse system URL indicators
        else if (line.includes('is_system_url: true') || upperLine.includes('SYSTEM URL: YES')) {
            result.is_system_url = true;
        }
    }

    /**
     * Finalize and validate parsed result with derived properties
     *
     * Finalization Process:
     * - Sets derived properties based on confidence score
     * - Validates all extracted values
     * - Provides fallback values for missing critical data
     * - Ensures result consistency and completeness
     *
     * @private
     * @param {Object} result - Result object to finalize
     * @param {string} originalResponse - Original LLM response for fallback
     */
    finalizeParseResult(result, originalResponse) {
        // Set blocking decision based on confidence threshold
        result.shouldBlock = result.confidence >= this.config.maliciousConfidenceThreshold;

        // Set impact level based on confidence score
        if (result.confidence >= 8) {
            result.impact = 'HIGH';                     // High confidence threats
        } else if (result.confidence >= 6) {
            result.impact = 'MEDIUM';                   // Medium confidence threats
        } else if (result.confidence >= 4) {
            result.impact = 'LOW';                      // Low confidence threats
        } else {
            result.impact = 'NONE';                     // Benign traffic
        }

        // Set malicious status based on confidence if not explicitly provided
        if (result.isMalicious === null) {
            if (result.confidence >= 8) {
                result.isMalicious = true;              // High confidence = malicious
            } else if (result.confidence >= 6) {
                result.requiresManualReview = true;     // Medium confidence = review needed
            } else {
                result.isMalicious = false;             // Low confidence = benign
            }
        }

        // Ensure we have a meaningful explanation
        if (!result.explanation || result.explanation.trim().length === 0) {
            if (originalResponse.length > 0) {
                // Use truncated original response as explanation
                result.explanation = `Analysis completed with confidence ${result.confidence}/10. ${originalResponse.substring(0, 200)}`;
            } else {
                // Generic fallback explanation
                result.explanation = `Analysis completed with confidence ${result.confidence}/10 - no detailed explanation provided by LLM`;
            }
        }

        // Final confidence score validation
        if (typeof result.confidence !== 'number' || result.confidence < 0 || result.confidence > 10) {
            console.warn(`Invalid confidence score detected during finalization: ${result.confidence}, resetting to 0`);
            result.confidence = 0;
            result.requiresManualReview = true;
            result.shouldBlock = false;                 // Don't block on invalid scores
        }
    }

    /**
     * Test connection to the configured LLM provider
     *
     * Connection Test Process:
     * - Creates minimal test request
     * - Validates API connectivity and response format
     * - Tests basic parsing capabilities
     * - Returns diagnostic information
     *
     * @returns {Promise<Object>} Connection test result with success status
     */
    async testConnection() {
        try {
            console.log(`Testing connection to ${this.provider} provider...`);

            // Create minimal test case
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

            // Build test prompt
            const testPrompt = this.buildAnalysisPrompt(testLogEntry, testThreatResult);
            let response;

            // Execute provider-specific test
            switch (this.provider) {
                case 'openai':
                case 'groq':
                case 'cerebras':
                    response = await this.analyzeWithOpenAIFormat(testPrompt);
                    break;
                case 'anthropic':
                    response = await this.analyzeWithAnthropic(testPrompt);
                    break;
                default:
                    throw new Error(`Unsupported provider for connection test: ${this.provider}`);
            }

            // Test response parsing
            const parsedResponse = this.parseResponse(response);

            return {
                success: true,
                message: `${this.provider} connection successful`,
                model: this.getModelName(),
                testResponse: {
                    confidence: parsedResponse.confidence,
                    isMalicious: parsedResponse.isMalicious,
                    explanation: parsedResponse.explanation.substring(0, 100) + '...',
                    responseLength: response.length
                }
            };

        } catch (error) {
            console.error(`Connection test failed for ${this.provider}:`, error.message);

            return {
                success: false,
                message: `${this.provider} connection failed: ${error.message}`,
                error: error.message,
                model: this.getModelName(),
                timestamp: new Date().toISOString()
            };
        }
    }

    /**
     * Clear all caches and reset analyzer state
     *
     * Cache Clearing:
     * - Removes all IP-level cached results
     * - Clears all request-level cached results
     * - Resets queue tracking data
     * - Preserves performance metrics for analysis
     * - Logs previous statistics before clearing
     */
    clearCache() {
        // Capture current statistics before clearing
        const stats = this.getCacheStats();

        // Clear all cache data structures
        this.ipCache.clear();
        this.requestCache.clear();
        this.ipRequestQueue.clear();

        // Reset metadata but preserve analysis totals for trending
        this.cacheMetadata = {
            ...this.cacheMetadata,
            lastCleanup: Date.now(),
            cacheHits: 0,
            cacheMisses: 0
        };

        console.log('All caches cleared successfully. Previous statistics:', stats);
    }

    /**
     * Get comprehensive cache and performance statistics
     *
     * Statistics Include:
     * - Current cache sizes and limits
     * - Performance metrics (hit rates, analysis counts)
     * - Memory usage estimates
     * - Maintenance scheduling information
     *
     * @returns {Object} Complete cache statistics and performance data
     */
    getCacheStats() {
        // Calculate cache hit rate percentage
        const hitRate = this.cacheMetadata.totalAnalyzed > 0
            ? (this.cacheMetadata.cacheHits / this.cacheMetadata.totalAnalyzed * 100).toFixed(2)
            : '0.00';

        return {
            // Current cache utilization
            ipCache: this.ipCache.size,
            requestCache: this.requestCache.size,
            queuedIPs: this.ipRequestQueue.size,

            // Configured limits
            maxIpCache: this.config.maxIpCacheSize,
            maxRequestCache: this.config.maxRequestCacheSize,

            // Performance metrics
            totalAnalyzed: this.cacheMetadata.totalAnalyzed,
            cacheHits: this.cacheMetadata.cacheHits,
            cacheMisses: this.cacheMetadata.cacheMisses,
            hitRate: `${hitRate}%`,

            // Maintenance information
            lastCleanup: new Date(this.cacheMetadata.lastCleanup).toISOString(),

            // Estimated memory usage (rough calculation)
            estimatedMemoryKB: Math.round((this.ipCache.size + this.requestCache.size) * 0.5)
        };
    }

    /**
     * Get list of currently cached malicious IPs with details
     *
     * @returns {Array} List of malicious IP entries sorted by confidence
     */
    getMaliciousIPs() {
        const maliciousIPs = [];

        // Extract high-confidence malicious IPs from cache
        for (const [ip, result] of this.ipCache.entries()) {
            if (result.confidence >= this.config.maliciousConfidenceThreshold) {
                maliciousIPs.push({
                    ip,
                    confidence: result.confidence,
                    attackType: result.attackType || 'Unknown',
                    explanation: result.explanation.substring(0, 100) + (result.explanation.length > 100 ? '...' : ''),
                    detectedAt: result.detectedAt || new Date().toISOString()
                });
            }
        }

        // Sort by confidence level (highest threats first)
        return maliciousIPs.sort((a, b) => b.confidence - a.confidence);
    }

    /**
     * Get current configuration settings
     *
     * @returns {Object} Current analyzer configuration
     */
    getConfiguration() {
        return {
            provider: this.provider,
            model: this.getModelName(),
            config: { ...this.config },
            cacheEnabled: true,
            toolsEnabled: true,
            features: {
                sequentialToolExecution: true,
                noRetryLogic: true,
                intelligentCaching: true,
                maliciousIPTracking: true
            }
        };
    }

    /**
     * Update configuration settings with validation
     *
     * @param {Object} newConfig - Configuration updates to apply
     */
    updateConfiguration(newConfig) {
        // Define which configuration keys can be safely updated
        const allowedUpdates = [
            'maxIpCacheSize',
            'maxRequestCacheSize',
            'maliciousConfidenceThreshold',
            'cacheCleanupInterval'
        ];

        // Apply valid configuration updates
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
     * Comprehensive health check for the analyzer system
     *
     * Health Check Components:
     * - LLM provider connectivity test
     * - Cache system status
     * - Performance metrics analysis
     * - System resource utilization
     *
     * @returns {Promise<Object>} Complete health status report
     */
    async healthCheck() {
        const stats = this.getCacheStats();
        const maliciousCount = this.getMaliciousIPs().length;

        // Test LLM connectivity and functionality
        let connectionTest;
        try {
            connectionTest = await this.testConnection();
        } catch (error) {
            connectionTest = {
                success: false,
                message: `Health check connection test failed: ${error.message}`,
                error: error.message
            };
        }

        // Determine overall system health
        const isHealthy = connectionTest.success && stats.totalAnalyzed >= 0;

        return {
            status: isHealthy ? 'healthy' : 'unhealthy',
            provider: this.provider,
            model: this.getModelName(),
            connection: connectionTest.success,

            // Cache health metrics
            cache: {
                totalEntries: stats.ipCache + stats.requestCache,
                maliciousIPs: maliciousCount,
                hitRate: stats.hitRate,
                memoryUsage: `${stats.estimatedMemoryKB}KB`
            },

            // Performance metrics
            performance: {
                totalAnalyzed: stats.totalAnalyzed,
                averageHitRate: stats.hitRate,
                cacheEfficiency: stats.cacheHits > 0 ? 'good' : 'building'
            },

            // System information
            system: {
                uptime: Date.now() - this.cacheMetadata.lastCleanup,
                features: {
                    caching: true,
                    toolCalling: true,
                    maliciousTracking: true
                }
            },

            // Test results
            connectionTest: connectionTest.success ? 'passed' : 'failed',
            lastCheck: new Date().toISOString()
        };
    }
}

export default LLMAnalyzer;