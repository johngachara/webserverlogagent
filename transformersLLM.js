import path from 'path';
import { fileURLToPath } from 'url';
import { cpus } from 'os';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/**
 * TransformersLLM - Optimized Ollama-powered Security Analyzer with Reasoning Support
 * Enhanced for reasoning models with thinking tag handling and real-time display
 */
class TransformersLLM {
    constructor(options = {}) {
        // Ollama configuration - optimized for CPU
        this.ollamaHost = options.ollamaHost || 'http://localhost:11434';

        // Use faster model for speed - consider switching to smaller reasoning model
        this.modelName = options.modelName || 'qwen3:1.7b'; // Smaller model for speed

        // Optimized parameters for fast reasoning
        this.temperature = options.temperature || 0.1; // Lower for faster, more focused reasoning
        this.maxTokens = options.maxTokens || 500; // Reduced for faster responses
        this.numCtx = options.numCtx || 2048; // Smaller context for speed
        this.reasoningMode = options.reasoningMode || 'fast'; // 'fast', 'balanced', 'thorough'

        // CPU optimization settings - ES module compatible
        this.numThread = options.numThread || this.getOptimalThreadCount();
        this.numGpu = 0; // Force CPU-only

        // Thinking display settings - simplified
        this.enableThinkingDisplay = options.enableThinkingDisplay !== false;

        // Runtime state
        this.isInitialized = false;
        this.ollamaAvailable = false;
        this.modelReady = false;

        // Performance tracking
        this.stats = {
            totalAnalyzed: 0,
            benignCount: 0,
            maliciousCount: 0,
            uncertainCount: 0,
            averageResponseTime: 0,
            averageThinkingTime: 0,
            initializationTime: null
        };

        console.log(`TransformersLLM initializing with reasoning model support`);
        console.log(`Ollama host: ${this.ollamaHost}`);
        console.log(`Model: ${this.modelName} (speed optimized)`);
        console.log(`Reasoning mode: ${this.reasoningMode}`);
        console.log(`CPU threads: ${this.numThread}`);
        console.log(`Max tokens: ${this.maxTokens} (reduced for speed)`);
        console.log(`Thinking display: ${this.enableThinkingDisplay ? 'enabled' : 'disabled'}`);
    }

    /**
     * Display final thinking content (no streaming)
     */
    displayThinking(thinkingText) {
        if (!this.enableThinkingDisplay || !thinkingText) return;

        console.log('\n[THINKING]');
        console.log(thinkingText.replace(/<\/?think>/g, '').trim());
        console.log('[THINKING COMPLETE]');
    }

    /**
     * Calculate optimal thread count for CPU inference
     */
    getOptimalThreadCount() {
        try {
            const cpuCount = cpus().length;
            const halfCores = Math.max(1, Math.floor(cpuCount / 2));

            let optimalThreads;
            if (cpuCount <= 2) {
                optimalThreads = 1;
            } else if (cpuCount <= 4) {
                optimalThreads = 2;
            } else if (cpuCount <= 8) {
                optimalThreads = Math.min(4, halfCores);
            } else if (cpuCount <= 16) {
                optimalThreads = Math.min(6, halfCores);
            } else {
                optimalThreads = Math.min(8, halfCores);
            }

            console.log(`CPU detection: ${cpuCount} cores detected, using ${optimalThreads} threads for inference`);
            return optimalThreads;

        } catch (error) {
            console.warn('Could not detect CPU count, defaulting to 2 threads:', error.message);
            return 2;
        }
    }

    /**
     * Check if Ollama is running and accessible
     */
    async checkOllamaStatus() {
        try {
            const response = await fetch(`${this.ollamaHost}/api/version`);
            if (response.ok) {
                const data = await response.json();
                console.log(`✓ Ollama available, version: ${data.version || 'unknown'}`);
                return true;
            } else {
                console.error(`❌ Ollama responded with status: ${response.status}`);
                return false;
            }
        } catch (error) {
            console.error(`❌ Ollama not accessible: ${error.message}`);
            return false;
        }
    }

    /**
     * Check if the specified model is available in Ollama
     */
    async checkModelAvailability() {
        try {
            const response = await fetch(`${this.ollamaHost}/api/tags`);
            if (!response.ok) {
                throw new Error(`Failed to get model list: ${response.status}`);
            }

            const data = await response.json();
            const availableModels = data.models || [];

            const modelExists = availableModels.some(model =>
                model.name === this.modelName ||
                model.name.startsWith(this.modelName.split(':')[0])
            );

            if (modelExists) {
                console.log(`✓ Model ${this.modelName} is available`);
                return true;
            } else {
                console.log(`❌ Model ${this.modelName} not found`);
                console.log('Available models:', availableModels.map(m => m.name).join(', '));
                console.log(`Attempting to pull model ${this.modelName}...`);
                return await this.pullModel();
            }
        } catch (error) {
            console.error(`Error checking model availability: ${error.message}`);
            return false;
        }
    }

    /**
     * Pull the model from Ollama registry
     */
    async pullModel() {
        try {
            console.log(`Pulling model ${this.modelName}... This may take a while.`);

            const response = await fetch(`${this.ollamaHost}/api/pull`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    name: this.modelName
                })
            });

            if (!response.ok) {
                throw new Error(`Failed to pull model: ${response.status}`);
            }

            const reader = response.body.getReader();
            const decoder = new TextDecoder();

            while (true) {
                const { done, value } = await reader.read();
                if (done) break;

                const chunk = decoder.decode(value);
                const lines = chunk.split('\n').filter(line => line.trim());

                for (const line of lines) {
                    try {
                        const data = JSON.parse(line);
                        if (data.status) {
                            console.log(`Pull progress: ${data.status}`);
                        }
                        if (data.error) {
                            throw new Error(data.error);
                        }
                    } catch (parseError) {
                        // Ignore JSON parse errors in streaming response
                    }
                }
            }

            console.log(`✓ Model ${this.modelName} pulled successfully`);
            return true;

        } catch (error) {
            console.error(`Failed to pull model: ${error.message}`);
            return false;
        }
    }

    async initialize() {
        if (this.isInitialized) {
            console.log('TransformersLLM already initialized');
            return;
        }

        const startTime = Date.now();

        try {
            console.log('Checking Ollama availability...');
            this.ollamaAvailable = await this.checkOllamaStatus();

            if (!this.ollamaAvailable) {
                throw new Error('Ollama is not running. Please start Ollama first.');
            }

            console.log('Checking model availability...');
            this.modelReady = await this.checkModelAvailability();

            if (!this.modelReady) {
                throw new Error(`Model ${this.modelName} is not available and could not be pulled.`);
            }

            const initTime = Date.now() - startTime;
            this.stats.initializationTime = initTime;
            this.isInitialized = true;

            console.log(`TransformersLLM initialized successfully in ${initTime}ms`);
            await this.validateModel();

        } catch (error) {
            console.error('TransformersLLM initialization failed:', error.message);
            throw new Error(`Failed to initialize Ollama model: ${error.message}`);
        }
    }

    async validateModel() {
        try {
            console.log('Validating reasoning model with test prompt...');

            const testResult = await this.generateResponse(
                this.buildReasoningPrompt({
                    ip: '127.0.0.1',
                    method: 'GET',
                    url: '/test',
                    queryString: '',
                    userAgent: 'Test-Validator/1.0'
                })
            );

            if (testResult && testResult.trim().length > 0) {
                console.log('✓ Model validation successful');
                console.log('Test response preview:', testResult.substring(0, 200) + '...');
            } else {
                console.warn('Model validation produced empty response');
            }

        } catch (error) {
            console.warn('Model validation failed:', error.message);
        }
    }

    /**
     * Generate response using Ollama API without streaming
     */
    async generateResponse(prompt, options = {}) {
        try {
            const requestBody = {
                model: this.modelName,
                prompt: prompt,
                stream: false, // No streaming - get complete response
                options: {
                    // Speed-optimized generation parameters
                    temperature: options.temperature || this.temperature,
                    num_predict: options.maxTokens || this.maxTokens,
                    num_ctx: this.numCtx,
                    num_thread: this.numThread,
                    num_gpu: this.numGpu,

                    // Fast sampling for quicker responses
                    top_p: 0.7, // More focused sampling
                    top_k: 10,  // Smaller candidate pool for speed
                    repeat_penalty: 1.05, // Lower penalty for speed

                    // Aggressive stopping for faster completion
                    stop: ["JSON:", "\n\n\n", "---", "<END>"]
                }
            };

            console.log(`[GENERATE] Sending prompt (${prompt.length} chars) - non-streaming`);

            const response = await fetch(`${this.ollamaHost}/api/generate`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(requestBody),
                signal: AbortSignal.timeout(60000) // Reduced to 20 seconds for faster responses
            });

            if (!response.ok) {
                throw new Error(`Ollama API error: ${response.status} ${response.statusText}`);
            }

            const data = await response.json();
            if (data.error) {
                throw new Error(`Ollama error: ${data.error}`);
            }

            const fullResponse = data.response || '';
            console.log(`[GENERATE] Received complete response (${fullResponse.length} chars)`);

            // Extract and display thinking if present
            const thinkMatch = fullResponse.match(/<think>([\s\S]*?)<\/think>/);
            if (thinkMatch) {
                this.displayThinking(thinkMatch[1]);
            }

            return fullResponse;

        } catch (error) {
            if (error.name === 'TimeoutError') {
                throw new Error('Model response timeout (20s) - switching to faster mode recommended');
            }
            throw error;
        }
    }

    /**
     * Build speed-optimized reasoning prompt based on mode
     */
    buildReasoningPrompt(logEntry) {
        const request = `${logEntry.method || 'GET'} ${logEntry.url || '/'}${logEntry.queryString ? '?' + logEntry.queryString : ''}`;
        const ip = logEntry.ip || 'unknown';
        const userAgent = (logEntry.userAgent || 'unknown').substring(0, 150);

        // Different prompt intensities based on reasoning mode
        if (this.reasoningMode === 'fast') {
            return this.buildFastPrompt(request, ip, userAgent);
        } else if (this.reasoningMode === 'balanced') {
            return this.buildBalancedPrompt(request, ip, userAgent);
        } else {
            return this.buildThoroughPrompt(request, ip, userAgent);
        }
    }

    /**
     * Ultra-fast reasoning prompt - minimal thinking
     */
    buildFastPrompt(request, ip, userAgent) {
        return `Evaluate if this web request follows normal website interaction patterns:
Does this look like someone browsing a website normally? Quick yes/no check.
Request: ${request}
IP: ${ip}
Agent: ${userAgent}
Simple classification:
- SAFE: Regular webpage visits, downloading files, standard API calls, typical user actions
- THREAT: System file access, unusual paths, uncommon parameter patterns, non-web resources
- UNCERTAIN: Could be either depending on context

Focus only on: Does this request match how people typically interact with websites?

Respond exactly:
{
  "result": "SAFE",
  "confidence": 8,
  "reason": "brief explanation"
}
JSON:`;
    }

    /**
     * Balanced reasoning prompt - moderate thinking
     */
    buildBalancedPrompt(request, ip, userAgent) {
        return `Security analysis of web request:

<think>
1. Check URL and method for obvious threats
2. Examine parameters for injection patterns
3. Review User-Agent for bot signatures
4. Make classification decision
</think>

Request: ${request}
Source: ${ip}
User-Agent: ${userAgent}

Classify as:
- SAFE: Legitimate traffic (home, API, resources)
- THREAT: Attack patterns (injection, traversal, scanning)
- UNCERTAIN: Suspicious but unclear (unusual params, uncommon paths)

You must respond with this exact JSON format:
{
  "result": "SAFE",
  "confidence": 7,
  "reason": "key finding"
}

JSON:`;
    }

    /**
     * Thorough reasoning prompt - detailed thinking
     */
    buildThoroughPrompt(request, ip, userAgent) {
        return `You are a cybersecurity expert analyzing web requests for threats.

<think>
Step by step analysis:
1. Examine the HTTP method and URL path for suspicious patterns
2. Check query parameters for injection attempts or malicious payloads  
3. Analyze the source IP for known threat indicators
4. Review the User-Agent for bot/scanner signatures or anomalies
5. Consider the overall context and threat likelihood
6. Decide on classification and confidence level
</think>

Request Details:
- Request: ${request}
- Source IP: ${ip}
- User-Agent: ${userAgent}

Classification Guidelines:
- SAFE: Normal legitimate requests (home pages, static resources, standard API calls)
- THREAT: Clear malicious activity (SQL injection, XSS, path traversal, known attack patterns)
- UNCERTAIN: Suspicious but ambiguous (unusual parameters, uncommon paths, need more context)

You must respond with this exact JSON format:
{
  "result": "SAFE",
  "confidence": 8,
  "reason": "brief explanation focusing on key indicators"
}

JSON:`;
    }

    async analyze(logEntry) {
        if (!this.isInitialized) {
            throw new Error('TransformersLLM not initialized. Call initialize() first.');
        }

        const startTime = Date.now();
        let thinkingTime = 0;

        try {
            console.log(`\n[ANALYSIS] Analyzing: ${logEntry.method || 'GET'} ${logEntry.url || '/'} from ${logEntry.ip}`);

            const prompt = this.buildReasoningPrompt(logEntry);


            const thinkingStart = Date.now();
            const result = await this.generateResponse(prompt);
            const responseTime = Date.now() - startTime;

            // Calculate thinking time (approximate based on thinking tags presence)
            if (result.includes('<think>') && result.includes('</think>')) {
                thinkingTime = Math.max(0, responseTime - 1000); // Rough estimate
            }

            if (!result || result.trim().length === 0) {
                throw new Error('No response generated from reasoning model');
            }

            const analysisResult = this.parseReasoningResponse(result, responseTime, thinkingTime);
            this.updateStats(analysisResult, responseTime, thinkingTime);

            return analysisResult;

        } catch (error) {
            console.error('[ANALYSIS] Error:', error.message);

            return {
                decision: 'UNCERTAIN',
                confidence: 0,
                explanation: `Analysis error: ${error.message}`,
                requiresSecondaryAnalysis: true,
                tier: 'primary',
                error: true,
                responseTime: Date.now() - startTime,
                thinkingTime: 0
            };
        }
    }

    /**
     * Parse response from reasoning model, handling thinking tags
     */
    parseReasoningResponse(rawResponse, responseTime, thinkingTime) {
        console.log(`\n[PARSING] Processing reasoning response (${rawResponse.length} chars)`);
        console.log(`[PARSING] Raw response: "${rawResponse}"`);

        let decision = 'UNCERTAIN';
        let confidence = 5;
        let explanation = 'Could not parse response';
        let requiresSecondaryAnalysis = true;
        let parseMethod = 'reasoning_json';
        let thinkingContent = '';

        try {
            // Extract thinking content if present
            const thinkingMatch = rawResponse.match(/<think>([\s\S]*?)<\/think>/);
            if (thinkingMatch) {
                thinkingContent = thinkingMatch[1].trim();
                console.log(`[PARSING] Extracted thinking content (${thinkingContent.length} chars)`);
            }

            // Remove thinking tags and extract JSON
            let cleanResponse = rawResponse
                .replace(/<think>[\s\S]*?<\/think>/g, '')
                .replace(/<\/?think>/g, '')
                .trim();

            console.log(`[PARSING] Clean response after removing thinking: "${cleanResponse}"`);

            // More aggressive JSON extraction - look for any JSON pattern
            let jsonMatch = cleanResponse.match(/\{[\s\S]*?\}/);

            // If no complete JSON, try to find JSON starting with {
            if (!jsonMatch) {
                console.log('[PARSING] No complete JSON found, looking for partial JSON...');

                // Look for JSON starting pattern
                const jsonStart = cleanResponse.indexOf('{');
                if (jsonStart !== -1) {
                    let potentialJson = cleanResponse.substring(jsonStart);

                    // Try to complete the JSON if it seems truncated
                    if (!potentialJson.includes('}')) {
                        // Try to construct basic JSON from content
                        if (cleanResponse.includes('SAFE') || cleanResponse.includes('safe')) {
                            potentialJson = '{"result": "SAFE", "confidence": 7, "reason": "appears safe"}';
                        } else if (cleanResponse.includes('THREAT') || cleanResponse.includes('threat') || cleanResponse.includes('malicious')) {
                            potentialJson = '{"result": "THREAT", "confidence": 7, "reason": "threat detected"}';
                        } else {
                            potentialJson = '{"result": "UNCERTAIN", "confidence": 5, "reason": "needs review"}';
                        }
                    }

                    jsonMatch = [potentialJson];
                    console.log(`[PARSING] Constructed/found JSON: "${jsonMatch[0]}"`);
                }
            }

            if (!jsonMatch) {
                throw new Error('No JSON found in response');
            }

            let jsonStr = jsonMatch[0].trim();
            console.log(`[PARSING] Extracted JSON: ${jsonStr}`);

            // Parse JSON
            let parsedData;
            try {
                parsedData = JSON.parse(jsonStr);
                console.log(`[PARSING] Successfully parsed JSON:`, parsedData);
            } catch (jsonError) {
                console.log(`[PARSING] JSON parse failed, attempting to fix: ${jsonError.message}`);

                // Try to fix common JSON issues
                let fixedJson = jsonStr
                    .replace(/'/g, '"')  // Replace single quotes
                    .replace(/([{,]\s*)([a-zA-Z_][a-zA-Z0-9_]*)\s*:/g, '$1"$2":')  // Quote keys
                    .replace(/:\s*([^",\{\[\d\s][^",\}\]]*)\s*([,\}])/g, ': "$1"$2')  // Quote string values
                    .replace(/,\s*}/g, '}')  // Remove trailing commas
                    .replace(/,\s*]/g, ']');

                console.log(`[PARSING] Fixed JSON attempt: "${fixedJson}"`);
                parsedData = JSON.parse(fixedJson);
                parseMethod = 'reasoning_json_fixed';
            }

            // Extract values from parsed JSON
            if (parsedData && typeof parsedData === 'object') {
                // Map result to our decision format
                if (parsedData.result) {
                    const result = parsedData.result.toString().toUpperCase();
                    console.log(`[PARSING] Found result: "${result}"`);

                    if (result === 'SAFE') {
                        decision = 'BENIGN';
                        requiresSecondaryAnalysis = false;
                    } else if (result === 'THREAT') {
                        decision = 'MALICIOUS';
                        requiresSecondaryAnalysis = false;
                    } else if (result === 'UNCERTAIN') {
                        decision = 'UNCERTAIN';
                        requiresSecondaryAnalysis = true;
                    }
                }

                // Extract confidence
                if (parsedData.confidence !== undefined) {
                    const conf = parseInt(parsedData.confidence);
                    if (!isNaN(conf)) {
                        confidence = Math.min(10, Math.max(1, conf));
                    }
                }

                // Extract reason
                if (parsedData.reason && typeof parsedData.reason === 'string') {
                    explanation = parsedData.reason.trim();

                    // Clean up explanation
                    if (explanation.length > 250) {
                        const truncated = explanation.substring(0, 250);
                        const lastPeriod = truncated.lastIndexOf('.');
                        explanation = lastPeriod > 50 ? truncated.substring(0, lastPeriod + 1) : truncated + '...';
                    }
                }

                console.log(`[PARSING] Final extracted values: result=${decision}, confidence=${confidence}, reason="${explanation}"`);
            }

        } catch (parseError) {
            console.error('[PARSING] All JSON parse attempts failed:', parseError.message);
            parseMethod = 'reasoning_fallback';

            // Enhanced fallback to text analysis
            const upperResponse = rawResponse.toUpperCase();
            console.log(`[PARSING] Using text fallback analysis on: "${upperResponse.substring(0, 100)}..."`);

            if (upperResponse.includes('SAFE') || upperResponse.includes('BENIGN') || upperResponse.includes('LEGITIMATE') ||
                upperResponse.includes('NORMAL') || upperResponse.includes('OK')) {
                decision = 'BENIGN';
                confidence = 6;
                explanation = 'Identified as safe through text analysis';
                requiresSecondaryAnalysis = false;
            } else if (upperResponse.includes('THREAT') || upperResponse.includes('MALICIOUS') || upperResponse.includes('ATTACK') ||
                upperResponse.includes('INJECTION') || upperResponse.includes('EXPLOIT')) {
                decision = 'MALICIOUS';
                confidence = 6;
                explanation = 'Threat indicators found in analysis';
                requiresSecondaryAnalysis = false;
            } else {
                decision = 'UNCERTAIN';
                confidence = 4;
                explanation = 'Response parsing failed - requires review';
                requiresSecondaryAnalysis = true;
            }
        }

        console.log(`[PARSING] Final result: ${decision} (confidence: ${confidence}) - "${explanation}"`);

        return {
            decision,
            confidence,
            explanation,
            requiresSecondaryAnalysis,
            tier: 'primary',
            model: 'ollama-reasoning',
            modelName: this.modelName,
            responseTime,
            thinkingTime,
            rawResponse: rawResponse,
            thinkingContent: thinkingContent.substring(0, 300),
            timestamp: new Date().toISOString(),
            parseMethod
        };
    }

    updateStats(result, responseTime, thinkingTime = 0) {
        this.stats.totalAnalyzed++;

        switch (result.decision) {
            case 'BENIGN': this.stats.benignCount++; break;
            case 'MALICIOUS': this.stats.maliciousCount++; break;
            case 'UNCERTAIN': this.stats.uncertainCount++; break;
        }

        this.stats.averageResponseTime =
            (this.stats.averageResponseTime * (this.stats.totalAnalyzed - 1) + responseTime) / this.stats.totalAnalyzed;

        this.stats.averageThinkingTime =
            (this.stats.averageThinkingTime * (this.stats.totalAnalyzed - 1) + thinkingTime) / this.stats.totalAnalyzed;
    }

    async testConnection() {
        try {
            if (!this.isInitialized) {
                await this.initialize();
            }

            const testStart = Date.now();

            const testResult = await this.analyze({
                ip: '192.168.1.100',
                method: 'GET',
                url: '/api/test',
                queryString: 'param=value',
                userAgent: 'Test-Browser/2.0'
            });

            const testTime = Date.now() - testStart;

            return {
                success: true,
                message: 'Reasoning model connection successful',
                model: 'ollama-reasoning',
                modelName: this.modelName,
                ollamaHost: this.ollamaHost,
                features: {
                    reasoningSupport: true,
                    thinkingDisplay: this.enableThinkingDisplay,
                    streamingRemoved: true,
                    enhancedPrompting: true
                },
                optimizations: {
                    cpuThreads: this.numThread,
                    contextSize: this.numCtx,
                    maxTokens: this.maxTokens
                },
                testTime,
                testResult: {
                    decision: testResult.decision,
                    confidence: testResult.confidence,
                    explanation: testResult.explanation,
                    responseTime: testResult.responseTime,
                    thinkingTime: testResult.thinkingTime,
                    hasThinking: testResult.thinkingContent?.length > 0
                },
                stats: this.getStats()
            };

        } catch (error) {
            return {
                success: false,
                message: `Reasoning model connection failed: ${error.message}`,
                model: 'ollama-reasoning',
                modelName: this.modelName,
                error: error.message,
                troubleshooting: {
                    steps: [
                        '1. Install Ollama: curl -fsSL https://ollama.ai/install.sh | sh',
                        '2. Start Ollama: ollama serve',
                        '3. Pull reasoning model: ollama pull qwen2.5-coder:7b',
                        '4. Verify: ollama list'
                    ],
                    features: [
                        'Enhanced reasoning with <think> tags',
                        'Final thinking display (no streaming)',
                        'Improved uncertainty handling',
                        'Speed-optimized prompting',
                        'Multiple reasoning modes (fast/balanced/thorough)'
                    ]
                }
            };
        }
    }

    getStats() {
        const total = this.stats.totalAnalyzed;
        return {
            model: 'ollama-reasoning',
            modelName: this.modelName,
            ollamaHost: this.ollamaHost,
            features: {
                reasoningSupport: true,
                thinkingDisplay: this.enableThinkingDisplay,
                streamingResponse: false
            },
            initialized: this.isInitialized,
            totalAnalyzed: total,
            benignCount: this.stats.benignCount,
            maliciousCount: this.stats.maliciousCount,
            uncertainCount: this.stats.uncertainCount,
            averageResponseTime: Math.round(this.stats.averageResponseTime),
            averageThinkingTime: Math.round(this.stats.averageThinkingTime),
            distributionPercent: {
                benign: total > 0 ? ((this.stats.benignCount / total) * 100).toFixed(1) : '0.0',
                malicious: total > 0 ? ((this.stats.maliciousCount / total) * 100).toFixed(1) : '0.0',
                uncertain: total > 0 ? ((this.stats.uncertainCount / total) * 100).toFixed(1) : '0.0'
            },
            performanceMetrics: {
                primaryResolutionRate: total > 0 ? (((total - this.stats.uncertainCount) / total) * 100).toFixed(1) + '%' : '0.0%',
                escalationRate: total > 0 ? ((this.stats.uncertainCount / total) * 100).toFixed(1) + '%' : '0.0%'
            }
        };
    }

    resetStats() {
        this.stats = {
            totalAnalyzed: 0,
            benignCount: 0,
            maliciousCount: 0,
            uncertainCount: 0,
            averageResponseTime: 0,
            averageThinkingTime: 0,
            initializationTime: this.stats.initializationTime
        };
        console.log('Reasoning model statistics reset');
    }

    getModelInfo() {
        return {
            model: 'ollama-reasoning',
            modelName: this.modelName,
            ollamaHost: this.ollamaHost,
            capabilities: {
                reasoning: true,
                thinking: true,
                streaming: true,
                uncertainty: true
            },
            initialized: this.isInitialized
        };
    }

    clearHistory() {
        console.log('Ollama reasoning model is stateless - no history to clear');
    }

    async dispose() {
        try {
            console.log('Disposing reasoning model resources...');
            this.isInitialized = false;
            console.log('Reasoning model disposed successfully');
        } catch (error) {
            console.warn('Error during disposal:', error.message);
        }
    }
}

export default TransformersLLM;