import path from 'path';
import { fileURLToPath } from 'url';
import { cpus } from 'os';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/**
 * TransformersLLM - Optimized Ollama-powered Security Analyzer with Reasoning Support
 * Enhanced for reasoning models with think tag handling and real-time display
 */
class TransformersLLM {
    constructor(options = {}) {
        // Ollama configuration - optimized for CPU
        this.ollamaHost = options.ollamaHost || 'http://localhost:11434';

        // Use reasoning model that supports think
        this.modelName = options.modelName || 'qwen3:1.7b';

        // Optimized parameters for reasoning models
        this.temperature = options.temperature || 0.3; // Slightly higher for better reasoning
        this.maxTokens = options.maxTokens || 800; // Much larger for reasoning + response
        this.numCtx = options.numCtx || 4096; // Larger context for reasoning

        // CPU optimization settings - ES module compatible
        this.numThread = options.numThread || this.getOptimalThreadCount();
        this.numGpu = 0; // Force CPU-only

        // think display settings
        this.enablethinkDisplay = options.enablethinkDisplay !== false;
        this.thinkCallback = options.thinkCallback || this.defaultthinkCallback;
        this.typewriterDelay = options.typewriterDelay || 15; // ms between characters

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
            averagethinkTime: 0,
            initializationTime: null
        };

        console.log(`TransformersLLM initializing with reasoning model support`);
        console.log(`Ollama host: ${this.ollamaHost}`);
        console.log(`Model: ${this.modelName} (reasoning optimized)`);
        console.log(`CPU threads: ${this.numThread}`);
        console.log(`Max tokens: ${this.maxTokens} (includes think)`);
        console.log(`think display: ${this.enablethinkDisplay ? 'enabled' : 'disabled'}`);
    }

    /**
     * Default think callback for console display
     */
    defaultthinkCallback(thinkText, isComplete = false) {
        if (isComplete) {
            console.log('\n[think COMPLETE]');
        } else {
            process.stdout.write(thinkText);
        }
    }

    /**
     * Display think text with typewriter effect
     */
    async displaythink(thinkText) {
        if (!this.enablethinkDisplay || !thinkText) return;

        console.log('\n[think]');

        // Clean up think text
        const cleanthink = thinkText
            .replace(/<\/?think>/g, '')
            .trim();

        // Typewriter effect
        for (let i = 0; i < cleanthink.length; i++) {
            this.thinkCallback(cleanthink[i]);
            if (this.typewriterDelay > 0) {
                await new Promise(resolve => setTimeout(resolve, this.typewriterDelay));
            }
        }

        this.thinkCallback('', true); // Signal completion
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
     * Generate response using Ollama API with streaming for think display
     */
    async generateResponse(prompt, options = {}) {
        try {
            const useStreaming = this.enablethinkDisplay && !options.noStreaming;

            const requestBody = {
                model: this.modelName,
                prompt: prompt,
                stream: useStreaming,
                options: {
                    temperature: options.temperature || this.temperature,
                    num_predict: options.maxTokens || this.maxTokens,
                    num_ctx: this.numCtx,
                    num_thread: this.numThread,
                    num_gpu: this.numGpu,
                    top_p: 0.9,
                    top_k: 40,
                    repeat_penalty: 1.1,
                    stop: ["<END_ANALYSIS>"]
                }
            };

            console.log(`[GENERATE] Sending prompt (${prompt.length} chars) with streaming: ${useStreaming}`);

            const response = await fetch(`${this.ollamaHost}/api/generate`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(requestBody),
                signal: AbortSignal.timeout(120000) // 120 second timeout for reasoning
            });

            if (!response.ok) {
                throw new Error(`Ollama API error: ${response.status} ${response.statusText}`);
            }

            if (useStreaming) {
                return await this.handleStreamingResponse(response);
            } else {
                const data = await response.json();
                if (data.error) {
                    throw new Error(`Ollama error: ${data.error}`);
                }
                return data.response || '';
            }

        } catch (error) {
            if (error.name === 'TimeoutError') {
                throw new Error('Model response timeout (60s) - reasoning may be incomplete');
            }
            throw error;
        }
    }

    /**
     * Handle streaming response with real-time think display
     */
    async handleStreamingResponse(response) {
        const reader = response.body.getReader();
        const decoder = new TextDecoder();

        let fullResponse = '';
        let thinkContent = '';
        let isInthink = false;
        let hasShownthink = false;

        try {
            while (true) {
                const { done, value } = await reader.read();
                if (done) break;

                const chunk = decoder.decode(value);
                const lines = chunk.split('\n').filter(line => line.trim());

                for (const line of lines) {
                    try {
                        const data = JSON.parse(line);
                        if (data.error) {
                            throw new Error(`Ollama error: ${data.error}`);
                        }

                        if (data.response) {
                            const newContent = data.response;
                            fullResponse += newContent;

                            // Check for think tags
                            const currentText = fullResponse;
                            const thinkStart = currentText.indexOf('<think>');
                            const thinkEnd = currentText.indexOf('</think>');

                            if (thinkStart !== -1 && thinkEnd !== -1 && !hasShownthink) {
                                // Extract complete think content
                                thinkContent = currentText.substring(thinkStart + 10, thinkEnd);
                                await this.displaythink(thinkContent);
                                hasShownthink = true;
                            } else if (thinkStart !== -1 && !isInthink && !hasShownthink) {
                                // Start of think detected, but not complete yet
                                isInthink = true;
                                console.log('\n[think] Model is reasoning...');
                            }
                        }

                    } catch (parseError) {
                        // Ignore JSON parse errors in streaming
                        continue;
                    }
                }
            }

            console.log(`\n[GENERATE] Received complete response (${fullResponse.length} chars)`);
            return fullResponse;

        } catch (error) {
            console.error('[STREAMING] Error during stream processing:', error.message);
            return fullResponse; // Return what we have so far
        }
    }

    /**
     * Build optimized reasoning prompt for security analysis
     */
    buildReasoningPrompt(logEntry) {
        const request = `${logEntry.method || 'GET'} ${logEntry.url || '/'}${logEntry.queryString ? '?' + logEntry.queryString : ''}`;
        const ip = logEntry.ip || 'unknown';
        const userAgent = (logEntry.userAgent || 'unknown').substring(0, 200);

        return `You are a cybersecurity expert analyzing web requests for threats. Your task is to determine if this request is SAFE, THREAT, or UNCERTAIN.
Think through your analysis step by step:
1. Examine the HTTP method and URL path for suspicious patterns
2. Check query parameters for injection attempts or malicious payloads  
3. Analyze the source IP for known threat indicators
4. Review the User-Agent for bot/scanner signatures or anomalies
5. Consider the overall context and threat likelihood
6. Decide on classification and confidence level
Request Details:
- Request: ${request}
- Source IP: ${ip}
- User-Agent: ${userAgent}

Classification Guidelines:
- SAFE: Normal legitimate requests (home pages, static resources, standard API calls)
- THREAT: Clear malicious activity (SQL injection, XSS, path traversal, known attack patterns)
- UNCERTAIN: Suspicious but ambiguous (unusual parameters, uncommon paths, need more context)

Respond with this exact JSON format:
{
  "result": "SAFE|THREAT|UNCERTAIN",
  "confidence": 1-10,
  "reason": "brief explanation focusing on key indicators"
}
`;
    }

    async analyze(logEntry) {
        if (!this.isInitialized) {
            throw new Error('TransformersLLM not initialized. Call initialize() first.');
        }

        const startTime = Date.now();
        let thinkTime = 0;

        try {
            console.log(`\n[ANALYSIS] Analyzing: ${logEntry.method || 'GET'} ${logEntry.url || '/'} from ${logEntry.ip}`);

            const prompt = this.buildReasoningPrompt(logEntry);

            const thinkStart = Date.now();
            const result = await this.generateResponse(prompt);
            const responseTime = Date.now() - startTime;

            // Calculate think time (approximate based on think tags presence)
            if (result.includes('<think>') && result.includes('</think>')) {
                thinkTime = Math.max(0, responseTime - 1000); // Rough estimate
            }

            if (!result || result.trim().length === 0) {
                throw new Error('No response generated from reasoning model');
            }

            const analysisResult = this.parseReasoningResponse(result, responseTime, thinkTime);
            this.updateStats(analysisResult, responseTime, thinkTime);

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
                thinkTime: 0
            };
        }
    }

    /**
     * Parse response from reasoning model, handling think tags
     */
    parseReasoningResponse(rawResponse, responseTime, thinkTime) {
        console.log(`\n[PARSING] Processing reasoning response (${rawResponse.length} chars)`);

        let decision = 'UNCERTAIN';
        let confidence = 5;
        let explanation = 'Could not parse response';
        let requiresSecondaryAnalysis = true;
        let parseMethod = 'reasoning_json';
        let thinkContent = '';

        try {
            // Extract think content if present
            const thinkMatch = rawResponse.match(/<think>([\s\S]*?)<\/think>/);
            if (thinkMatch) {
                thinkContent = thinkMatch[1].trim();
                console.log(`[PARSING] Extracted think content (${thinkContent.length} chars)`);
            }

            // Remove think tags and extract JSON
            let cleanResponse = rawResponse
                .replace(/<think>[\s\S]*?<\/think>/g, '')
                .replace(/<\/?think>/g, '')
                .trim();

            // Look for JSON object
            const jsonMatch = cleanResponse.match(/\{[\s\S]*?\}/);
            if (!jsonMatch) {
                throw new Error('No JSON found in response');
            }

            let jsonStr = jsonMatch[0];
            console.log(`[PARSING] Extracted JSON: ${jsonStr}`);

            // Parse JSON
            let parsedData;
            try {
                parsedData = JSON.parse(jsonStr);
            } catch (jsonError) {
                // Try to fix common JSON issues
                let fixedJson = jsonStr
                    .replace(/'/g, '"')
                    .replace(/([{,]\s*)([a-zA-Z_][a-zA-Z0-9_]*)\s*:/g, '$1"$2":')
                    .replace(/:\s*([^",\{\[\d\s][^",\}\]]*)\s*([,\}])/g, ': "$1"$2')
                    .replace(/,\s*}/g, '}')
                    .replace(/,\s*]/g, ']');

                parsedData = JSON.parse(fixedJson);
                parseMethod = 'reasoning_json_fixed';
            }

            // Extract values
            if (parsedData && typeof parsedData === 'object') {
                // Map result to our decision format
                if (parsedData.result) {
                    const result = parsedData.result.toString().toUpperCase();
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
            }

            console.log(`[PARSING] Reasoning result: ${decision} (confidence: ${confidence})`);
            console.log(`[PARSING] Explanation: "${explanation}"`);

        } catch (parseError) {
            console.error('[PARSING] JSON parse failed:', parseError.message);
            parseMethod = 'reasoning_fallback';

            // Fallback to text analysis
            const upperResponse = rawResponse.toUpperCase();

            if (upperResponse.includes('SAFE') || upperResponse.includes('BENIGN') || upperResponse.includes('LEGITIMATE')) {
                decision = 'BENIGN';
                confidence = 6;
                explanation = 'Identified as safe through text analysis';
                requiresSecondaryAnalysis = false;
            } else if (upperResponse.includes('THREAT') || upperResponse.includes('MALICIOUS') || upperResponse.includes('ATTACK')) {
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

        return {
            decision,
            confidence,
            explanation,
            requiresSecondaryAnalysis,
            tier: 'primary',
            model: 'ollama-reasoning',
            modelName: this.modelName,
            responseTime,
            thinkTime,
            rawResponse: rawResponse.substring(0, 800),
            thinkContent: thinkContent.substring(0, 300),
            timestamp: new Date().toISOString(),
            parseMethod
        };
    }

    updateStats(result, responseTime, thinkTime = 0) {
        this.stats.totalAnalyzed++;

        switch (result.decision) {
            case 'BENIGN': this.stats.benignCount++; break;
            case 'MALICIOUS': this.stats.maliciousCount++; break;
            case 'UNCERTAIN': this.stats.uncertainCount++; break;
        }

        this.stats.averageResponseTime =
            (this.stats.averageResponseTime * (this.stats.totalAnalyzed - 1) + responseTime) / this.stats.totalAnalyzed;

        this.stats.averagethinkTime =
            (this.stats.averagethinkTime * (this.stats.totalAnalyzed - 1) + thinkTime) / this.stats.totalAnalyzed;
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
                    thinkDisplay: this.enablethinkDisplay,
                    streamingResponse: true,
                    enhancedPrompting: true
                },
                optimizations: {
                    cpuThreads: this.numThread,
                    contextSize: this.numCtx,
                    maxTokens: this.maxTokens,
                    typewriterDelay: this.typewriterDelay
                },
                testTime,
                testResult: {
                    decision: testResult.decision,
                    confidence: testResult.confidence,
                    explanation: testResult.explanation,
                    responseTime: testResult.responseTime,
                    thinkTime: testResult.thinkTime,
                    hasthink: testResult.thinkContent?.length > 0
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
                        'Real-time think display with typewriter effect',
                        'Improved uncertainty handling',
                        'Streaming response support',
                        'Optimized prompting for reasoning models'
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
                thinkDisplay: this.enablethinkDisplay,
                streamingResponse: true
            },
            initialized: this.isInitialized,
            totalAnalyzed: total,
            benignCount: this.stats.benignCount,
            maliciousCount: this.stats.maliciousCount,
            uncertainCount: this.stats.uncertainCount,
            averageResponseTime: Math.round(this.stats.averageResponseTime),
            averagethinkTime: Math.round(this.stats.averagethinkTime),
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
            averagethinkTime: 0,
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
                think: true,
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