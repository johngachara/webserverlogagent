import path from 'path';
import { fileURLToPath } from 'url';
import { cpus } from 'os';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/**
 * TransformersLLM - Optimized Ollama-powered Security Analyzer
 * Optimized for CPU performance and better response generation
 */
class TransformersLLM {
    constructor(options = {}) {
        // Ollama configuration - optimized for CPU
        this.ollamaHost = options.ollamaHost || 'http://localhost:11434';

        // Use smollm for better reasoning while still CPU-friendly
        this.modelName = options.modelName || 'llama3.2:1b';

        // Optimized parameters for CPU performance with explanation support
        this.temperature = options.temperature || 0.1; // Lower for consistent responses
        this.maxTokens = options.maxTokens || 150; // Increased to ensure complete responses
        this.numCtx = options.numCtx || 2048; // Slightly larger context for better understanding

        // CPU optimization settings - ES module compatible
        this.numThread = options.numThread || this.getOptimalThreadCount();
        this.numGpu = 0; // Force CPU-only

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
            initializationTime: null
        };

        console.log(`TransformersLLM initializing with optimized CPU settings`);
        console.log(`Ollama host: ${this.ollamaHost}`);
        console.log(`Model: ${this.modelName} (CPU optimized)`);
        console.log(`CPU threads: ${this.numThread}`);
        console.log(`Max tokens increased to: ${this.maxTokens}`);
    }

    /**
     * Calculate optimal thread count for CPU inference
     * Uses multiple strategies for better performance detection
     */
    getOptimalThreadCount() {
        try {
            const cpuCount = cpus().length;

            // Strategy 1: Use half of available cores (leave room for OS and other processes)
            const halfCores = Math.max(1, Math.floor(cpuCount / 2));

            // Strategy 2: Optimize based on CPU count ranges
            let optimalThreads;

            if (cpuCount <= 2) {
                // Low-end systems: use 1 thread to avoid overwhelming
                optimalThreads = 1;
            } else if (cpuCount <= 4) {
                // Quad-core: use 2 threads for good balance
                optimalThreads = 2;
            } else if (cpuCount <= 8) {
                // 6-8 core systems: use 3-4 threads
                optimalThreads = Math.min(4, halfCores);
            } else if (cpuCount <= 16) {
                // High-end consumer: use up to 6 threads
                optimalThreads = Math.min(6, halfCores);
            } else {
                // Server/workstation: use up to 8 threads (diminishing returns beyond this)
                optimalThreads = Math.min(8, halfCores);
            }

            console.log(`CPU detection: ${cpuCount} cores detected, using ${optimalThreads} threads for inference`);
            return optimalThreads;

        } catch (error) {
            console.warn('Could not detect CPU count, defaulting to 2 threads:', error.message);
            return 2; // Safe default
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

                // Try to pull the model automatically
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

            // Stream the response to show progress
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

            // Perform validation
            await this.validateModel();

        } catch (error) {
            console.error('TransformersLLM initialization failed:', error.message);
            throw new Error(`Failed to initialize Ollama model: ${error.message}`);
        }
    }

    async validateModel() {
        try {
            console.log('Validating model with test JSON prompt...');

            const testResult = await this.generateResponse('Task: Is GET /home safe?\n\nRespond with ONLY this JSON format:\n{\n  "result": "SAFE",\n  "confidence": 8,\n  "reason": "Normal homepage request"\n}\n\nJSON:', { maxTokens: 80 });

            if (testResult && testResult.trim().length > 0) {
                console.log('✓ Model validation successful');
                console.log('Test response:', testResult.trim());

                // Try to parse the test response
                try {
                    const jsonMatch = testResult.match(/\{[\s\S]*\}/);
                    if (jsonMatch) {
                        const parsed = JSON.parse(jsonMatch[0]);
                        console.log('✓ JSON parsing validation successful:', parsed);
                    }
                } catch (parseError) {
                    console.warn('⚠ JSON parsing validation failed:', parseError.message);
                }
            } else {
                console.warn('Model validation produced empty response');
            }

        } catch (error) {
            console.warn('Model validation failed:', error.message);
        }
    }

    /**
     * Generate response using Ollama API with CPU optimizations
     * Enhanced to ensure complete response generation
     */
    async generateResponse(prompt, options = {}) {
        try {
            const requestBody = {
                model: this.modelName,
                prompt: prompt,
                stream: false, // Important: non-streaming for complete responses
                options: {
                    // CPU performance optimizations
                    temperature: options.temperature || this.temperature,
                    num_predict: options.maxTokens || this.maxTokens, // Increased limit
                    num_ctx: this.numCtx,
                    num_thread: this.numThread,
                    num_gpu: this.numGpu,

                    // Sampling optimizations for speed and consistency
                    top_p: 0.9, // Slightly higher for more complete responses
                    top_k: 20,  // Increased for better variety
                    repeat_penalty: 1.1, // Prevent repetition

                    // Remove aggressive stop tokens to allow complete responses
                    stop: ["<END>", "---", "\n\n\n"] // Only use clear end markers, allow some newlines for JSON
                }
            };

            console.log(`[GENERATE] Sending prompt (${prompt.length} chars) with max_tokens: ${requestBody.options.num_predict}`);

            const response = await fetch(`${this.ollamaHost}/api/generate`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(requestBody),
                // Extended timeout for complete response generation
                signal: AbortSignal.timeout(35000) // 35 second timeout
            });

            if (!response.ok) {
                throw new Error(`Ollama API error: ${response.status} ${response.statusText}`);
            }

            const data = await response.json();

            if (data.error) {
                throw new Error(`Ollama error: ${data.error}`);
            }

            const generatedResponse = data.response || '';
            console.log(`[GENERATE] Received response (${generatedResponse.length} chars): "${generatedResponse.substring(0, 100)}${generatedResponse.length > 100 ? '...' : ''}"`);

            return generatedResponse;

        } catch (error) {
            if (error.name === 'TimeoutError') {
                throw new Error('Model response timeout (35s) - response may be incomplete');
            }
            throw error;
        }
    }

    /**
     * Simplified, clear prompt for small model with JSON format
     * Focused on getting complete structured responses
     */
    buildPrompt(logEntry) {
        // Much simpler and clearer prompt for small models
        const request = `METHOD: ${logEntry.method || 'GET'} URL:${logEntry.url || '/'} QUERY: ${logEntry.queryString || 'NONE'}
`;
        const ip = logEntry.ip || 'unknown';
        const userAgent = (logEntry.userAgent || 'unknown')

        return `Task: Analyze this web request for security threats.
Request: ${request}
From IP: ${ip}
User-Agent: ${userAgent}

Respond with ONLY this JSON format (no other text):
{
  "result": "SAFE or THREAT or UNKNOWN",
  "confidence": 1-10,
  "reason": "one sentence explanation"
}

JSON:`;
    }

    async analyze(logEntry) {
        if (!this.isInitialized) {
            throw new Error('TransformersLLM not initialized. Call initialize() first.');
        }

        const startTime = Date.now();

        try {
            console.log(`[PRIMARY] Analyzing request: ${logEntry.method || 'GET'} ${logEntry.url || '/'} from IP: ${logEntry.ip}`);

            const prompt = this.buildPrompt(logEntry);
            console.log(`[PRIMARY] Using prompt: ${prompt.substring(0, 200)}...`);

            const result = await this.generateResponse(prompt, {
                maxTokens: this.maxTokens,
                temperature: 0.1
            });

            if (!result || result.trim().length === 0) {
                throw new Error('No response generated from primary model');
            }

            const responseTime = Date.now() - startTime;
            const rawResponse = result.trim();

            console.log(`[PRIMARY] Full raw response (${rawResponse.length} chars): "${rawResponse}"`);

            const analysisResult = this.parseResponse(rawResponse, responseTime);
            this.updateStats(analysisResult, responseTime);

            return analysisResult;

        } catch (error) {
            console.error('[PRIMARY] Analysis error:', error.message);

            return {
                decision: 'UNCERTAIN',
                confidence: 0,
                explanation: `Primary model error: ${error.message}`,
                requiresSecondaryAnalysis: true,
                tier: 'primary',
                error: true,
                responseTime: Date.now() - startTime
            };
        }
    }

    parseResponse(rawResponse, responseTime) {
        console.log(`[PRIMARY] Parsing JSON response: "${rawResponse}"`);

        let decision = 'UNCERTAIN';
        let confidence = 5;
        let explanation = 'Could not parse response';
        let requiresSecondaryAnalysis = true;
        let parseMethod = 'json'; // Track how we parsed the response

        try {
            // First, try to extract JSON from the response
            let jsonStr = rawResponse.trim();

            // Look for JSON object in the response
            const jsonMatch = jsonStr.match(/\{[\s\S]*?\}/);
            if (jsonMatch) {
                jsonStr = jsonMatch[0];
            }

            console.log(`[PRIMARY] Extracted JSON string: "${jsonStr}"`);

            // Parse the JSON
            let parsedData;
            try {
                parsedData = JSON.parse(jsonStr);
                console.log(`[PRIMARY] Successfully parsed JSON:`, parsedData);
            } catch (jsonError) {
                console.log(`[PRIMARY] JSON parse failed, attempting to fix common issues...`);

                // Try to fix common JSON issues
                let fixedJson = jsonStr
                    .replace(/'/g, '"')  // Replace single quotes with double quotes
                    .replace(/([{,]\s*)([a-zA-Z_][a-zA-Z0-9_]*)\s*:/g, '$1"$2":') // Add quotes to unquoted keys
                    .replace(/:\s*([^",\{\[\d\s][^",\}\]]*)\s*([,\}])/g, ': "$1"$2') // Quote unquoted string values
                    .replace(/,\s*}/g, '}') // Remove trailing commas
                    .replace(/,\s*]/g, ']'); // Remove trailing commas in arrays

                console.log(`[PRIMARY] Attempting to parse fixed JSON: "${fixedJson}"`);
                parsedData = JSON.parse(fixedJson);
                console.log(`[PRIMARY] Successfully parsed fixed JSON:`, parsedData);
                parseMethod = 'json_fixed';
            }

            // Extract values from parsed JSON
            if (parsedData && typeof parsedData === 'object') {
                // Extract result
                if (parsedData.result) {
                    const result = parsedData.result.toString().toUpperCase();
                    if (result === 'SAFE') {
                        decision = 'BENIGN';
                        requiresSecondaryAnalysis = false;
                    } else if (result === 'THREAT') {
                        decision = 'MALICIOUS';
                        requiresSecondaryAnalysis = false;
                    } else if (result === 'UNKNOWN') {
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
                    if (explanation.length > 200) {
                        // Find the last complete sentence within 200 chars
                        const truncated = explanation.substring(0, 200);
                        const lastPeriod = truncated.lastIndexOf('.');
                        if (lastPeriod > 50) {
                            explanation = truncated.substring(0, lastPeriod + 1);
                        } else {
                            explanation = truncated + '...';
                        }
                    }
                }

                console.log(`[PRIMARY] Extracted from JSON - Result: ${parsedData.result}, Confidence: ${parsedData.confidence}, Reason: ${parsedData.reason}`);
            } else {
                throw new Error('Parsed data is not a valid object');
            }

        } catch (parseError) {
            console.error('[PRIMARY] JSON parse error:', parseError.message);
            console.log(`[PRIMARY] Falling back to text parsing for: "${rawResponse.substring(0, 100)}..."`);
            parseMethod = 'text_fallback';

            // Fallback to text parsing if JSON fails
            const upperResponse = rawResponse.toUpperCase();

            if (upperResponse.includes('SAFE') || upperResponse.includes('BENIGN') || upperResponse.includes('NORMAL')) {
                decision = 'BENIGN';
                confidence = 6;
                explanation = 'Safe request identified (text fallback)';
                requiresSecondaryAnalysis = false;
            } else if (upperResponse.includes('THREAT') || upperResponse.includes('MALICIOUS') || upperResponse.includes('ATTACK')) {
                decision = 'MALICIOUS';
                confidence = 6;
                explanation = 'Threat indicators found (text fallback)';
                requiresSecondaryAnalysis = false;
            } else {
                decision = 'UNCERTAIN';
                confidence = 3;
                explanation = 'JSON parsing failed - needs review';
                requiresSecondaryAnalysis = true;
            }
        }

        // Final validation of explanation
        if (!explanation || explanation.length < 3) {
            explanation = decision === 'MALICIOUS' ? 'Threat detected' :
                decision === 'BENIGN' ? 'Normal request' : 'Needs analysis';
        }

        console.log(`[PRIMARY] Final parsed result:`);
        console.log(`  Decision: "${decision}"`);
        console.log(`  Confidence: ${confidence}`);
        console.log(`  Explanation: "${explanation}"`);
        console.log(`  Requires secondary: ${requiresSecondaryAnalysis}`);
        console.log(`  Parse method: ${parseMethod}`);

        return {
            decision,
            confidence,
            explanation,
            requiresSecondaryAnalysis,
            tier: 'primary',
            model: 'ollama',
            modelName: this.modelName,
            responseTime,
            rawResponse: rawResponse.substring(0, 500), // Show more of the response for debugging
            timestamp: new Date().toISOString(),
            parseMethod
        };
    }

    updateStats(result, responseTime) {
        this.stats.totalAnalyzed++;

        switch (result.decision) {
            case 'BENIGN': this.stats.benignCount++; break;
            case 'MALICIOUS': this.stats.maliciousCount++; break;
            case 'UNCERTAIN': this.stats.uncertainCount++; break;
        }

        this.stats.averageResponseTime =
            (this.stats.averageResponseTime * (this.stats.totalAnalyzed - 1) + responseTime) / this.stats.totalAnalyzed;
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
                url: '/home',
                queryString: '',
                userAgent: 'Test-Browser/1.0'
            });

            const testTime = Date.now() - testStart;

            return {
                success: true,
                message: 'Improved primary model connection successful',
                model: 'ollama',
                modelName: this.modelName,
                ollamaHost: this.ollamaHost,
                optimizations: {
                    cpuThreads: this.numThread,
                    contextSize: this.numCtx,
                    maxTokens: this.maxTokens,
                    gpuDisabled: true,
                    improvedParsing: true
                },
                testTime,
                testResult: {
                    decision: testResult.decision,
                    confidence: testResult.confidence,
                    explanation: testResult.explanation,
                    responseTime: testResult.responseTime,
                    rawResponseLength: testResult.rawResponse ? testResult.rawResponse.length : 0
                },
                stats: this.getStats()
            };

        } catch (error) {
            console.error('[PRIMARY] Connection test failed:', error.message);

            return {
                success: false,
                message: `Primary model connection failed: ${error.message}`,
                model: 'ollama',
                modelName: this.modelName,
                ollamaHost: this.ollamaHost,
                error: error.message,
                initialized: this.isInitialized,
                troubleshooting: {
                    steps: [
                        '1. Install Ollama: curl -fsSL https://ollama.ai/install.sh | sh',
                        '2. Start Ollama: ollama serve',
                        '3. Pull model: ollama pull phi3:3.8b',
                        '4. Verify: ollama list'
                    ],
                    improvements: [
                        'Increased max tokens to 150 for complete responses',
                        'Simplified prompt for small model compatibility',
                        'Enhanced response parsing with fallbacks',
                        'Extended timeout for complete generation',
                        'Removed aggressive stop tokens'
                    ],
                    ollamaStatus: this.ollamaAvailable ? 'Available' : 'Not accessible',
                    modelStatus: this.modelReady ? 'Ready' : 'Not available'
                }
            };
        }
    }

    getStats() {
        const total = this.stats.totalAnalyzed;
        return {
            model: 'ollama',
            modelName: this.modelName,
            ollamaHost: this.ollamaHost,
            optimizations: {
                cpuThreads: this.numThread,
                contextSize: this.numCtx,
                maxTokens: this.maxTokens,
                modelSize: '3.8B parameters (CPU optimized)',
                enhancedParsing: true
            },
            initialized: this.isInitialized,
            ollamaAvailable: this.ollamaAvailable,
            modelReady: this.modelReady,
            initializationTime: this.stats.initializationTime,
            totalAnalyzed: total,
            benignCount: this.stats.benignCount,
            maliciousCount: this.stats.maliciousCount,
            uncertainCount: this.stats.uncertainCount,
            benignPercent: total > 0 ? ((this.stats.benignCount / total) * 100).toFixed(1) : '0.0',
            maliciousPercent: total > 0 ? ((this.stats.maliciousCount / total) * 100).toFixed(1) : '0.0',
            uncertainPercent: total > 0 ? ((this.stats.uncertainCount / total) * 100).toFixed(1) : '0.0',
            averageResponseTime: Math.round(this.stats.averageResponseTime),
            escalationRate: total > 0 ? ((this.stats.uncertainCount / total) * 100).toFixed(1) + '%' : '0.0%',
            primaryResolutionRate: total > 0 ? (((total - this.stats.uncertainCount) / total) * 100).toFixed(1) + '%' : '0.0%'
        };
    }

    resetStats() {
        const oldStats = { ...this.stats };
        this.stats = {
            totalAnalyzed: 0,
            benignCount: 0,
            maliciousCount: 0,
            uncertainCount: 0,
            averageResponseTime: 0,
            initializationTime: this.stats.initializationTime
        };
        console.log('Primary model statistics reset');
    }

    getModelInfo() {
        return {
            model: 'ollama',
            modelName: this.modelName,
            ollamaHost: this.ollamaHost,
            optimizations: {
                cpuThreads: this.numThread,
                contextSize: this.numCtx,
                maxTokens: this.maxTokens,
                modelSize: '3.8B parameters',
                enhancedResponseHandling: true
            },
            initialized: this.isInitialized,
            ollamaAvailable: this.ollamaAvailable,
            modelReady: this.modelReady
        };
    }

    clearHistory() {
        // Ollama is stateless, so no history to clear
        console.log('Ollama is stateless - no history to clear');
    }

    async dispose() {
        try {
            console.log('Disposing TransformersLLM resources...');
            // Ollama doesn't require explicit cleanup
            this.isInitialized = false;
            console.log('TransformersLLM disposed successfully');
        } catch (error) {
            console.warn('Error during disposal:', error.message);
        }
    }
}

export default TransformersLLM;