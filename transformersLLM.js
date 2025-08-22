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

        // Use phi3:3.8b for better reasoning while still CPU-friendly
        this.modelName = options.modelName || 'phi3.5:3.8b';

        // Optimized parameters for CPU performance with explanation support
        this.temperature = options.temperature || 0.1; // Lower for consistent responses
        this.maxTokens = options.maxTokens || 80; // Increased for confidence + explanation
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
            console.log('Validating model with test prompt...');

            const testResult = await this.generateResponse("Classify: GET /home\nBENIGN CONFIDENCE 8 Normal homepage request", { maxTokens: 50 });

            if (testResult && testResult.trim().length > 0) {
                console.log('✓ Model validation successful');
                console.log('Test response:', testResult.trim());
            } else {
                console.warn('Model validation produced empty response');
            }

        } catch (error) {
            console.warn('Model validation failed:', error.message);
        }
    }

    /**
     * Generate response using Ollama API with CPU optimizations
     */
    async generateResponse(prompt, options = {}) {
        try {
            const requestBody = {
                model: this.modelName,
                prompt: prompt,
                stream: false,
                options: {
                    // CPU performance optimizations
                    temperature: options.temperature || this.temperature,
                    num_predict: options.maxTokens || this.maxTokens,
                    num_ctx: this.numCtx,
                    num_thread: this.numThread,
                    num_gpu: this.numGpu,

                    // Sampling optimizations for speed and consistency
                    top_p: 0.7, // Focused sampling
                    top_k: 15,  // Lower for speed
                    repeat_penalty: 1.05, // Prevent repetition

                    // Stop tokens to prevent over-generation
                    stop: ["\n\n", "Request:", "Classify:"]
                }
            };

            const response = await fetch(`${this.ollamaHost}/api/generate`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(requestBody),
                // Timeout for CPU performance
                signal: AbortSignal.timeout(25000) // 25 second timeout for phi3
            });

            if (!response.ok) {
                throw new Error(`Ollama API error: ${response.status} ${response.statusText}`);
            }

            const data = await response.json();

            if (data.error) {
                throw new Error(`Ollama error: ${data.error}`);
            }

            return data.response || '';

        } catch (error) {
            if (error.name === 'TimeoutError') {
                throw new Error('Model response timeout (25s)');
            }
            throw error;
        }
    }

    /**
     * Optimized prompt for structured responses with confidence and explanation
     */
    buildPrompt(logEntry) {
        // Clear, structured prompt that guides the model to the exact format we want
        return `Classify this single request as MALICIOUS, BENIGN, or UNCERTAIN.
If MALICIOUS or BENIGN, include CONFIDENCE (0-10) and one short sentence explanation.
If UNCERTAIN, do not include a confidence score.

Request: ${logEntry.method || 'GET'} ${logEntry.url || '/'} from ${logEntry.ip || 'unknown'}${logEntry.queryString ? '?' + logEntry.queryString : ''}
User-Agent: ${(logEntry.userAgent || 'unknown').substring(0, 50)}

Response format:
BENIGN CONFIDENCE 8 Normal homepage request
MALICIOUS CONFIDENCE 9 SQL injection attempt detected
UNCERTAIN Ambiguous request pattern

Classification:`;
    }

    async analyze(logEntry) {
        if (!this.isInitialized) {
            throw new Error('TransformersLLM not initialized. Call initialize() first.');
        }

        const startTime = Date.now();

        try {
            console.log(`[PRIMARY] Analyzing request from IP: ${logEntry.ip}`);

            const prompt = this.buildPrompt(logEntry);

            const result = await this.generateResponse(prompt, {
                maxTokens: this.maxTokens,
                temperature: 0.1
            });

            if (!result || result.trim().length === 0) {
                throw new Error('No response generated from primary model');
            }

            const responseTime = Date.now() - startTime;
            const rawResponse = result.trim();

            console.log(`[PRIMARY] Raw response: "${rawResponse}" (${responseTime}ms)`);

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
        console.log(`[PRIMARY] Full response: "${rawResponse}"`);

        const response = rawResponse.trim();
        let decision, confidence = 0, explanation = '', requiresSecondaryAnalysis = false;

        // Parse structured response format
        const upperResponse = response.toUpperCase();

        if (upperResponse.startsWith('MALICIOUS')) {
            decision = 'MALICIOUS';
            requiresSecondaryAnalysis = false;

            // Extract confidence and explanation
            const confidenceMatch = response.match(/CONFIDENCE\s+(\d+)/i);
            if (confidenceMatch) {
                confidence = Math.min(10, Math.max(0, parseInt(confidenceMatch[1])));
                // Extract explanation after confidence number
                const explanationMatch = response.match(/CONFIDENCE\s+\d+\s+(.+)/i);
                if (explanationMatch) {
                    explanation = explanationMatch[1].trim().substring(0, 120); // Limit explanation length
                } else {
                    explanation = 'Malicious request detected';
                }
            } else {
                confidence = 7; // Default confidence
                explanation = response.replace(/MALICIOUS/i, '').trim() || 'Malicious request detected';
            }

        } else if (upperResponse.startsWith('BENIGN')) {
            decision = 'BENIGN';
            requiresSecondaryAnalysis = false;

            // Extract confidence and explanation
            const confidenceMatch = response.match(/CONFIDENCE\s+(\d+)/i);
            if (confidenceMatch) {
                confidence = Math.min(10, Math.max(0, parseInt(confidenceMatch[1])));
                // Extract explanation after confidence number
                const explanationMatch = response.match(/CONFIDENCE\s+\d+\s+(.+)/i);
                if (explanationMatch) {
                    explanation = explanationMatch[1].trim().substring(0, 120);
                } else {
                    explanation = 'Benign request identified';
                }
            } else {
                confidence = 7; // Default confidence
                explanation = response.replace(/BENIGN/i, '').trim() || 'Benign request identified';
            }

        } else if (upperResponse.startsWith('UNCERTAIN')) {
            decision = 'UNCERTAIN';
            confidence = 5; // Set moderate confidence for uncertain cases
            requiresSecondaryAnalysis = true;

            // Extract explanation (no confidence expected for uncertain)
            explanation = response.replace(/UNCERTAIN/i, '').trim() || 'Uncertain request pattern';
            if (explanation.length > 120) {
                explanation = explanation.substring(0, 120);
            }

        } else {
            // Fallback parsing - look for keywords anywhere in response
            if (upperResponse.includes('MALICIOUS')) {
                decision = 'MALICIOUS';
                confidence = 6;
                explanation = 'Malicious indicators found';
                requiresSecondaryAnalysis = false;
            } else if (upperResponse.includes('BENIGN')) {
                decision = 'BENIGN';
                confidence = 6;
                explanation = 'Benign patterns detected';
                requiresSecondaryAnalysis = false;
            } else {
                decision = 'UNCERTAIN';
                confidence = 3;
                explanation = 'Unclear response format - escalating';
                requiresSecondaryAnalysis = true;
            }
        }

        // Clean up explanation
        explanation = explanation.replace(/^\W+|\W+$/g, ''); // Remove leading/trailing punctuation
        if (!explanation || explanation.length < 5) {
            explanation = decision === 'MALICIOUS' ? 'Threat detected' :
                decision === 'BENIGN' ? 'Normal request' :
                    'Needs further analysis';
        }

        console.log(`[PRIMARY] Parsed - Decision: "${decision}", Confidence: ${confidence}, Explanation: "${explanation}"`);

        return {
            decision,
            confidence,
            explanation,
            requiresSecondaryAnalysis,
            tier: 'primary',
            model: 'ollama',
            modelName: this.modelName,
            responseTime,
            rawResponse: rawResponse.substring(0, 200),
            timestamp: new Date().toISOString()
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
                message: 'Optimized primary model connection successful',
                model: 'ollama',
                modelName: this.modelName,
                ollamaHost: this.ollamaHost,
                optimizations: {
                    cpuThreads: this.numThread,
                    contextSize: this.numCtx,
                    maxTokens: this.maxTokens,
                    gpuDisabled: true
                },
                testTime,
                testResult: {
                    decision: testResult.decision,
                    confidence: testResult.confidence,
                    explanation: testResult.explanation,
                    responseTime: testResult.responseTime
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
                    cpuOptimizations: [
                        'Using phi3:3.8b for better reasoning',
                        `CPU threads: ${this.numThread}`,
                        `Context window: ${this.numCtx}`,
                        'GPU disabled for CPU-only inference'
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
                modelSize: '3.8B parameters (CPU optimized)'
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
                modelSize: '3.8B parameters'
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