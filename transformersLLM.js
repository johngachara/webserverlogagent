import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/**
 * TransformersLLM - Ollama-powered Primary Security Analyzer
 *
 * Uses Ollama for reliable local LLM inference without native compilation issues.
 * Much more stable than node-llama-cpp and easier to set up.
 */
class TransformersLLM {
    constructor(options = {}) {
        // Ollama configuration
        this.ollamaHost = options.ollamaHost || 'http://localhost:11434';
        this.modelName = options.modelName || 'gemma2:2b';
        this.temperature = options.temperature || 0.1;
        this.maxTokens = options.maxTokens || 50;

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

        console.log(`TransformersLLM initializing with Ollama`);
        console.log(`Ollama host: ${this.ollamaHost}`);
        console.log(`Model: ${this.modelName}`);
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

            const testResult = await this.generateResponse("Test", { maxTokens: 50 });

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
     * Generate response using Ollama API
     */
    async generateResponse(prompt, options = {}) {
        try {
            const requestBody = {
                model: this.modelName,
                prompt: prompt,
                stream: false,
                options: {
                    temperature: options.temperature || this.temperature,
                    num_predict: options.maxTokens || this.maxTokens,
                    stop: options.stop || ['\n', '.', '!', '?'],
                    top_p: options.topP || 0.9,
                    top_k: options.topK || 40
                }
            };

            const response = await fetch(`${this.ollamaHost}/api/generate`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(requestBody),
                // Add timeout for fast responses
                signal: AbortSignal.timeout(30000) // 30 second timeout
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
                throw new Error('Model response timeout (30s)');
            }
            throw error;
        }
    }

    buildPrompt(logEntry) {
        return `
IP: ${logEntry.ip || 'unknown'}
Method: ${logEntry.method || 'unknown'}
URL: ${logEntry.url || 'unknown'}
Query: ${logEntry.queryString || 'none'}
User-Agent: ${logEntry.userAgent || 'unknown'}
Respond with either 'MALICIOUS' or 'BENIGN' or 'UNCERTAIN'.

`}


    async analyze(logEntry) {
        if (!this.isInitialized) {
            throw new Error('TransformersLLM not initialized. Call initialize() first.');
        }

        const startTime = Date.now();

        try {
            console.log(`[PRIMARY] Analyzing request from IP: ${logEntry.ip}`);

            const prompt = this.buildPrompt(logEntry);

            const result = await this.generateResponse(prompt, {
                maxTokens: 50,
                temperature: 0.1,
                stop: ['\n', ' ', '.', '!', '?']
            });

            if (!result || result.trim().length === 0) {
                throw new Error('No response generated from primary model');
            }

            const responseTime = Date.now() - startTime;
            const rawResponse = result.trim().toUpperCase();

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
        console.log(rawResponse)
        const cleanResponse = rawResponse
            .replace(/[^\w\s]/g, '')
            .split(/\s+/)[0]
            .toUpperCase();

        console.log(`[PRIMARY] Parsed decision word: "${cleanResponse}"`);

        let decision, confidence, explanation, requiresSecondaryAnalysis;

        if (cleanResponse === 'MALICIOUS') {
            decision = 'MALICIOUS';
            confidence = 9;
            explanation = 'Primary model identified obvious malicious patterns';
            requiresSecondaryAnalysis = false;
        } else if (cleanResponse === 'BENIGN') {
            decision = 'BENIGN';
            confidence = 2;
            explanation = 'Primary model identified request as benign';
            requiresSecondaryAnalysis = false;
        } else {
            decision = 'UNCERTAIN';
            confidence = 5;
            explanation = 'Primary model uncertain - escalating to advanced analysis';
            requiresSecondaryAnalysis = true;
        }

        return {
            decision,
            confidence,
            explanation,
            requiresSecondaryAnalysis,
            tier: 'primary',
            model: 'ollama',
            modelName: this.modelName,
            responseTime,
            rawResponse: rawResponse.substring(0, 100),
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
                message: 'Primary model connection successful',
                model: 'ollama',
                modelName: this.modelName,
                ollamaHost: this.ollamaHost,
                testTime,
                testResult: {
                    decision: testResult.decision,
                    confidence: testResult.confidence,
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
                        '3. Pull model: ollama pull llama3.2:1b',
                        '4. Verify: ollama list'
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