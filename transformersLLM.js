import path from 'path';
import { fileURLToPath } from 'url';
import { cpus } from 'os';
import { spawn } from 'child_process';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/**
 * TransformersLLM - Curl-based Ollama Security Analyzer
 * Optimized for small models with better parsing
 */
class TransformersLLM {
    constructor(options = {}) {
        // Ollama configuration
        this.ollamaHost = options.ollamaHost || process.env.OLLAMA_HOST;
        this.modelName = options.modelName || 'phi3.5:3.8b';

        // Optimized parameters for small model
        this.temperature = 0.0; // More deterministic
        this.maxTokens = 200;    // Shorter responses
        this.topP = 0.9;        // Focus on likely tokens

        // CPU optimization
        this.numThread = options.numThread || this.getOptimalThreadCount();

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
            parseFailures: 0,
            averageResponseTime: 0,
            initializationTime: null,
            networkErrors: 0,
            timeouts: 0
        };

        console.log(`TransformersLLM initializing with curl (optimized for small model)`);
        console.log(`Ollama host: ${this.ollamaHost}`);
        console.log(`Model: ${this.modelName} (minimal config)`);
        console.log(`CPU threads: ${this.numThread}`);
    }

    /**
     * Calculate optimal thread count for CPU inference
     */
    getOptimalThreadCount() {
        try {
            const cpuCount = cpus().length;
            const optimalThreads = Math.max(1, Math.min(4, Math.floor(cpuCount / 2)));
            console.log(`CPU detection: ${cpuCount} cores detected, using ${optimalThreads} threads`);
            return optimalThreads;
        } catch (error) {
            console.warn('Could not detect CPU count, defaulting to 2 threads:', error.message);
            return 2;
        }
    }

    /**
     * Execute curl command and return parsed response
     */
    async executeCurl(endpoint, method = 'GET', data = null, timeout = 120) {
        return new Promise((resolve, reject) => {
            const url = `${this.ollamaHost}${endpoint}`;

            const curlArgs = [
                '-s', // Silent
                '-X', method,
                '--connect-timeout', '10',
                '--max-time', timeout.toString(),
                '-H', 'Content-Type: application/json',
                '-H', 'Accept: application/json'
            ];

            if (data) {
                curlArgs.push('-d', JSON.stringify(data));
            }

            curlArgs.push(url);

            console.log(`[CURL] ${method} ${url}`);
            if (data) {
                console.log(`[CURL] Data: ${JSON.stringify(data).substring(0, 100)}...`);
            }

            const curl = spawn('curl', curlArgs);

            let output = '';
            let error = '';

            curl.stdout.on('data', (chunk) => {
                output += chunk.toString();
            });

            curl.stderr.on('data', (chunk) => {
                error += chunk.toString();
            });

            curl.on('close', (code) => {
                if (code === 0) {
                    try {
                        const result = output.trim() ? JSON.parse(output) : {};
                        resolve(result);
                    } catch (parseError) {
                        resolve({ rawOutput: output, parseError: parseError.message });
                    }
                } else {
                    reject(new Error(`Curl failed with code ${code}: ${error}`));
                }
            });

            curl.on('error', (err) => {
                reject(new Error(`Curl execution error: ${err.message}`));
            });
        });
    }

    /**
     * Check Ollama status using curl
     */
    async checkOllamaStatus() {
        try {
            console.log(`Checking Ollama status...`);

            const response = await this.executeCurl('/api/version', 'GET', null, 10);

            if (response.version) {
                console.log(`✓ Ollama available, version: ${response.version}`);
                return true;
            } else if (response.rawOutput) {
                console.log(`✓ Ollama responding (non-JSON): ${response.rawOutput.substring(0, 100)}`);
                return true;
            } else {
                console.error(`❌ Unexpected response:`, response);
                return false;
            }
        } catch (error) {
            console.error(`❌ Ollama connection failed: ${error.message}`);
            return false;
        }
    }

    /**
     * Check model availability
     */
    async checkModelAvailability() {
        try {
            console.log('Checking available models...');
            const response = await this.executeCurl('/api/tags');

            const availableModels = response.models || [];
            console.log(`Found ${availableModels.length} available models`);

            availableModels.forEach(model => {
                console.log(`  - ${model.name}`);
            });

            const modelExists = availableModels.some(model =>
                model.name === this.modelName ||
                model.name.startsWith(this.modelName.split(':')[0])
            );

            if (modelExists) {
                console.log(`✓ Model ${this.modelName} is available`);
                return true;
            } else {
                console.log(`❌ Model ${this.modelName} not found`);
                console.log(`Attempting to pull model ${this.modelName}...`);
                return await this.pullModel();
            }
        } catch (error) {
            console.error(`Error checking model availability:`, error.message);
            return false;
        }
    }

    /**
     * Pull model using curl
     */
    async pullModel() {
        try {
            console.log(`Pulling model ${this.modelName}... This may take a while.`);

            const response = await this.executeCurl('/api/pull', 'POST', {
                name: this.modelName
            }, 600); // 10 minutes timeout

            if (response.status === 'success' || !response.error) {
                console.log(`✓ Model ${this.modelName} pulled successfully`);
                return true;
            } else {
                console.error(`Failed to pull model:`, response);
                return false;
            }
        } catch (error) {
            console.error(`Failed to pull model:`, error.message);
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
            console.log('=== TransformersLLM Initialization ===');

            console.log('Step 1: Checking Ollama availability...');
            this.ollamaAvailable = await this.checkOllamaStatus();

            if (!this.ollamaAvailable) {
                throw new Error(`Ollama is not accessible at ${this.ollamaHost}`);
            }

            console.log('Step 2: Checking model availability...');
            this.modelReady = await this.checkModelAvailability();

            if (!this.modelReady) {
                throw new Error(`Model ${this.modelName} is not available`);
            }

            const initTime = Date.now() - startTime;
            this.stats.initializationTime = initTime;
            this.isInitialized = true;

            console.log(`✓ TransformersLLM initialized successfully in ${initTime}ms`);
            console.log('=== Initialization Complete ===');

            await this.validateModel();

        } catch (error) {
            console.error('=== Initialization Failed ===');
            console.error('Error:', error.message);
            throw error;
        }
    }

    async validateModel() {
        try {
            console.log('Running model validation test...');

            const testResult = await this.generateResponse('Classify: SAFE');

            if (testResult && testResult.trim().length > 0) {
                console.log('✓ Model validation successful');
                console.log('Test response:', testResult.trim().substring(0, 100));
            } else {
                console.warn('⚠ Model validation produced empty response');
            }

        } catch (error) {
            console.warn('⚠ Model validation failed:', error.message);
        }
    }

    /**
     * Generate response using curl with optimized parameters for small model
     */
    async generateResponse(prompt, options = {}) {
        const startTime = Date.now();

        try {
            const requestBody = {
                model: this.modelName,
                prompt: prompt,
                stream: false,
                options: {
                    temperature: this.temperature,
                    top_p: this.topP,
                    num_predict: this.maxTokens,
                    num_thread: this.numThread,
                    repeat_penalty: 1.1,
                    stop: ['\n\n', 'ANALYSIS:', 'NEXT:'] // Stop tokens to prevent rambling
                }
            };

            console.log(`[GENERATE] Sending request (${prompt.length} chars)`);

            const response = await this.executeCurl('/api/generate', 'POST', requestBody, 60);

            const responseTime = Date.now() - startTime;

            if (response.error) {
                throw new Error(`Ollama error: ${response.error}`);
            }

            const generatedResponse = response.response || '';
            console.log(`[GENERATE] Success in ${responseTime}ms`);
            console.log(`[GENERATE] Response: "${generatedResponse.substring(0, 100)}${generatedResponse.length > 100 ? '...' : ''}"`);

            return generatedResponse;

        } catch (error) {
            const responseTime = Date.now() - startTime;
            console.error(`[GENERATE] Failed after ${responseTime}ms:`, error.message);

            if (error.message.includes('timeout')) {
                this.stats.timeouts++;
            } else {
                this.stats.networkErrors++;
            }

            throw error;
        }
    }

    /**
     * Highly simplified prompt optimized for small model
     */
    buildPrompt(logEntry) {
        // Extract only essential info to avoid overwhelming small model
        const ip = logEntry.ip || 'unknown';
        const method = logEntry.method || 'GET';
        const url = (logEntry.url || '/').substring(0, 100); // Limit URL length
        const query = (logEntry.queryString || '').substring(0, 200); // Limit query length
        const userAgent = (logEntry.userAgent || '').substring(0, 50); // Limit UA length

        // Simplify payload to just keys if it's an object
        let payloadInfo = 'none';
        if (logEntry.payload) {
            if (typeof logEntry.payload === 'object') {
                const keys = Object.keys(logEntry.payload);
                payloadInfo = keys.length > 0 ? `${keys.length} fields: ${keys.slice(0, 3).join(', ')}` : 'empty object';
            } else {
                payloadInfo = String(logEntry.payload).substring(0, 100);
            }
        }

        // Ultra-simple prompt for small model
        return `Security check:
IP: ${ip}
${method} ${url}
Query: ${query}
Agent: ${userAgent}
Data: ${payloadInfo}

Classify as exactly one word: SAFE, THREAT, or UNCERTAIN
Then add one sentence why.

Response format:
RESULT: [classification]
REASON: [brief explanation]`;
    }

    async analyze(logEntry) {
        if (!this.isInitialized) {
            throw new Error('TransformersLLM not initialized. Call initialize() first.');
        }

        const startTime = Date.now();

        try {
            console.log(`[ANALYZE] ${logEntry.method || 'GET'} ${logEntry.url || '/'} from ${logEntry.ip}`);

            const prompt = this.buildPrompt(logEntry);
            const result = await this.generateResponse(prompt);

            if (!result || result.trim().length === 0) {
                throw new Error('No response generated');
            }

            const responseTime = Date.now() - startTime;
            const analysisResult = this.parseResponse(result.trim(), responseTime);
            this.updateStats(analysisResult, responseTime);

            return analysisResult;

        } catch (error) {
            console.error('[ANALYZE] Error:', error.message);

            if (error.message.includes('timeout')) {
                this.stats.timeouts++;
            } else {
                this.stats.networkErrors++;
            }

            return {
                decision: 'UNCERTAIN',
                confidence: 0,
                explanation: `Analysis error: ${error.message}`,
                requiresSecondaryAnalysis: true,
                tier: 'primary',
                error: true,
                responseTime: Date.now() - startTime
            };
        }
    }

    /**
     * Robust response parsing with multiple fallback strategies
     */
    parseResponse(rawResponse, responseTime) {
        console.log(`[PARSE] Raw response: "${rawResponse}"`);

        let decision = 'UNCERTAIN';
        let confidence = 3;
        let explanation = 'Could not parse response';
        let requiresSecondaryAnalysis = true;
        let parseSuccess = false;

        try {
            // Clean the response
            const cleanResponse = rawResponse.trim().replace(/\s+/g, ' ');
            const upperResponse = cleanResponse.toUpperCase();

            // Strategy 1: Look for structured RESULT: format
            const resultMatch = cleanResponse.match(/RESULT:\s*(SAFE|THREAT|UNCERTAIN)/i);
            const reasonMatch = cleanResponse.match(/REASON:\s*(.+?)(?:\n|$)/is);

            if (resultMatch) {
                const result = resultMatch[1].toUpperCase();
                parseSuccess = true;
                confidence = 8;

                switch (result) {
                    case 'SAFE':
                        decision = 'BENIGN';
                        requiresSecondaryAnalysis = false;
                        break;
                    case 'THREAT':
                        decision = 'MALICIOUS';
                        requiresSecondaryAnalysis = false;
                        break;
                    case 'UNCERTAIN':
                        decision = 'UNCERTAIN';
                        requiresSecondaryAnalysis = true;
                        break;
                }

                if (reasonMatch) {
                    explanation = reasonMatch[1].trim();
                }
            }
            // Strategy 2: Look for keywords at start of response
            else if (/^(SAFE|BENIGN|NORMAL|OK)/i.test(cleanResponse)) {
                decision = 'BENIGN';
                confidence = 6;
                explanation = 'Safe request identified';
                requiresSecondaryAnalysis = false;
                parseSuccess = true;
            }
            else if (/^(THREAT|MALICIOUS|ATTACK|DANGEROUS|EXPLOIT)/i.test(cleanResponse)) {
                decision = 'MALICIOUS';
                confidence = 6;
                explanation = 'Threat indicators found';
                requiresSecondaryAnalysis = false;
                parseSuccess = true;
            }
            else if (/^(UNCERTAIN|UNKNOWN|UNCLEAR|MAYBE)/i.test(cleanResponse)) {
                decision = 'UNCERTAIN';
                confidence = 6;
                explanation = 'Requires further analysis';
                requiresSecondaryAnalysis = true;
                parseSuccess = true;
            }
            // Strategy 3: Keyword presence anywhere in response
            else {
                const keywords = {
                    safe: ['SAFE', 'BENIGN', 'NORMAL', 'LEGITIMATE', 'CLEAN', 'OK'],
                    threat: ['THREAT', 'MALICIOUS', 'ATTACK', 'EXPLOIT', 'INJECTION', 'XSS', 'SQL', 'DANGEROUS'],
                    uncertain: ['UNCERTAIN', 'UNKNOWN', 'UNCLEAR', 'SUSPICIOUS', 'MAYBE', 'POSSIBLE']
                };

                let safeScore = 0;
                let threatScore = 0;
                let uncertainScore = 0;

                // Count keyword matches
                keywords.safe.forEach(word => {
                    if (upperResponse.includes(word)) safeScore++;
                });
                keywords.threat.forEach(word => {
                    if (upperResponse.includes(word)) threatScore++;
                });
                keywords.uncertain.forEach(word => {
                    if (upperResponse.includes(word)) uncertainScore++;
                });

                console.log(`[PARSE] Keyword scores - Safe: ${safeScore}, Threat: ${threatScore}, Uncertain: ${uncertainScore}`);

                if (threatScore > 0 && threatScore >= safeScore) {
                    decision = 'MALICIOUS';
                    confidence = Math.min(7, 3 + threatScore);
                    explanation = 'Threat keywords detected';
                    requiresSecondaryAnalysis = false;
                    parseSuccess = true;
                } else if (safeScore > 0 && safeScore > threatScore) {
                    decision = 'BENIGN';
                    confidence = Math.min(7, 3 + safeScore);
                    explanation = 'Safe keywords detected';
                    requiresSecondaryAnalysis = false;
                    parseSuccess = true;
                } else if (uncertainScore > 0) {
                    decision = 'UNCERTAIN';
                    confidence = Math.min(6, 3 + uncertainScore);
                    explanation = 'Uncertain classification';
                    requiresSecondaryAnalysis = true;
                    parseSuccess = true;
                }
            }

            // Strategy 4: Length-based fallback for very short responses
            if (!parseSuccess && cleanResponse.length < 10) {
                decision = 'UNCERTAIN';
                confidence = 2;
                explanation = 'Response too short to analyze';
                requiresSecondaryAnalysis = true;
                console.log('[PARSE] Using short response fallback');
            }

        } catch (parseError) {
            console.error('[PARSE] Error:', parseError.message);
            this.stats.parseFailures++;
        }

        // Ensure explanation exists and is reasonable length
        if (!explanation || explanation.length < 3) {
            explanation = decision === 'MALICIOUS' ? 'Threat detected' :
                decision === 'BENIGN' ? 'Normal request' : 'Needs analysis';
        }

        // Clean explanation
        explanation = explanation.replace(/[^\w\s\-\.,!?]/g, '').trim();


        if (!parseSuccess) {
            this.stats.parseFailures++;
            console.warn('[PARSE] Failed to parse response properly, using fallback');
        }

        console.log(`[PARSE] Final result:`);
        console.log(`  Decision: "${decision}"`);
        console.log(`  Confidence: ${confidence}/10`);
        console.log(`  Explanation: "${explanation}"`);
        console.log(`  Parse success: ${parseSuccess}`);

        return {
            decision,
            confidence,
            explanation,
            requiresSecondaryAnalysis,
            tier: 'primary',
            model: 'ollama-curl',
            modelName: this.modelName,
            responseTime,
            rawResponse: rawResponse,
            timestamp: new Date().toISOString(),
            parseSuccess
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

    /**
     * Test connection with simplified prompt
     */
    async testConnection() {
        try {
            console.log('=== Connection Test Starting ===');

            if (!this.isInitialized) {
                console.log('Initializing for connection test...');
                await this.initialize();
            }

            const testStart = Date.now();

            // Use simple test case
            const testResult = await this.analyze({
                ip: '192.168.1.100',
                method: 'GET',
                url: '/home',
                queryString: '',
                userAgent: 'Mozilla/5.0'
            });

            const testTime = Date.now() - testStart;

            console.log('=== Connection Test Successful ===');

            return {
                success: true,
                message: 'Curl-based connection successful',
                model: 'ollama-curl',
                modelName: this.modelName,
                ollamaHost: this.ollamaHost,
                httpClient: 'curl',
                optimizations: {
                    cpuThreads: this.numThread,
                    shortPrompts: true,
                    lowTemperature: true,
                    shortResponses: true,
                    stopTokens: true
                },
                testTime,
                testResult: {
                    decision: testResult.decision,
                    confidence: testResult.confidence,
                    explanation: testResult.explanation,
                    responseTime: testResult.responseTime,
                    parseSuccess: testResult.parseSuccess
                },
                stats: this.getStats()
            };

        } catch (error) {
            console.error('=== Connection Test Failed ===');
            console.error('Error details:', error);

            return {
                success: false,
                message: `Connection failed: ${error.message}`,
                model: 'ollama-curl',
                modelName: this.modelName,
                ollamaHost: this.ollamaHost,
                httpClient: 'curl',
                error: error.message,
                troubleshooting: [
                    '1. Check if Ollama is running: systemctl status ollama',
                    '2. Test connectivity: curl http://parrot.tail3f550b.ts.net:11434/api/version',
                    '3. Verify curl is installed and accessible',
                    '4. Check network connectivity and firewall',
                    '5. Try simpler model like llama3.2:1b'
                ]
            };
        }
    }

    getStats() {
        const total = this.stats.totalAnalyzed;
        const parseSuccessRate = total > 0 ? ((total - this.stats.parseFailures) / total * 100).toFixed(1) : '0.0';

        return {
            model: 'ollama-curl',
            modelName: this.modelName,
            ollamaHost: this.ollamaHost,
            httpClient: 'curl',
            optimizations: {
                cpuThreads: this.numThread,
                shortPrompts: true,
                lowTemperature: true,
                shortResponses: true,
                stopTokens: true
            },
            initialized: this.isInitialized,
            ollamaAvailable: this.ollamaAvailable,
            modelReady: this.modelReady,
            initializationTime: this.stats.initializationTime,
            totalAnalyzed: total,
            benignCount: this.stats.benignCount,
            maliciousCount: this.stats.maliciousCount,
            uncertainCount: this.stats.uncertainCount,
            parseFailures: this.stats.parseFailures,
            parseSuccessRate: parseSuccessRate + '%',
            networkErrors: this.stats.networkErrors,
            timeouts: this.stats.timeouts,
            benignPercent: total > 0 ? ((this.stats.benignCount / total) * 100).toFixed(1) : '0.0',
            maliciousPercent: total > 0 ? ((this.stats.maliciousCount / total) * 100).toFixed(1) : '0.0',
            uncertainPercent: total > 0 ? ((this.stats.uncertainCount / total) * 100).toFixed(1) : '0.0',
            averageResponseTime: Math.round(this.stats.averageResponseTime)
        };
    }

    resetStats() {
        const initTime = this.stats.initializationTime;
        this.stats = {
            totalAnalyzed: 0,
            benignCount: 0,
            maliciousCount: 0,
            uncertainCount: 0,
            parseFailures: 0,
            averageResponseTime: 0,
            initializationTime: initTime,
            networkErrors: 0,
            timeouts: 0
        };
        console.log('Statistics reset');
    }

    getModelInfo() {
        return {
            model: 'ollama-curl',
            modelName: this.modelName,
            ollamaHost: this.ollamaHost,
            httpClient: 'curl',
            optimizations: {
                cpuThreads: this.numThread,
                shortPrompts: true,
                lowTemperature: true,
                shortResponses: true,
                stopTokens: true
            },
            initialized: this.isInitialized,
            ollamaAvailable: this.ollamaAvailable,
            modelReady: this.modelReady
        };
    }

    clearHistory() {
        console.log('Ollama is stateless - no history to clear');
    }

    async dispose() {
        try {
            console.log('Disposing TransformersLLM resources...');
            this.isInitialized = false;
            console.log('TransformersLLM disposed successfully');
        } catch (error) {
            console.warn('Error during disposal:', error.message);
        }
    }

    /**
     * Enhanced diagnostics with parsing tests
     */
    async diagnoseConnection() {
        console.log('=== Network Diagnostics (Curl) ===');

        const diagnostics = {
            timestamp: new Date().toISOString(),
            host: this.ollamaHost,
            httpClient: 'curl',
            tests: []
        };

        // Test 1: Basic connectivity
        try {
            console.log('Testing basic connectivity...');
            const response = await this.executeCurl('/api/version', 'GET', null, 10);
            diagnostics.tests.push({
                name: 'Basic Connectivity',
                status: 'PASS',
                details: `Ollama version: ${response.version || 'detected'}`
            });
        } catch (error) {
            diagnostics.tests.push({
                name: 'Basic Connectivity',
                status: 'FAIL',
                details: error.message,
                suggestion: 'Check if Ollama is running and accessible'
            });
        }

        // Test 2: Model list
        try {
            console.log('Testing model list endpoint...');
            const response = await this.executeCurl('/api/tags', 'GET', null, 15);
            const models = response.models || [];
            diagnostics.tests.push({
                name: 'Model List',
                status: 'PASS',
                details: `Found ${models.length} models`
            });
        } catch (error) {
            diagnostics.tests.push({
                name: 'Model List',
                status: 'FAIL',
                details: error.message
            });
        }

        // Test 3: Parsing test with known responses
        try {
            console.log('Testing response parsing...');

            const testCases = [
                'RESULT: SAFE\nREASON: Normal request',
                'RESULT: THREAT\nREASON: SQL injection detected',
                'RESULT: UNCERTAIN\nREASON: Needs more analysis',
                'SAFE - looks normal',
                'THREAT detected',
                'UNCERTAIN classification'
            ];

            let parseSuccesses = 0;
            for (const testCase of testCases) {
                const parsed = this.parseResponse(testCase, 100);
                if (parsed.parseSuccess || parsed.decision !== 'UNCERTAIN' || testCase.includes('UNCERTAIN')) {
                    parseSuccesses++;
                }
            }

            diagnostics.tests.push({
                name: 'Response Parsing',
                status: parseSuccesses >= 4 ? 'PASS' : 'PARTIAL',
                details: `${parseSuccesses}/${testCases.length} test cases parsed correctly`
            });

        } catch (error) {
            diagnostics.tests.push({
                name: 'Response Parsing',
                status: 'FAIL',
                details: error.message
            });
        }

        // Test 4: Quick generation with simple prompt
        try {
            console.log('Testing quick generation...');
            const response = await this.executeCurl('/api/generate', 'POST', {
                model: this.modelName,
                prompt: 'Classify this as: SAFE, THREAT, or UNCERTAIN\nRequest: GET /home\nClassify:',
                stream: false,
                options: {
                    temperature: 0.0,
                    num_predict: 20,
                    stop: ['\n']
                }
            }, 30);

            const result = response.response || '';
            diagnostics.tests.push({
                name: 'Quick Generation',
                status: 'PASS',
                details: `Response: "${result.substring(0, 50)}${result.length > 50 ? '...' : ''}"`
            });
        } catch (error) {
            diagnostics.tests.push({
                name: 'Quick Generation',
                status: 'FAIL',
                details: error.message
            });
        }

        console.log('=== Diagnostic Results ===');
        diagnostics.tests.forEach(test => {
            console.log(`${test.status === 'PASS' ? '✓' : test.status === 'PARTIAL' ? '⚠' : '❌'} ${test.name}: ${test.details}`);
            if (test.suggestion) {
                console.log(`   Suggestion: ${test.suggestion}`);
            }
        });

        return diagnostics;
    }

    /**
     * Run calibration tests to improve parsing
     */
    async runCalibrationTests() {
        console.log('=== Running Calibration Tests ===');

        const testCases = [
            {
                name: 'Normal Request',
                logEntry: { ip: '192.168.1.1', method: 'GET', url: '/home', queryString: '', userAgent: 'Mozilla/5.0' },
                expected: 'BENIGN'
            },
            {
                name: 'SQL Injection',
                logEntry: { ip: '10.0.0.1', method: 'GET', url: '/search', queryString: "q=' OR 1=1--", userAgent: 'curl/7.68.0' },
                expected: 'MALICIOUS'
            },
            {
                name: 'XSS Attempt',
                logEntry: { ip: '172.16.0.1', method: 'POST', url: '/comment', payload: { text: '<script>alert(1)</script>' }, userAgent: 'Mozilla/5.0' },
                expected: 'MALICIOUS'
            },
            {
                name: 'Suspicious Pattern',
                logEntry: { ip: '203.0.113.1', method: 'GET', url: '/admin/../../../etc/passwd', queryString: '', userAgent: 'wget/1.20.3' },
                expected: 'MALICIOUS'
            },
            {
                name: 'Ambiguous Request',
                logEntry: { ip: '198.51.100.1', method: 'POST', url: '/api/data', payload: { action: 'delete_all' }, userAgent: 'CustomApp/1.0' },
                expected: 'UNCERTAIN'
            }
        ];

        const results = [];
        let correctClassifications = 0;

        for (const testCase of testCases) {
            try {
                console.log(`\nTesting: ${testCase.name}`);
                const result = await this.analyze(testCase.logEntry);

                const isCorrect = result.decision === testCase.expected;
                if (isCorrect) correctClassifications++;

                results.push({
                    name: testCase.name,
                    expected: testCase.expected,
                    actual: result.decision,
                    confidence: result.confidence,
                    explanation: result.explanation,
                    responseTime: result.responseTime,
                    parseSuccess: result.parseSuccess,
                    correct: isCorrect
                });

                console.log(`  Expected: ${testCase.expected}, Got: ${result.decision} (${isCorrect ? 'CORRECT' : 'INCORRECT'})`);
                console.log(`  Confidence: ${result.confidence}/10, Parse: ${result.parseSuccess ? 'OK' : 'FAILED'}`);
                console.log(`  Explanation: "${result.explanation}"`);

                // Small delay to avoid overwhelming the model
                await new Promise(resolve => setTimeout(resolve, 1000));

            } catch (error) {
                console.error(`  Test failed: ${error.message}`);
                results.push({
                    name: testCase.name,
                    expected: testCase.expected,
                    actual: 'ERROR',
                    error: error.message,
                    correct: false
                });
            }
        }

        const accuracy = (correctClassifications / testCases.length * 100).toFixed(1);

        console.log(`\n=== Calibration Results ===`);
        console.log(`Accuracy: ${correctClassifications}/${testCases.length} (${accuracy}%)`);
        console.log(`Parse success rate: ${this.getStats().parseSuccessRate}`);

        return {
            accuracy: parseFloat(accuracy),
            correctClassifications,
            totalTests: testCases.length,
            results,
            recommendations: this.generateRecommendations(results)
        };
    }

    /**
     * Generate recommendations based on calibration results
     */
    generateRecommendations(results) {
        const recommendations = [];

        const parseFailures = results.filter(r => r.parseSuccess === false).length;
        const lowConfidence = results.filter(r => r.confidence < 5).length;
        const incorrectClassifications = results.filter(r => !r.correct).length;

        if (parseFailures > 0) {
            recommendations.push({
                issue: 'Parse Failures',
                count: parseFailures,
                suggestion: 'Consider using even simpler prompts or adding more stop tokens'
            });
        }

        if (lowConfidence > 0) {
            recommendations.push({
                issue: 'Low Confidence',
                count: lowConfidence,
                suggestion: 'Model may need more specific examples or different temperature settings'
            });
        }

        if (incorrectClassifications > 0) {
            recommendations.push({
                issue: 'Incorrect Classifications',
                count: incorrectClassifications,
                suggestion: 'Consider fine-tuning prompt or using a larger model'
            });
        }

        if (recommendations.length === 0) {
            recommendations.push({
                issue: 'Performance',
                suggestion: 'Model performing well with current configuration'
            });
        }

        return recommendations;
    }

    /**
     * Batch analysis with rate limiting for small model
     */
    async analyzeBatch(logEntries, options = {}) {
        const batchSize = options.batchSize || 5; // Small batches
        const delayBetweenBatches = options.delay || 2000; // 2 second delay

        console.log(`[BATCH] Analyzing ${logEntries.length} entries in batches of ${batchSize}`);

        const results = [];

        for (let i = 0; i < logEntries.length; i += batchSize) {
            const batch = logEntries.slice(i, i + batchSize);
            console.log(`[BATCH] Processing batch ${Math.floor(i/batchSize) + 1}/${Math.ceil(logEntries.length/batchSize)}`);

            const batchPromises = batch.map(entry => this.analyze(entry));
            const batchResults = await Promise.allSettled(batchPromises);

            batchResults.forEach((result, index) => {
                if (result.status === 'fulfilled') {
                    results.push(result.value);
                } else {
                    console.error(`[BATCH] Entry ${i + index} failed:`, result.reason.message);
                    results.push({
                        decision: 'UNCERTAIN',
                        confidence: 0,
                        explanation: 'Batch processing error',
                        error: true,
                        responseTime: 0
                    });
                }
            });

            // Delay between batches to avoid overwhelming small model
            if (i + batchSize < logEntries.length) {
                console.log(`[BATCH] Waiting ${delayBetweenBatches}ms before next batch...`);
                await new Promise(resolve => setTimeout(resolve, delayBetweenBatches));
            }
        }

        console.log(`[BATCH] Completed ${results.length} analyses`);
        return results;
    }
}

export default TransformersLLM;