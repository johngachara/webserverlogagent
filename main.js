const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const YAML = require('yaml');
const winston = require('winston');
const LogParser = require('./logparser');
const ThreatDetector = require('./threatdetector');
const LLMAnalyzer = require('./llmanalyzer');
const IntelChecker = require('./intelchecker');
const PushoverNotifier = require('./pushover');

class LogSecurityAgent {
    constructor() {
        this.config = this.loadConfig();
        this.setupLogger();
        this.initializeComponents();
        this.threatQueue = [];
        this.isProcessing = false;
    }

    /**
     * Load configuration from YAML file
     */
    loadConfig() {
        try {
            const configFile = fs.readFileSync('config.yaml', 'utf8');
            return YAML.parse(configFile);
        } catch (error) {
            console.error('Failed to load config:', error.message);
            process.exit(1);
        }
    }

    /**
     * Setup Winston logger for structured logging
     */
    setupLogger() {
        this.logger = winston.createLogger({
            level: 'info',
            format: winston.format.combine(
                winston.format.timestamp(),
                winston.format.json()
            ),
            transports: [
                new winston.transports.File({ filename: 'agent.log' }),
                new winston.transports.Console({
                    format: winston.format.simple()
                })
            ]
        });
    }

    /**
     * Initialize all agent components
     */
    initializeComponents() {
        this.logParser = new LogParser(this.config.logs, this.onLogEntry.bind(this));
        this.threatDetector = new ThreatDetector(this.config.thresholds);
        this.llmAnalyzer = new LLMAnalyzer(process.env.GROQKEY);
        this.intelChecker = new IntelChecker();
        this.pushOverNotification = new PushoverNotifier(
            process.env.PUSHOVERUSERKEY,
            process.env.PUSHOVERAPPTOKEN
        );
    }

    async blockIpAddress(ipAddress) {
        const command = `iptables -A INPUT -s ${ipAddress} -j DROP`;
        exec(command, (error, stdout, stderr) => {
            if (error) {
                console.error(`Error blocking IP: ${error}`);
                return;
            }
            console.log(`IP ${ipAddress} blocked successfully`);
        });
    }

    /**
     * Handle new log entries from parser
     */
    async onLogEntry(logEntry) {
        try {
            this.logger.info('Processing log entry', { ip: logEntry.ip, url: logEntry.url });

            // Run initial threat detection to identify potential threats
            const threatResult = await this.threatDetector.analyze(logEntry);

            // Only proceed if initial detection finds potential threats OR if we want to analyze all traffic
            if (threatResult.isThreat || this.config.analyze_all_traffic) {
                this.logger.info('Potential threat detected, queuing for LLM analysis', threatResult);

                // Add to processing queue - LLM will make final decision
                this.threatQueue.push({ logEntry, threatResult });

                if (!this.isProcessing) {
                    await this.processThreatQueue();
                }
            }
        } catch (error) {
            this.logger.error('Error processing log entry:', error);
        }
    }

    /**
     * Process queued threats with LLM as final decision maker
     */
    async processThreatQueue() {
        this.isProcessing = true;

        while (this.threatQueue.length > 0) {
            const { logEntry, threatResult } = this.threatQueue.shift();

            try {
                // Gather intelligence data first to provide context to LLM
                const intelData = await this.intelChecker.checkIP(logEntry.ip);
                threatResult.intelData = intelData;

                // LLM makes the final decision with all available context
                this.logger.info('Requesting LLM analysis for final threat determination');
                const llmAnalysis = await this.llmAnalyzer.analyze(logEntry, threatResult);

                // LLM decision overrides everything else
                // Handle both old and new LLM response formats
                const isMalicious = llmAnalysis.isMalicious !== null ? llmAnalysis.isMalicious : false;
                const confidence = llmAnalysis.confidence || 0;

                const finalResult = {
                    ...threatResult,
                    llmAnalysis: llmAnalysis,
                    isMalicious: isMalicious,
                    finalScore: confidence,
                    finalDecision: isMalicious ? 'MALICIOUS' : 'BENIGN',
                    decisionMaker: 'LLM'
                };

                this.logger.info('LLM Analysis Complete', {
                    ip: logEntry.ip,
                    decision: finalResult.finalDecision,
                    confidence: finalResult.finalScore,
                    reasoning: llmAnalysis.explanation
                });

                // Act based on LLM decision
                if (isMalicious) {
                    // Send alert for all LLM-confirmed threats
                    await this.pushOverNotification.sendThreatAlert(logEntry, finalResult);

                    // Block IP if LLM confidence is high enough
                    if (confidence >= this.config.thresholds.block_ip_threshold) {
                        await this.blockIpAddress(logEntry.ip);
                        this.logger.warn('IP blocked based on LLM decision', {
                            ip: logEntry.ip,
                            confidence: confidence,
                            reason: llmAnalysis.explanation
                        });
                    }
                } else {
                    // Log benign classification for monitoring
                    this.logger.info('Request classified as benign by LLM', {
                        ip: logEntry.ip,
                        confidence: confidence,
                        reason: llmAnalysis.explanation
                    });
                }

                // Rate limiting - wait between API calls
                await new Promise(resolve => setTimeout(resolve, 1000));

            } catch (error) {
                this.logger.error('Error in LLM threat processing:', error);

                // Fallback to traditional scoring if LLM fails
                const fallbackScore = this.calculateFallbackScore(threatResult);
                if (fallbackScore >= this.config.thresholds.alert_threshold) {
                    this.logger.warn('Using fallback scoring due to LLM failure');
                    await this.pushOverNotification.sendThreatAlert(logEntry, {
                        ...threatResult,
                        finalScore: fallbackScore,
                        finalDecision: 'THREAT_FALLBACK',
                        decisionMaker: 'FALLBACK'
                    });
                }
            }
        }

        this.isProcessing = false;
    }

    /**
     * Fallback scoring method when LLM is unavailable
     */
    calculateFallbackScore(threatResult) {
        let score = threatResult.confidence;

        // Boost score if IP has bad reputation
        if (threatResult.intelData && threatResult.intelData.maliciousCount > 0) {
            score += 2;
        }

        return Math.min(score, 10); // Cap at 10
    }

    /**
     * Start the agent
     */
    async start() {
        this.logger.info('Starting LLM-Powered Log Security Agent');

        try {
            // Test LLM connection before starting
            const llmTest = await this.llmAnalyzer.testConnection();
            if (!llmTest.success) {
                this.logger.error('LLM connection failed:', llmTest.message);
                throw new Error(`LLM connection failed: ${llmTest.message}`);
            }

            await this.logParser.start();
            await this.pushOverNotification.start();

            this.logger.info('Agent started successfully with LLM decision making');

            // Send startup notification
            await this.pushOverNotification.sendMessage('🟢 LLM-Powered Log Security Agent started');

        } catch (error) {
            this.logger.error('Failed to start agent:', error);
            process.exit(1);
        }
    }

    /**
     * Graceful shutdown
     */
    async shutdown() {
        this.logger.info('Shutting down agent');

        await this.logParser.stop();
        await this.pushOverNotification.sendMessage('🔴 Log Security Agent stopped');

        process.exit(0);
    }
}

// Handle graceful shutdown
process.on('SIGINT', async () => {
    if (global.agent) {
        await global.agent.shutdown();
    }
});

// Start the agent
if (require.main === module) {
    global.agent = new LogSecurityAgent();
    global.agent.start();
}

module.exports = LogSecurityAgent;