import fs from 'fs';
import YAML from 'yaml';
import winston from 'winston';
import LogParser from './logparser.js';
import ThreatDetector from './threatdetector.js';
import LLMAnalyzer from './llmanalyzer.js';
import IntelChecker from './intelchecker.js';
import PushoverNotifier from './pushover.js';
import { blockIpAddress } from './llmtools.js';
import { createClient } from '@supabase/supabase-js';

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

class LogSecurityAgent {
    constructor() {
        this.config = this.loadConfig();
        this.setupLogger();
        this.initializeComponents();
        this.threatQueue = [];
        this.isProcessing = false;
        this.maxQueueSize = this.config.max_queue_size || 1000;
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

                // Check queue size to prevent memory issues
                if (this.threatQueue.length >= this.maxQueueSize) {
                    this.logger.warn('Threat queue is full, dropping oldest entry');
                    this.threatQueue.shift();
                }

                // Add to processing queue - LLM will make final decision
                this.threatQueue.push({ logEntry, threatResult });

                // Start processing if not already running
                if (!this.isProcessing) {
                    this.processThreatQueue().catch(error => {
                        this.logger.error('Error in threat queue processing:', error);
                    });
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
        if (this.isProcessing) {
            return; // Already processing
        }

        this.isProcessing = true;

        try {
            while (this.threatQueue.length > 0) {
                const { logEntry, threatResult } = this.threatQueue.shift();

                try {
                    // Stopped using this,created it as a tool for the llm to use
                    // Gather intelligence data first to provide context to LLM
                    // const intelData = await this.intelChecker.checkIP(logEntry.ip);
                    // threatResult.intelData = intelData;

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
                        // await this.pushOverNotification.sendThreatAlert(logEntry, finalResult);

                        // Save malicious requests to supabase
                        const { error: postgresError } = await supabase
                            .from('logagent')
                            .insert({
                                ip_address: logEntry.ip,
                                method: logEntry.method,
                                query_string: logEntry.queryString,
                                user_agent: logEntry.userAgent,
                                url: logEntry.url,
                                status: logEntry.status,
                                decision: finalResult.finalDecision,
                                reasoning: llmAnalysis.explanation,
                                decision_maker: 'LLM',
                                confidence: finalResult.finalScore
                            });

                        if (postgresError) {
                            this.logger.error('Error while creating supabase record:', postgresError);
                        }

                        // Block IP if LLM confidence is high enough
                        if (confidence >= this.config.thresholds.block_ip_threshold) {
                            try {
                                 blockIpAddress(logEntry.ip);
                                this.logger.warn('IP blocked based on LLM decision', {
                                    ip: logEntry.ip,
                                    confidence: confidence,
                                    reason: llmAnalysis.explanation
                                });
                            } catch (blockError) {
                                this.logger.error('Failed to block IP address:', blockError);
                            }
                        }
                    } else {
                        // Log benign classification for monitoring
                        this.logger.info('Request classified as benign by LLM', {
                            ip: logEntry.ip,
                            confidence: confidence,
                            reason: llmAnalysis.explanation
                        });
                    }

                    // Rate limiting - configurable delay between API calls
                    const processingDelay = this.config.processing_delay || 1000;
                    await new Promise(resolve => setTimeout(resolve, processingDelay));

                } catch (error) {
                    this.logger.error('Error in LLM threat processing:', error);

                    // Fallback to traditional scoring if LLM fails
                    const fallbackScore = this.calculateFallbackScore(threatResult);
                    if (fallbackScore >= this.config.thresholds.alert_threshold) {
                        this.logger.warn('Using fallback scoring due to LLM failure');

                        try {
                            await this.pushOverNotification.sendThreatAlert(logEntry, {
                                ...threatResult,
                                finalScore: fallbackScore,
                                finalDecision: 'THREAT_FALLBACK',
                                decisionMaker: 'FALLBACK'
                            });
                        } catch (notificationError) {
                            this.logger.error('Failed to send threat alert:', notificationError);
                        }

                        try {
                            const { error: fallbackError } = await supabase
                                .from('logagent')
                                .insert({
                                    ip_address: logEntry.ip,
                                    method: logEntry.method,
                                    query_string: logEntry.queryString,
                                    user_agent: logEntry.userAgent,
                                    url: logEntry.url,
                                    status: logEntry.status,
                                    decision: 'THREAT_FALLBACK',
                                    decision_maker: 'FALLBACK',
                                    confidence: fallbackScore
                                });

                            if (fallbackError) {
                                this.logger.error('Error while creating fallback supabase record:', fallbackError);
                            }
                        } catch (dbError) {
                            this.logger.error('Database error in fallback:', dbError);
                        }
                    }
                }
            }
        } finally {
            this.isProcessing = false;
        }
    }

    /**
     * Fallback scoring method when LLM is unavailable
     */
    calculateFallbackScore(threatResult) {
        let score = threatResult.confidence || 0;

        // Boost score if IP has bad reputation
        if (threatResult.intelData?.maliciousCount > 0) {
            score += 2;
        }

        // Additional fallback scoring logic
        if (threatResult.intelData?.isMalicious) {
            score += 1;
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
            try {
                await this.pushOverNotification.sendMessage('🟢 LLM-Powered Log Security Agent started');
            } catch (notificationError) {
                this.logger.warn('Failed to send startup notification:', notificationError);
            }

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

        try {
            // Wait for current processing to complete
            while (this.isProcessing) {
                await new Promise(resolve => setTimeout(resolve, 100));
            }

            await this.logParser.stop();

            try {
                await this.pushOverNotification.sendMessage('🔴 Log Security Agent stopped');
            } catch (notificationError) {
                this.logger.warn('Failed to send shutdown notification:', notificationError);
            }

            this.logger.info('Agent shutdown complete');
        } catch (error) {
            this.logger.error('Error during shutdown:', error);
        }

        process.exit(0);
    }
}

// Handle graceful shutdown
process.on('SIGINT', async () => {
    if (global.agent) {
        await global.agent.shutdown();
    }
});

process.on('SIGTERM', async () => {
    if (global.agent) {
        await global.agent.shutdown();
    }
});

// Start the agent
const agent = new LogSecurityAgent();
global.agent = agent;
agent.start().catch(error => {
    console.error('Failed to start agent:', error);
    process.exit(1);
});

export default LogSecurityAgent;