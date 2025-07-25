import Push from 'pushover-notifications';
import moment from 'moment';
import { promises as fs } from 'fs';
import path from 'path';

class PushoverNotifier {
    constructor(userKey, appToken, options = {}) {
        this.push = new Push({
            user: userKey,
            token: appToken,
            // Optional: set default device if you want to target specific devices
            device: options.device || null
        });

        this.userKey = userKey;
        this.appToken = appToken;
        this.options = {
            soundProfile: options.soundProfile || 'default', // default, high, low
            enableGrouping: options.enableGrouping || true,
            maxDailyAlerts: options.maxDailyAlerts || 100,
            statsFile: options.statsFile || './pushover_stats.json',
            ...options
        };

        this.alertCounts = {
            daily: 0,
            weekly: 0,
            monthly: 0,
            lastReset: moment().startOf('day'),
            lastWeeklyReset: moment().startOf('week'),
            lastMonthlyReset: moment().startOf('month')
        };

        // Load existing stats on startup
        this.loadStats();
    }

    /**
     * Initialize the notifier and validate API credentials
     */
    async start() {
        try {
            console.log('🚀 Starting Pushover Notifier...');

            // Validate API credentials
            const validation = await this.validateCredentials();
            if (!validation.success) {
                throw new Error(`Pushover API validation failed: ${validation.error}`);
            }

            console.log(`✅ Pushover validated for user: ${validation.userInfo.name || 'Unknown'}`);
            console.log(`📱 Available devices: ${validation.userInfo.devices ? validation.userInfo.devices.join(', ') : 'All devices'}`);

            // Send startup notification
            await this.sendStartupNotification();

            // Set up periodic stats saving
            this.setupPeriodicSave();

            return true;
        } catch (error) {
            console.error('❌ Failed to start Pushover notifier:', error.message);
            throw error;
        }
    }

    /**
     * Validate Pushover API credentials
     */
    async validateCredentials() {
        return new Promise((resolve) => {
            this.push.send({
                message: "API Validation Test",
                title: "Pushover Test",
                priority: -2, // Silent notification
                sound: 'none'
            }, (err, result) => {
                if (err) {
                    resolve({ success: false, error: err.message });
                } else {
                    // Get user info if possible
                    resolve({
                        success: true,
                        result,
                        userInfo: result.user || {}
                    });
                }
            });
        });
    }

    /**
     * Send threat alert via Pushover
     */
    async sendThreatAlert(logEntry, threatResult) {
        try {
            // Check daily alert limit
            if (this.alertCounts.daily >= this.options.maxDailyAlerts) {
                console.log(`⚠️ Daily alert limit (${this.options.maxDailyAlerts}) reached. Skipping alert.`);
                return;
            }

            const priority = this.getThreatPriority(threatResult.finalScore);
            const sound = this.getThreatSound(threatResult.finalScore);
            const message = this.formatThreatMessage(logEntry, threatResult);
            const title = this.formatThreatTitle(logEntry, threatResult);

            const pushoverMessage = {
                message: message,
                title: title,
                priority: priority,
                sound: sound,
                timestamp: moment(logEntry.timestamp).unix(),
                url: this.generateDashboardUrl(logEntry),
                url_title: "View Details"
            };

            // Add retry and expire for high priority alerts
            if (priority === 2) {
                pushoverMessage.retry = 60; // Retry every 60 seconds
                pushoverMessage.expire = 3600; // Stop trying after 1 hour
            }

            // Add HTML formatting if message is long or has rich content
            const hasRichContent = threatResult.llmAnalysis ||
                (threatResult.intelData && threatResult.intelData.maliciousCount > 0);

            if (message.length > 512 || hasRichContent) {
                pushoverMessage.html = 1;
                pushoverMessage.message = this.formatHtmlMessage(logEntry, threatResult);
            }

            await this.sendPushoverMessage(pushoverMessage);
            this.incrementAlertCount();

            console.log(`📱 Threat alert sent: ${logEntry.ip} (Score: ${threatResult.finalScore}/10)`);

        } catch (error) {
            console.error('❌ Failed to send Pushover threat alert:', error);
            // Try to send a fallback notification about the error
            await this.sendErrorNotification(error, 'threat_alert');
        }
    }

    /**
     * Format threat message for Pushover
     */
    formatThreatMessage(logEntry, threatResult) {
        const timestamp = moment(logEntry.timestamp).format('MMM DD HH:mm:ss');
        const threats = threatResult.threats.map(t => t.type).join(', ');
        const emoji = this.getThreatEmoji(threatResult.finalScore);

        let message = `${emoji} THREAT DETECTED\n\n`;
        message += `Time: ${timestamp}\n`;
        message += `IP: ${logEntry.ip}\n`;
        message += `Method: ${logEntry.method}\n`;
        message += `URL: ${this.truncateUrl(logEntry.url, 60)}\n`;

        if (logEntry.queryString) {
            message += `Query: ${logEntry.queryString.substring(0, 80)}${logEntry.queryString.length > 80 ? '...' : ''}\n`;
        }

        message += `Status: ${logEntry.status}\n`;
        message += `User-Agent: ${logEntry.userAgent.substring(0, 40)}...\n\n`;

        message += `Threats: ${threats}\n`;
        message += `Confidence: ${threatResult.confidence}/10\n`;
        message += `Score: ${threatResult.finalScore}/10\n`;

        // Add LLM analysis if available and space permits
        if (threatResult.llmAnalysis) {
            const remainingSpace = 1024 - message.length - 200; // Reserve space for threat intel and action
            if (remainingSpace > 50) {
                const maxAnalysisLength = Math.min(remainingSpace, 300);
                const analysis = threatResult.llmAnalysis.explanation;

                if (analysis.length <= maxAnalysisLength) {
                    message += `\nAI Analysis: ${analysis}\n`;
                } else {
                    // Find the last complete sentence within the limit
                    const truncated = analysis.substring(0, maxAnalysisLength);
                    const lastPeriod = truncated.lastIndexOf('.');
                    const lastExclamation = truncated.lastIndexOf('!');
                    const lastQuestion = truncated.lastIndexOf('?');
                    const lastSentenceEnd = Math.max(lastPeriod, lastExclamation, lastQuestion);

                    if (lastSentenceEnd > maxAnalysisLength * 0.6) {
                        message += `\nAI Analysis: ${analysis.substring(0, lastSentenceEnd + 1)}\n`;
                    } else {
                        message += `\nAI Analysis: ${truncated}...\n`;
                    }
                }

                if (threatResult.llmAnalysis.attackType) {
                    message += `Attack Type: ${threatResult.llmAnalysis.attackType}\n`;
                }
            }
        }

        // Add threat intel summary
        if (threatResult.intelData && threatResult.intelData.maliciousCount > 0) {
            const remainingSpace = 1024 - message.length - 100; // Reserve space for action
            if (remainingSpace > 30) {
                message += `\nThreat Intel: ${threatResult.intelData.maliciousCount} source(s) flagged this IP`;

                // Add top source details if space permits
                const topSource = this.getTopThreatIntelSource(threatResult.intelData);
                if (topSource && remainingSpace > 80) {
                    message += `\nTop Source: ${topSource}`;
                }
            }
        }

        message += `\n\nAction: ${this.getRecommendedAction(threatResult.finalScore)}`;

        return message;
    }

    /**
     * Format HTML message for longer content
     */
    formatHtmlMessage(logEntry, threatResult) {
        const timestamp = moment(logEntry.timestamp).format('YYYY-MM-DD HH:mm:ss');
        const threats = threatResult.threats.map(t => t.type).join(', ');
        const emoji = this.getThreatEmoji(threatResult.finalScore);

        let html = `<b>${emoji} THREAT DETECTED</b><br><br>`;
        html += `<b>Time:</b> ${timestamp}<br>`;
        html += `<b>IP:</b> <font face="monospace">${logEntry.ip}</font><br>`;
        html += `<b>Method:</b> ${logEntry.method}<br>`;
        html += `<b>URL:</b> <font face="monospace">${this.escapeHtml(logEntry.url)}</font><br>`;

        if (logEntry.queryString) {
            html += `<b>Query:</b> <font face="monospace">${this.escapeHtml(logEntry.queryString.substring(0, 100))}${logEntry.queryString.length > 100 ? '...' : ''}</font><br>`;
        }

        html += `<b>Status:</b> ${logEntry.status}<br>`;
        html += `<b>User-Agent:</b> <font face="monospace">${this.escapeHtml(logEntry.userAgent.substring(0, 60))}...</font><br><br>`;

        html += `<b>Threats:</b> ${threats}<br>`;
        html += `<b>Confidence:</b> ${threatResult.confidence}/10<br>`;
        html += `<b>Score:</b> ${threatResult.finalScore}/10<br>`;

        // Add LLM analysis
        if (threatResult.llmAnalysis) {
            html += `<br><b>AI Analysis:</b> ${this.escapeHtml(threatResult.llmAnalysis.explanation)}<br>`;
            if (threatResult.llmAnalysis.attackType) {
                html += `<b>Attack Type:</b> ${this.escapeHtml(threatResult.llmAnalysis.attackType)}<br>`;
            }
        }

        // Add detailed threat intel
        if (threatResult.intelData && threatResult.intelData.maliciousCount > 0) {
            html += `<br><b>Threat Intel:</b> ${threatResult.intelData.maliciousCount} source(s) flagged this IP<br>`;

            Object.entries(threatResult.intelData.details).forEach(([source, data]) => {
                if (data.isMalicious) {
                    html += `• <b>${source}:</b> `;
                    if (source === 'abuseipdb' && data.abuseConfidence) {
                        html += `${data.abuseConfidence}% confidence`;
                    } else if (source === 'virustotal' && data.maliciousCount) {
                        html += `${data.maliciousCount}/${data.totalEngines} engines flagged`;
                        if (data.maliciousEngines && data.maliciousEngines.length > 0) {
                            const topEngines = data.maliciousEngines.slice(0, 2).map(e => e.engine).join(', ');
                            html += ` (${topEngines})`;
                        }
                    }
                    html += '<br>';
                }
            });
        }

        html += `<br><b>Recommended Action:</b> ${this.getRecommendedAction(threatResult.finalScore)}`;

        return html;
    }

    /**
     * Format threat title for Pushover
     */
    formatThreatTitle(logEntry, threatResult) {
        const severity = this.getThreatSeverityText(threatResult.finalScore);
        return `${severity} Threat - ${logEntry.ip} (${threatResult.finalScore}/10)`;
    }

    /**
     * Get Pushover priority based on threat score
     */
    getThreatPriority(score) {
        if (score >= 9) return 2;  // Emergency (requires acknowledgment)
        if (score >= 7) return 1;  // High priority (bypass quiet hours)
        if (score >= 5) return 0;  // Normal priority
        return -1; // Low priority (send no notification sound)
    }

    /**
     * Get Pushover sound based on threat score
     */
    getThreatSound(score) {
        const profile = this.options.soundProfile;

        if (profile === 'high') {
            if (score >= 9) return 'siren';
            if (score >= 7) return 'alien';
            if (score >= 5) return 'climb';
            return 'pushover';
        } else if (profile === 'low') {
            if (score >= 9) return 'persistent';
            if (score >= 7) return 'pushover';
            if (score >= 5) return 'bike';
            return 'none';
        } else { // default
            if (score >= 9) return 'persistent';
            if (score >= 7) return 'tugboat';
            if (score >= 5) return 'pushover';
            return 'pushover';
        }
    }

    /**
     * Get emoji based on threat score
     */
    getThreatEmoji(score) {
        if (score >= 9) return '🚨';
        if (score >= 7) return '⚠️';
        if (score >= 5) return '🔍';
        return 'ℹ️';
    }

    /**
     * Get threat severity text
     */
    getThreatSeverityText(score) {
        if (score >= 9) return 'CRITICAL';
        if (score >= 7) return 'HIGH';
        if (score >= 5) return 'MEDIUM';
        return 'LOW';
    }

    /**
     * Get recommended action based on threat score
     */
    getRecommendedAction(score) {
        if (score >= 9) return 'IMMEDIATE BLOCK RECOMMENDED';
        if (score >= 7) return 'Monitor closely, consider blocking';
        if (score >= 5) return 'Review and monitor';
        return 'Log for analysis';
    }

    /**
     * Send long-form threat analysis as separate message
     */
    async sendDetailedAnalysis(logEntry, threatResult) {
        if (!threatResult.llmAnalysis || !threatResult.llmAnalysis.explanation) {
            return;
        }

        try {
            const title = `🔍 Detailed Analysis - ${logEntry.ip}`;
            const analysis = threatResult.llmAnalysis.explanation;

            // If analysis is very long, split into chunks
            if (analysis.length > 1000) {
                const chunks = this.splitIntoChunks(analysis, 900);

                for (let i = 0; i < chunks.length; i++) {
                    const chunkTitle = chunks.length > 1 ? `${title} (${i + 1}/${chunks.length})` : title;

                    await this.sendMessage(chunks[i], {
                        title: chunkTitle,
                        priority: -1, // Low priority for detailed analysis
                        sound: 'none'
                    });

                    // Small delay between chunks
                    if (i < chunks.length - 1) {
                        await new Promise(resolve => setTimeout(resolve, 1000));
                    }
                }
            } else {
                await this.sendMessage(analysis, {
                    title: title,
                    priority: -1,
                    sound: 'none'
                });
            }

        } catch (error) {
            console.error('❌ Failed to send detailed analysis:', error);
        }
    }

    /**
     * Split text into chunks at sentence boundaries
     */
    splitIntoChunks(text, maxChunkSize) {
        const chunks = [];
        let currentChunk = '';
        const sentences = text.match(/[^\.!?]+[\.!?]+/g) || [text];

        for (const sentence of sentences) {
            if (currentChunk.length + sentence.length > maxChunkSize && currentChunk.length > 0) {
                chunks.push(currentChunk.trim());
                currentChunk = sentence;
            } else {
                currentChunk += sentence;
            }
        }

        if (currentChunk.trim()) {
            chunks.push(currentChunk.trim());
        }

        return chunks.length > 0 ? chunks : [text];
    }
    async sendMessage(text, options = {}) {
        try {
            const message = {
                message: text,
                title: options.title || 'Security Monitor',
                priority: options.priority || 0,
                sound: options.sound || 'pushover',
                ...options
            };

            await this.sendPushoverMessage(message);
            console.log('📱 Message sent via Pushover');
        } catch (error) {
            console.error('❌ Failed to send Pushover message:', error);
        }
    }

    /**
     * Send system status update
     */
    async sendStatus() {
        try {
            const uptime = process.uptime();
            const hours = Math.floor(uptime / 3600);
            const minutes = Math.floor((uptime % 3600) / 60);
            const memoryUsage = Math.round(process.memoryUsage().heapUsed / 1024 / 1024);

            const message = `🟢 AGENT STATUS\n\n` +
                `Uptime: ${hours}h ${minutes}m\n` +
                `Alerts Today: ${this.alertCounts.daily}\n` +
                `Alerts This Week: ${this.alertCounts.weekly}\n` +
                `Memory Usage: ${memoryUsage}MB\n` +
                `Last Check: ${moment().format('HH:mm:ss')}\n\n` +
                `Status: Active and monitoring`;

            await this.sendMessage(message, {
                title: 'System Status',
                priority: -1, // Low priority
                sound: 'none'
            });

        } catch (error) {
            console.error('❌ Failed to send status update:', error);
        }
    }

    /**
     * Send daily statistics
     */
    async sendDailyStats() {
        try {
            const stats = await this.getDailyStats();

            const message = `📊 DAILY STATISTICS\n\n` +
                `Total Alerts: ${stats.totalAlerts}\n` +
                `Unique IPs: ${stats.uniqueIPs}\n` +
                `Critical Threats: ${stats.criticalThreats}\n` +
                `High Threats: ${stats.highThreats}\n` +
                `Medium Threats: ${stats.mediumThreats}\n` +
                `Low Threats: ${stats.lowThreats}\n\n` +
                `Top Threat Type: ${stats.topThreatType || 'N/A'}\n` +
                `Busiest Hour: ${stats.busiestHour || 'N/A'}`;

            await this.sendMessage(message, {
                title: 'Daily Statistics',
                priority: -1,
                sound: 'none'
            });

        } catch (error) {
            console.error('❌ Failed to send daily stats:', error);
        }
    }

    /**
     * Send weekly summary
     */
    async sendWeeklySummary() {
        try {
            const summary = await this.getWeeklySummary();

            const message = `📈 WEEKLY SUMMARY\n\n` +
                `Total Alerts: ${summary.totalAlerts}\n` +
                `Daily Average: ${Math.round(summary.dailyAverage)}\n` +
                `Unique IPs: ${summary.uniqueIPs}\n` +
                `Most Active Day: ${summary.mostActiveDay}\n` +
                `Threat Trend: ${summary.trendDirection}\n\n` +
                `System Uptime: ${summary.systemUptime}%\n` +
                `Performance: ${summary.performance}`;

            await this.sendMessage(message, {
                title: 'Weekly Summary',
                priority: 0,
                sound: 'cashregister'
            });

        } catch (error) {
            console.error('❌ Failed to send weekly summary:', error);
        }
    }

    /**
     * Send startup notification
     */
    async sendStartupNotification() {
        const message = `🚀 Security Monitor Started\n\n` +
            `Time: ${moment().format('YYYY-MM-DD HH:mm:ss')}\n` +
            `Version: ${process.env.APP_VERSION || '1.0.0'}\n` +
            `Node.js: ${process.version}\n` +
            `Platform: ${process.platform}\n\n` +
            `Ready to monitor threats!`;

        await this.sendMessage(message, {
            title: 'System Startup',
            priority: -1,
            sound: 'magic'
        });
    }

    /**
     * Send shutdown notification
     */
    async sendShutdownNotification() {
        const uptime = process.uptime();
        const hours = Math.floor(uptime / 3600);
        const minutes = Math.floor((uptime % 3600) / 60);

        const message = `🔴 Security Monitor Shutdown\n\n` +
            `Time: ${moment().format('YYYY-MM-DD HH:mm:ss')}\n` +
            `Uptime: ${hours}h ${minutes}m\n` +
            `Alerts Today: ${this.alertCounts.daily}\n\n` +
            `Monitor stopped gracefully.`;

        await this.sendMessage(message, {
            title: 'System Shutdown',
            priority: 0,
            sound: 'falling'
        });
    }

    /**
     * Send error notification
     */
    async sendErrorNotification(error, context = 'unknown') {
        try {
            const message = `❌ SYSTEM ERROR\n\n` +
                `Context: ${context}\n` +
                `Error: ${error.message}\n` +
                `Time: ${moment().format('HH:mm:ss')}\n\n` +
                `Check logs for details.`;

            await this.sendMessage(message, {
                title: 'System Error',
                priority: 1,
                sound: 'falling'
            });

        } catch (sendError) {
            console.error('❌ Failed to send error notification:', sendError);
        }
    }

    /**
     * Send Pushover message with retry logic
     */
    async sendPushoverMessage(message) {
        return new Promise((resolve, reject) => {
            let attempts = 0;
            const maxAttempts = 3;

            const attemptSend = () => {
                attempts++;
                this.push.send(message, (err, result) => {
                    if (err) {
                        if (attempts < maxAttempts) {
                            console.log(`⚠️ Pushover send failed (attempt ${attempts}/${maxAttempts}), retrying...`);
                            setTimeout(attemptSend, 1000 * attempts); // Exponential backoff
                        } else {
                            reject(new Error(`Pushover send failed after ${maxAttempts} attempts: ${err.message}`));
                        }
                    } else {
                        resolve(result);
                    }
                });
            };

            attemptSend();
        });
    }

    /**
     * Increment alert counters
     */
    incrementAlertCount() {
        const now = moment();

        // Reset daily counter if it's a new day
        if (now.isAfter(this.alertCounts.lastReset.clone().add(1, 'day'))) {
            this.alertCounts.daily = 0;
            this.alertCounts.lastReset = now.startOf('day');
        }

        // Reset weekly counter if it's a new week
        if (now.isAfter(this.alertCounts.lastWeeklyReset.clone().add(1, 'week'))) {
            this.alertCounts.weekly = 0;
            this.alertCounts.lastWeeklyReset = now.startOf('week');
        }

        // Reset monthly counter if it's a new month
        if (now.isAfter(this.alertCounts.lastMonthlyReset.clone().add(1, 'month'))) {
            this.alertCounts.monthly = 0;
            this.alertCounts.lastMonthlyReset = now.startOf('month');
        }

        this.alertCounts.daily++;
        this.alertCounts.weekly++;
        this.alertCounts.monthly++;

        // Save stats periodically
        this.saveStats();
    }

    /**
     * Load statistics from file
     */
    async loadStats() {
        try {
            const data = await fs.readFile(this.options.statsFile, 'utf8');
            const stats = JSON.parse(data);

            this.alertCounts = {
                ...this.alertCounts,
                ...stats,
                lastReset: moment(stats.lastReset),
                lastWeeklyReset: moment(stats.lastWeeklyReset),
                lastMonthlyReset: moment(stats.lastMonthlyReset)
            };

            console.log('📊 Statistics loaded from file');
        } catch (error) {
            console.log('📊 No existing stats file found, starting fresh');
        }
    }

    /**
     * Save statistics to file
     */
    async saveStats() {
        try {
            const stats = {
                ...this.alertCounts,
                lastReset: this.alertCounts.lastReset.toISOString(),
                lastWeeklyReset: this.alertCounts.lastWeeklyReset.toISOString(),
                lastMonthlyReset: this.alertCounts.lastMonthlyReset.toISOString(),
                lastSaved: moment().toISOString()
            };

            await fs.writeFile(this.options.statsFile, JSON.stringify(stats, null, 2));
        } catch (error) {
            console.error('❌ Failed to save statistics:', error);
        }
    }

    /**
     * Setup periodic stats saving
     */
    setupPeriodicSave() {
        // Save stats every 5 minutes
        setInterval(() => {
            this.saveStats();
        }, 5 * 60 * 1000);

        // Send daily stats at midnight
        const now = moment();
        const midnight = moment().add(1, 'day').startOf('day');
        const msUntilMidnight = midnight.diff(now);

        setTimeout(() => {
            this.sendDailyStats();
            // Then send daily stats every 24 hours
            setInterval(() => {
                this.sendDailyStats();
            }, 24 * 60 * 60 * 1000);
        }, msUntilMidnight);

        // Send weekly summary on Sundays
        const sunday = moment().day(7).startOf('day');
        if (sunday.isBefore(now)) {
            sunday.add(1, 'week');
        }
        const msUntilSunday = sunday.diff(now);

        setTimeout(() => {
            this.sendWeeklySummary();
            // Then send weekly summary every 7 days
            setInterval(() => {
                this.sendWeeklySummary();
            }, 7 * 24 * 60 * 60 * 1000);
        }, msUntilSunday);
    }

    /**
     * Utility functions
     */
    truncateUrl(url, maxLength) {
        if (url.length <= maxLength) return url;
        return url.substring(0, maxLength - 3) + '...';
    }

    escapeHtml(text) {
        return text
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    generateDashboardUrl(logEntry) {
        // Customize this URL to point to your security dashboard
        return `https://your-security-dashboard.com/threats/${logEntry.id || 'latest'}`;
    }

    getTopThreatIntelSource(intelData) {
        for (const [source, data] of Object.entries(intelData.details)) {
            if (data.isMalicious) {
                if (source === 'abuseipdb' && data.abuseConfidence) {
                    return `${source} (${data.abuseConfidence}% confidence)`;
                } else if (source === 'virustotal' && data.maliciousCount) {
                    return `${source} (${data.maliciousCount}/${data.totalEngines} engines)`;
                }
                return source;
            }
        }
        return null;
    }

    /**
     * Get daily statistics (placeholder - implement based on your data storage)
     */
    async getDailyStats() {
        // This would typically query your database or log files
        return {
            totalAlerts: this.alertCounts.daily,
            uniqueIPs: 0, // Implement based on your tracking
            criticalThreats: 0,
            highThreats: 0,
            mediumThreats: 0,
            lowThreats: 0,
            topThreatType: null,
            busiestHour: null
        };
    }

    /**
     * Get weekly summary (placeholder - implement based on your data storage)
     */
    async getWeeklySummary() {
        return {
            totalAlerts: this.alertCounts.weekly,
            dailyAverage: this.alertCounts.weekly / 7,
            uniqueIPs: 0,
            mostActiveDay: 'Monday',
            trendDirection: 'Stable',
            systemUptime: 99.5,
            performance: 'Good'
        };
    }

    /**
     * Graceful shutdown
     */
    async shutdown() {
        console.log('🔄 Shutting down Pushover notifier...');

        try {
            await this.sendShutdownNotification();
            await this.saveStats();
            console.log('✅ Pushover notifier shut down gracefully');
        } catch (error) {
            console.error('❌ Error during shutdown:', error);
        }
    }
}

export default PushoverNotifier;