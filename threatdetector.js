import fs from 'fs';
import path from 'path';

// Rule-based detection

class ThreatDetector {
    constructor(thresholds) {
        this.thresholds = thresholds;
        this.patterns = this.loadPatterns();
        this.whitelist = this.loadWhitelist();
        this.ipAttempts = new Map(); // Track brute force attempts
    }

    /**
     * Load threat detection patterns from JSON
     */
    loadPatterns() {
        try {
            const patternsFile = fs.readFileSync(path.join('rules', 'patterns.json'), 'utf8');
            return JSON.parse(patternsFile);
        } catch (error) {
            console.error('Failed to load patterns:', error);
            return this.getDefaultPatterns();
        }
    }

    /**
     * Load IP whitelist
     */
    loadWhitelist() {
        try {
            const whitelistFile = fs.readFileSync(path.join('rules', 'whitelist.txt'), 'utf8');
            return whitelistFile.split('\n').filter(ip => ip.trim());
        } catch (error) {
            console.error('Failed to load whitelist:', error);
            return [];
        }
    }

    /**
     * Default threat patterns if file doesn't exist
     */
    getDefaultPatterns() {
        return {
            sql_injection: {
                patterns: [
                    "(union\\s+select|union\\s+all\\s+select)",
                    "('|(\\\\')|('')|(\\\\\")|(\\\"\\\")|(%27)|(%22))",
                    "(or\\s+1=1|or\\s+1\\s*=\\s*1)",
                    "(and\\s+1=1|and\\s+1\\s*=\\s*1)"
                ],
                score: 8
            },
            xss: {
                patterns: [
                    "(<script|</script>|javascript:|onerror=|onload=)",
                    "(alert\\(|confirm\\(|prompt\\()",
                    "(<img[^>]*src[^>]*javascript:)",
                    "(document\\.cookie|document\\.write)"
                ],
                score: 7
            },
            path_traversal: {
                patterns: [
                    "(\\.\\./|\\.\\.\\\\/|%2e%2e%2f|%2e%2e/)",
                    "(/etc/passwd|/etc/shadow|\\\\windows\\\\system32)",
                    "(boot\\.ini|win\\.ini)"
                ],
                score: 9
            },
            command_injection: {
                patterns: [
                    "(;|&&|\\||\\$\\(|`)",
                    "(whoami|cat\\s+|ls\\s+|dir\\s+|cmd\\.exe)",
                    "(nc\\s+|netcat|wget|curl)",
                    "(/bin/bash|/bin/sh|cmd\\.exe)"
                ],
                score: 9
            },
            file_inclusion: {
                patterns: [
                    "(file://|ftp://|gopher://)",
                    "(php://input|php://filter|data://)",
                    "(include\\(|require\\(|include_once\\()"
                ],
                score: 8
            }
        };
    }

    /**
     * Analyze log entry for threats
     */
    async analyze(logEntry) {
        // Skip whitelisted IPs
        if (this.whitelist.includes(logEntry.ip)) {
            return { isThreat: false, reason: 'Whitelisted IP' };
        }

        const threats = [];
        let maxScore = 0;

        // Check all patterns against URL and payload
        const textToAnalyze = [
            logEntry.url,
            logEntry.queryString,
            logEntry.userAgent,
            JSON.stringify(logEntry.payload)
        ].join(' ');

        for (const [threatType, config] of Object.entries(this.patterns)) {
            for (const pattern of config.patterns) {
                const regex = new RegExp(pattern, 'gi');
                if (regex.test(textToAnalyze)) {
                    threats.push({
                        type: threatType,
                        pattern: pattern,
                        score: config.score,
                        matches: textToAnalyze.match(regex)
                    });
                    maxScore = Math.max(maxScore, config.score);
                }
            }
        }

        // Check for brute force attacks
        const bruteForceResult = this.checkBruteForce(logEntry);
        if (bruteForceResult.isBruteForce) {
            threats.push(bruteForceResult);
            maxScore = Math.max(maxScore, bruteForceResult.score);
        }

        // Determine if this is a threat
        const isThreat = maxScore >= this.thresholds.minimum_score || threats.length > 0;

        return {
            isThreat,
            confidence: maxScore,
            threats,
            ip: logEntry.ip,
            timestamp: logEntry.timestamp,
            method: logEntry.method,
            url: logEntry.url,
            userAgent: logEntry.userAgent
        };
    }

    /**
     * Check for brute force attack patterns
     */
    checkBruteForce(logEntry) {
        const ip = logEntry.ip;
        const now = Date.now();
        const timeWindow = 5 * 60 * 1000; // 5 minutes

        // Initialize or get existing attempts for this IP
        if (!this.ipAttempts.has(ip)) {
            this.ipAttempts.set(ip, []);
        }

        const attempts = this.ipAttempts.get(ip);

        // Clean old attempts outside time window
        const recentAttempts = attempts.filter(time => now - time < timeWindow);

        // Add current attempt if it's a failed login (401, 403)
        if ([401, 403].includes(logEntry.status)) {
            recentAttempts.push(now);
        }

        // Update the map
        this.ipAttempts.set(ip, recentAttempts);

        // Check if this qualifies as brute force
        if (recentAttempts.length >= this.thresholds.brute_force_attempts) {
            return {
                type: 'brute_force',
                isBruteForce: true,
                score: this.thresholds.brute_force_score || 7,
                attempts: recentAttempts.length,
                timeWindow: '5 minutes'
            };
        }

        return { isBruteForce: false };
    }
}

export default ThreatDetector;