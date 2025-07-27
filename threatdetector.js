import fs from 'fs';
import path from 'path';
import YAML from 'yaml';

// Rule-based detection

class ThreatDetector {
    constructor(thresholds) {
        this.thresholds = thresholds;
        this.patterns = this.loadPatterns();
        this.whitelist = this.loadWhitelist();
        this.ipAttempts = new Map(); // Track brute force attempts
        this.systemUrls = this.loadSystemUrls();
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
     * Load system URLs from config.yaml
     * These URLs will be skipped during threat detection unless they contain malicious content
     */
    loadSystemUrls() {
        try {
            const configFile = fs.readFileSync('config.yaml', 'utf8');
            const config = YAML.parse(configFile);

            // Return empty arrays if system_urls section doesn't exist
            if (!config.system_urls) {
                return { patterns: [], specific: [] };
            }

            return {
                patterns: config.system_urls.patterns || [],
                specific: config.system_urls.specific || []
            };
        } catch (error) {
            console.error('Failed to load system URLs:', error);
            return { patterns: [], specific: [] };
        }
    }

    /**
     * Check if a URL is a system URL
     * 
     * System URLs are URLs that are part of the system and should be treated differently
     * during threat detection. They are only considered threats if they contain malicious
     * content that exceeds the minimum score threshold.
     * 
     * System URLs can be configured in config.yaml in two ways:
     * 1. As specific URLs: Exact URL paths without query parameters (e.g., "/login", "/dashboard")
     * 2. As regex patterns: JavaScript regex patterns to match multiple URLs
     * 
     * Examples of regex patterns:
     * - "^/api" - Matches all URLs starting with "/api"
     * - "^/admin" - Matches all URLs starting with "/admin"
     * - "^/home$" - Matches exactly "/home" URL
     * - "^/(home|about|contact)$" - Matches exactly "/home", "/about", or "/contact" URLs
     * 
     * @param {string} url - The URL to check
     * @returns {boolean} - True if the URL is a system URL, false otherwise
     */
    isSystemUrl(url) {
        // Check if the URL matches any of the specific URLs
        if (this.systemUrls.specific.includes(url)) {
            return true;
        }

        // Check if the URL matches any of the regex patterns
        for (const pattern of this.systemUrls.patterns) {
            try {
                const regex = new RegExp(pattern);
                if (regex.test(url)) {
                    return true;
                }
            } catch (error) {
                console.error(`Invalid regex pattern: ${pattern}`, error);
            }
        }

        return false;
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

        // Check if this is a system URL
        const isSystemUrl = this.isSystemUrl(logEntry.url);

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
        // For system URLs, only consider it a threat if it contains malicious content
        // that exceeds the minimum score threshold. This allows legitimate requests
        // to system URLs to pass through without being flagged as threats, while still
        // protecting against malicious requests to system URLs.
        // 
        // For non-system URLs, consider it a threat if:
        // 1. The maximum score exceeds the minimum threshold, OR
        // 2. Any threats were detected (even if they don't exceed the threshold)
        let isThreat;
        if (isSystemUrl) {
            isThreat = maxScore >= this.thresholds.minimum_score;
        } else {
            isThreat = maxScore >= this.thresholds.minimum_score || threats.length > 0;
        }

        return {
            isThreat,
            confidence: maxScore,
            threats,
            ip: logEntry.ip,
            timestamp: logEntry.timestamp,
            method: logEntry.method,
            url: logEntry.url,
            userAgent: logEntry.userAgent,
            is_system_url: isSystemUrl // Add the is_system_url attribute
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
