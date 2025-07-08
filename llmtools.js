import {execSync} from 'child_process';
import axios from "axios";
/**
 * Block an IP address using iptables
 * @param {string} ipAddress - The IP address to block
 * @returns {string} - Result message
 */
export function blockIpAddress(ipAddress) {
    try {
        // Validate input
        if (!ipAddress || typeof ipAddress !== 'string') {
            return "Error: Invalid IP address parameter - must be a non-empty string";
        }

        // Validate IP format
        const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        if (!ipRegex.test(ipAddress)) {
            return `Error: Invalid IPv4 address format: ${ipAddress}`;
        }

        // Block the IP using iptables
        const blockCmd = `iptables -I INPUT -s ${ipAddress} -j DROP`;
        execSync(blockCmd, { encoding: 'utf8' });

        console.log(`🚫 SECURITY ACTION: Blocked IP address ${ipAddress}`);
        return `Successfully blocked IP address: ${ipAddress}`;

    } catch (error) {
        const errorMsg = `Failed to block IP address ${ipAddress}: ${error.message}`;
        console.error(`❌ SECURITY ERROR: ${errorMsg}`);
        return errorMsg;
    }
}

// Cache for storing IP check results
const ipCache = new Map();
const CACHE_TIMEOUT = 300000; // 5 minutes

/**
 * Check IP against multiple threat intelligence sources
 */
export async function checkIPIntelligence(ip) {
    // Check cache first
    const cacheKey = `ip_${ip}`;
    const cached = ipCache.get(cacheKey);
    if (cached && Date.now() - cached.timestamp < CACHE_TIMEOUT) {
        return cached.data;
    }

    const result = {
        ip,
        maliciousCount: 0,
        sources: [],
        details: {}
    };

    try {
        // Run all checks in parallel
        const checks = await Promise.allSettled([
            checkVirusTotal(ip),
            checkAbuseIPDB(ip)
        ]);

        checks.forEach((check, index) => {
            if (check.status === 'fulfilled' && check.value) {
                const source = ['virustotal', 'abuseipdb'][index];
                result.sources.push(source);
                result.details[source] = check.value;

                if (check.value.isMalicious) {
                    result.maliciousCount++;
                }
            }
        });

        // Cache the result
        ipCache.set(cacheKey, {
            data: result,
            timestamp: Date.now()
        });

        return result;

    } catch (error) {
        console.error('Intel check error:', error);
        return result;
    }
}

/**
 * Check IP against VirusTotal (API v3)
 */
export async function checkVirusTotal(ip) {
    const virusTotalKey = process.env.VIRUSTOTAL_API_KEY;

    if (!virusTotalKey) {
        return null;
    }

    try {
        const response = await axios.get(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`, {
            headers: {
                'x-apikey': virusTotalKey,
                'Accept': 'application/json'
            },
            timeout: 10000
        });

        const data = response.data.data;
        const attributes = data.attributes;

        if (attributes) {
            // Get analysis stats
            const stats = attributes.last_analysis_stats || {};
            const maliciousCount = stats.malicious || 0;
            const suspiciousCount = stats.suspicious || 0;

            // Get detailed results for malicious engines
            const results = attributes.last_analysis_results || {};
            const maliciousEngines = [];

            Object.entries(results).forEach(([engine, result]) => {
                if (result.category === 'malicious') {
                    maliciousEngines.push({
                        engine: engine,
                        result: result.result || 'malicious'
                    });
                }
            });

            return {
                isMalicious: maliciousCount > 0 || suspiciousCount > 0,
                maliciousCount: maliciousCount,
                suspiciousCount: suspiciousCount,
                totalEngines: Object.keys(results).length,
                maliciousEngines: maliciousEngines,
                asn: attributes.asn,
                country: attributes.country,
                network: attributes.network,
                reputation: attributes.reputation || 0,
                lastAnalysisDate: attributes.last_analysis_date ? new Date(attributes.last_analysis_date * 1000) : null
            };
        }

        return { isMalicious: false };

    } catch (error) {
        // Handle rate limiting (429) and other errors gracefully
        if (error.response?.status === 429) {
            console.warn('VirusTotal API rate limit exceeded');
            return {
                isMalicious: false,
                error: 'Rate limited',
                rateLimited: true
            };
        }

        console.error('VirusTotal check failed:', error.message);
        return null;
    }
}

/**
 * Check IP against AbuseIPDB
 */
export async function checkAbuseIPDB(ip) {
    const abuseIPDBKey = process.env.ABUSEIPDB_API_KEY;

    if (!abuseIPDBKey) {
        return null;
    }

    try {
        const response = await axios.get('https://api.abuseipdb.com/api/v2/check', {
            params: {
                ipAddress: ip,
                maxAgeInDays: 90,
                verbose: ''
            },
            headers: {
                'Key': abuseIPDBKey,
                'Accept': 'application/json'
            },
            timeout: 10000
        });

        const data = response.data.data;

        return {
            isMalicious: data.abuseConfidencePercentage > 50,
            abuseConfidence: data.abuseConfidencePercentage,
            totalReports: data.totalReports,
            country: data.countryCode,
            usage: data.usageType
        };

    } catch (error) {
        console.error('AbuseIPDB check failed:', error.message);
        return null;
    }
}

