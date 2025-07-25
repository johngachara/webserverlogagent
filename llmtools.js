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




/**
 * Check IP against VirusTotal (API v3)
 */
export async function checkVirusTotal(ip) {
    const virusTotalKey = process.env.VIRUSTOTALKEY;

    if (!virusTotalKey) {
        console.warn('VirusTotal API key not found in environment variables');
        return 'VirusTotal API key not configured';
    }

    try {
        console.log(`Checking VirusTotal for IP: ${ip}`);

        const response = await axios.get(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`, {
            headers: {
                'x-apikey': virusTotalKey,
                'Accept': 'application/json'
            },
            timeout: 15000 // Increased timeout
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

            const vtResult = {
                isMalicious: maliciousCount > 0 || suspiciousCount > 0,
                maliciousCount: maliciousCount,
                suspiciousCount: suspiciousCount,
                totalEngines: Object.keys(results).length,
                maliciousEngines: maliciousEngines.map(entry => entry),
                asn: attributes.asn,
                country: attributes.country,
                network: attributes.network,
                reputation: attributes.reputation || 0,
                lastAnalysisDate: attributes.last_analysis_date ? new Date(attributes.last_analysis_date * 1000) : null
            };

            console.log(`VirusTotal result for ${ip}:`, vtResult);
            return vtResult;
        }

        console.log(`No attributes found for ${ip} in VirusTotal`);
        return { isMalicious: false, error: 'No data available' };

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

        if (error.response?.status === 404) {
            console.log(`IP ${ip} not found in VirusTotal database`);
            return {
                isMalicious: false,
                error: 'IP not found in database'
            };
        }

        console.error('VirusTotal check failed:', {
            message: error.message,
            status: error.response?.status,
            statusText: error.response?.statusText
        });

        return {
            isMalicious: false,
            error: `Request failed: ${error.message}`,
            status: error.response?.status
        };
    }
}

/**
 * Check IP against AbuseIPDB
 */
export async function checkAbuseIPDB(ip) {
    const abuseIPDBKey = process.env.ABUSEIPDBKEY;

    if (!abuseIPDBKey) {
        console.warn('AbuseIPDB API key not found in environment variables');
        return 'AbuseIPDB API key not configured';
    }

    try {
        console.log(`Checking AbuseIPDB for IP: ${ip}`);

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
            timeout: 15000 // Increased timeout
        });

        const data = response.data.data;

        const abuseResult = {
            isMalicious: data.abuseConfidenceScore > 50,
            abuseConfidence: data.abuseConfidenceScore,
            totalReports: data.totalReports,
            country: data.countryCode,
            usage: data.usageType
        };

        console.log(`AbuseIPDB result for ${ip}:`, abuseResult);
        return abuseResult;

    } catch (error) {
        console.error('AbuseIPDB check failed:', {
            message: error.message,
            status: error.response?.status,
            statusText: error.response?.statusText
        });

        return {
            isMalicious: false,
            error: `Request failed: ${error.message}`,
            status: error.response?.status
        };
    }
}

// Test function for manual testing
export async function testIPCheck(ip = '8.8.8.8') {
    console.log(`\n=== Testing IP Intelligence for ${ip} ===`);

    // Test individual functions
    console.log('\n--- Testing VirusTotal ---');
    const vtResult = await checkVirusTotal(ip);
    console.log('VirusTotal Result:', vtResult);

    console.log('\n--- Testing AbuseIPDB ---');
    const abuseResult = await checkAbuseIPDB(ip);
    console.log('AbuseIPDB Result:', abuseResult);


    return {success: true, message: 'IP check completed successfully'};
}