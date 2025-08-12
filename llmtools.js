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
        return 'VirusTotal API key is not configured. Unable to perform IP reputation check.';
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
            const totalEngines = Object.keys(attributes.last_analysis_results || {}).length;

            // Get detailed results for malicious engines
            const results = attributes.last_analysis_results || {};
            const maliciousEngines = [];

            Object.entries(results).forEach(([engine, result]) => {
                if (result.category === 'malicious') {
                    maliciousEngines.push(`${engine}: ${result.result || 'malicious'}`);
                }
            });

            // Build comprehensive string report
            let report = `VirusTotal IP Analysis for ${ip}:\n`;

            // Threat assessment
            if (maliciousCount > 0 || suspiciousCount > 0) {
                report += `⚠️ THREAT DETECTED: This IP is flagged as potentially malicious.\n`;
                report += `- ${maliciousCount} security engines flagged it as malicious\n`;
                if (suspiciousCount > 0) {
                    report += `- ${suspiciousCount} security engines flagged it as suspicious\n`;
                }
                report += `- Total engines that analyzed: ${totalEngines}\n`;

                if (maliciousEngines.length > 0) {
                    report += `\nMalicious detections:\n`;
                    maliciousEngines.slice(0, 5).forEach(engine => {
                        report += `  • ${engine}\n`;
                    });
                    if (maliciousEngines.length > 5) {
                        report += `  • ... and ${maliciousEngines.length - 5} more engines\n`;
                    }
                }
            } else {
                report += `✅ CLEAN: No security engines flagged this IP as malicious (${totalEngines} engines checked).\n`;
            }

            // Network information
            if (attributes.asn || attributes.country || attributes.network) {
                report += `\nNetwork Information:\n`;
                if (attributes.country) {
                    report += `- Country: ${attributes.country}\n`;
                }
                if (attributes.asn) {
                    report += `- ASN: ${attributes.asn}\n`;
                }
                if (attributes.network) {
                    report += `- Network: ${attributes.network}\n`;
                }
            }

            // Reputation score
            if (attributes.reputation !== undefined) {
                const reputation = attributes.reputation;
                report += `- Reputation Score: ${reputation}`;
                if (reputation < 0) {
                    report += ` (negative - indicates bad reputation)`;
                } else if (reputation > 0) {
                    report += ` (positive - indicates good reputation)`;
                } else {
                    report += ` (neutral)`;
                }
                report += `\n`;
            }

            // Last analysis date
            if (attributes.last_analysis_date) {
                const lastAnalysis = new Date(attributes.last_analysis_date * 1000);
                report += `- Last analyzed: ${lastAnalysis.toISOString().split('T')[0]} (${lastAnalysis.toLocaleString()})\n`;
            }

            console.log(`VirusTotal analysis completed for ${ip}`);
            console.log(`report for ${ip}`, report.trim());
            return report.trim();
        }

        console.log(`No attributes found for ${ip} in VirusTotal`);
        return `VirusTotal check for IP ${ip}: No analysis data available. This IP may not have been previously analyzed by VirusTotal or may be a private/internal IP address.`;

    } catch (error) {
        // Handle rate limiting (429) and other errors gracefully
        if (error.response?.status === 429) {
            console.warn('VirusTotal API rate limit exceeded');
            return `VirusTotal API rate limit exceeded. Cannot check IP ${ip} at this time. The free tier allows 4 requests per minute. Please try again later.`;
        }

        if (error.response?.status === 404) {
            console.log(`IP ${ip} not found in VirusTotal database`);
            return `IP ${ip} was not found in the VirusTotal database. This could mean the IP has never been analyzed or is not publicly routable.`;
        }

        if (error.response?.status === 403) {
            return `VirusTotal API access forbidden. Please check that your API key is valid and has the necessary permissions.`;
        }

        console.error('VirusTotal check failed:', {
            message: error.message,
            status: error.response?.status,
            statusText: error.response?.statusText
        });

        return `VirusTotal check failed for IP ${ip}. Error: ${error.message}${error.response?.status ? ` (HTTP ${error.response.status})` : ''}. Unable to determine threat status.`;
    }
}

/**
 * Check IP against AbuseIPDB
 */
export async function checkAbuseIPDB(ip) {
    const abuseIPDBKey = process.env.ABUSEIPDBKEY;

    if (!abuseIPDBKey) {
        console.warn('AbuseIPDB API key not found in environment variables');
        return 'AbuseIPDB API key not configured - unable to check IP reputation';
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

        // Return formatted string for LLM consumption instead of raw object
        const isMalicious = abuseResult.isMalicious;
        const confidence = abuseResult.abuseConfidence;
        const reports = abuseResult.totalReports;

        if (isMalicious) {
            return `AbuseIPDB ALERT: IP ${ip} is flagged as malicious with ${confidence}% abuse confidence based on ${reports} reports. Country: ${abuseResult.country}, Usage: ${abuseResult.usage}`;
        } else if (reports > 0) {
            return `AbuseIPDB: IP ${ip} has ${reports} historical reports but low abuse confidence (${confidence}%). Country: ${abuseResult.country}, Usage: ${abuseResult.usage}`;
        } else {
            return `AbuseIPDB: IP ${ip} has clean reputation with no abuse reports. Country: ${abuseResult.country}, Usage: ${abuseResult.usage}`;
        }

    } catch (error) {
        console.error('AbuseIPDB check failed:', {
            message: error.message,
            status: error.response?.status,
            statusText: error.response?.statusText
        });

        // Return formatted error string instead of object
        const status = error.response?.status || 'unknown';
        return `AbuseIPDB check failed for IP ${ip}: ${error.message} (HTTP ${status}). Unable to determine reputation.`;
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

