import axios from "axios";
class IntelChecker {
    constructor() {
        this.virusTotalKey = process.env.VIRUSTOTALKEY;
        this.abuseIPDBKey = process.env.ABUSEIPDBKEY;
        this.cache = new Map(); // Simple cache to avoid duplicate lookups
        this.cacheTimeout = 30 * 60 * 1000; // 30 minutes
    }

    /**
     * Check IP reputation across multiple sources
     */
    async checkIP(ip) {
        // Check cache first
        const cacheKey = `ip_${ip}`;
        const cached = this.cache.get(cacheKey);
        if (cached && Date.now() - cached.timestamp < this.cacheTimeout) {
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
                this.checkVirusTotal(ip),
                this.checkAbuseIPDB(ip)
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
            this.cache.set(cacheKey, {
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
    async checkVirusTotal(ip) {
        if (!this.virusTotalKey) {
            return null;
        }

        try {
            const response = await axios.get(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`, {
                headers: {
                    'x-apikey': this.virusTotalKey,
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
    async checkAbuseIPDB(ip) {
        if (!this.abuseIPDBKey) {
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
                    'Key': this.abuseIPDBKey,
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
    /**
     * Check for known CVEs for specific software and version using NVD API v2
     */
    async  checkCVE(software, version) {
        try {
            const response = await axios.get('https://services.nvd.nist.gov/rest/json/cves/2.0', {
                params: {
                    keywordSearch: `${software} ${version}`,
                    resultsPerPage: 5
                },
                timeout: 15000
            });

            const cves = response.data.vulnerabilities || [];

            return cves.map(entry => {
                const cve = entry.cve;
                const description = cve.descriptions.find(desc => desc.lang === 'en')?.value || 'No description';


                const cvssMetric = cve.metrics?.cvssMetricV31?.[0]?.cvssData
                    || cve.metrics?.cvssMetricV30?.[0]?.cvssData
                    || cve.metrics?.cvssMetricV2?.[0]?.cvssData;

                return {
                    id: cve.id,
                    description,
                    severity: cvssMetric?.baseSeverity || 'Unknown',
                    score: cvssMetric?.baseScore || 0
                };
            });

        } catch (error) {
            console.error('CVE check failed:', error.message);
            return [];
        }
    }

}

export default IntelChecker;