import {Redis} from "@upstash/redis";

/**
 * Upstash Redis client configuration
 * Make sure to set these environment variables:
 * - UPSTASH_REDIS_REST_URL
 * - UPSTASH_REDIS_REST_TOKEN
 */
const redis = new Redis({
    url: process.env.UPSTASH_REDIS_REST_URL,
    token: process.env.UPSTASH_REDIS_REST_TOKEN,
});

/**
 * Test Redis connection
 * @returns {Promise<boolean>} - Connection status
 */
async function testRedisConnection() {
    try {
        await redis.set('test', 'value');
        const result = await redis.get('test');
        console.log('Redis test result:', result);
        await redis.del('test'); // Clean up test key
        return result === 'value';
    } catch (error) {
        console.error('Redis connection error:', error);
        return false;
    }
}

/**
 * Stores log entry data in Upstash Redis with 1-hour expiration
 * Enhanced version with better validation and verification
 *
 * @param {Object} logEntry - The log entry object
 * @param {string} logEntry.ip - IP address
 * @param {string} logEntry.method - HTTP method
 * @param {string} logEntry.queryString - Query string
 * @param {string} logEntry.userAgent - User agent
 * @param {string} logEntry.url - URL
 * @param {number} logEntry.status - HTTP status code
 * @param {string} explanation - Explanation from LLM
 * @param {number} score - Confidence score (0-10)
 * @param {string} [keyPrefix='threat_log'] - Optional key prefix for Redis
 * @returns {Promise<Object>} - Success/error response
 */
async function storeThreatLog(logEntry, explanation, score, keyPrefix = 'threat_log') {
    try {
        console.log('storeThreatLog called with:', { logEntry, explanation, score, keyPrefix });

        // Validate inputs
        if (!logEntry || !logEntry.ip) {
            throw new Error('Invalid log entry: missing IP address');
        }

        if (typeof score !== 'number' || score < 0 || score > 10) {
            throw new Error('Invalid confidence score: must be a number between 0-10');
        }

        if (!explanation || typeof explanation !== 'string') {
            throw new Error('Invalid explanation: must be a non-empty string');
        }

        // Create the data object to store
        const threatData = {
            ip_address: logEntry.ip,
            method: logEntry.method || 'UNKNOWN',
            query_string: logEntry.queryString || '',
            user_agent: logEntry.userAgent || '',
            url: logEntry.url || '',
            status: logEntry.status || 0,
            explanation: explanation,
            confidence: score,
            timestamp: new Date().toISOString(),
        };

        // Generate a unique key using timestamp and IP
        const timestamp = Date.now();
        const redisKey = `${keyPrefix}:${logEntry.ip}:${timestamp}`;

        console.log('Storing data with key:', redisKey);
        console.log('Data to store:', threatData);

        // Ensure we're storing a JSON string, not an object
        const jsonString = JSON.stringify(threatData);
        console.log('JSON string to store:', jsonString);

        // Store the data with 1-hour expiration (3600 seconds)
        await redis.setex(redisKey, 3600, jsonString);

        // Verify the data was stored correctly
        const storedData = await redis.get(redisKey);
        console.log('Verification - stored data type:', typeof storedData);

        // Handle both string and object responses from Upstash
        if (typeof storedData === 'string') {
            console.log('Verification - stored data preview:', storedData.substring(0, 100));
        } else if (typeof storedData === 'object') {
            console.log('Verification - stored data (object):', JSON.stringify(storedData).substring(0, 100));
        } else {
            console.log('Verification - stored data:', storedData);
        }

        console.log("Threat monitored successfully", threatData);

        return {
            success: true,
            key: redisKey,
            data: threatData,
            expiresIn: '1 hour',
        };

    } catch (error) {
        console.error('Error in storeThreatLog:', error);
        return {
            success: false,
            error: error.message,
            stack: error.stack,
        };
    }
}

/**
 * Retrieves a threat log entry from Redis
 * Enhanced version with better error handling
 *
 * @param {string} key - Redis key to retrieve
 * @returns {Promise<Object>} - Retrieved data or error
 */
async function getThreatLog(key) {
    try {
        console.log('Retrieving threat log with key:', key);
        const data = await redis.get(key);

        if (!data) {
            return {
                success: false,
                error: 'Key not found or expired',
            };
        }

        try {
            // Handle Upstash returning objects vs strings
            let parsedData;
            if (typeof data === 'object') {
                // Upstash returned an object directly
                console.log('Data returned as object:', data);
                parsedData = data;
            } else if (typeof data === 'string') {
                // Data is a JSON string, parse it
                parsedData = JSON.parse(data);
            } else {
                throw new Error(`Unexpected data type: ${typeof data}`);
            }

            console.log('Retrieved data:', parsedData);
            return {
                success: true,
                data: parsedData,
            };
        } catch (parseError) {
            console.error(`Failed to parse data for key ${key}:`, data);
            console.error('Parse error:', parseError.message);
            return {
                success: false,
                error: `Invalid JSON data: ${parseError.message}`,
                rawData: data,
            };
        }

    } catch (error) {
        console.error('Error in getThreatLog:', error);
        return {
            success: false,
            error: error.message,
        };
    }
}

/**
 * Retrieves all threat logs for a specific IP address
 * Enhanced version with better error handling for malformed JSON
 *
 * @param {string} ipAddress - IP address to search for
 * @param {string} [keyPrefix='threat_log'] - Key prefix used when storing
 * @returns {Promise<Object>} - Array of matching logs or error
 */
async function getThreatLogsByIP(ipAddress, keyPrefix = 'threat_log') {
    try {
        console.log('Searching for logs with IP:', ipAddress, 'and prefix:', keyPrefix);
        const pattern = `${keyPrefix}:${ipAddress}:*`;
        const keys = await redis.keys(pattern);

        console.log('Found keys:', keys);

        if (keys.length === 0) {
            return {
                success: true,
                data: [],
                message: 'No logs found for this IP address',
            };
        }

        const logs = [];
        const corruptedKeys = [];

        for (const key of keys) {
            const data = await redis.get(key);
            if (data) {
                try {
                    let parsedData;

                    // Handle Upstash returning objects vs strings
                    if (typeof data === 'object') {
                        // Upstash returned an object directly
                        parsedData = data;
                    } else if (typeof data === 'string') {
                        // Check for the specific "[object Object]" corruption
                        if (data === '[object Object]' || data.includes('[object Object]')) {
                            console.warn(`Key ${key} contains corrupted data: ${data}`);
                            corruptedKeys.push(key);
                            continue;
                        }
                        // Parse the JSON string
                        parsedData = JSON.parse(data);
                    } else {
                        throw new Error(`Unexpected data type: ${typeof data}`);
                    }

                    logs.push({
                        key,
                        data: parsedData,
                    });
                } catch (parseError) {
                    console.error(`Failed to parse data for key ${key}:`, data);
                    console.error('Parse error:', parseError.message);
                    corruptedKeys.push(key);
                    continue;
                }
            }
        }

        console.log('Retrieved logs count:', logs.length);
        if (corruptedKeys.length > 0) {
            console.warn('Found corrupted keys:', corruptedKeys);
        }

        return {
            success: true,
            data: logs,
            count: logs.length,
            corruptedKeys: corruptedKeys,
            totalKeysFound: keys.length,
        };

    } catch (error) {
        console.error('Error in getThreatLogsByIP:', error);
        return {
            success: false,
            error: error.message,
        };
    }
}

/**
 * Retrieves all threat logs matching a pattern
 * Enhanced version with better error handling
 *
 * @param {string} [keyPrefix='threat_log'] - Key prefix to search for
 * @param {number} [limit=100] - Maximum number of logs to retrieve
 * @returns {Promise<Object>} - Array of all matching logs or error
 */
async function getAllThreatLogs(keyPrefix = 'threat_log', limit = 100) {
    try {
        console.log('Retrieving all logs with prefix:', keyPrefix);
        const pattern = `${keyPrefix}:*`;
        const keys = await redis.keys(pattern);

        console.log('Found total keys:', keys.length);

        if (keys.length === 0) {
            return {
                success: true,
                data: [],
                message: 'No logs found',
            };
        }

        // Sort keys by timestamp (newest first) and limit results
        const sortedKeys = keys
            .sort((a, b) => {
                const timestampA = parseInt(a.split(':').pop());
                const timestampB = parseInt(b.split(':').pop());
                return timestampB - timestampA;
            })
            .slice(0, limit);

        const logs = [];
        const corruptedKeys = [];

        for (const key of sortedKeys) {
            const data = await redis.get(key);
            if (data) {
                try {
                    let parsedData;

                    // Handle Upstash returning objects vs strings
                    if (typeof data === 'object') {
                        // Upstash returned an object directly
                        parsedData = data;
                    } else if (typeof data === 'string') {
                        // Check for corruption
                        if (data === '[object Object]' || data.includes('[object Object]')) {
                            console.warn(`Key ${key} contains corrupted data: ${data}`);
                            corruptedKeys.push(key);
                            continue;
                        }
                        // Parse the JSON string
                        parsedData = JSON.parse(data);
                    } else {
                        throw new Error(`Unexpected data type: ${typeof data}`);
                    }

                    logs.push({
                        key,
                        data: parsedData,
                    });
                } catch (parseError) {
                    console.error(`Failed to parse data for key ${key}:`, data);
                    console.error('Parse error:', parseError.message);
                    corruptedKeys.push(key);
                    continue;
                }
            }
        }

        return {
            success: true,
            data: logs,
            count: logs.length,
            totalKeys: keys.length,
            corruptedKeys: corruptedKeys,
        };

    } catch (error) {
        console.error('Error in getAllThreatLogs:', error);
        return {
            success: false,
            error: error.message,
        };
    }
}

/**
 * Utility function to clean up corrupted Redis entries
 * Call this to remove entries that contain "[object Object]" strings
 *
 * @param {string} [keyPrefix='monitoring_log'] - Key prefix to clean
 * @returns {Promise<Object>} - Cleanup results
 */
export async function cleanupCorruptedEntries(keyPrefix = 'monitoring_log') {
    try {
        console.log('Cleaning up corrupted entries with prefix:', keyPrefix);
        const pattern = `${keyPrefix}:*`;
        const keys = await redis.keys(pattern);

        let deletedCount = 0;
        const deletedKeys = [];

        for (const key of keys) {
            const data = await redis.get(key);
            if (data === '[object Object]' || (typeof data === 'string' && data.includes('[object Object]'))) {
                console.log('Deleting corrupted key:', key);
                await redis.del(key);
                deletedCount++;
                deletedKeys.push(key);
            }
        }

        return {
            success: true,
            deletedCount,
            deletedKeys,
            message: `Cleaned up ${deletedCount} corrupted entries`
        };

    } catch (error) {
        console.error('Error in cleanupCorruptedEntries:', error);
        return {
            success: false,
            error: error.message
        };
    }
}

/**
 * LLM-friendly wrapper for storing monitoring logs
 * This function is designed to be called by the LLM via function calling
 * Returns detailed information about the storage operation
 *
 * @param {Object} logEntry - The log entry object
 * @param {number} confidenceScore - Confidence score from LLM (0-10)
 * @param {string} explanation - LLM explanation
 * @returns {Promise<Object>} - Success/error response with details
 */
export async function storeMonitoringLog(logEntry, confidenceScore, explanation) {
    console.log('=== storeMonitoringLog called ===');
    console.log('Input params:', {
        logEntry: JSON.stringify(logEntry, null, 2),
        confidenceScore,
        explanation
    });

    // Fixed parameter order to match storeThreatLog signature
    const result = await storeThreatLog(logEntry, explanation, confidenceScore, 'monitoring_log');

    if (result.success) {
        console.log('Storage successful:', JSON.stringify({
            key: result.key,
            stored_data: result.data,
            expires_in: result.expiresIn
        }, null, 2));

        // Return enhanced result for LLM
        return {
            ...result,
            message: `Successfully stored monitoring log for IP ${logEntry.ip}`,
            stored_at: new Date().toISOString(),
            monitoring_active: true
        };
    }

    console.log('Storage failed:', result);
    console.log('=== storeMonitoringLog completed ===');
    return result;
}

/**
 * LLM-friendly wrapper for checking stored logs
 * This function is designed to be called by the LLM via function calling
 * Returns properly serialized data that the LLM can read
 *
 * @param {string} ipAddress - IP address to check
 * @returns {Promise<Object>} - Existing logs with readable data
 */
export async function checkStoredLogs(ipAddress) {
    console.log('=== checkStoredLogs called ===');
    console.log('IP Address:', ipAddress);

    const result = await getThreatLogsByIP(ipAddress, 'monitoring_log');

    // If successful, ensure the data is properly serialized for the LLM
    if (result.success && result.data && result.data.length > 0) {
        // Create a clean, readable version for the LLM
        const readableData = result.data.map(item => ({
            key: item.key,
            timestamp: item.data.timestamp,
            ip_address: item.data.ip_address,
            method: item.data.method,
            url: item.data.url,
            query_string: item.data.query_string,
            user_agent: item.data.user_agent,
            status: item.data.status,
            explanation: item.data.explanation,
            confidence: item.data.confidence
        }));

        console.log('Check result with readable data:', JSON.stringify({
            ...result,
            data: readableData
        }, null, 2));

        // Return data in a format the LLM can understand
        return {
            ...result,
            data: readableData,
            summary: `Found ${result.count} previous monitoring entries for IP ${ipAddress}`,
            latest_entry: readableData[0] || null,
            pattern_summary: {
                total_requests: result.count,
                date_range: {
                    oldest: readableData[readableData.length - 1]?.timestamp,
                    newest: readableData[0]?.timestamp
                },
                confidence_scores: readableData.map(item => item.confidence),
                urls_accessed: [...new Set(readableData.map(item => item.url))],
                methods_used: [...new Set(readableData.map(item => item.method))]
            }
        };
    }

    console.log('Check result:', result);
    console.log('=== checkStoredLogs completed ===');
    return result;
}

/**
 * LLM-friendly wrapper for retrieving all monitoring logs
 * This function is designed to be called by the LLM via function calling
 *
 * @param {number} [limit=50] - Maximum number of logs to retrieve
 * @returns {Promise<Object>} - Array of all monitoring logs or error
 */
export async function getAllMonitoringLogs(limit = 50) {
    console.log('=== getAllMonitoringLogs called ===');
    console.log('Limit:', limit);

    const result = await getAllThreatLogs('monitoring_log', limit);

    console.log('Retrieved logs count:', result.success ? result.count : 0);
    console.log('=== getAllMonitoringLogs completed ===');
    return result;
}

/**
 * Test function to verify Redis connection and basic operations
 * @returns {Promise<Object>} - Test results
 */
export async function testRedisOperations() {
    console.log('=== Testing Redis Operations ===');

    try {
        // Test connection
        const connectionTest = await testRedisConnection();
        console.log('Connection test passed:', connectionTest);

        if (!connectionTest) {
            return {
                success: false,
                error: 'Redis connection failed',
            };
        }

        // Test storing a log
        const testLogEntry = {
            ip: '192.168.1.100',
            method: 'GET',
            queryString: '/test',
            userAgent: 'Test-Agent',
            url: 'https://example.com/test',
            status: 200,
        };

        const storeResult = await storeMonitoringLog(testLogEntry, 5, 'Test log entry');
        console.log('Store test result:', storeResult);

        if (!storeResult.success) {
            return {
                success: false,
                error: 'Failed to store test log',
                details: storeResult,
            };
        }

        // Test retrieving logs
        const retrieveResult = await checkStoredLogs('192.168.1.100');
        console.log('Retrieve test result:', retrieveResult);

        // Clean up test data
        if (storeResult.success && storeResult.key) {
            await redis.del(storeResult.key);
            console.log('Cleaned up test data');
        }

        return {
            success: true,
            message: 'All Redis operations working correctly',
            testResults: {
                connection: connectionTest,
                store: storeResult.success,
                retrieve: retrieveResult.success,
            },
        };

    } catch (error) {
        console.error('Error in testRedisOperations:', error);
        return {
            success: false,
            error: error.message,
            stack: error.stack,
        };
    }
}

// Export additional utility functions for direct use
export { testRedisConnection, getAllThreatLogs, getThreatLog };