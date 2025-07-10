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
            method: logEntry.method,
            query_string: logEntry.queryString,
            user_agent: logEntry.userAgent,
            url: logEntry.url,
            status: logEntry.status,
            explanation: explanation,
            confidence: score,
            timestamp: new Date().toISOString(),
        };

        // Generate a unique key using timestamp and IP
        const timestamp = Date.now();
        const redisKey = `${keyPrefix}:${logEntry.ip}:${timestamp}`;

        console.log('Storing data with key:', redisKey);
        console.log('Data to store:', threatData);

        // Store the data with 1-hour expiration (3600 seconds)
        await redis.setex(redisKey, 3600, JSON.stringify(threatData));

        console.log("Threat monitored successfully");

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

        const parsedData = JSON.parse(data);
        console.log('Retrieved data:', parsedData);

        return {
            success: true,
            data: parsedData,
        };

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
        for (const key of keys) {
            const data = await redis.get(key);
            if (data) {
                logs.push({
                    key,
                    data: JSON.parse(data),
                });
            }
        }

        console.log('Retrieved logs count:', logs.length);

        return {
            success: true,
            data: logs,
            count: logs.length,
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
        for (const key of sortedKeys) {
            const data = await redis.get(key);
            if (data) {
                logs.push({
                    key,
                    data: JSON.parse(data),
                });
            }
        }

        return {
            success: true,
            data: logs,
            count: logs.length,
            totalKeys: keys.length,
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
 * LLM-friendly wrapper for storing monitoring logs
 * This function is designed to be called by the LLM via function calling
 *
 * @param {Object} logEntry - The log entry object
 * @param {number} confidenceScore - Confidence score from LLM (0-10)
 * @param {string} explanation - LLM explanation
 * @returns {Promise<Object>} - Success/error response
 */
export async function storeMonitoringLog(logEntry, confidenceScore, explanation) {
    console.log('=== storeMonitoringLog called ===');
    console.log('Input params:', { logEntry, confidenceScore, explanation });

    // Fixed parameter order to match storeThreatLog signature
    const result = await storeThreatLog(logEntry, explanation, confidenceScore, 'monitoring_log');

    console.log('Storage result:', result);
    console.log('=== storeMonitoringLog completed ===');
    return result;
}

/**
 * LLM-friendly wrapper for checking stored logs
 * This function is designed to be called by the LLM via function calling
 *
 * @param {string} ipAddress - IP address to check
 * @returns {Promise<Object>} - Existing logs or empty array
 */
export async function checkStoredLogs(ipAddress) {
    console.log('=== checkStoredLogs called ===');
    console.log('IP Address:', ipAddress);

    const result = await getThreatLogsByIP(ipAddress, 'monitoring_log');

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