import { WebSiteManagementClient } from '@azure/arm-appservice';
import { DefaultAzureCredential } from '@azure/identity';
import * as dotenv from "dotenv";
dotenv.config();

// Configuration from environment variables
const config = {
    subscriptionId: process.env.AZURE_SUBSCRIPTION_ID,
    resourceGroupName: process.env.AZURE_RESOURCE_GROUP,
    appName: process.env.AZURE_APP_NAME
};

// Global client instance with retry logic
let azureClient = null;
let clientExpiry = null;
const CLIENT_REFRESH_HOURS = 1; // Refresh client every hour

/**
 * Get Azure client with automatic re-authentication on 401 errors
 * Only creates new client if needed or if previous requests failed with 401
 */
async function getAzureClient(forceRefresh = false) {
    const now = Date.now();

    // Create new client if:
    // 1. Client doesn't exist
    // 2. Force refresh requested (after 401 error)
    // 3. Client is older than refresh interval
    if (!azureClient || forceRefresh || (clientExpiry && now > clientExpiry)) {
        console.log('🔐 Initializing Azure client...');

        try {
            // Create credential with retry options
            const credential = new DefaultAzureCredential({
                retryOptions: {
                    maxRetries: 3,
                    retryDelayInMs: 1000
                }
            });

            // Test credential before creating client
            console.log('   Testing credential...');
            const tokenResponse = await credential.getToken('https://management.azure.com/.default');
            console.log(`   ✅ Token obtained (expires: ${new Date(tokenResponse.expiresOnTimestamp).toISOString()})`);

            // Create client
            azureClient = new WebSiteManagementClient(credential, config.subscriptionId);

            // Set expiry time for client refresh
            clientExpiry = now + (CLIENT_REFRESH_HOURS * 60 * 60 * 1000);
            console.log('   ✅ Azure client ready');

        } catch (error) {
            console.error('❌ Failed to initialize Azure client:', error.message);
            throw new Error(`Authentication failed: ${error.message}`);
        }
    } else {
        console.log('♻️  Using existing Azure client');
    }

    return azureClient;
}

/**
 * Execute Azure API call with automatic retry on 401 errors
 * @param {Function} apiCall - The Azure API function to execute
 * @param {string} operationName - Name of operation for logging
 * @returns {Promise} - Result of API call
 */
async function executeWithRetry(apiCall, operationName) {
    let client = await getAzureClient();

    try {
        console.log(`   Executing ${operationName}...`);
        return await apiCall(client);
    } catch (error) {
        // Check if error is authentication-related (401 or token expired)
        const is401Error = error.statusCode === 401 ||
            error.code === 'AuthenticationFailed' ||
            error.message?.includes('token') ||
            error.message?.includes('authentication');

        if (is401Error) {
            console.log('   ⚠️  Authentication error detected, refreshing client...');

            // Force refresh client and retry once
            client = await getAzureClient(true);
            console.log('   🔄 Retrying operation with fresh client...');

            try {
                return await apiCall(client);
            } catch (retryError) {
                console.error('   ❌ Retry also failed:', retryError.message);
                throw retryError;
            }
        } else {
            // Non-auth error, don't retry
            throw error;
        }
    }
}

/**
 * Block an IP address by adding it to Azure App Service access restrictions
 * @param {string} ipAddress - IP address to block (e.g., "192.168.1.1")
 * @param {string} reason - Optional reason for blocking (default: "Blocked by script")
 * @returns {Promise<Object>} - Result object with success status and details
 */
async function blockIP(ipAddress, reason = "Blocked by script") {
    console.log(`\n🚫 Blocking IP: ${ipAddress}`);
    console.log(`   Reason: ${reason}`);

    // Validate IP address format
    const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    if (!ipRegex.test(ipAddress)) {
        const error = new Error(`Invalid IP address format: ${ipAddress}`);
        console.error('❌', error.message);
        throw error;
    }

    try {
        // Step 1: Get current site configuration with retry logic
        console.log('📥 Retrieving current site configuration...');
        const siteConfig = await executeWithRetry(
            (client) => client.webApps.getConfiguration(config.resourceGroupName, config.appName),
            'get configuration'
        );

        const existingRestrictions = siteConfig.ipSecurityRestrictions || [];
        console.log(`   Current restrictions: ${existingRestrictions.length}`);

        // Step 2: Check if IP is already blocked
        const targetIP = `${ipAddress}/32`;
        const existingRule = existingRestrictions.find(rule => rule.ipAddress === targetIP && rule.action === 'Deny');

        if (existingRule) {
            console.log(`   ⚠️  IP already blocked (rule: ${existingRule.name})`);
            return {
                success: true,
                ipAddress,
                alreadyBlocked: true,
                existingRule: existingRule.name,
                message: 'IP was already blocked'
            };
        }

        // Step 3: Create new blocking rule
        const timestamp = Date.now();
        const ruleName = `Block-${ipAddress.replace(/\./g, '-')}-${timestamp}`;

        // Generate priority (higher number = lower priority, range 100-2000)
        const priority = Math.floor(Math.random() * 1900) + 100;

        console.log(`   Creating rule: ${ruleName}`);
        console.log(`   Priority: ${priority}`);

        const newRestriction = {
            ipAddress: targetIP,
            action: 'Deny',
            name: ruleName,
            description: `${reason} at ${new Date().toISOString()}`,
            priority: priority
        };

        // Step 4: Add new restriction to existing ones
        const updatedRestrictions = [...existingRestrictions, newRestriction];
        console.log(`   Total restrictions after update: ${updatedRestrictions.length}`);

        // Step 5: Update site configuration with retry logic
        console.log('📤 Updating site configuration...');
        const updatedConfig = await executeWithRetry(
            (client) => client.webApps.updateConfiguration(
                config.resourceGroupName,
                config.appName,
                {
                    ...siteConfig,
                    ipSecurityRestrictions: updatedRestrictions
                }
            ),
            'update configuration'
        );

        // Verify the rule was added
        const finalRestrictions = updatedConfig.ipSecurityRestrictions || [];
        const addedRule = finalRestrictions.find(rule => rule.name === ruleName);

        if (addedRule) {
            console.log('✅ IP blocked successfully');
            console.log(`   Rule name: ${addedRule.name}`);
            console.log(`   Target: ${addedRule.ipAddress}`);
            console.log(`   Action: ${addedRule.action}`);
            console.log(`   Priority: ${addedRule.priority}`);

            return {
                success: true,
                ipAddress,
                ruleName: addedRule.name,
                priority: addedRule.priority,
                totalRestrictions: finalRestrictions.length,
                message: 'IP blocked successfully'
            };
        } else {
            throw new Error('Rule was not found in updated configuration');
        }

    } catch (error) {
        console.error('❌ Failed to block IP:', error.message);

        // Log additional error details for debugging
        if (error.code) console.error(`   Error code: ${error.code}`);
        if (error.statusCode) console.error(`   Status code: ${error.statusCode}`);
        if (error.response?.data) console.error(`   Response:`, JSON.stringify(error.response.data, null, 2));

        // Re-throw with context
        throw new Error(`Failed to block IP ${ipAddress}: ${error.message}`);
    }
}

export { blockIP };
