import fs from 'fs';
import chokidar from 'chokidar';
import { EventEmitter } from 'events';

// Enhanced log parser supporting multiple formats
class LogParser extends EventEmitter {
    constructor(logPaths, onLogEntry, options = {}) {
        super();
        this.logPaths = logPaths;
        this.onLogEntry = onLogEntry;
        this.watchers = [];
        this.filePositions = new Map();

        // Configuration options
        this.options = {
            autoDetectFormat: true,
            customPatterns: [],
            timezone: 'UTC',
            ...options
        };

        // Built-in log format patterns
        this.logPatterns = [
            {
                name: 'apache_common',
                regex: /^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) ([^"]*)" (\d+) (\d+|-) "([^"]*)" "([^"]*)"/,
                fields: ['ip', 'timestamp', 'method', 'url', 'status', 'size', 'referer', 'userAgent'],
                timestampFormat: 'apache'
            },
            {
                name: 'nginx_combined',
                regex: /^(\S+) - (\S+) \[([^\]]+)\] "(\S+) ([^"]*)" (\d+) (\d+|-) "([^"]*)" "([^"]*)"/,
                fields: ['ip', 'user', 'timestamp', 'method', 'url', 'status', 'size', 'referer', 'userAgent'],
                timestampFormat: 'apache'
            },
            {
                name: 'json',
                regex: /^\{.*\}$/,
                fields: null, // JSON will be parsed as-is
                timestampFormat: 'iso'
            },
            {
                name: 'syslog',
                regex: /^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?\s*:\s*(.*)$/,
                fields: ['timestamp', 'hostname', 'process', 'pid', 'message'],
                timestampFormat: 'syslog'
            },
            {
                name: 'custom_app',
                regex: /^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[(\w+)\]\s+(.*)$/,
                fields: ['timestamp', 'level', 'message'],
                timestampFormat: 'iso'
            },
            {
                name: 'clf_extended',
                regex: /^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) ([^"]*)" (\d+) (\d+|-) "([^"]*)" "([^"]*)" (\d+) (\d+)$/,
                fields: ['ip', 'timestamp', 'method', 'url', 'status', 'size', 'referer', 'userAgent', 'responseTime', 'requestTime'],
                timestampFormat: 'apache'
            },
            {
                name: 'iis',
                regex: /^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}) (\S+) (\S+) (\S+) (\d+) (\S+) (\S+) (\d+) (\d+) (\d+) (\d+) (\d+) (\S+) (\S+) (\S+) (\S+)$/,
                fields: ['date', 'time', 'serverIp', 'method', 'uri', 'query', 'port', 'username', 'clientIp', 'userAgent', 'referer', 'status', 'substatus', 'win32Status', 'timeTaken'],
                timestampFormat: 'iis'
            },
            {
                name: 'apache_variant_for_logagent',
                regex: /^(\S+) - - \[([^\]]+)] "(\S+) ([^"]+)" (\d+) "([^"]+)" "([^"]+)"$/,
                fields: ['ip', 'timestamp', 'method', 'url', 'status', 'userAgent', 'referer'],
                timestampFormat: 'apache'
            }

        ];

        // Add custom patterns if provided
        if (this.options.customPatterns.length > 0) {
            this.logPatterns.unshift(...this.options.customPatterns);
        }
    }

    async start() {
        for (const logPath of this.logPaths) {
            await this.watchLogFile(logPath);
        }
    }

    async watchLogFile(logPath) {
        const stats = fs.statSync(logPath);
        this.filePositions.set(logPath, stats.size);

        const watcher = chokidar.watch(logPath, {
            usePolling: true,
            interval: 1000
        });

        watcher.on('change', () => {
            this.processNewLines(logPath);
        });

        this.watchers.push(watcher);
    }

    processNewLines(logPath) {
        const currentPos = this.filePositions.get(logPath) || 0;
        const stream = fs.createReadStream(logPath, {
            start: currentPos,
            encoding: 'utf8'
        });

        let buffer = '';

        stream.on('data', (chunk) => {
            buffer += chunk;
            const lines = buffer.split('\n');
            buffer = lines.pop();

            lines.forEach(line => {
                if (line.trim()) {
                    const parsed = this.parseLogLine(line, logPath);
                    if (parsed) {
                        this.onLogEntry(parsed);
                    }
                }
            });
        });

        stream.on('end', () => {
            const stats = fs.statSync(logPath);
            this.filePositions.set(logPath, stats.size);
        });
    }

    parseLogLine(line, logPath = '') {
        try {
            // Try JSON parsing first
            if (line.trim().startsWith('{')) {
                return this.parseJsonLog(line);
            }

            // Try each pattern until one matches
            for (const pattern of this.logPatterns) {
                if (pattern.name === 'json') continue; // Skip JSON pattern here

                const match = line.match(pattern.regex);
                if (match) {
                    return this.buildLogEntry(match, pattern, line, logPath);
                }
            }

            // If no pattern matches, return a generic entry
            return {
                rawLine: line,
                timestamp: new Date(),
                source: logPath,
                format: 'unknown',
                message: line
            };

        } catch (error) {
            console.error('Error parsing log line:', error);
            return null;
        }
    }

    parseJsonLog(line) {
        try {
            const parsed = JSON.parse(line);

            // Normalize timestamp if present
            if (parsed.timestamp || parsed.time || parsed['@timestamp']) {
                const timestampField = parsed.timestamp || parsed.time || parsed['@timestamp'];
                parsed.timestamp = new Date(timestampField);
            } else {
                parsed.timestamp = new Date();
            }

            // Extract payload if URL is present
            if (parsed.url) {
                parsed.payload = this.extractPayload(parsed.url);
            }

            return {
                ...parsed,
                format: 'json',
                rawLine: line
            };
        } catch (error) {
            console.error('Error parsing JSON log:', error);
            return null;
        }
    }

    buildLogEntry(match, pattern, line, logPath) {
        const entry = {
            rawLine: line,
            format: pattern.name,
            source: logPath
        };

        // Map matched groups to field names
        if (pattern.fields) {
            pattern.fields.forEach((field, index) => {
                const value = match[index + 1];
                if (value !== undefined) {
                    entry[field] = value;
                }
            });
        }

        // Parse timestamp
        entry.timestamp = this.parseTimestamp(entry.timestamp || entry.date + ' ' + entry.time, pattern.timestampFormat);

        // Parse numeric fields
        ['status', 'size', 'responseTime', 'requestTime', 'timeTaken', 'port', 'substatus', 'win32Status'].forEach(field => {
            if (entry[field] && entry[field] !== '-') {
                entry[field] = parseInt(entry[field]) || 0;
            }
        });

        // Extract payload from URL if present
        if (entry.url) {
            entry.payload = this.extractPayload(entry.url);
            // Clean URL (remove query string)
            if (entry.url.includes('?')) {
                entry.queryString = entry.url.split('?')[1];
                entry.url = entry.url.split('?')[0];
            }
        }

        return entry;
    }

    parseTimestamp(timestampStr, format) {
        if (!timestampStr) return new Date();

        try {
            switch (format) {
                case 'apache':
                    // Format: [dd/MMM/yyyy:HH:mm:ss +0000]
                    const cleaned = timestampStr.replace(/\[|\]/g, '');
                    return new Date(cleaned);

                case 'syslog':
                    // Format: MMM dd HH:mm:ss
                    const currentYear = new Date().getFullYear();
                    return new Date(`${currentYear} ${timestampStr}`);

                case 'iis':
                    // Format: yyyy-MM-dd HH:mm:ss
                    return new Date(timestampStr);

                case 'iso':
                default:
                    // ISO format or similar
                    return new Date(timestampStr);
            }
        } catch (error) {
            console.error('Error parsing timestamp:', error);
            return new Date();
        }
    }

    extractPayload(url) {
        const payload = {};

        if (url.includes('?')) {
            const queryString = url.split('?')[1];
            const params = new URLSearchParams(queryString);

            for (const [key, value] of params.entries()) {
                try {
                    payload[key] = decodeURIComponent(value);
                } catch {
                    payload[key] = value;
                }
            }
        }

        return payload;
    }

    // Method to add custom patterns at runtime
    addCustomPattern(pattern) {
        this.logPatterns.unshift(pattern);
    }

    // Method to get supported formats
    getSupportedFormats() {
        return this.logPatterns.map(p => p.name);
    }

    async stop() {
        for (const watcher of this.watchers) {
            await watcher.close();
        }
        this.watchers = [];
    }
}

export default LogParser;