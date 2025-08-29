import { createServerObject } from '../utils.js';

/**
 * Parses the content from the Curl GitHub Wiki source.
 * The source is a Markdown file with a large table of DoH servers.
 * This parser creates a separate server entry for each protocol found for a provider.
 * @param {string} content The raw Markdown content.
 * @returns {Array<object>} A list of server objects, with each object representing a single protocol.
 */
export function parseCurl(content) {
    const servers = [];
    const lines = content.split('\n');
    let inTable = false;
    let currentProvider = '';

    // A more robust regex to validate a potential hostname.
    const isValidHostname = (str) => /^[a-zA-Z0-9.-]+(?::\d{1,5})?$/.test(str) && !/^\d+$/.test(str.split(':')[0]);

    for (const line of lines) {
        // Find the table header to start parsing
        if (line.includes('| Who runs it') && line.includes('| Base URL')) {
            inTable = true;
            continue;
        }
        if (!inTable || !line.startsWith('|')) continue;

        const parts = line.split('|').map(p => p.trim());
        // Basic validation for a valid table row
        if (parts.length < 5 || parts[1].includes('---')) continue;
        
        // Ignore single-letter section headers like | A | | | |
        const providerNameRaw = parts[1];
        if (providerNameRaw.length === 1 && providerNameRaw.match(/[A-Z]/) && parts[2] === '' && parts[3] === '') {
            continue;
        }

        // Persist the provider name for entries that span multiple rows
        const providerName = providerNameRaw.replace(/\[([^\]]+)\]\([^\)]+\)/, '$1');
        if (providerName) {
            currentProvider = providerName;
        }

        // Extract all https URLs from the 'Base URL' cell for DoH
        const dohUrls = (parts[2].match(/https:\/\/[^\s<]+/g) || []);
        if (dohUrls.length === 0) continue;

        const rawCommentText = parts[4];
        const commentTextLower = rawCommentText.toLowerCase();

        // --- COMMON PROPERTIES FACTORY ---
        const createBaseServer = () => {
            const server = createServerObject();
            server.provider = currentProvider;
            
            const combinedText = (commentTextLower + " " + dohUrls.join(' '));
            if (combinedText.includes('adblock') || combinedText.includes('block ads')) server.filters.ads = true;
            if (combinedText.includes('malware') || combinedText.includes('phishing')) server.filters.malware = true;
            if (combinedText.includes('family') || combinedText.includes('parental') || combinedText.includes('adult content') || combinedText.includes('porn')) server.filters.family = true;
            
            if (commentTextLower.includes('dnssec')) server.features.dnssec = true;
            if (commentTextLower.includes('no log') || commentTextLower.includes('no-log') || commentTextLower.includes('non-logging')) server.features.no_log = true;

            if (!server.filters.ads && !server.filters.malware && !server.filters.family) {
                if (commentTextLower.includes('no filter') || commentTextLower.includes('unfiltered') || commentTextLower.includes('non-filtering')) {
                    server.filters.unfiltered = true;
                } else {
                    server.filters.unfiltered = true;
                }
            }
            return server;
        };

        // --- PROTOCOL-SPECIFIC PARSING ---

        // 1. DoH (Default)
        const dohServer = createBaseServer();
        dohServer.protocols.push('doh');
        dohServer.addresses.push(...dohUrls);
        servers.push(dohServer);

        let baseHostname = null;
        try {
            baseHostname = new URL(dohUrls[0]).hostname;
        } catch (e) { /* Ignore invalid URLs */ }

        // --- Helper function to find explicit hostnames with very strict patterns ---
        const findExplicitHostname = (protocolKeywordRegex) => {
            const patterns = [
                new RegExp(`${protocolKeywordRegex.source}\\s*:\\s*([a-zA-Z0-9.-]+(?::\\d{1,5})?)`, 'i'), // Pattern: DoT: hostname
                new RegExp(`${protocolKeywordRegex.source}\\s*\\(\\s*([a-zA-Z0-9.-]+(?::\\d{1,5})?)\\s*\\)`, 'i'), // Pattern: DoT (hostname)
                new RegExp(`${protocolKeywordRegex.source}\\s*\\s*\`\\s*([a-zA-Z0-9.-]+(?::\\d{1,5})?)\\s*\`\\s*`, 'i'), // Pattern: DoT `hostname`
            ];
            for (const pattern of patterns) {
                const match = rawCommentText.match(pattern);
                if (match && match[1] && isValidHostname(match[1])) {
                    return match[1];
                }
            }
            // Check for shared pattern as a last resort
            const sharedMatch = rawCommentText.match(/(?:DoT\/DoQ|DoQ\/DoT)\s*:?\s*([a-zA-Z0-9.-]+(?::\d{1,5})?)/i);
            if (sharedMatch && sharedMatch[1] && isValidHostname(sharedMatch[1])) {
                return sharedMatch[1];
            }
            return null;
        };
        
        // 2. DoT
        if (/\b(dot|tls)\b/i.test(rawCommentText)) {
            const dotServer = createBaseServer();
            dotServer.protocols.push('dot');
            const explicitHostname = findExplicitHostname(/(?:DoT|TLS)/);
            
            if (explicitHostname) {
                dotServer.addresses.push(`tls://${explicitHostname}`);
            } else if (baseHostname) {
                dotServer.addresses.push(`tls://${baseHostname}`);
            }
            if (dotServer.addresses.length > 0) servers.push(dotServer);
        }

        // 3. DoQ
        if (/\bdoq\b/i.test(rawCommentText)) {
            const doqServer = createBaseServer();
            doqServer.protocols.push('doq');
            const explicitHostname = findExplicitHostname(/DoQ/);

            if (explicitHostname) {
                doqServer.addresses.push(`quic://${explicitHostname}`);
            } else if (baseHostname) {
                doqServer.addresses.push(`quic://${baseHostname}`);
            }
            if (doqServer.addresses.length > 0) servers.push(doqServer);
        }

        // 4. DoH3
        if (/\bdoh3\b/i.test(rawCommentText)) {
            const doh3Server = createBaseServer();
            doh3Server.protocols.push('doh3');
            doh3Server.addresses.push(...dohUrls);
            servers.push(doh3Server);
        }

        // 5. DNSCrypt
        if (/\bdnscrypt\b/i.test(rawCommentText)) {
            const dnsCryptServer = createBaseServer();
            dnsCryptServer.protocols.push('dnscrypt');
            const dnsCryptMatches = rawCommentText.match(/sdns:\/\/[^\s`)]+/g);
            if (dnsCryptMatches) {
                dnsCryptServer.addresses.push(...dnsCryptMatches);
            }
            if (dnsCryptServer.addresses.length > 0) servers.push(dnsCryptServer);
        }
    }
    return servers;
}
