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
        // A function to create a base server object with shared properties.
        const createBaseServer = () => {
            const server = createServerObject();
            server.provider = currentProvider;
            
            // Infer filters
            const combinedText = (commentTextLower + " " + dohUrls.join(' '));
            if (combinedText.includes('adblock') || combinedText.includes('block ads')) server.filters.ads = true;
            if (combinedText.includes('malware') || combinedText.includes('phishing')) server.filters.malware = true;
            if (combinedText.includes('family') || combinedText.includes('parental') || combinedText.includes('adult content') || combinedText.includes('porn')) server.filters.family = true;
            
            // Infer features
            if (commentTextLower.includes('dnssec')) server.features.dnssec = true;
            if (commentTextLower.includes('no log') || commentTextLower.includes('no-log') || commentTextLower.includes('non-logging')) server.features.no_log = true;

            // Set 'unfiltered' status
            if (!server.filters.ads && !server.filters.malware && !server.filters.family) {
                if (commentTextLower.includes('no filter') || commentTextLower.includes('unfiltered') || commentTextLower.includes('non-filtering')) {
                    server.filters.unfiltered = true;
                } else {
                    server.filters.unfiltered = true; // Default fallback
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

        // Extract base hostname from the main DoH URL for other protocols
        let baseHostname = null;
        try {
            baseHostname = new URL(dohUrls[0]).hostname;
        } catch (e) { /* Ignore invalid URLs */ }

        // 2. DoT
        if (/\b(dot|tls)\b/i.test(rawCommentText)) {
            const dotServer = createBaseServer();
            dotServer.protocols.push('dot');
            const explicitMatch = rawCommentText.match(/(?:DoT|TLS)\s*(?:\(|`|:)\s*([a-zA-Z0-9.-]+(?::\d{1,5})?)/i) || rawCommentText.match(/(?:DoT\/DoQ|DoQ\/DoT)\s*:?\s*([a-zA-Z0-9.-]+(?::\d{1,5})?)/i);
            
            if (explicitMatch && explicitMatch[1]) {
                dotServer.addresses.push(`tls://${explicitMatch[1]}`);
            } else if (baseHostname) {
                dotServer.addresses.push(`tls://${baseHostname}`);
            }
            if (dotServer.addresses.length > 0) servers.push(dotServer);
        }

        // 3. DoQ
        if (/\bdoq\b/i.test(rawCommentText)) {
            const doqServer = createBaseServer();
            doqServer.protocols.push('doq');
            const explicitMatch = rawCommentText.match(/DoQ\s*(?:\(|`|:)\s*([a-zA-Z0-9.-]+(?::\d{1,5})?)/i) || rawCommentText.match(/(?:DoT\/DoQ|DoQ\/DoT)\s*:?\s*([a-zA-Z0-9.-]+(?::\d{1,5})?)/i);

            if (explicitMatch && explicitMatch[1]) {
                doqServer.addresses.push(`quic://${explicitMatch[1]}`);
            } else if (baseHostname) {
                doqServer.addresses.push(`quic://${baseHostname}`);
            }
            if (doqServer.addresses.length > 0) servers.push(doqServer);
        }

        // 4. DoH3
        if (/\bdoh3\b/i.test(rawCommentText)) {
            const doh3Server = createBaseServer();
            doh3Server.protocols.push('doh3');
            // DoH3 reuses the DoH URLs
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
