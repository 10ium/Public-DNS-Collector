import { createServerObject } from '../utils.js';

/**
 * Parses the content from the Curl GitHub Wiki source.
 * The source is a Markdown file with a large table of DoH servers.
 * @param {string} content The raw Markdown content.
 * @returns {Array<object>} A list of server objects.
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

        // Extract all https URLs from the 'Base URL' cell
        const urls = (parts[2].match(/https:\/\/[^\s<]+/g) || []);
        if (urls.length === 0) continue;

        const commentText = parts[4].toLowerCase();
        
        // Create a server object for each group of URLs with the same comment
        const server = createServerObject();
        server.provider = currentProvider;
        server.protocols.push('doh'); // DoH is the default for this list
        server.addresses.push(...urls);

        // --- IMPROVED PROTOCOL DETECTION ---
        // Dynamically detect other supported protocols from the comment text.
        // Using word boundaries (\b) to avoid partial matches (e.g., 'dot' in 'dotcom').
        const protocolPatterns = {
            dot: /\bdot\b/i,
            doq: /\bdoq\b/i,
            doh3: /\bdoh3\b/i,
            dnscrypt: /\bdnscrypt\b/i
        };

        for (const [protocol, pattern] of Object.entries(protocolPatterns)) {
            if (pattern.test(commentText)) {
                server.protocols.push(protocol);
            }
        }

        // Infer filters by searching for keywords in the comment text and URLs
        const combinedText = (commentText + " " + urls.join(' ')).toLowerCase();
        if (combinedText.includes('adblock') || combinedText.includes('block ads')) server.filters.ads = true;
        if (combinedText.includes('malware') || combinedText.includes('phishing')) server.filters.malware = true;
        if (combinedText.includes('family') || combinedText.includes('parental') || combinedText.includes('adult content') || combinedText.includes('porn')) server.filters.family = true;
        
        // Infer features from the comment text
        if (commentText.includes('dnssec')) server.features.dnssec = true;
        if (commentText.includes('no log') || commentText.includes('no-log') || commentText.includes('non-logging')) server.features.no_log = true;

        // Set 'unfiltered' status if no specific filtering is detected
        if (!server.filters.ads && !server.filters.malware && !server.filters.family) {
            if (commentText.includes('no filter') || commentText.includes('unfiltered') || commentText.includes('non-filtering')) {
                server.filters.unfiltered = true;
            }
        }
        
        // Final fallback: if no filtering information is found at all, assume unfiltered
        if (!server.filters.ads && !server.filters.malware && !server.filters.family && !server.filters.unfiltered) {
            server.filters.unfiltered = true;
        }

        servers.push(server);
    }
    return servers;
}
