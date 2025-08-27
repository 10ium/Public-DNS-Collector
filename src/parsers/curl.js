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
        if (line.includes('| Who runs it')) {
            inTable = true;
            continue;
        }
        if (!inTable || !line.startsWith('|')) continue;

        const parts = line.split('|').map(p => p.trim());
        if (parts.length < 5 || parts[1].includes('---')) continue;
        
        // Ignore single-letter section headers like | A | | | |
        const providerNameRaw = parts[1];
        if (providerNameRaw.length === 1 && parts[2] === '' && parts[3] === '') continue;

        const providerName = providerNameRaw.replace(/\[([^\]]+)\]\([^\)]+\)/, '$1');
        if (providerName) {
            currentProvider = providerName;
        }

        // Handle multi-line URLs separated by newlines within the cell
        const urls = (parts[2].match(/https:\/\/[^\s<]+/g) || []);
        if (urls.length === 0) continue;

        const commentText = parts[4].toLowerCase();
        
        // Create a new server object for each provider entry
        const server = createServerObject();
        server.provider = currentProvider;
        server.protocols.push('doh');
        server.addresses.push(...urls);

        // Infer filters from comment and URL
        const combinedText = (commentText + " " + urls.join(' ')).toLowerCase();
        if (combinedText.includes('adblock') || combinedText.includes('block ads')) server.filters.ads = true;
        if (combinedText.includes('malware') || combinedText.includes('phishing')) server.filters.malware = true;
        if (combinedText.includes('family') || combinedText.includes('parental') || combinedText.includes('adult content') || combinedText.includes('porn')) server.filters.family = true;
        
        // Infer features from comment
        if (commentText.includes('dnssec')) server.features.dnssec = true;
        if (commentText.includes('no log') || commentText.includes('no-log') || commentText.includes('non-logging')) server.features.no_log = true;

        // Set unfiltered if no other filter is active
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
