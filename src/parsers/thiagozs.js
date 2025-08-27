import { createServerObject } from '../utils.js';

/**
 * Parses the content from the thiagozs Gist source.
 * The source is a Markdown file with a table of DoH servers.
 * @param {string} content The raw Markdown content.
 * @returns {Array<object>} A list of server objects.
 */
export function parseGist(content) {
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
        
        // Ignore single-letter section headers like | **A** | | | |
        const providerNameRaw = parts[1];
        if (providerNameRaw.startsWith('**') && providerNameRaw.endsWith('**')) continue;

        const providerName = providerNameRaw.replace(/\[([^\]]+)\]\([^\)]+\)/, '$1');
        if (providerName) {
            currentProvider = providerName;
        }

        // Handle multi-line URLs separated by <br>
        const urls = (parts[2].replace(/<br>/g, '\n').match(/https:\/\/[^\s<]+/g) || []);
        if (urls.length === 0) continue;

        const commentText = parts[4].toLowerCase();
        
        const server = createServerObject();
        server.provider = currentProvider;
        server.protocols.push('doh');
        server.addresses.push(...urls);

        // Infer filters from comment text
        if (commentText.includes('ad-blocking') || commentText.includes('adblocking') || commentText.includes('block advertising')) server.filters.ads = true;
        if (commentText.includes('malware')) server.filters.malware = true;
        if (commentText.includes('family protection') || commentText.includes('adult site blocking') || commentText.includes('parental control')) server.filters.family = true;
        
        // Infer features from comment text
        if (commentText.includes('dnssec')) server.features.dnssec = true;
        if (commentText.includes('no logging') || commentText.includes('zero ip and dns query logging')) server.features.no_log = true;

        // Set unfiltered if no other filter is active
        if (!server.filters.ads && !server.filters.malware && !server.filters.family) {
            if(commentText.includes('no filtering') || commentText.includes('uncensored')) {
                 server.filters.unfiltered = true;
            }
        }
        
        // Fallback for providers known to be unfiltered
        if (!server.filters.ads && !server.filters.malware && !server.filters.family && !server.filters.unfiltered) {
             server.filters.unfiltered = true;
        }

        servers.push(server);
    }
    return servers;
}
