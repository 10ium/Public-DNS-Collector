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

        const rawCommentText = parts[4]; // Use raw text for case-insensitive regex matching
        
        // Create a server object for each group of URLs with the same comment
        const server = createServerObject();
        server.provider = currentProvider;
        server.protocols.push('doh'); // DoH is the default for this list
        server.addresses.push(...urls);

        // --- IMPROVED & BUG-FIXED PROTOCOL & ADDRESS DETECTION ---
        // Extract base hostname from the main DoH URL to use as a safe fallback.
        let baseHostname = null;
        try {
            const mainUrl = new URL(urls[0]);
            baseHostname = mainUrl.hostname;
        } catch (e) {
            // Ignore if URL is invalid, though it shouldn't happen with the regex above.
        }

        // Handle shared DoT/DoQ addresses (e.g., "DoT/DoQ: dns.example.com")
        const sharedMatch = rawCommentText.match(/(?:DoT\/DoQ|DoQ\/DoT)\s*:?\s*([a-zA-Z0-9.-]+(?::\d{1,5})?)/i);
        if (sharedMatch && sharedMatch[1]) {
            const hostname = sharedMatch[1];
            if (!server.protocols.includes('dot')) server.protocols.push('dot');
            server.addresses.push(`tls://${hostname}`);
            if (!server.protocols.includes('doq')) server.protocols.push('doq');
            server.addresses.push(`quic://${hostname}`);
        }

        // Handle individual DoT (DNS-over-TLS)
        if (/\bdot\b/i.test(rawCommentText)) {
            if (!server.protocols.includes('dot')) server.protocols.push('dot');
            // Try to find an explicitly defined address first
            const dotMatch = rawCommentText.match(/DoT\s*(?:\(|`|:)\s*([a-zA-Z0-9.-]+(?::\d{1,5})?)/i);
            if (dotMatch && dotMatch[1]) {
                server.addresses.push(`tls://${dotMatch[1]}`);
            } else if (baseHostname && !sharedMatch) { // Fallback to the base hostname if no explicit or shared address found
                server.addresses.push(`tls://${baseHostname}`);
            }
        }
        
        // Handle individual DoQ (DNS-over-QUIC)
        if (/\bdoq\b/i.test(rawCommentText)) {
            if (!server.protocols.includes('doq')) server.protocols.push('doq');
            // Try to find an explicitly defined address first
            const doqMatch = rawCommentText.match(/DoQ\s*(?:\(|`|:)\s*([a-zA-Z0-9.-]+(?::\d{1,5})?)/i);
            if (doqMatch && doqMatch[1]) {
                server.addresses.push(`quic://${doqMatch[1]}`);
            } else if (baseHostname && !sharedMatch) { // Fallback to the base hostname if no explicit or shared address found
                server.addresses.push(`quic://${baseHostname}`);
            }
        }

        // Handle DoH3
        if (/\bdoh3\b/i.test(rawCommentText)) {
            if (!server.protocols.includes('doh3')) server.protocols.push('doh3');
        }

        // Handle DNSCrypt (often includes full sdns:// URIs)
        if (/\bdnscrypt\b/i.test(rawCommentText)) {
            if (!server.protocols.includes('dnscrypt')) server.protocols.push('dnscrypt');
            const dnsCryptMatches = rawCommentText.match(/sdns:\/\/[^\s`)]+/g);
            if (dnsCryptMatches) {
                server.addresses.push(...dnsCryptMatches);
            }
        }
        
        // Ensure addresses and protocols are unique before proceeding
        server.addresses = [...new Set(server.addresses)];
        server.protocols = [...new Set(server.protocols)];

        // Infer filters by searching for keywords in the comment text and URLs
        const commentText = rawCommentText.toLowerCase(); // Lowercase for keyword matching
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
