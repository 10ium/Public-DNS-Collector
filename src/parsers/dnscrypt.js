import { createServerObject } from '../utils.js';

/**
 * Parses the content from the DNSCrypt source.
 * The source is now a Markdown file with sections for each provider.
 * @param {string} content The raw Markdown content.
 * @returns {Array<object>} A list of server objects.
 */
export function parseDNSCrypt(content) {
    const servers = [];
    // Split the content by '## ' which marks the beginning of each provider's section.
    // We discard the first element as it's the introductory text.
    const sections = content.split('\n## ').slice(1);

    for (const section of sections) {
        const lines = section.split('\n');
        const providerName = lines[0].trim();
        if (!providerName) continue;
        
        const server = createServerObject();
        server.provider = providerName;
        server.protocols.push('dnscrypt');

        const descriptionLines = [];
        const addresses = [];

        // Separate description lines from address lines
        for (let i = 1; i < lines.length; i++) {
            const line = lines[i].trim();
            if (line.startsWith('sdns://')) {
                addresses.push(line);
            } else if (line) {
                descriptionLines.push(line);
            }
        }
        
        if (addresses.length === 0) continue;
        
        server.addresses = addresses;
        const description = descriptionLines.join(' ').toLowerCase();

        // Infer features and filters from the description text
        if (description.includes('dnssec')) server.features.dnssec = true;
        if (description.includes('no-logging') || description.includes('no logs') || description.includes('no persistent logs')) {
            server.features.no_log = true;
        }
        if (description.includes('ipv6')) server.features.ipv6 = true;
        
        if (description.includes('blocks ads') || description.includes('adblock')) server.filters.ads = true;
        if (description.includes('malware')) server.filters.malware = true;
        if (description.includes('family') || description.includes('adult content blocking')) server.filters.family = true;
        
        // If no specific filter is mentioned, check for non-filtering keywords
        if (description.includes('non-filtering') || description.includes('no filter') || description.includes('uncensored')) {
            server.filters.unfiltered = true;
        }

        // Final fallback: if no filtering information is found at all, assume unfiltered
        if (!server.filters.ads && !server.filters.malware && !server.filters.family && !server.filters.unfiltered) {
            server.filters.unfiltered = true;
        }

        servers.push(server);
    }

    return servers;
}
