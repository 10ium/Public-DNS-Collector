import { createServerObject } from '../utils.js';

/**
 * Parses the content from the paulmillr/encrypted-dns source.
 * The source is a Markdown file with a table of providers.
 * NOTE: This parser is simplified and makes assumptions based on provider names
 * as the actual DoH/DoT URLs are not directly available in the table.
 * @param {string} content The raw Markdown content.
 * @returns {Array<object>} A list of server objects.
 */
export function parsePaulmillr(content) {
    const servers = [];
    const lines = content.split('\n');
    let inTable = false;

    for (const line of lines) {
        if (line.startsWith('| Name')) {
            inTable = true;
            continue;
        }
        if (!inTable || !line.startsWith('|')) continue;

        const parts = line.split('|').map(p => p.trim());
        if (parts.length < 5 || parts[1].includes('---') || parts[1] === '') continue;

        const server = createServerObject();
        server.provider = parts[1].replace(/\[([^\]]+)\]\([^\)]+\)/, '$1');

        // Infer protocols from the 'Install' columns' content
        const installLinks = (parts[4] + parts[5]).toLowerCase();
        if (installLinks.includes('https')) server.protocols.push('doh');
        if (installLinks.includes('tls')) server.protocols.push('dot');

        // This is a placeholder since exact addresses aren't directly in the table.
        // We rely on other, more detailed sources to provide the actual addresses for these common providers.
        // This parser primarily helps in identifying filtering rules for known providers.
        const providerLower = server.provider.toLowerCase();
        if (providerLower.includes('adguard')) server.addresses.push('dns.adguard.com');
        else if (providerLower.includes('cloudflare')) server.addresses.push('1.1.1.1');
        else if (providerLower.includes('google')) server.addresses.push('dns.google');
        else if (providerLower.includes('quad9')) server.addresses.push('dns.quad9.net');
        else if (providerLower.includes('opendns')) server.addresses.push('doh.opendns.com');
        
        // If we can't map to a known address, we can't use this entry.
        if (server.addresses.length === 0) continue;

        const censorship = parts[3].toLowerCase();
        server.filters.unfiltered = censorship.includes('no');

        // Infer detailed filters from the provider's name and notes
        const nameAndNotes = (server.provider + " " + parts[4]).toLowerCase();
        if (nameAndNotes.includes('family')) server.filters.family = true;
        if (nameAndNotes.includes('adblock') || nameAndNotes.includes('ads') || (censorship.includes('yes') && !nameAndNotes.includes('family'))) {
            server.filters.ads = true;
        }
        if (nameAndNotes.includes('malware') || nameAndNotes.includes('security') || nameAndNotes.includes('protected') || nameAndNotes.includes('phishing')) {
            server.filters.malware = true;
        }

        servers.push(server);
    }
    return servers;
}
