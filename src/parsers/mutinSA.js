import { createServerObject } from '../utils.js';

/**
 * Parses the content from the MutinSA Gist source.
 * The source is a Markdown file with tables for standard DNS and DNS64 servers.
 * It correctly identifies and categorizes IPv4, IPv6, and DNS64 addresses.
 * @param {string} content The raw Markdown content from the source.
 * @returns {Array<object>} A list of server objects, grouped by provider.
 */
export function parseMutinSA(content) {
    const providerMap = new Map();
    const lines = content.split('\n');

    let currentTable = null; // Can be 'DNS' or 'DNS64'

    for (const line of lines) {
        // Determine which table we are in
        if (line.startsWith('|    IPv4 Addr')) {
            currentTable = 'DNS';
            continue;
        } else if (line.startsWith('|        IPv6 Addr')) {
            // This header is for the DNS64 table
            const isDns64Header = lines[lines.indexOf(line) - 2]?.trim() === '# DNS64:';
            if (isDns64Header) {
                currentTable = 'DNS64';
                continue;
            }
        } else if (line.startsWith('#')) {
            // A new section header means we've exited any table
            currentTable = null;
            continue;
        }

        // Skip lines that are not part of a table we care about
        if (!currentTable || !line.startsWith('|') || line.includes('---')) {
            continue;
        }

        const parts = line.split('|').map(p => p.trim());

        if (currentTable === 'DNS' && parts.length >= 8) {
            const ipv4 = parts[1];
            const ipv6 = parts[2];
            const provider = parts[7];

            if (!provider) continue;

            if (!providerMap.has(provider)) {
                providerMap.set(provider, createServerObject());
                providerMap.get(provider).provider = provider;
            }
            const server = providerMap.get(provider);

            if (ipv4) {
                server.addresses.push(ipv4);
                if (!server.protocols.includes('ipv4')) {
                    server.protocols.push('ipv4');
                }
            }
            if (ipv6) {
                server.addresses.push(ipv6);
                server.features.ipv6 = true;
                if (!server.protocols.includes('ipv6')) {
                    server.protocols.push('ipv6');
                }
            }
        } else if (currentTable === 'DNS64' && parts.length >= 7) {
            const dns64Address = parts[1];
            const provider = parts[6];

            if (!provider || !dns64Address) continue;

            if (!providerMap.has(provider)) {
                providerMap.set(provider, createServerObject());
                providerMap.get(provider).provider = provider;
            }
            const server = providerMap.get(provider);
            
            server.addresses.push(dns64Address);
            server.features.dns64 = true; // Add DNS64 feature flag
            if (!server.protocols.includes('dns64')) {
                server.protocols.push('dns64');
            }
        }
    }

    const servers = [];
    for (const server of providerMap.values()) {
        // General assumptions for these public servers
        server.filters.unfiltered = true;
        server.features.dnssec = true;
        // Remove duplicates just in case
        server.addresses = [...new Set(server.addresses)];
        servers.push(server);
    }

    return servers;
}
