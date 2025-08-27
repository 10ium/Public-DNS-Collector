import { createServerObject } from '../utils.js';

/**
 * Parses the content from the MutinSA Gist source.
 * The source is a Markdown file with a table of public recursive name servers.
 * @param {string} content The raw Markdown content.
 * @returns {Array<object>} A list of server objects.
 */
export function parseMutinSA(content) {
    const servers = [];
    const lines = content.split('\n');
    let inDnsTable = false;
    
    // We will process the tables and the detailed sections below them
    const ipv4Map = new Map();
    const ipv6Map = new Map();

    for (const line of lines) {
        if (line.startsWith('|    IPv4 Addr')) {
            inDnsTable = true;
            continue;
        }
        if (line.startsWith('# DNS64:')) {
            inDnsTable = false; // Stop processing the first table
        }
        if (!inDnsTable || !line.startsWith('|')) continue;

        const parts = line.split('|').map(p => p.trim());
        if (parts.length < 8 || parts[1].includes('---')) continue;

        const ipv4 = parts[1];
        const ipv6 = parts[2];
        const provider = parts[7];
        const svc = parts[6].toLowerCase();

        if (ipv4) ipv4Map.set(ipv4, { provider, svc });
        if (ipv6) ipv6Map.set(ipv6, { provider, svc });
    }
    
    const combinedServers = new Map();

    // Combine IPv4 addresses
    for (const [address, data] of ipv4Map.entries()) {
        if (!combinedServers.has(data.provider)) {
            const newServer = createServerObject();
            newServer.provider = data.provider;
            combinedServers.set(data.provider, newServer);
        }
        const server = combinedServers.get(data.provider);
        server.addresses.push(address);
        
        if(data.svc.includes('doh') || data.svc.includes('cloudflare') || data.svc.includes('google')) server.protocols.push('doh');
        if(data.svc.includes('dot')) server.protocols.push('dot');
    }

    // Combine IPv6 addresses
    for (const [address, data] of ipv6Map.entries()) {
        if (!combinedServers.has(data.provider)) {
             const newServer = createServerObject();
            newServer.provider = data.provider;
            combinedServers.set(data.provider, newServer);
        }
        const server = combinedServers.get(data.provider);
        server.addresses.push(address);
        server.features.ipv6 = true;

        if(data.svc.includes('doh') || data.svc.includes('cloudflare') || data.svc.includes('google')) server.protocols.push('doh');
        if(data.svc.includes('dot')) server.protocols.push('dot');
    }

    // Finalize server objects and assume unfiltered for this source
    for (const server of combinedServers.values()) {
        server.filters.unfiltered = true;
        server.features.dnssec = true; // A common feature for major providers
        servers.push(server);
    }

    return servers;
}
