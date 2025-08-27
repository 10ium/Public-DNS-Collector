import { createServerObject } from '../utils.js';

/**
 * Parses the content from the blacklanternsecurity source.
 * The source is a simple text file with a list of IPv4 addresses.
 * @param {string} content The raw text content.
 * @returns {Array<object>} A list containing a single server object with all addresses.
 */
export function parseBlacklantern(content) {
    const servers = [];
    
    // Split by newline, trim whitespace, and filter out empty lines
    const addresses = content.split('\n')
        .map(line => line.trim())
        .filter(line => /^\d{1,3}(\.\d{1,3}){3}$/.test(line));

    if (addresses.length > 0) {
        const server = createServerObject();
        server.provider = 'Blacklantern Security';
        server.addresses = addresses;
        
        // This source provides only plain DNS IPs, so no encrypted protocols are set.
        // The main build script will categorize these into the ipv4 list.
        server.filters.unfiltered = true; // Assume unfiltered

        servers.push(server);
    }
    
    return servers;
}
