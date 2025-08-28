import { JSDOM } from 'jsdom';
import { createServerObject } from '../utils.js';

/**
 * Parses the content from the dnsprivacy.org source.
 * The source is an HTML page with tables for DoT, DoH, and DoQ resolvers.
 * This parser now correctly extracts DoQ addresses, often found in the 'notes' column,
 * and preserves all address prefixes and ports.
 * @param {string} content The raw HTML content.
 * @returns {Array<object>} A list of server objects.
 */
export function parseDnsPrivacyOrg(content) {
    const servers = [];
    const dom = new JSDOM(content);
    const document = dom.window.document;
    // Use a Map to store servers, keyed by provider name, to aggregate data from different tables.
    const providerMap = new Map();

    // A robust regex to find all kinds of DNS addresses we're interested in.
    const addressRegex = /(https?|tls|quic):\/\/[^\s<,)]+|\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b|\[?[a-fA-F0-9:]+\]?(?::\d+)?|(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?::\d+)?/g;

    /**
     * Helper function to get or create a server object for a given provider name.
     * @param {string} providerName The raw provider name from the table.
     * @returns {object} The server object.
     */
    const getOrCreateServer = (providerName) => {
        const cleanedName = providerName.replace(/^(.*?)(\s*(\(secure\)|\(insecure\)))?$/, '$1').trim();
        if (!providerMap.has(cleanedName)) {
            const newServer = createServerObject();
            newServer.provider = cleanedName;
            providerMap.set(cleanedName, newServer);
        }
        return providerMap.get(cleanedName);
    };

    const mainContent = document.querySelector('#body-inner');
    if (!mainContent) {
        console.warn("  ⚠️ [هشدار DNSPrivacyOrg] بخش اصلی محتوای صفحه پیدا نشد.");
        return [];
    }
    
    const allTables = mainContent.querySelectorAll('table');
    
    allTables.forEach(table => {
        const rows = table.querySelectorAll('tbody tr');
        rows.forEach(row => {
            const cells = Array.from(row.querySelectorAll('td'));
            if (cells.length < 2) return;

            const providerName = cells[0].textContent.trim();
            if (!providerName || providerName.toLowerCase().includes('various')) return;

            const server = getOrCreateServer(providerName);
            
            // Combine text from all cells to find any and all addresses
            const combinedText = cells.map(cell => cell.textContent).join(' ');
            const foundAddresses = combinedText.match(addressRegex) || [];

            foundAddresses.forEach(addr => {
                if (addr.startsWith('https://')) server.protocols.push('doh');
                else if (addr.startsWith('tls://')) server.protocols.push('dot');
                else if (addr.startsWith('quic://')) server.protocols.push('doq');
                
                // Add any non-duplicate, valid address
                if (!server.addresses.includes(addr)) {
                    server.addresses.push(addr);
                }
            });
        });
    });

    // Process the aggregated server data.
    for (const server of providerMap.values()) {
        server.addresses = [...new Set(server.addresses.filter(Boolean))];
        server.protocols = [...new Set(server.protocols)];
        
        // Default filtering status: if no specific filtering is detected, assume unfiltered.
        // Note: This source is less explicit about filtering, so this is a heuristic.
        if (server.addresses.some(addr => addr.toLowerCase().includes('filter'))) {
             server.filters.ads = true;
        }

        if (!server.filters.ads && !server.filters.malware && !server.filters.family) {
            server.filters.unfiltered = true;
        }
        
        server.features.dnssec = true;
        server.features.no_log = true;
        
        if (server.addresses.length > 0) {
            servers.push(server);
        }
    }

    if (servers.length === 0) {
        console.warn("  ⚠️ [هشدار DNSPrivacyOrg] هیچ سرور DNS معتبری از صفحه DNSPrivacyOrg یافت نشد.");
    }

    return servers;
}
