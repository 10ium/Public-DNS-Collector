import { JSDOM } from 'jsdom';
import { createServerObject } from '../utils.js';

/**
 * Parses the content from the dnsprivacy.org source.
 * The source is an HTML page with tables for DoT and DoH resolvers.
 * @param {string} content The raw HTML content.
 * @returns {Array<object>} A list of server objects.
 */
export function parseDnsPrivacyOrg(content) {
    const servers = [];
    const dom = new JSDOM(content);
    const document = dom.window.document;
    const providerMap = new Map();

    // Helper to get or create a server object from the map
    const getOrCreateServer = (providerName) => {
        if (!providerMap.has(providerName)) {
            const newServer = createServerObject();
            newServer.provider = providerName;
            providerMap.set(providerName, newServer);
        }
        return providerMap.get(providerName);
    };

    // --- Process DNS-over-TLS (DoT) Table ---
    const dotHeader = Array.from(document.querySelectorAll('h3')).find(h => h.textContent.includes('DNS-over-TLS (DoT)'));
    if (dotHeader) {
        let dotTable = dotHeader.nextElementSibling;
        while (dotTable && dotTable.tagName !== 'TABLE') {
            dotTable = dotTable.nextElementSibling;
        }

        if (dotTable) {
            const rows = dotTable.querySelectorAll('tbody tr');
            rows.forEach(row => {
                const cells = row.querySelectorAll('td');
                if (cells.length < 5) return;

                const providerName = cells[0].textContent.trim();
                const server = getOrCreateServer(providerName);
                
                server.protocols.push('dot');

                const ips = cells[1].textContent.trim().split(/\s*or\s*|\s+/).filter(Boolean);
                const hostname = cells[3].textContent.trim();
                
                if (hostname && !hostname.toLowerCase().includes('various')) server.addresses.push(hostname);
                server.addresses.push(...ips);
                
                const notes = cells[5].textContent.toLowerCase();
                if (notes.includes('filter')) server.filters.ads = true;
                if (notes.includes('malware')) server.filters.malware = true;
                if (notes.includes('family')) server.filters.family = true;
                if (notes.includes('doh')) server.protocols.push('doh'); // Note may indicate DoH support
            });
        }
    }

    // --- Process DNS-over-HTTPS (DoH) Table ---
    const dohHeader = Array.from(document.querySelectorAll('h3')).find(h => h.textContent.includes('DNS-over-HTTPS (DoH)'));
    if (dohHeader) {
        let dohTable = dohHeader.nextElementSibling;
        while (dohTable && dohTable.tagName !== 'TABLE') {
            dohTable = dohTable.nextElementSibling;
        }
        
        if (dohTable) {
            const rows = dohTable.querySelectorAll('tbody tr');
            rows.forEach(row => {
                const cells = row.querySelectorAll('td');
                if (cells.length < 3) return;

                const providerName = cells[0].textContent.trim();
                const server = getOrCreateServer(providerName);

                server.protocols.push('doh');

                const urls = (cells[1].textContent.match(/https:\/\/[^\s<]+/g) || []);
                server.addresses.push(...urls);

                const notes = cells[2].textContent.toLowerCase();
                if (notes.includes('filter')) server.filters.ads = true;
                if (notes.includes('malware')) server.filters.malware = true;
                if (notes.includes('family')) server.filters.family = true;
            });
        }
    }

    // Finalize and return the list of servers
    for (const server of providerMap.values()) {
        // Deduplicate addresses and protocols
        server.addresses = [...new Set(server.addresses)];
        server.protocols = [...new Set(server.protocols)];

        if (!server.filters.ads && !server.filters.malware && !server.filters.family) {
            server.filters.unfiltered = true;
        }
        server.features.dnssec = true; // Most on this list support it

        if (server.addresses.length > 0) {
            servers.push(server);
        }
    }

    return servers;
}
