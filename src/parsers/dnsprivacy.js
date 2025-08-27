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

    const getOrCreateServer = (providerName) => {
        const cleanedName = providerName.replace(/'secure'|'insecure'/, '').trim();
        if (!providerMap.has(cleanedName)) {
            const newServer = createServerObject();
            newServer.provider = cleanedName;
            providerMap.set(cleanedName, newServer);
        }
        return providerMap.get(cleanedName);
    };

    // --- Final Corrected Logic: Target the main content container first ---
    const mainContent = document.querySelector('#body-inner');
    if (!mainContent) {
        console.warn('  ⚠️ [DNSPrivacy Parser] کانتینر اصلی محتوا (#body-inner) پیدا نشد.');
        return [];
    }
    
    const allTables = mainContent.querySelectorAll('table');
    allTables.forEach(table => {
        const headers = Array.from(table.querySelectorAll('thead th')).map(th => th.textContent.toLowerCase().replace(/\s+/g, ' '));
        
        // Identify and Process DNS-over-TLS (DoT) Table
        const isDoTTable = headers.some(h => h.includes('hostname for tls') && h.includes('authentication'));
        if (isDoTTable) {
            const rows = table.querySelectorAll('tbody tr');
            rows.forEach(row => {
                const cells = row.querySelectorAll('td');
                if (cells.length < 6) return;
                const providerName = cells[0].textContent.trim();
                if (!providerName) return;
                
                const server = getOrCreateServer(providerName);
                server.protocols.push('dot');

                const ips = cells[1].textContent.trim().split(/\s*or\s*|\s+/).filter(Boolean);
                const hostname = cells[3].textContent.trim();
                
                if (hostname && !hostname.toLowerCase().includes('various')) server.addresses.push(hostname);
                server.addresses.push(...ips);
                
                const notes = cells[5].textContent.toLowerCase();
                if (notes.includes('filter')) server.filters.ads = true;
                if (notes.includes('dns-over-https is also available') || notes.includes('it also does doh')) {
                    server.protocols.push('doh');
                }
            });
        }

        // Identify and Process DNS-over-HTTPS (DoH) Table
        const isDoHTable = headers.includes('url') && headers.includes('notes');
        if (isDoHTable) {
            const rows = table.querySelectorAll('tbody tr');
            rows.forEach(row => {
                const cells = row.querySelectorAll('td');
                if (cells.length < 3) return;
                const providerName = cells[0].textContent.trim();
                if (!providerName) return;

                const server = getOrCreateServer(providerName);
                server.protocols.push('doh');
                
                const urls = (cells[1].textContent.match(/https:\/\/[^\s<]+/g) || []);
                server.addresses.push(...urls);

                const notes = cells[2].textContent.toLowerCase();
                if (notes.includes('filter')) server.filters.ads = true;
            });
        }
    });

    for (const server of providerMap.values()) {
        server.addresses = [...new Set(server.addresses.filter(Boolean))];
        server.protocols = [...new Set(server.protocols)];
        if (!server.filters.ads && !server.filters.malware && !server.filters.family) {
            server.filters.unfiltered = true;
        }
        server.features.dnssec = true;
        server.features.no_log = true;
        if (server.addresses.length > 0) {
            servers.push(server);
        }
    }

    return servers;
}
