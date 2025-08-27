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
    
    // --- Process DNS-over-TLS (DoT) Table using its specific anchor ID ---
    const dotHeader = mainContent.querySelector('#dns-over-tls-dot');
    if (dotHeader) {
        let dotTable = dotHeader.nextElementSibling;
        while (dotTable && dotTable.tagName !== 'DIV' && !dotTable.querySelector('table')) {
            dotTable = dotTable.nextElementSibling;
        }
        
        const table = dotTable ? dotTable.querySelector('table') : null;
        if (table) {
            const rows = table.querySelectorAll('tbody tr');
            rows.forEach(row => {
                const cells = row.querySelectorAll('td');
                if (cells.length < 6) return; // Expecting at least 6 cells in DoT table rows
                const providerName = cells[0].textContent.trim();
                if (!providerName) return;
                
                const server = getOrCreateServer(providerName);
                if (!server.protocols.includes('dot')) server.protocols.push('dot');

                const ips = cells[1].textContent.trim().split(/\s*or\s*|\s+/).filter(Boolean);
                const hostname = cells[3].textContent.trim();
                
                if (hostname && !hostname.toLowerCase().includes('various')) server.addresses.push(hostname);
                server.addresses.push(...ips);
                
                const notes = cells[5].textContent.toLowerCase();
                if (notes.includes('filter')) server.filters.ads = true;
                if (notes.includes('dns-over-https is also available') || notes.includes('it also does doh')) {
                    if (!server.protocols.includes('doh')) server.protocols.push('doh');
                }
            });
        }
    }

    // --- Process DNS-over-HTTPS (DoH) Table using its specific anchor ID ---
    const dohHeader = mainContent.querySelector('#dns-over-https-doh');
    if (dohHeader) {
        let dohTable = dohHeader.nextElementSibling;
        while (dohTable && dohTable.tagName !== 'DIV' && !dohTable.querySelector('table')) {
            dohTable = dohTable.nextElementSibling;
        }
        
        const table = dohTable ? dohTable.querySelector('table') : null;
        if (table) {
            const rows = table.querySelectorAll('tbody tr');
            rows.forEach(row => {
                const cells = row.querySelectorAll('td');
                if (cells.length < 2) return; // Simplified check for DoH table
                const providerName = cells[0].textContent.trim();
                if (!providerName) return;

                const server = getOrCreateServer(providerName);
                if (!server.protocols.includes('doh')) server.protocols.push('doh');
                
                const urls = (cells[1].textContent.match(/https:\/\/[^\s<]+/g) || []);
                server.addresses.push(...urls);

                const notes = (cells[2] ? cells[2].textContent : '').toLowerCase();
                if (notes.includes('filter')) server.filters.ads = true;
            });
        }
    }

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
