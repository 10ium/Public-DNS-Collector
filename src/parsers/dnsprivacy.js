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

    const mainContent = document.querySelector('#body-inner');
    if (!mainContent) {
        console.warn('  ⚠️ [DNSPrivacy Parser] کانتینر اصلی محتوا (#body-inner) پیدا نشد.');
        return [];
    }
    
    const allTables = mainContent.querySelectorAll('table');
    allTables.forEach(table => {
        const headers = Array.from(table.querySelectorAll('thead th, tr.header th')).map(th => th.textContent.toLowerCase().replace(/\s+/g, ' ').trim());
        
        const isDoTTable = headers.some(h => h.includes('hostname for tls'));
        if (isDoTTable) {
            const rows = table.querySelectorAll('tbody tr');
            rows.forEach(row => {
                const cells = row.querySelectorAll('td');
                if (cells.length < 6) return;
                const providerName = cells[0].textContent.trim();
                const ipsText = cells[1].textContent.trim();
                const hostnameText = cells[3].textContent.trim();
                
                if (!providerName || hostnameText.toLowerCase().includes('various')) return;
                
                const server = getOrCreateServer(providerName);
                if (!server.protocols.includes('dot')) server.protocols.push('dot');

                const ips = ipsText.split(/\s*or\s*|\s+/).filter(Boolean);
                if (hostnameText) server.addresses.push(hostnameText);
                server.addresses.push(...ips);
                
                const notes = cells[5].textContent.toLowerCase();
                if (notes.includes('filter')) server.filters.ads = true;
                if (notes.includes('dns-over-https is also available') || notes.includes('it also does doh')) {
                    if (!server.protocols.includes('doh')) server.protocols.push('doh');
                }
            });
        }

        const isDoHTable = headers.includes('url') && headers.includes('notes');
        if (isDoHTable) {
            const rows = table.querySelectorAll('tbody tr');
            rows.forEach(row => {
                const cells = row.querySelectorAll('td');
                if (cells.length < 2) return;
                const providerName = cells[0].textContent.trim();
                const urlText = cells[1].textContent.trim();
                if (!providerName || urlText.toLowerCase().includes('various')) return;

                const server = getOrCreateServer(providerName);
                if (!server.protocols.includes('doh')) server.protocols.push('doh');
                
                const urls = (urlText.match(/https:\/\/[^\s<]+/g) || []);
                server.addresses.push(...urls);

                const notes = (cells[2] ? cells[2].textContent : '').toLowerCase();
                if (notes.includes('filter')) server.filters.ads = true;
            });
        }
    });

    for (const server of providerMap.values()) {
        server.addresses = [...new Set(server.addresses.filter(Boolean))];
        server.protocols = [...new Set(server.protocols)];
        if (!server.filters.ads && !server.filters.malware && !server.filters.family) server.filters.unfiltered = true;
        server.features.dnssec = true;
        server.features.no_log = true;
        if (server.addresses.length > 0) servers.push(server);
    }

    return servers;
}
