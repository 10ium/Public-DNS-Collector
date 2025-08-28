import { JSDOM } from 'jsdom';
import { createServerObject } from '../utils.js';

/**
 * Parses the content from the dnsprivacy.org source.
 * This is a robust, context-aware parser that understands the table structure
 * to correctly assign protocols (DoT, DoH, DoQ) to addresses, whether they have prefixes or not.
 * It preserves all prefixes and ports.
 * @param {string} content The raw HTML content.
 * @returns {Array<object>} A list of server objects.
 */
export function parseDnsPrivacyOrg(content) {
    const servers = [];
    const dom = new JSDOM(content);
    const document = dom.window.document;
    const providerMap = new Map();

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
        const headers = Array.from(table.querySelectorAll('thead th, tr.header th')).map(th => th.textContent.toLowerCase().replace(/\s+/g, ' ').trim());
        
        // --- Context-Aware Logic for DoT Tables ---
        const isDoTTable = headers.some(h => h.includes('hostname for tls') || h.includes('dns over tls'));
        if (isDoTTable) {
            const rows = table.querySelectorAll('tbody tr');
            rows.forEach(row => {
                const cells = row.querySelectorAll('td');
                if (cells.length < 2) return;
                
                const providerName = cells[0].textContent.trim();
                const combinedAddressesText = Array.from(cells).map(c => c.textContent).join(' ');
                
                if (!providerName || providerName.toLowerCase().includes('various')) return;
                
                const server = getOrCreateServer(providerName);
                if (!server.protocols.includes('dot')) server.protocols.push('dot');

                const addressRegex = /([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+(?::\d+)?)|(\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?)|(\[?[a-fA-F0-9:]+\]?(?::\d+)?)/g;
                const foundAddresses = combinedAddressesText.match(addressRegex) || [];
                
                foundAddresses.forEach(addr => {
                    if (!server.addresses.includes(addr)) server.addresses.push(addr);
                });

                // Also check for explicit DoH/DoQ mentions in notes
                const notes = (cells[5] ? cells[5].textContent : '').toLowerCase();
                if (notes.includes('doh') || notes.includes('dns-over-https')) {
                    if (!server.protocols.includes('doh')) server.protocols.push('doh');
                }
                const quicAddresses = notes.match(/quic:\/\/[^\s<,)]+/g) || [];
                if(quicAddresses.length > 0) {
                    if (!server.protocols.includes('doq')) server.protocols.push('doq');
                    quicAddresses.forEach(addr => {
                        if (!server.addresses.includes(addr)) server.addresses.push(addr);
                    });
                }
            });
        }

        // --- Context-Aware Logic for DoH Tables ---
        const isDoHTable = headers.includes('url') && headers.includes('provider');
        if (isDoHTable) {
            const rows = table.querySelectorAll('tbody tr');
            rows.forEach(row => {
                const cells = row.querySelectorAll('td');
                if (cells.length < 2) return;
                const providerName = cells[0].textContent.trim();
                const urlText = cells[1].textContent.trim();
                if (!providerName || providerName.toLowerCase().includes('various')) return;

                const server = getOrCreateServer(providerName);
                if (!server.protocols.includes('doh')) server.protocols.push('doh');
                
                const urls = (urlText.match(/https:\/\/[^\s<]+/g) || []);
                urls.forEach(url => {
                    if (!server.addresses.includes(url)) server.addresses.push(url);
                });
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

    if (servers.length === 0) {
        console.warn("  ⚠️ [هشدار DNSPrivacyOrg] هیچ سرور DNS معتبری از صفحه DNSPrivacyOrg یافت نشد.");
    }

    return servers;
}
