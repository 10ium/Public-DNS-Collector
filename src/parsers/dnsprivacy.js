import { JSDOM } from 'jsdom';
import { createServerObject } from '../utils.js';

/**
 * Parses filter types from provider name and notes.
 * @param {string} providerName - The name of the provider, e.g., "Quad9 'secure'".
 * @param {string} notesText - The text content from the notes column.
 * @returns {object} An object representing the detected filters.
 */
function parseFilters(providerName, notesText) {
    const filters = { ads: false, malware: false, family: false };
    const combinedText = `${providerName.toLowerCase()} ${notesText.toLowerCase()}`;

    if (combinedText.includes('ad blocking') || providerName.toLowerCase().includes('adguard')) {
        filters.ads = true;
    }
    if (combinedText.includes('secure') || combinedText.includes('protective') || combinedText.includes('security')) {
        filters.malware = true;
    }
    if (combinedText.includes('family') || combinedText.includes('child protective') || combinedText.includes('adult')) {
        filters.family = true;
    }
    return filters;
}

/**
 * Parses the content from the dnsprivacy.org source.
 * This version creates separate server objects for each protocol (DoT, DoH, etc.)
 * to prevent address mixing.
 * @param {string} content The raw HTML content.
 * @returns {Array<object>} A list of server objects.
 */
export function parseDnsPrivacyOrg(content) {
    const servers = [];
    const dom = new JSDOM(content);
    const document = dom.window.document;
    
    const mainContent = document.querySelector('#body-inner');
    if (!mainContent) {
        return [];
    }
    
    const placeholderRegex = /various|see the|website/i;

    // --- 1. Parse DoT Table ---
    const dotTable = Array.from(mainContent.querySelectorAll('table')).find(table => 
        Array.from(table.querySelectorAll('th')).some(th => th.textContent.includes('Hostname for TLS'))
    );

    if (dotTable) {
        const rows = dotTable.querySelectorAll('tbody tr');
        rows.forEach(row => {
            const cells = Array.from(row.querySelectorAll('td'));
            if (cells.length < 5) return;

            const providerName = cells[0]?.textContent.trim();
            const hostnameText = cells[3]?.textContent.trim();
            const notesText = cells[5]?.textContent.trim() || '';

            if (!providerName || !hostnameText || placeholderRegex.test(hostnameText)) return;
            
            const server = createServerObject();
            server.provider = providerName.replace(/'secure'|'insecure'|'unfiltered'/, '').trim();
            server.protocols.push('dot');
            server.addresses.push(`tls://${hostnameText}`);
            
            const detectedFilters = parseFilters(providerName, notesText);
            server.filters = { ...server.filters, ...detectedFilters };
            
            servers.push(server);
        });
    }

    // --- 2. Parse DoH Table ---
    const dohTable = Array.from(mainContent.querySelectorAll('table')).find(table => 
        Array.from(table.querySelectorAll('th')).some(th => th.textContent.trim().toLowerCase() === 'url')
    );

    if (dohTable) {
        const rows = dohTable.querySelectorAll('tbody tr');
        rows.forEach(row => {
            const cells = Array.from(row.querySelectorAll('td'));
            if (cells.length < 2) return;

            const providerName = cells[0]?.textContent.trim();
            const urlText = cells[1]?.textContent.trim();
            const notesText = cells[2]?.textContent.trim() || '';

            if (!providerName || placeholderRegex.test(urlText)) return;
            
            const urls = (urlText.match(/https:\/\/[^\s<]+/g) || []);
            if (urls.length > 0) {
                const server = createServerObject();
                server.provider = providerName.replace(/'secure'|'insecure'|'unfiltered'/, '').trim();
                server.protocols.push('doh');
                server.addresses.push(...urls);
                
                const detectedFilters = parseFilters(providerName, notesText);
                server.filters = { ...server.filters, ...detectedFilters };
                
                servers.push(server);
            }
        });
    }
    
    // --- 3. Parse DoQ Section ---
    const doqHeader = Array.from(document.querySelectorAll('h2, h3')).find(h => h.textContent.includes('DNS-over-QUIC (DoQ)'));
    if (doqHeader) {
        let nextElement = doqHeader.nextElementSibling;
        if (nextElement && nextElement.textContent.toLowerCase().includes('adguard')) {
            const server = createServerObject();
            server.provider = 'Adguard';
            server.protocols.push('doq');
            server.addresses.push('quic://dns.adguard-dns.com');
            // Adguard's default is ad-blocking and malware protection
            server.filters.ads = true;
            server.filters.malware = true;
            servers.push(server);
        }
    }

    // --- 4. Final Cleanup ---
    return servers.map(server => {
        const hasAnyFilter = server.filters.ads || server.filters.malware || server.filters.family;
        if (!hasAnyFilter) {
            server.filters.unfiltered = true;
        }

        server.features.dnssec = true;
        server.features.no_log = true;
        
        return server;
    }).filter(server => server.addresses.length > 0);
}
