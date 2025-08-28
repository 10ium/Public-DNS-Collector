import { JSDOM } from 'jsdom';
import { createServerObject } from '../utils.js';

/**
 * Parses filter types from provider name and notes.
 * @param {string} providerName - The name of the provider, e.g., "Quad9 'secure'".
 * @param {string} notesText - The text content from the notes column.
 * @returns {object} An object representing the detected filters.
 */
function parseFilters(providerName, notesText) {
    const filters = {
        ads: false,
        malware: false,
        family: false,
        unfiltered: false,
    };
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
    if (combinedText.includes('insecure') || combinedText.includes('unfiltered')) {
        filters.unfiltered = true;
    }

    return filters;
}


/**
 * Parses the content from the dnsprivacy.org source.
 * The source is an HTML page with tables for DoT, DoH, and a section for DoQ resolvers.
 * @param {string} content The raw HTML content.
 * @returns {Array<object>} A list of server objects.
 */
export function parseDnsPrivacyOrg(content) {
    const servers = [];
    const dom = new JSDOM(content);
    const document = dom.window.document;
    const providerMap = new Map();

    const getOrCreateServer = (providerName) => {
        // Clean up name for consistent grouping, e.g., "Quad9 'secure'" -> "Quad9"
        const cleanedName = providerName.replace(/'secure'|'insecure'|'unfiltered'/, '').trim();
        if (!providerMap.has(cleanedName)) {
            const newServer = createServerObject();
            newServer.provider = cleanedName;
            providerMap.set(cleanedName, newServer);
        }
        return providerMap.get(cleanedName);
    };

    const mainContent = document.querySelector('#body-inner');
    if (!mainContent) {
        return [];
    }

    // --- 1. Parse DoT and DoH Tables ---
    const allTables = mainContent.querySelectorAll('table');
    allTables.forEach(table => {
        const headers = Array.from(table.querySelectorAll('thead th, tr.header th')).map(th => th.textContent.toLowerCase().replace(/\s+/g, ' ').trim());

        // DoT Table Parsing
        const isDoTTable = headers.some(h => h.includes('hostname for tls'));
        if (isDoTTable) {
            const rows = table.querySelectorAll('tbody tr');
            rows.forEach(row => {
                const cells = Array.from(row.querySelectorAll('td'));
                if (cells.length < 5) return;
                
                const providerName = cells[0]?.textContent.trim();
                const hostnameText = cells[3]?.textContent.trim();
                const notesText = cells[5]?.textContent.trim() || '';

                if (!providerName || !hostnameText || hostnameText.toLowerCase().includes('various')) return;

                const server = getOrCreateServer(providerName);
                if (!server.protocols.includes('dot')) server.protocols.push('dot');

                // Add standardized DoT address with tls:// prefix
                server.addresses.push(`tls://${hostnameText}`);

                // Detect filters from provider name and notes
                const detectedFilters = parseFilters(providerName, notesText);
                server.filters.ads = server.filters.ads || detectedFilters.ads;
                server.filters.malware = server.filters.malware || detectedFilters.malware;
                server.filters.family = server.filters.family || detectedFilters.family;
                server.filters.unfiltered = server.filters.unfiltered || detectedFilters.unfiltered;
                
                // Check if notes mention DoH availability
                if (notesText.toLowerCase().includes('it also does doh')) {
                    if (!server.protocols.includes('doh')) server.protocols.push('doh');
                }
            });
        }

        // DoH Table Parsing
        const isDoHTable = headers.includes('url') && headers.includes('notes');
        if (isDoHTable) {
            const rows = table.querySelectorAll('tbody tr');
            rows.forEach(row => {
                const cells = Array.from(row.querySelectorAll('td'));
                if (cells.length < 2) return;

                const providerName = cells[0]?.textContent.trim();
                const urlText = cells[1]?.textContent.trim();
                const notesText = cells[2]?.textContent.trim() || '';
                
                if (!providerName || urlText.toLowerCase().includes('various')) return;

                const server = getOrCreateServer(providerName);
                if (!server.protocols.includes('doh')) server.protocols.push('doh');
                
                const urls = (urlText.match(/https:\/\/[^\s<]+/g) || []);
                server.addresses.push(...urls);

                const detectedFilters = parseFilters(providerName, notesText);
                server.filters.ads = server.filters.ads || detectedFilters.ads;
                server.filters.malware = server.filters.malware || detectedFilters.malware;
                server.filters.family = server.filters.family || detectedFilters.family;
            });
        }
    });

    // --- 2. Parse DoQ Section ---
    const doqHeader = Array.from(document.querySelectorAll('h2, h3')).find(h => h.textContent.includes('DNS-over-QUIC (DoQ)'));
    if (doqHeader) {
        let nextElement = doqHeader.nextElementSibling;
        if (nextElement && nextElement.textContent.toLowerCase().includes('adguard')) {
            const server = getOrCreateServer('Adguard');
            if (!server.protocols.includes('doq')) server.protocols.push('doq');
            // Add the standard AdGuard default DoQ endpoint
            server.addresses.push('quic://dns.adguard-dns.com');
        }
    }

    // --- 3. Finalize and Clean Up Server List ---
    for (const server of providerMap.values()) {
        server.addresses = [...new Set(server.addresses.filter(Boolean))];
        server.protocols = [...new Set(server.protocols.sort())];

        const hasAnyFilter = server.filters.ads || server.filters.malware || server.filters.family;
        
        // If a specific filter is set, 'unfiltered' must be false.
        if (hasAnyFilter) {
            server.filters.unfiltered = false;
        } 
        // If no filters were detected at all, mark it as unfiltered.
        else if (!server.filters.unfiltered) {
            server.filters.unfiltered = true;
        }

        // Assume standard features for these public resolvers
        server.features.dnssec = true;
        server.features.no_log = true;
        
        if (server.addresses.length > 0) {
            servers.push(server);
        }
    }

    return servers;
}
