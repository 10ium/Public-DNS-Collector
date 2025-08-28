import { JSDOM } from 'jsdom';
import { createServerObject } from '../utils.js';

/**
 * Parses the content from the dnsprivacy.org source using a robust, context-aware approach.
 * This parser identifies the protocol context (DoT, DoH, DoQ) from page headings
 * and then processes the subsequent tables with specific column-aware logic.
 * It correctly extracts addresses from their designated columns and preserves prefixes/ports.
 * @param {string} content The raw HTML content.
 * @returns {Array<object>} A list of server objects.
 */
export function parseDnsPrivacyOrg(content) {
    const servers = [];
    const dom = new JSDOM(content);
    const document = dom.window.document;
    const providerMap = new Map();

    /**
     * Retrieves an existing server object for a provider or creates a new one.
     * It cleans the provider name by removing suffixes like '(secure)' or '(insecure)'.
     * @param {string} providerName - The raw name of the provider.
     * @returns {object} The server object.
     */
    const getOrCreateServer = (providerName) => {
        // Cleans up names like "Quad9 'secure'" to just "Quad9"
        const cleanedName = providerName.replace(/'(secure|insecure)'/g, '').trim();
        if (!providerMap.has(cleanedName)) {
            const newServer = createServerObject();
            newServer.provider = cleanedName;
            providerMap.set(cleanedName, newServer);
        }
        return providerMap.get(cleanedName);
    };

    const mainContent = document.querySelector('#body-inner');
    if (!mainContent) {
        console.warn("  ⚠️ [DNSPrivacyOrg] Main content section not found.");
        return [];
    }

    let currentProtocol = null; // To track context: 'dot', 'doh', or 'doq'

    // Iterate through all child nodes of the main content area to read headings and tables in order.
    mainContent.childNodes.forEach(node => {
        // 1. Determine the protocol context from H3 headings
        if (node.tagName === 'H3') {
            const headingText = node.textContent.toLowerCase();
            if (headingText.includes('dns-over-tls') || headingText.includes('dot')) {
                currentProtocol = 'dot';
            } else if (headingText.includes('dns-over-https') || headingText.includes('doh')) {
                currentProtocol = 'doh';
            } else if (headingText.includes('dns-over-quic') || headingText.includes('doq')) {
                currentProtocol = 'doq';
            }
        }

        // 2. Process tables based on the current protocol context
        if (node.tagName === 'TABLE') {
            const headerCells = Array.from(node.querySelectorAll('thead th, tr.header th'));
            const headers = headerCells.map(th => th.textContent.toLowerCase().trim());
            
            // Map headers to their column index for precise data extraction
            const headerMap = {
                provider: headers.indexOf('hosted by'),
                ips: headers.indexOf('ip addresses'),
                hostname: headers.indexOf('hostname for tls authentication'),
                url: headers.indexOf('url'),
                notes: headers.indexOf('notes'),
            };

            const rows = node.querySelectorAll('tbody tr');
            rows.forEach(row => {
                const cells = Array.from(row.querySelectorAll('td'));
                if (cells.length < 2) return;

                const providerName = cells[headerMap.provider]?.textContent.trim();
                if (!providerName || providerName.toLowerCase().includes('various')) return;

                const server = getOrCreateServer(providerName);
                
                // --- DoT Processing Logic ---
                if (currentProtocol === 'dot' && headerMap.ips !== -1) {
                    if (!server.protocols.includes('dot')) server.protocols.push('dot');
                    
                    // Extract from "IP addresses" and "Hostname for TLS" columns specifically
                    const ipText = cells[headerMap.ips]?.textContent || '';
                    const hostnameText = cells[headerMap.hostname]?.textContent || '';
                    const combinedText = `${ipText} ${hostnameText}`;

                    const addresses = combinedText.match(/(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}|(?:\d{1,3}\.){3}\d{1,3}|(?:[a-fA-F0-9:]+){2,}/g) || [];
                    addresses.forEach(addr => {
                        if (!server.addresses.includes(addr)) server.addresses.push(addr);
                    });

                    // Check notes for additional protocols like DoH/DoQ
                    const notesText = cells[headerMap.notes]?.textContent.toLowerCase() || '';
                    if (notesText.includes('doh') || notesText.includes('dns-over-https')) {
                        if (!server.protocols.includes('doh')) server.protocols.push('doh');
                    }
                    if (notesText.includes('doq') || notesText.includes('dns-over-quic')) {
                        if (!server.protocols.includes('doq')) server.protocols.push('doq');
                    }
                }

                // --- DoH Processing Logic ---
                if (currentProtocol === 'doh' && headerMap.url !== -1) {
                    if (!server.protocols.includes('doh')) server.protocols.push('doh');
                    
                    // Extract URLs specifically from the "URL" column
                    const urlText = cells[headerMap.url]?.textContent || '';
                    const urls = urlText.match(/https:\/\/[^\s<,)]+/g) || [];
                    urls.forEach(url => {
                        if (!server.addresses.includes(url)) server.addresses.push(url);
                    });
                }
            });
        }
    });

    // 3. Finalize and filter the collected server data
    for (const server of providerMap.values()) {
        server.addresses = [...new Set(server.addresses.filter(Boolean))];
        server.protocols = [...new Set(server.protocols.filter(Boolean))];

        // Default assumptions if no specific filter info is found
        if (!server.filters.ads && !server.filters.malware && !server.filters.family) {
            server.filters.unfiltered = true;
        }
        
        // Default features for this source
        server.features.dnssec = true;
        server.features.no_log = true;
        
        if (server.addresses.length > 0 && server.protocols.length > 0) {
            servers.push(server);
        }
    }

    if (servers.length === 0) {
        console.warn("  ⚠️ [DNSPrivacyOrg] No valid DNS servers were found.");
    }

    return servers;
}
