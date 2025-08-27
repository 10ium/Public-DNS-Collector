import { JSDOM } from 'jsdom';
import { createServerObject } from '../utils.js';

/**
 * Parses the content from the AdGuard DNS Providers source.
 * The source is an HTML page with a structured layout.
 * This revised parser creates a separate server object for each protocol entry (table row)
 * to prevent cross-contamination of addresses and protocols.
 * @param {string} content The raw HTML content.
 * @returns {Array<object>} A list of server objects.
 */
export function parseAdGuard(content) {
    const servers = [];
    const dom = new JSDOM(content);
    const document = dom.window.document;

    // Regex to strictly match valid addresses within the text
    const addressRegex = /(https:\/\/[^\s`]+)|(tls:\/\/[^\s`]+)|(quic:\/\/[^\s`]+)|(\b\d{1,3}(\.\d{1,3}){3}\b)|(\b[0-9a-fA-F:]*:[0-9a-fA-F:.]+\b)/g;

    const mainContent = document.querySelector('.theme-doc-markdown.markdown');
    if (!mainContent) {
        return [];
    }
    
    const providerHeaders = mainContent.querySelectorAll('h3');
    providerHeaders.forEach(providerHeader => {
        const providerName = providerHeader.textContent.trim().replace(/ DNS$/, '');
        let currentElement = providerHeader.nextElementSibling;
        let lastFilterType = 'default'; // Use 'default' if no h4/h5 is found before a table

        while (currentElement && currentElement.tagName !== 'H3') {
            if (currentElement.tagName === 'H4' || currentElement.tagName === 'H5') {
                lastFilterType = currentElement.textContent.toLowerCase();
            }

            if (currentElement.tagName === 'TABLE') {
                const table = currentElement;
                const rows = table.querySelectorAll('tbody tr');
                
                rows.forEach(row => {
                    const cells = row.querySelectorAll('td');
                    if (cells.length < 2) return;

                    // Create a new server object for each row to ensure data isolation
                    const server = createServerObject();
                    server.provider = providerName;

                    // --- Advanced Filter Logic ---
                    const ft = lastFilterType;
                    if (ft.includes('family') || ft.includes('adult content')) {
                        server.filters.family = true;
                    }
                    if (ft.includes('malware') || ft.includes('security') || ft.includes('protected') || ft.includes('threat') || ft.includes('phishing')) {
                        server.filters.malware = true;
                    }
                    if (ft.includes('ads') || ft.includes('ad blocking') || ft.includes('ad-blocking')) {
                        server.filters.ads = true;
                    }
                    if (ft.includes('default')) {
                        server.filters.ads = true;
                        server.filters.malware = true;
                    } else if (ft.includes('standard')) {
                        // Handle ambiguity of "standard" keyword
                        if (providerName.toLowerCase() === 'cloudflare') {
                            server.filters.unfiltered = true;
                        } else {
                            server.filters.malware = true;
                        }
                    }
                    if (ft.includes('non-filtering') || ft.includes('unfiltered') || ft.includes('sandbox') || (providerName.toLowerCase().includes('cira') && ft.includes('private'))) {
                        server.filters.ads = false;
                        server.filters.malware = false;
                        server.filters.family = false;
                        server.filters.unfiltered = true;
                    }

                    // --- Protocol and Address Extraction for the current row ---
                    const protocolText = cells[0].textContent.toLowerCase();
                    const addressCellText = cells[1].textContent;
                    
                    const currentProtocols = new Set();
                    if (protocolText.includes('dns-over-https')) currentProtocols.add('doh');
                    if (protocolText.includes('dns-over-tls')) currentProtocols.add('dot');
                    if (protocolText.includes('dns-over-quic')) currentProtocols.add('doq');
                    if (protocolText.includes('dnscrypt')) currentProtocols.add('dnscrypt');
                    if (protocolText.startsWith('dns,')) currentProtocols.add('plain');
                    
                    const currentAddresses = new Set();
                    const foundAddresses = addressCellText.match(addressRegex) || [];
                    foundAddresses.forEach(address => {
                        currentAddresses.add(address.replace(/^(tls|quic):\/\//, ''));
                    });

                    const sdnstamp = row.querySelector('a[href^="sdns://"]');
                    if (sdnstamp) {
                        currentProtocols.add('dnscrypt');
                        currentAddresses.add(sdnstamp.href);
                    }
                    
                    if (currentAddresses.size > 0 && currentProtocols.size > 0) {
                        server.protocols = [...currentProtocols];
                        server.addresses = [...currentAddresses];
                        servers.push(server);
                    }
                });
            }
            currentElement = currentElement.nextElementSibling;
        }
    });

    return servers;
}
