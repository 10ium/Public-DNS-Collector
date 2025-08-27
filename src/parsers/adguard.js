import { JSDOM } from 'jsdom';
import { createServerObject } from '../utils.js';

/**
 * Parses the content from the AdGuard DNS Providers source.
 * The source is an HTML page with a structured layout.
 * This revised parser creates a separate server object for each protocol entry (table row)
 * and intelligently removes default ports while preserving non-default ones.
 * @param {string} content The raw HTML content.
 * @returns {Array<object>} A list of server objects.
 */
export function parseAdGuard(content) {
    const servers = [];
    const dom = new JSDOM(content);
    const document = dom.window.document;

    // A more general regex to capture potential address-like strings. Cleanup logic will refine them.
    const addressRegex = /(https:\/\/[^\s`'"]+)|(tls:\/\/[^\s`'"]+)|(quic:\/\/[^\s`'"]+)|(\b\d{1,3}(\.\d{1,3}){3}(:\d+)?\b)|(\[?[0-9a-fA-F:]+:[0-9a-fA-F:.]+\]?(:\d+)?)/g;

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

                    const server = createServerObject();
                    server.provider = providerName;

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
                        if (address.startsWith('https://')) {
                            currentProtocols.add('doh');
                        } else if (address.startsWith('tls://')) {
                            currentProtocols.add('dot');
                        } else if (address.startsWith('quic://')) {
                            currentProtocols.add('doq');
                        }
                        
                        let cleanAddress = address;

                        // Conditionally remove default ports based on protocol
                        if (cleanAddress.startsWith('https://') && cleanAddress.endsWith(':443')) {
                            cleanAddress = cleanAddress.slice(0, -4); // Remove ":443"
                        } else if (cleanAddress.startsWith('tls://') && cleanAddress.endsWith(':853')) {
                            cleanAddress = cleanAddress.slice(0, -4); // Remove ":853"
                        } else if (cleanAddress.startsWith('quic://') && cleanAddress.endsWith(':853')) {
                            cleanAddress = cleanAddress.slice(0, -4); // Remove ":853"
                        }
                        
                        // Always remove brackets from IPv6 for standardization
                        cleanAddress = cleanAddress.replace(/[\[\]]/g, '');

                        if (cleanAddress) {
                            currentAddresses.add(cleanAddress);
                        }
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
