import { JSDOM } from 'jsdom';
import { createServerObject } from '../utils.js';

/**
 * Parses the content from the AdGuard DNS Providers source.
 * The source is an HTML page with a structured layout.
 * @param {string} content The raw HTML content.
 * @returns {Array<object>} A list of server objects.
 */
export function parseAdGuard(content) {
    const servers = [];
    const dom = new JSDOM(content);
    const document = dom.window.document;

    const mainContent = document.querySelector('.theme-doc-markdown.markdown');
    if (!mainContent) {
        return [];
    }
    
    const providerHeaders = mainContent.querySelectorAll('h3');
    providerHeaders.forEach(providerHeader => {
        const providerName = providerHeader.textContent.trim().replace(/ DNS$/, '');
        let currentElement = providerHeader.nextElementSibling;
        
        while (currentElement && currentElement.tagName !== 'H3') {
            if (currentElement.tagName === 'H4' || currentElement.tagName === 'H5') {
                const filterType = currentElement.textContent.toLowerCase();
                
                let table = currentElement.nextElementSibling;
                while (table && table.tagName !== 'TABLE') {
                    table = table.nextElementSibling;
                }

                if (table) {
                    const server = createServerObject();
                    server.provider = providerName;

                    if (filterType.includes('family')) server.filters.family = true;
                    if (filterType.includes('default') || filterType.includes('malware') || filterType.includes('ad blocking') || filterType.includes('standard') || filterType.includes('security') || filterType.includes('protective')) {
                        server.filters.ads = true;
                        server.filters.malware = true;
                    }
                    if (filterType.includes('non-filtering') || filterType.includes('unfiltered') || filterType.includes('sandbox')) {
                        server.filters.unfiltered = true;
                    }

                    const rows = table.querySelectorAll('tbody tr');
                    rows.forEach(row => {
                        const cells = row.querySelectorAll('td');
                        if (cells.length < 2) return;
                        
                        const protocolText = cells[0].textContent.toLowerCase();
                        const addressCellText = cells[1].textContent;
                        
                        // Final Correction: Extract addresses using regex to be more precise and avoid garbage text.
                        const foundAddresses = addressCellText.match(/(https:\/\/[^\s`]+)|(tls:\/\/[^\s`]+)|(quic:\/\/[^\s`]+)|(\d{1,3}(\.\d{1,3}){3})|([0-9a-fA-F:]+::[0-9a-fA-F:]*)/g) || [];

                        foundAddresses.forEach(address => {
                            if (protocolText.includes('dns-over-https')) server.protocols.push('doh');
                            else if (protocolText.includes('dns-over-tls')) server.protocols.push('dot');
                            else if (protocolText.includes('dnscrypt')) server.protocols.push('dnscrypt');
                            
                            server.addresses.push(address.replace(/tls:\/\/|quic:\/\//, '').replace(/:\d+$/, ''));
                        });
                        
                        // Special handling for DNSCrypt stamps which are in hrefs
                        if (protocolText.includes('dnscrypt')) {
                            const sdnstamp = row.querySelector('a[href^="sdns://"]');
                            if (sdnstamp) {
                                server.protocols.push('dnscrypt');
                                server.addresses.push(sdnstamp.href);
                            }
                        }
                    });

                    if (server.addresses.length > 0) {
                        server.addresses = [...new Set(server.addresses)];
                        server.protocols = [...new Set(server.protocols)];
                        servers.push(server);
                    }
                }
            }
            currentElement = currentElement.nextElementSibling;
        }
    });

    return servers;
}
