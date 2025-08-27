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

    // Target the main content container which holds all the provider information
    const mainContent = document.querySelector('.theme-doc-markdown.markdown');
    if (!mainContent) {
        console.warn('  ⚠️ [AdGuard Parser] کانتینر اصلی محتوا (.theme-doc-markdown) پیدا نشد.');
        return [];
    }
    
    // Get all H3 elements, which represent the start of a provider's section
    const providerHeaders = mainContent.querySelectorAll('h3');

    providerHeaders.forEach(providerHeader => {
        const providerName = providerHeader.textContent.trim().replace(/ DNS$/, '');
        let currentElement = providerHeader.nextElementSibling;
        
        // Process elements only until the next provider header (H3) or end of content
        while (currentElement && currentElement.tagName !== 'H3') {
            // H4 tags define the filter type (e.g., Default, Family Protection)
            if (currentElement.tagName === 'H4') {
                const filterType = currentElement.textContent.toLowerCase();
                
                // Find the table associated with this filter type
                let table = currentElement.nextElementSibling;
                while (table && table.tagName !== 'TABLE') {
                    table = table.nextElementSibling;
                }

                if (table) {
                    const server = createServerObject();
                    server.provider = providerName;

                    // Set filters based on the H4 title
                    if (filterType.includes('family')) server.filters.family = true;
                    if (filterType.includes('default') || filterType.includes('malware') || filterType.includes('ad blocking') || filterType.includes('standard') || filterType.includes('security')) {
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
                        const addressCell = cells[1];
                        
                        // Extract addresses, which are inside `<code>` tags
                        const addresses = Array.from(addressCell.querySelectorAll('code')).map(c => c.textContent.trim());

                        addresses.forEach(address => {
                            if (protocolText.includes('dns-over-https')) {
                                server.protocols.push('doh');
                                server.addresses.push(address);
                            } else if (protocolText.includes('dns-over-tls')) {
                                server.protocols.push('dot');
                                server.addresses.push(address.replace('tls://', ''));
                            } else if (protocolText.includes('dnscrypt')) {
                                // For DNSCrypt, we extract the SDNS stamp from the link's href
                                const sdnstamp = row.querySelector('a[href^="sdns://"]');
                                if (sdnstamp) {
                                    server.protocols.push('dnscrypt');
                                    server.addresses.push(sdnstamp.href);
                                }
                            } else if (protocolText.includes('dns, ipv4') || protocolText.includes('dns, ipv6')) {
                                // We also collect plain DNS addresses
                                server.addresses.push(address);
                            }
                        });
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
