import { JSDOM } from 'jsdom';
import { createServerObject } from '../utils.js';

/**
 * Parses the content from the AdGuard DNS Providers source.
 * The source is an HTML page with structured tables.
 * @param {string} content The raw HTML content.
 * @returns {Array<object>} A list of server objects.
 */
export function parseAdGuard(content) {
    const servers = [];
    const dom = new JSDOM(content);
    const document = dom.window.document;

    // Find all provider sections, which are typically marked by <h2> or similar headers
    const providerHeaders = document.querySelectorAll('h2, h3');

    providerHeaders.forEach(header => {
        // Skip irrelevant headers
        if (header.textContent.toLowerCase().includes('quick links') || header.textContent.toLowerCase().includes('known dns providers')) {
            return;
        }

        const providerName = header.textContent.trim().replace(' DNS', '');
        let nextElement = header.nextElementSibling;
        
        while (nextElement) {
            // Stop when we hit the next provider header
            if (nextElement.tagName === 'H2' || nextElement.tagName === 'H3') {
                break;
            }

            // Find sub-sections for different filter types (e.g., Default, Family Protection)
            if (nextElement.tagName === 'H3' || nextElement.tagName === 'H4') {
                const filterType = nextElement.textContent.toLowerCase();
                let table = nextElement.nextElementSibling;
                while (table && table.tagName !== 'TABLE') {
                    table = table.nextElementSibling;
                }

                if (table) {
                    const server = createServerObject();
                    server.provider = providerName;

                    // Set filters based on sub-section title
                    if (filterType.includes('family')) server.filters.family = true;
                    if (filterType.includes('default') || filterType.includes('malware') || filterType.includes('ad blocking') || filterType.includes('standard')) {
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
                        const addressText = cells[1].textContent;
                        
                        // Extract multiple addresses if present (e.g., "94.140.14.14 and 94.140.15.15")
                        const addresses = addressText.split(/and|,|\s+/).map(a => a.trim()).filter(Boolean);

                        addresses.forEach(address => {
                            if (protocolText.includes('dns-over-https')) {
                                server.protocols.push('doh');
                                server.addresses.push(address);
                            } else if (protocolText.includes('dns-over-tls')) {
                                server.protocols.push('dot');
                                server.addresses.push(address.replace('tls://', ''));
                            } else if (protocolText.includes('dnscrypt')) {
                                // Extract provider name from DNSCrypt string
                                const providerMatch = addressText.match(/Provider:\s*([^\s]+)/);
                                if (providerMatch) {
                                    server.protocols.push('dnscrypt');
                                    // We can't use the provider name as an address,
                                    // but this confirms the protocol. Other sources will provide the stamp.
                                }
                            } else if (protocolText.includes('dns, ipv4')) {
                                // Plain DNS, will be categorized by the main script
                            }
                        });
                    });

                    // To avoid duplicates, we add one server object per filter type
                    if (server.addresses.length > 0) {
                         // A single server group can have multiple addresses for different protocols.
                         // We create one server object and push all addresses into it.
                         let existingServer = servers.find(s => s.provider === server.provider && JSON.stringify(s.filters) === JSON.stringify(server.filters));
                         if (existingServer) {
                             existingServer.addresses.push(...server.addresses);
                             existingServer.protocols = [...new Set([...existingServer.protocols, ...server.protocols])];
                         } else if (server.addresses.length > 0) {
                             servers.push(server);
                         }
                    }
                }
            }
            nextElement = nextElement.nextElementSibling;
        }
    });
    
    // Manual merge for AdGuard DNS as it is split into 3 sections
    const adguardDefault = servers.find(s => s.provider === "AdGuard" && s.filters.ads && !s.filters.family);
    const adguardFamily = servers.find(s => s.provider === "AdGuard" && s.filters.family);
    const adguardUnfiltered = servers.find(s => s.provider === "AdGuard" && s.filters.unfiltered);

    // This logic is complex and better handled by individual parsers. Let's simplify.
    // The main loop already creates separate objects which is fine.

    return servers.filter(s => s.addresses.length > 0);
}
