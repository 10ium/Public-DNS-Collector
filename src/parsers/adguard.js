import { JSDOM } from 'jsdom';
import { createServerObject } from '../utils.js';

/**
 * Parses the content from the AdGuard DNS Providers source.
 * The source is an HTML page with a structured layout.
 * This revised parser creates a separate server object for each protocol entry (table row)
 * and preserves all prefixes and ports. It also adds support for DoQ.
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
        console.warn("  ⚠️ [هشدار AdGuard] بخش اصلی محتوای صفحه پیدا نشد.");
        return [];
    }
    
    const providerHeaders = mainContent.querySelectorAll('h3');
    providerHeaders.forEach(providerHeader => {
        const providerName = providerHeader.textContent.trim().replace(/ DNS$/, '');
        let currentElement = providerHeader.nextElementSibling;
        let lastFilterType = 'default'; // Use 'default' if no h4/h5 is found before a table

        while (currentElement && currentElement.tagName !== 'H3') {
            if (currentElement.tagName === 'H4' || currentElement.tagName === 'H5') {
                lastFilterType = currentElement.textContent.toLowerCase().replace(' ', ''); // Remove spaces for easier matching
            }

            if (currentElement.tagName === 'TABLE') {
                const table = currentElement;
                const rows = table.querySelectorAll('tbody tr');
                
                rows.forEach(row => {
                    const cells = row.querySelectorAll('td');
                    if (cells.length < 2) {
                        console.warn(`  ⚠️ [هشدار AdGuard] سطر جدول در ${providerName} سلول‌های کافی ندارد، نادیده گرفته شد.`);
                        return;
                    }

                    const server = createServerObject();
                    server.provider = providerName;

                    const ft = lastFilterType;
                    if (ft.includes('family') || ft.includes('adultcontent')) {
                        server.filters.family = true;
                    }
                    if (ft.includes('malware') || ft.includes('security') || ft.includes('protected') || ft.includes('threat') || ft.includes('phishing')) {
                        server.filters.malware = true;
                    }
                    if (ft.includes('ads') || ft.includes('adblocking') || ft.includes('ad-blocking')) {
                        server.filters.ads = true;
                    }
                    // Default handling for AdGuard's own categories
                    if (ft.includes('default')) {
                        server.filters.ads = true;
                        server.filters.malware = true;
                    } else if (ft.includes('standard')) {
                        if (providerName.toLowerCase() === 'cloudflare') {
                            server.filters.unfiltered = true;
                        } else {
                            server.filters.malware = true; // Assuming 'standard' implies some level of protection unless stated otherwise
                        }
                    }
                    if (ft.includes('nonfiltering') || ft.includes('unfiltered') || ft.includes('sandbox') || (providerName.toLowerCase().includes('cira') && ft.includes('private'))) {
                        server.filters.ads = false;
                        server.filters.malware = false;
                        server.filters.family = false;
                        server.filters.unfiltered = true;
                    }

                    const protocolCellText = cells[0].textContent.toLowerCase();
                    const addressCellText = cells[1].textContent;
                    
                    const currentProtocols = new Set();
                    if (protocolCellText.includes('dns-over-https')) currentProtocols.add('doh');
                    if (protocolCellText.includes('dns-over-tls')) currentProtocols.add('dot');
                    if (protocolCellText.includes('dns-over-quic')) currentProtocols.add('doq');
                    if (protocolCellText.includes('dnscrypt')) currentProtocols.add('dnscrypt');
                    // If it contains "dns," it's likely a plain DNS entry
                    if (protocolCellText.includes('dns,')) currentProtocols.add('plain');
                    
                    const currentAddresses = new Set();
                    const foundAddresses = addressCellText.match(addressRegex) || [];

                    foundAddresses.forEach(address => {
                        // Determine protocol from address format if not clear from text
                        if (address.startsWith('https://')) {
                            currentProtocols.add('doh');
                        } else if (address.startsWith('tls://')) {
                            currentProtocols.add('dot');
                        } else if (address.startsWith('quic://')) {
                            currentProtocols.add('doq');
                        }
                        
                        let cleanAddress = address;
                        
                        // Always remove brackets from IPv6 for standardization, but keep ports and prefixes.
                        cleanAddress = cleanAddress.replace(/[\[\]]/g, '');

                        if (cleanAddress) {
                            currentAddresses.add(cleanAddress);
                        }
                    });

                    // Check for sdns:// links specifically
                    const sdnstampLink = row.querySelector('a[href^="sdns://"]');
                    if (sdnstampLink) {
                        currentProtocols.add('dnscrypt');
                        currentAddresses.add(sdnstampLink.href);
                    }
                    
                    // Only add if we found valid addresses and protocols
                    if (currentAddresses.size > 0 && currentProtocols.size > 0) {
                        server.protocols = [...currentProtocols];
                        server.addresses = [...currentAddresses];
                        servers.push(server);
                    } else if (currentAddresses.size > 0 && !protocolCellText.includes('dns')) {
                         // Fallback: If protocols weren't explicitly found but addresses exist, assume 'plain' for IP addresses
                        const hasPlainAddress = [...currentAddresses].some(addr => /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(addr) || /^[0-9a-fA-F:]+$/.test(addr));
                        if (hasPlainAddress) {
                            server.protocols.push('plain');
                            server.addresses = [...currentAddresses];
                            servers.push(server);
                        }
                    }
                });
            }
            currentElement = currentElement.nextElementSibling;
        }
    });

    if (servers.length === 0) {
        console.warn("  ⚠️ [هشدار AdGuard] هیچ سرور DNS معتبری از صفحه AdGuard استخراج نشد.");
    }
    return servers;
}
