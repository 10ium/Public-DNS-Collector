import { JSDOM } from 'jsdom';
import { createServerObject } from '../utils.js';

/**
 * Parses DNS server information from the Mullvad DNS documentation page.
 * This parser dynamically detects supported protocols (DoH, DoT) and extracts
 * servers from multiple tables on the page.
 * @param {string} content The raw HTML content from the Mullvad source.
 * @returns {Array<object>} A list of server objects.
 */
export function parseMullvad(content) {
    const servers = [];
    const dom = new JSDOM(content);
    const document = dom.window.document;

    // --- Step 1: Parse the "Hostnames and content blockers" table to map hostnames to filters ---
    const filterMap = new Map();
    const headers = Array.from(document.querySelectorAll('h3'));
    const hostnamesHeader = headers.find(h => h.textContent.includes('Hostnames and content blockers'));

    if (hostnamesHeader) {
        let filterTable = hostnamesHeader.nextElementSibling;
        while (filterTable && filterTable.tagName !== 'TABLE') {
            filterTable = filterTable.nextElementSibling;
        }

        if (filterTable) {
            const filterRows = filterTable.querySelectorAll('tbody tr');
            filterRows.forEach(row => {
                const cells = row.querySelectorAll('td');
                if (cells.length < 7) return;

                const hostname = cells[0].textContent.trim();
                const checks = Array.from(cells).map(cell => cell.textContent.includes('✅'));

                const filters = {
                    ads: checks[1], trackers: checks[2], malware: checks[3],
                    adult: checks[4], gambling: checks[5], social: checks[6],
                };
                filterMap.set(hostname, filters);
            });
        } else {
            console.warn('  ⚠️ [Mullvad Parser] جدول فیلترینگ ("Hostnames and content blockers") پیدا نشد.');
        }
    } else {
        console.warn('  ⚠️ [Mullvad Parser] هدر جدول فیلترینگ پیدا نشد.');
    }


    // --- Step 2: Parse the "IP-addresses and ports" table for main servers ---
    const ipsHeader = headers.find(h => h.textContent.includes('IP-addresses and ports'));
    if (ipsHeader) {
        let ipTable = ipsHeader.nextElementSibling;
        while (ipTable && ipTable.tagName !== 'TABLE') {
            ipTable = ipTable.nextElementSibling;
        }

        if (ipTable) {
            const ipRows = ipTable.querySelectorAll('tbody tr');
            ipRows.forEach(row => {
                const cells = row.querySelectorAll('td');
                if (cells.length < 5) return; // Expecting at least 5 columns now

                const hostname = cells[0].textContent.trim();
                const ipv4 = cells[1].textContent.trim();
                const ipv6 = cells[2].textContent.trim();
                const dohPort = cells[3].textContent.trim();
                const dotPort = cells[4].textContent.trim();

                if (filterMap.has(hostname)) {
                    const server = createServerObject();
                    server.provider = 'Mullvad';

                    // Set filters
                    const serverFilters = filterMap.get(hostname);
                    server.filters.ads = serverFilters.ads || serverFilters.trackers;
                    server.filters.malware = serverFilters.malware;
                    server.filters.family = serverFilters.adult || serverFilters.gambling;
                    if (!server.filters.ads && !server.filters.malware && !server.filters.family && !serverFilters.social) {
                        server.filters.unfiltered = true;
                    }

                    // Dynamically detect protocols
                    const protocols = [];
                    if (dohPort) protocols.push('doh');
                    if (dotPort) protocols.push('dot');
                    server.protocols = protocols;

                    // Add addresses based on detected protocols
                    if (ipv4) server.addresses.push(ipv4);
                    if (ipv6) server.addresses.push(ipv6);
                    if (protocols.includes('doh')) {
                        server.addresses.push(`https://${hostname}/dns-query`);
                    }
                    if (protocols.includes('dot')) {
                        server.addresses.push(hostname);
                    }
                    
                    // Set features
                    server.features.dnssec = true;
                    server.features.no_log = true;
                    server.features.ipv6 = !!ipv6;
                    
                    server.addresses = [...new Set(server.addresses)];
                    servers.push(server);
                }
            });
        } else {
             console.warn('  ⚠️ [Mullvad Parser] جدول IP آدرس‌ها ("IP-addresses and ports") پیدا نشد.');
        }
    } else {
         console.warn('  ⚠️ [Mullvad Parser] هدر جدول IP آدرس‌ها پیدا نشد.');
    }

    // --- Step 3: Parse the "Using a specific DNS server" table for DoH-only servers ---
    const specificHeader = headers.find(h => h.textContent.includes('Using a specific DNS server'));
    if (specificHeader) {
        let specificTable = specificHeader.nextElementSibling;
        while (specificTable && specificTable.tagName !== 'TABLE') {
            specificTable = specificTable.nextElementSibling;
        }

        if (specificTable) {
            const specificRows = specificTable.querySelectorAll('tbody tr');
            specificRows.forEach(row => {
                const cells = row.querySelectorAll('td');
                if (cells.length < 1) return;

                const dohUrl = cells[0].textContent.trim();
                if (dohUrl.startsWith('https://')) {
                    const server = createServerObject();
                    server.provider = 'Mullvad';
                    server.filters.unfiltered = true;
                    server.protocols = ['doh'];
                    server.addresses = [dohUrl];
                    server.features.dnssec = true;
                    server.features.no_log = true;
                    
                    // IPv6 support is likely but not explicitly stated for these, so we leave it false
                    server.features.ipv6 = false; 

                    servers.push(server);
                }
            });
        } else {
            console.warn('  ⚠️ [Mullvad Parser] جدول سرورهای خاص ("Using a specific DNS server") پیدا نشد.');
        }
    } else {
        console.warn('  ⚠️ [Mullvad Parser] هدر جدول سرورهای خاص پیدا نشد.');
    }

    return servers;
}
