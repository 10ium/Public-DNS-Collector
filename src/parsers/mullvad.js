import { JSDOM } from 'jsdom';
import { createServerObject } from '../utils.js';

/**
 * Parses the content from the updated Mullvad source.
 * The source is an HTML page with two distinct tables for hostnames/filters and IPs.
 * @param {string} content The raw HTML content.
 * @returns {Array<object>} A list of server objects.
 */
export function parseMullvad(content) {
    const servers = [];
    const dom = new JSDOM(content);
    const document = dom.window.document;
    
    // --- Step 1: Parse the first table to map hostnames to filter settings ---
    const filterMap = new Map();
    // Find the header for the content blockers table
    const hostnamesHeader = Array.from(document.querySelectorAll('h3')).find(h => h.textContent.includes('Hostnames and content blockers'));
    
    if (!hostnamesHeader) {
        console.warn('  ⚠️ [Mullvad Parser] جدول فیلترینگ ("Hostnames and content blockers") پیدا نشد.');
        return [];
    }
    
    const filterTable = hostnamesHeader.nextElementSibling;
    if (!filterTable || filterTable.tagName !== 'TABLE') {
        console.warn('  ⚠️ [Mullvad Parser] عنصر جدول بعد از هدر فیلترینگ پیدا نشد.');
        return [];
    }
    
    const filterRows = filterTable.querySelectorAll('tbody tr');
    filterRows.forEach(row => {
        const cells = row.querySelectorAll('td');
        if (cells.length < 7) return;

        const hostname = cells[0].textContent.trim();
        const checks = Array.from(cells).map(cell => cell.textContent.includes('✅'));
        
        const filters = {
            ads: checks[1],
            trackers: checks[2],
            malware: checks[3],
            adult: checks[4],
            gambling: checks[5],
            social: checks[6],
        };
        filterMap.set(hostname, filters);
    });

    // --- Step 2: Parse the second table to get IPs and combine with filter data ---
    const ipsHeader = Array.from(document.querySelectorAll('h3')).find(h => h.textContent.includes('IP-addresses and ports'));
    if (!ipsHeader) {
        console.warn('  ⚠️ [Mullvad Parser] جدول IP آدرس‌ها ("IP-addresses and ports") پیدا نشد.');
        return [];
    }

    const ipTable = ipsHeader.nextElementSibling;
    if (!ipTable || ipTable.tagName !== 'TABLE') {
        console.warn('  ⚠️ [Mullvad Parser] عنصر جدول بعد از هدر IP آدرس‌ها پیدا نشد.');
        return [];
    }

    const ipRows = ipTable.querySelectorAll('tbody tr');
    ipRows.forEach(row => {
        const cells = row.querySelectorAll('td');
        if (cells.length < 3) return;

        const hostname = cells[0].textContent.trim();
        const ipv4 = cells[1].textContent.trim();
        const ipv6 = cells[2].textContent.trim();

        if (filterMap.has(hostname)) {
            const server = createServerObject();
            server.provider = 'Mullvad';

            const serverFilters = filterMap.get(hostname);
            server.filters.ads = serverFilters.ads || serverFilters.trackers;
            server.filters.malware = serverFilters.malware;
            server.filters.family = serverFilters.adult || serverFilters.gambling;
            
            if (!server.filters.ads && !server.filters.malware && !server.filters.family && !serverFilters.social) {
                server.filters.unfiltered = true;
            }

            // Add all relevant addresses and protocols
            server.protocols.push('doh', 'dot');
            if (ipv4) server.addresses.push(ipv4);
            if (ipv6) server.addresses.push(ipv6);
            server.addresses.push(`https://${hostname}/dns-query`); // DoH endpoint
            server.addresses.push(hostname); // DoT endpoint

            // Set standard features for Mullvad
            server.features.dnssec = true;
            server.features.no_log = true;
            server.features.ipv6 = !!ipv6;

            // Deduplicate addresses and add to the final list
            server.addresses = [...new Set(server.addresses)];
            servers.push(server);
        }
    });

    return servers;
}
