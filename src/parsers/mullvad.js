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
    
    const filterMap = new Map();
    const headers = Array.from(document.querySelectorAll('h3'));
    const hostnamesHeader = headers.find(h => h.textContent.includes('Hostnames and content blockers'));
    
    if (!hostnamesHeader) {
        console.warn('  ⚠️ [Mullvad Parser] هدر جدول فیلترینگ ("Hostnames and content blockers") پیدا نشد.');
        return [];
    }
    
    // Corrected Logic: Traverse next siblings to find the table
    let filterTable = hostnamesHeader.nextElementSibling;
    while (filterTable && filterTable.tagName !== 'TABLE') {
        filterTable = filterTable.nextElementSibling;
    }

    if (!filterTable) {
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
            ads: checks[1], trackers: checks[2], malware: checks[3],
            adult: checks[4], gambling: checks[5], social: checks[6],
        };
        filterMap.set(hostname, filters);
    });

    const ipsHeader = headers.find(h => h.textContent.includes('IP-addresses and ports'));
    if (!ipsHeader) {
        console.warn('  ⚠️ [Mullvad Parser] هدر جدول IP آدرس‌ها ("IP-addresses and ports") پیدا نشد.');
        return [];
    }

    let ipTable = ipsHeader.nextElementSibling;
    while (ipTable && ipTable.tagName !== 'TABLE') {
        ipTable = ipTable.nextElementSibling;
    }

    if (!ipTable) {
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
            server.protocols.push('doh', 'dot');
            if (ipv4) server.addresses.push(ipv4);
            if (ipv6) server.addresses.push(ipv6);
            server.addresses.push(`https://${hostname}/dns-query`);
            server.addresses.push(hostname);
            server.features.dnssec = true;
            server.features.no_log = true;
            server.features.ipv6 = !!ipv6;
            server.addresses = [...new Set(server.addresses)];
            servers.push(server);
        }
    });

    return servers;
}
