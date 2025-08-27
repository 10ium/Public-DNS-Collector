import { JSDOM } from 'jsdom';
import { createServerObject } from '../utils.js';

/**
 * Parses the content from the Mullvad source.
 * The source is an HTML page with tables detailing their DNS servers.
 * @param {string} content The raw HTML content.
 * @returns {Array<object>} A list of server objects.
 */
export function parseMullvad(content) {
    const servers = [];
    const dom = new JSDOM(content);
    const document = dom.window.document;
    
    // Find all tables on the page
    const tables = document.querySelectorAll('table');

    tables.forEach(table => {
        const rows = table.querySelectorAll('tbody tr');
        rows.forEach(row => {
            const cells = row.querySelectorAll('td');
            // Ensure the row has the expected number of columns
            if (cells.length < 5) return;

            const server = createServerObject();
            server.provider = 'Mullvad';

            // First cell contains the IP address
            const address = cells[0].textContent.trim();
            if (address) {
                // This is the plain DNS IP, also used for DoT
                server.addresses.push(address);
            }
            
            // Mullvad uses a generic DoH endpoint for all their IPs
            server.addresses.push(`https://dns.mullvad.net/dns-query`);
            server.protocols.push('doh', 'dot'); 

            // Check for features indicated by a checkmark (✔)
            const features = Array.from(cells).map(cell => cell.innerHTML.includes('✔'));
            
            // According to Mullvad's policy, all their resolvers are no-log and support DNSSEC
            server.features.dnssec = true;
            server.features.no_log = true;
            server.features.ipv6 = address.includes(':');
            
            // Infer filters from the checkmarks in the table columns
            // Column indices: 1=Ad-blocking, 2=Tracker-blocking, 3=Malware-blocking, 4=Gambling, 5=Adult content
            server.filters.ads = features[1] || features[2]; // Ad-blocking or Tracker-blocking
            server.filters.malware = features[3];
            server.filters.family = features[5]; // Adult content blocking
            
            // If no specific blocking is enabled, it's unfiltered
            if (!server.filters.ads && !server.filters.malware && !server.filters.family) {
                server.filters.unfiltered = true;
            }
            
            if (server.addresses.length > 0) {
                servers.push(server);
            }
        });
    });

    return servers;
}
