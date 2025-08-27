import fs from 'fs';
import path from 'path';
import axios from 'axios';
import { JSDOM } from 'jsdom';

// --- CONFIGURATION ---
const OUTPUT_DIR = 'lists';
const SOURCES = [
    // ... (همان منابع قبلی، بدون تغییر)
    { url: 'https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md', parser: parseDNSCrypt, name: 'DNSCrypt' },
    { url: 'https://raw.githubusercontent.com/paulmillr/encrypted-dns/master/readme.md', parser: parsePaulmillr, name: 'Paulmillr' },
    { url: 'https://raw.githubusercontent.com/blacklanternsecurity/public-dns-servers/master/dns-list.md', parser: parseBlacklantern, name: 'Blacklantern' },
    { url: 'https://gist.githubusercontent.com/mutin-sa/5dcbd35ee436eb629db7872581093bc5/raw/', parser: parseMutinSA, name: 'MutinSA Gist' },
    { url: 'https://adguard-dns.io/kb/general/dns-providers/', parser: parseAdGuard, name: 'AdGuard' },
    { url: 'https://mullvad.net/en/help/dns-over-https-and-dns-over-tls', parser: parseMullvad, name: 'Mullvad' },
    { url: 'https://dnsprivacy.org/public_resolvers/', parser: parseDnsPrivacyOrg, name: 'DNSPrivacy.org' },
    { url: 'https://raw.githubusercontent.com/curl/curl/master/docs/DOH-RESOLVERS.md', parser: parseCurl, name: 'Curl' },
];

// --- PARSER FUNCTIONS ---
// ... (تمام توابع parse... که قبلا نوشته شد، بدون تغییر در اینجا قرار می‌گیرند)
function parseDNSCrypt(content) {
    const servers = [];
    const lines = content.split('\n');
    for (const line of lines) {
        if (!line.startsWith('|')) continue;
        const parts = line.split('|').map(p => p.trim());
        if (parts.length < 5 || parts[1].includes('Name')) continue;

        const server = createServerObject();
        server.provider = parts[1].replace(/`/g, '');
        
        const addresses = parts[3].replace(/`/g, '').split(/\s*,\s*|\s+/);
        for(const addr of addresses) {
            if (addr.startsWith('sdns://')) {
                server.protocols.push('dnscrypt');
                server.addresses.push(addr);
            } else if (addr.startsWith('https://')) {
                server.protocols.push('doh');
                server.addresses.push(addr);
            } else if (/^\d{1,3}(\.\d{1,3}){3}$/.test(addr)) {
                // Assuming plain IPs might be DoT/DoH endpoints mentioned elsewhere
            }
        }

        const attributes = parts[4].toLowerCase();
        if (attributes.includes('dnssec')) server.features.dnssec = true;
        if (attributes.includes('no log')) server.features.no_log = true;
        if (attributes.includes('ipv6')) server.features.ipv6 = true;
        
        // Assume unfiltered unless specified otherwise
        server.filters.unfiltered = true;

        if (server.addresses.length > 0) servers.push(server);
    }
    return servers;
}

function parsePaulmillr(content) {
    const servers = [];
    const lines = content.split('\n');
    let inDoHTable = false;

    for (const line of lines) {
        if (line.includes('DNS-over-HTTPS')) inDoHTable = true;
        if (!inDoHTable || !line.startsWith('|')) continue;

        const parts = line.split('|').map(p => p.trim());
        if (parts.length < 4 || parts[1].includes('Provider')) continue;

        const server = createServerObject();
        server.provider = parts[1].replace(/\[([^\]]+)\]\([^\)]+\)/, '$1'); // Extract text from Markdown link

        const dohMatch = parts[2].match(/https\:\/\/[^\s`\)]+/);
        if (dohMatch) {
            server.protocols.push('doh');
            server.addresses.push(dohMatch[0]);
        }
        
        const dotMatch = parts[3].match(/tls:\/\/[^\s`\)]+/);
        if (dotMatch) {
            server.protocols.push('dot');
            server.addresses.push(dotMatch[0].replace('tls://', ''));
        }

        if (line.toLowerCase().includes('dnssec')) server.features.dnssec = true;
        if (line.toLowerCase().includes('no-log')) server.features.no_log = true;
        
        // Assume unfiltered unless tags say otherwise
        if (line.toLowerCase().includes('filtering')) {
            server.filters.ads = true; // General assumption
        } else {
            server.filters.unfiltered = true;
        }

        if (server.addresses.length > 0) servers.push(server);
    }
    return servers;
}

function parseBlacklantern(content) {
    const servers = [];
    content.split('\n').forEach(line => {
        if (!line.startsWith('|')) return;
        const parts = line.split('|').map(p => p.trim());
        if (parts.length < 6 || parts[1].includes('Provider')) return;

        const server = createServerObject();
        server.provider = parts[1];
        
        if(parts[2] && !parts[2].includes('N/A')) {
            server.protocols.push('doh');
            server.addresses.push(...parts[2].replace(/`/g, '').split(', '));
        }
        if(parts[3] && !parts[3].includes('N/A')) {
            server.protocols.push('dot');
            server.addresses.push(...parts[3].replace(/`/g, '').split(', '));
        }
        
        const filtering = parts[4].toLowerCase();
        if (filtering.includes('malware')) server.filters.malware = true;
        if (filtering.includes('ads')) server.filters.ads = true;
        if (filtering.includes('family') || filtering.includes('adult')) server.filters.family = true;
        if (!server.filters.ads && !server.filters.malware && !server.filters.family) {
            server.filters.unfiltered = true;
        }

        server.features.dnssec = !parts[5].toLowerCase().includes('no');
        
        if (server.addresses.length > 0) servers.push(server);
    });
    return servers;
}

function parseMutinSA(content) {
    const servers = [];
    content.split('\n').forEach(line => {
        if (!line.startsWith('|')) return;
        const parts = line.split('|').map(p => p.trim());
        if (parts.length < 5 || parts[1].includes('Name')) return;

        const server = createServerObject();
        server.provider = parts[1].replace(/`/g, '');
        
        const address = parts[3].replace(/`/g, '');
        if (address.startsWith('https://')) server.protocols.push('doh');
        else if (address.startsWith('sdns://')) server.protocols.push('dnscrypt');
        else server.protocols.push('dot');
        server.addresses.push(address.replace('tls://', ''));

        const comment = parts[4].toLowerCase();
        if (comment.includes('dnssec')) server.features.dnssec = true;
        if (comment.includes('no log')) server.features.no_log = true;
        if (comment.includes('no filter')) server.filters.unfiltered = true;
        if (comment.includes('adblock')) server.filters.ads = true;
        if (comment.includes('malware')) server.filters.malware = true;
        
        if (!server.filters.unfiltered && !server.filters.ads && !server.filters.malware) {
            server.filters.unfiltered = true; // Default assumption
        }

        if (server.addresses.length > 0) servers.push(server);
    });
    return servers;
}

function parseAdGuard(content) {
    const servers = [];
    const dom = new JSDOM(content);
    const document = dom.window.document;
    
    const sections = document.querySelectorAll('h3');
    sections.forEach(section => {
        let currentFilters = { ads: false, malware: false, family: false, unfiltered: false };
        const sectionText = section.textContent.toLowerCase();

        if (sectionText.includes('default')) {
            currentFilters.ads = true;
            currentFilters.malware = true;
        } else if (sectionText.includes('non-filtering')) {
            currentFilters.unfiltered = true;
        } else if (sectionText.includes('family protection')) {
            currentFilters.family = true;
            currentFilters.ads = true;
            currentFilters.malware = true;
        } else {
            return;
        }

        let table = section.nextElementSibling;
        while(table && table.tagName !== 'TABLE') {
            table = table.nextElementSibling;
        }
        if (!table) return;

        const rows = table.querySelectorAll('tbody tr');
        rows.forEach(row => {
            const cells = row.querySelectorAll('td');
            if (cells.length < 2) return;
            
            const protocolText = cells[0].textContent.toLowerCase();
            const addresses = cells[1].textContent.trim().split(/\s+/).filter(Boolean);
            
            if (addresses.length === 0) return;

            const server = createServerObject();
            server.provider = 'AdGuard';
            server.filters = { ...currentFilters };
            server.features = { dnssec: true, no_log: true, ipv6: addresses.some(a => a.includes(':')) };
            
            if (protocolText.includes('dns-over-https')) server.protocols.push('doh');
            if (protocolText.includes('dns-over-tls')) server.protocols.push('dot');
            if (protocolText.includes('dnscrypt')) server.protocols.push('dnscrypt');
            
            server.addresses.push(...addresses.map(a => a.replace('tls://', '')));
            if(server.protocols.length > 0) servers.push(server);
        });
    });
    return servers;
}

function parseMullvad(content) {
    const servers = [];
    const dom = new JSDOM(content);
    const document = dom.window.document;
    const tables = document.querySelectorAll('table');

    tables.forEach(table => {
        const rows = table.querySelectorAll('tbody tr');
        rows.forEach(row => {
            const cells = row.querySelectorAll('td');
            if (cells.length < 5) return;

            const server = createServerObject();
            server.provider = 'Mullvad';

            const address = cells[0].textContent.trim();
            if(address) server.addresses.push(address);
            
            // Assume both DoH and DoT for Mullvad IPs
            server.protocols.push('doh', 'dot'); 
            server.addresses.push(`https://dns.mullvad.net/${address.includes(':') ? 'ipv6-' : ''}${address.split('.').slice(0,1)}.json`);

            const features = Array.from(cells).map(cell => cell.innerHTML.includes('✔'));
            server.features.dnssec = true; // Mullvad supports DNSSEC on all
            server.features.no_log = true;  // Mullvad is a no-log provider
            server.features.ipv6 = address.includes(':');
            server.filters.ads = features[1] || features[2]; // Ad-blocking or Tracker-blocking
            server.filters.malware = features[2]; // Tracker-blocking as malware
            
            if (!server.filters.ads && !server.filters.malware) {
                server.filters.unfiltered = true;
            }
            
            if (server.addresses.length > 0) servers.push(server);
        });
    });
    return servers;
}

function parseDnsPrivacyOrg(content) {
    const servers = [];
    const dom = new JSDOM(content);
    const table = dom.window.document.querySelector('#dot_resolvers');
    if (!table) return [];

    const rows = table.querySelectorAll('tbody tr');
    rows.forEach(row => {
        const cells = row.querySelectorAll('td');
        if (cells.length < 3) return;

        const server = createServerObject();
        server.provider = cells[0].textContent.trim();
        
        const addressCell = cells[1].innerHTML;
        const addresses = addressCell.split('<br>').map(a => a.replace(/<[^>]*>/g, '').trim()).filter(Boolean);
        server.addresses.push(...addresses);

        if (addresses.length > 0) {
            // Assume DoT from the table name, check for DoH in notes
            server.protocols.push('dot');
        }

        const notes = cells[2].textContent.toLowerCase();
        if (notes.includes('doh')) server.protocols.push('doh');
        if (notes.includes('dnscrypt')) server.protocols.push('dnscrypt');
        if (notes.includes('dnssec')) server.features.dnssec = true;
        if (notes.includes('no log')) server.features.no_log = true;
        if (notes.includes('ipv6')) server.features.ipv6 = true;

        if (notes.includes('filter')) server.filters.ads = true;
        else server.filters.unfiltered = true;
        
        if (server.addresses.length > 0) servers.push(server);
    });
    return servers;
}

function parseCurl(content) {
    const servers = [];
    content.split('\n').forEach(line => {
        if (!line.startsWith('|')) return;
        const parts = line.split('|').map(p => p.trim());
        if (parts.length < 3 || parts[1].includes('---')) return;

        const url = parts[2].replace(/`/g, '');
        if (url && url.startsWith('https://')) {
            const server = createServerObject();
            server.provider = parts[1];
            server.protocols.push('doh');
            server.addresses.push(url);
            server.filters.unfiltered = true; // Assume unfiltered for this list
            server.features.dnssec = true; // Often implied for public DoH
            servers.push(server);
        }
    });
    return servers;
}

// --- UTILITY FUNCTIONS ---
async function fetchData(url) {
    try {
        const response = await axios.get(url, { timeout: 15000 });
        return response.data;
    } catch (error) {
        console.error(`  ❌ [خطای دریافت] دریافت اطلاعات از ${url} با شکست مواجه شد. علت: ${error.message}`);
        return null;
    }
}
function createServerObject() {
    return {
        provider: 'Unknown',
        protocols: [],
        addresses: [],
        filters: { ads: false, malware: false, family: false, unfiltered: false },
        features: { dnssec: false, no_log: false, ipv6: false },
    };
}
// --- MAIN EXECUTION ---
async function main() {
    console.log('🚀 [شروع] فرآیند جمع‌آوری و به‌روزرسانی لیست‌های DNS آغاز شد.');
    let allServers = [];

    for (const source of SOURCES) {
        console.log(`\n📥 [دریافت] در حال دریافت اطلاعات از منبع: ${source.name}`);
        const content = await fetchData(source.url);
        
        if (content) {
            console.log(`  🔬 [پردازش] در حال تجزیه و تحلیل محتوای دریافت شده از ${source.name}...`);
            try {
                const parsedServers = source.parser(content);
                if (parsedServers.length === 0) {
                    console.warn(`  ⚠️ [هشدار] هیچ سروری از منبع ${source.name} استخراج نشد. ممکن است ساختار منبع تغییر کرده باشد.`);
                } else {
                    allServers.push(...parsedServers);
                    console.log(`  ✅ [موفقیت] تعداد ${parsedServers.length} گروه سرور از ${source.name} با موفقیت استخراج شد.`);
                }
            } catch (error) {
                console.error(`  ❌ [خطای پردازش] تجزیه محتوای ${source.name} با خطای جدی مواجه شد: ${error.message}`);
            }
        }
    }
    
    console.log(`\n📊 [تجمیع] مجموعاً ${allServers.length} گروه سرور از تمام منابع جمع‌آوری شد.`);
    console.log('  🧹 [پاک‌سازی] در حال حذف موارد تکراری و دسته‌بندی آدرس‌ها...');

    const addressSets = {
        doh: new Set(), dot: new Set(), dnscrypt: new Set(),
        adblock: new Set(), malware: new Set(), family: new Set(),
        unfiltered: new Set(), ipv6: new Set(),
    };

    for (const server of allServers) {
        for (const address of server.addresses) {
            const cleanedAddress = address.trim();
            if (!cleanedAddress) continue;
            
            if (server.protocols.includes('doh') && cleanedAddress.startsWith('https://')) addressSets.doh.add(cleanedAddress);
            if (server.protocols.includes('dot') && !cleanedAddress.startsWith('https://') && !cleanedAddress.startsWith('sdns://')) addressSets.dot.add(cleanedAddress);
            if (server.protocols.includes('dnscrypt') && cleanedAddress.startsWith('sdns://')) addressSets.dnscrypt.add(cleanedAddress);

            if (server.filters.ads) addressSets.adblock.add(cleanedAddress);
            if (server.filters.malware) addressSets.malware.add(cleanedAddress);
            if (server.filters.family) addressSets.family.add(cleanedAddress);
            if (server.filters.unfiltered) addressSets.unfiltered.add(cleanedAddress);

            if (server.features.ipv6 || cleanedAddress.includes(':')) addressSets.ipv6.add(cleanedAddress);
        }
    }

    if (!fs.existsSync(OUTPUT_DIR)) {
        fs.mkdirSync(OUTPUT_DIR);
    }
    
    console.log('\n💾 [نوشتن فایل‌ها] در حال تولید و ذخیره فایل‌های خروجی...');
    for (const [listName, addressSet] of Object.entries(addressSets)) {
        const sortedList = Array.from(addressSet).sort();
        const filePath = path.join(OUTPUT_DIR, `${listName}.txt`);
        fs.writeFileSync(filePath, sortedList.join('\n'));
        console.log(`  📄 فایل ${filePath} با ${sortedList.length} آدرس منحصر به فرد نوشته شد.`);
    }

    console.log('\n🎉 [پایان] فرآیند با موفقیت به اتمام رسید.');
}

main().catch(error => {
    console.error('\n🚨 [خطای حیاتی] یک خطای پیش‌بینی‌نشده در اجرای اصلی رخ داد:', error);
    process.exit(1);
});
