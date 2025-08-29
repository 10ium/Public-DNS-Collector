import fs from 'fs';
import path from 'path';
import { fetchData } from './src/utils.js';
import * as parsers from './src/parsers/index.js';
import { generateReadme, writeReadme } from './src/readme-generator.js';

// --- CONFIGURATION ---
const OUTPUT_DIR = 'lists';
const SOURCES_DIR = path.join(OUTPUT_DIR, 'sources');
const GITHUB_REPO_URL = `https://github.com/${process.env.GITHUB_REPOSITORY}`;

const SOURCES = [
    { name: 'DNSCrypt', url: 'https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/refs/heads/master/v3/public-resolvers.md', parser: parsers.parseDNSCrypt },
    { name: 'Paulmillr', url: null, readmeUrl: 'https://github.com/paulmillr/encrypted-dns', parser: parsers.parsePaulmillr },
    { name: 'Blacklantern', url: 'https://raw.githubusercontent.com/blacklanternsecurity/public-dns-servers/refs/heads/master/nameservers.txt', parser: parsers.parseBlacklantern },
    { name: 'MutinSA', url: 'https://gist.githubusercontent.com/mutin-sa/5dcbd35ee436eb629db7872581093bc5/raw/', parser: parsers.parseMutinSA },
    { name: 'AdGuard', url: 'https://adguard-dns.io/kb/general/dns-providers/', parser: parsers.parseAdGuard },
    { name: 'Mullvad', url: 'https://mullvad.net/en/help/dns-over-https-and-dns-over-tls', parser: parsers.parseMullvad },
    { name: 'DNSPrivacyOrg', url: 'https://dnsprivacy.org/public_resolvers/', parser: parsers.parseDnsPrivacyOrg },
    { name: 'Curl', url: 'https://raw.githubusercontent.com/wiki/curl/curl/DNS-over-HTTPS.md', parser: parsers.parseCurl },
    { name: 'Thiagozs', url: 'https://gist.githubusercontent.com/thiagozs/088fd8f8129ca06df524f6711116ee8f/raw/', parser: parsers.parseThiagozs },
];

// --- FINAL VALIDATION UTILITY ---
const IPV4_REGEX = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
const IPV6_REGEX = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/i;
const HOSTNAME_REGEX = /^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][a-zA-Z0-9-]*[A-Za-z0-9])$/;

function isValidDnsAddress(address) {
    if (typeof address !== 'string' || address.length === 0) return false;
    const addr = address.trim();
    if (addr.startsWith('https://') || addr.startsWith('tls://') || addr.startsWith('quic://') || addr.startsWith('sdns://')) {
        return true;
    }
    // Test the base address part, ignoring potential ports
    const baseAddr = addr.split(':')[0];
    if (IPV4_REGEX.test(addr) || IPV6_REGEX.test(addr) || HOSTNAME_REGEX.test(baseAddr)) {
        return true;
    }
    const hostnamePart = addr.split(':')[0];
    if (HOSTNAME_REGEX.test(hostnamePart)) {
        return true;
    }
    return false;
}

/**
 * Generates a deduplication key for a DNS address by removing its port, if present.
 * This allows 'dns.example.com' and 'dns.example.com:853' to be treated as the same entry.
 * @param {string} address The DNS address.
 * @returns {string} The address without the port, used as a key.
 */
function getAddressKey(address) {
    try {
        if (address.startsWith('https://') || address.startsWith('tls://') || address.startsWith('quic://')) {
            const url = new URL(address);
            return `${url.protocol}//${url.hostname}${url.pathname}${url.search}${url.hash}`;
        }
    } catch (e) { /* Not a standard URL, continue. */ }

    if (address.startsWith('sdns://')) {
        return address;
    }

    const bracketedIpv6Match = address.match(/^(\[.*\]):[0-9]+$/);
    if (bracketedIpv6Match) {
        return bracketedIpv6Match[1];
    }

    const lastColonIndex = address.lastIndexOf(':');
    // Check if there is a colon, it's not the first character, and the base doesn't have a colon (to avoid IPv6).
    if (lastColonIndex > 0 && !address.substring(0, lastColonIndex).includes(':')) {
        const portPart = address.substring(lastColonIndex + 1);
        if (/^[0-9]+$/.test(portPart)) {
            return address.substring(0, lastColonIndex);
        }
    }
    
    return address;
}


/**
 * Categorizes a list of server objects into different sets based on their properties.
 * This version ensures protocol-specific lists (DoH, DoT, etc.) only contain addresses
 * with the correct URI scheme prefix. It also de-duplicates servers that are identical
 * except for the port number.
 * @param {Array<object>} servers - The list of server objects to categorize.
 * @returns {object} An object containing sets of categorized addresses.
 */
function categorizeServers(servers) {
    const sets = {
        all: new Set(), doh: new Set(), dot: new Set(), doq: new Set(), doh3: new Set(), dnscrypt: new Set(),
        adblock: new Set(), malware: new Set(), family: new Set(),
        unfiltered: new Set(), ipv4: new Set(), ipv6: new Set(), dns64: new Set(),
        no_log: new Set(), dnssec: new Set(),
    };
    
    // Use a helper Set to track processed address keys for de-duplication.
    const processedKeys = new Set();

    for (const server of servers) {
        for (const address of server.addresses) {
            const cleanedAddress = address.trim();
            if (!isValidDnsAddress(cleanedAddress)) {
                continue;
            }

            // De-duplicate addresses with and without ports.
            const key = getAddressKey(cleanedAddress);
            if (processedKeys.has(key)) {
                continue; // Already added a variant of this address.
            }
            processedKeys.add(key);

            // Add the original, cleaned address to the main lists.
            sets.all.add(cleanedAddress);

            // Strictly categorize protocols based on their required prefix.
            let isUrlBased = false;
            if (cleanedAddress.startsWith('https://')) {
                sets.doh.add(cleanedAddress);
                isUrlBased = true;
            } else if (cleanedAddress.startsWith('tls://')) {
                sets.dot.add(cleanedAddress);
                isUrlBased = true;
            } else if (cleanedAddress.startsWith('quic://')) {
                sets.doq.add(cleanedAddress);
                isUrlBased = true;
            } else if (cleanedAddress.startsWith('sdns://')) {
                sets.dnscrypt.add(cleanedAddress);
                isUrlBased = true;
            }
            
            // Categorize IPs and Hostnames that are not full URLs.
            // This also fixes a bug where IPs with ports were not being categorized.
            if (!isUrlBased) {
                const ipAddrPart = getAddressKey(cleanedAddress).replace(/\[|\]/g, '');
                if (IPV6_REGEX.test(ipAddrPart)) {
                    sets.ipv6.add(cleanedAddress);
                }
                if (IPV4_REGEX.test(ipAddrPart)) {
                    sets.ipv4.add(cleanedAddress);
                }
            }
            
            // This allows hostnames that support DoH3 to be added.
            if (server.protocols.includes('doh3')) sets.doh3.add(cleanedAddress);
            
            // Categorize by server-wide properties (filters, features) for all valid addresses.
            if (server.filters.ads) sets.adblock.add(cleanedAddress);
            if (server.filters.malware) sets.malware.add(cleanedAddress);
            if (server.filters.family) sets.family.add(cleanedAddress);
            if (server.filters.unfiltered) sets.unfiltered.add(cleanedAddress);
            if (server.features.no_log) sets.no_log.add(cleanedAddress);
            if (server.features.dnssec) sets.dnssec.add(cleanedAddress);
            if (server.features.dns64) sets.dns64.add(cleanedAddress);
        }
    }
    return sets;
}


// --- MAIN EXECUTION ---
async function main() {
    console.log('🚀 [شروع] فرآیند جمع‌آوری و به‌روزرسانی لیست‌های DNS آغاز شد.');
    let allServers = [];
    const listFileCounts = {};

    if (!fs.existsSync(OUTPUT_DIR)) fs.mkdirSync(OUTPUT_DIR);
    if (!fs.existsSync(SOURCES_DIR)) fs.mkdirSync(SOURCES_DIR);

    for (const source of SOURCES) {
        let content = null;
        if (source.url) {
            console.log(`\n📥 [دریافت] در حال دریافت اطلاعات از منبع: ${source.name}`);
            content = await fetchData(source.url);
        } else {
            console.log(`\n📥 [شروع پردازشگر خود-واکشی] منبع: ${source.name}`);
        }
        
        if (content !== null || source.url === null) {
            console.log(`  🔬 [پردازش] در حال تجزیه و تحلیل محتوای دریافت شده از ${source.name}...`);
            try {
                const parsedServers = await Promise.resolve(source.parser(content));
                if (!parsedServers || parsedServers.length === 0) {
                     console.warn(`  ⚠️ [هشدار] هیچ سروری از منبع ${source.name} استخراج نشد.`);
                } else {
                    // Add servers to the final aggregation list ONLY if the source is not Blacklantern
                    if (source.name !== 'Blacklantern') {
                        allServers.push(...parsedServers);
                    }
                    
                    console.log(`  ✅ [موفقیت] تعداد ${parsedServers.length} گروه سرور از ${source.name} با موفقیت استخراج شد.`);
                    
                    console.log(`  💾 [نوشتن فایل‌های منبع: ${source.name}] در حال تولید فایل‌های خروجی...`);
                    const sourceDir = path.join(SOURCES_DIR, source.name);
                    if (!fs.existsSync(sourceDir)) fs.mkdirSync(sourceDir);

                    const sourceSets = categorizeServers(parsedServers);
                    for (const [listName, addressSet] of Object.entries(sourceSets)) {
                        if(addressSet.size > 0) {
                            const sortedList = Array.from(addressSet).sort();
                            const fileName = `${listName}.txt`;
                            listFileCounts[`${source.name}/${fileName}`] = sortedList.length;
                            const filePath = path.join(sourceDir, fileName);
                            fs.writeFileSync(filePath, sortedList.join('\n'));
                            console.log(`    📄 فایل ${filePath} با ${sortedList.length} آدرس نوشته شد.`);
                        }
                    }
                }
            } catch (error) {
                console.error(`  ❌ [خطای پردازش] تجزیه محتوای ${source.name} با خطای جدی مواجه شد: ${error.message}\n${error.stack}`);
            }
        }
    }
    
    console.log('\n- - - - - - - - - - - - - - - - - - - - - -');
    console.log('\n📊 [تجمیع نهایی] در حال ترکیب و پاک‌سازی تمام داده‌ها...');
    const aggregatedSets = categorizeServers(allServers);

    console.log('\n💾 [نوشتن فایل‌های تجمیعی] در حال تولید و ذخیره فایل‌های خروجی اصلی...');
    for (const [listName, addressSet] of Object.entries(aggregatedSets)) {
        if(listName !== 'all') {
            const sortedList = Array.from(addressSet).sort();
            const fileName = `${listName}.txt`;
            listFileCounts[fileName] = sortedList.length;
            const filePath = path.join(OUTPUT_DIR, fileName);
            fs.writeFileSync(filePath, sortedList.join('\n'));
            console.log(`  📄 فایل ${filePath} با ${sortedList.length} آدرس منحصر به فرد نوشته شد.`);
        }
    }

    console.log('\n📝 [تولید README] در حال ساخت فایل README.md پویا...');
    const readmeContent = generateReadme(SOURCES, GITHUB_REPO_URL, listFileCounts);
    writeReadme(readmeContent);

    console.log('\n🎉 [پایان] فرآیند با موفقیت به اتمام رسید.');
}

main().catch(error => {
    console.error('\n🚨 [خطای حیاتی] یک خطای پیش‌بینی‌نشده در اجرای اصلی رخ داد:', error);
    process.exit(1);
});
