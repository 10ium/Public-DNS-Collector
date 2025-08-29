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
 * Merges and categorizes a list of server objects into different sets based on their properties.
 * This version aggregates all information for a unique address (across multiple server objects)
 * before categorization to prevent data loss from premature de-duplication. For example, if one
 * source lists an address for 'doh' and another lists the same address for 'doh3', this function
 * ensures the final address is correctly categorized under both.
 * @param {Array<object>} servers - The list of server objects to categorize.
 * @returns {object} An object containing sets of categorized addresses.
 */
function categorizeServers(servers) {
    const addressInfoMap = new Map();

    // Step 1: Aggregate all properties for each unique address key.
    for (const server of servers) {
        for (const address of server.addresses) {
            const cleanedAddress = address.trim();
            if (!isValidDnsAddress(cleanedAddress)) {
                continue;
            }

            const key = getAddressKey(cleanedAddress);
            
            // Initialize if it's the first time we see this address key.
            if (!addressInfoMap.has(key)) {
                addressInfoMap.set(key, {
                    originalAddress: cleanedAddress, // Store the first encountered version with port, etc.
                    protocols: new Set(),
                    filters: { ads: false, malware: false, family: false, unfiltered: false },
                    features: { no_log: false, dnssec: false, dns64: false },
                });
            }

            const info = addressInfoMap.get(key);

            // Merge properties from the current server object.
            server.protocols.forEach(p => info.protocols.add(p));
            
            if (server.filters.ads) info.filters.ads = true;
            if (server.filters.malware) info.filters.malware = true;
            if (server.filters.family) info.filters.family = true;
            if (server.filters.unfiltered) info.filters.unfiltered = true;

            if (server.features.no_log) info.features.no_log = true;
            if (server.features.dnssec) info.features.dnssec = true;
            if (server.features.dns64) info.features.dns64 = true;
        }
    }

    // Step 2: Populate the final sets from the aggregated data map.
    const sets = {
        all: new Set(), doh: new Set(), dot: new Set(), doq: new Set(), doh3: new Set(), dnscrypt: new Set(),
        adblock: new Set(), malware: new Set(), family: new Set(),
        unfiltered: new Set(), ipv4: new Set(), ipv6: new Set(), dns64: new Set(),
        no_log: new Set(), dnssec: new Set(),
    };

    for (const info of addressInfoMap.values()) {
        const addr = info.originalAddress;
        sets.all.add(addr);

        // Populate protocol sets from aggregated info
        if (info.protocols.has('doh')) sets.doh.add(addr);
        if (info.protocols.has('dot')) sets.dot.add(addr);
        if (info.protocols.has('doq')) sets.doq.add(addr);
        if (info.protocols.has('doh3')) sets.doh3.add(addr);
        if (info.protocols.has('dnscrypt')) sets.dnscrypt.add(addr);

        // Handle plain IP/Hostname addresses (for Do53)
        const isUrlBased = addr.startsWith('https://') || addr.startsWith('tls://') || addr.startsWith('quic://') || addr.startsWith('sdns://');
        if (!isUrlBased) {
            const ipAddrPart = getAddressKey(addr).replace(/\[|\]/g, ''); // Get base IP/host
            if (IPV6_REGEX.test(ipAddrPart)) sets.ipv6.add(addr);
            if (IPV4_REGEX.test(ipAddrPart)) sets.ipv4.add(addr);
        }

        // Populate filter sets
        if (info.filters.ads) sets.adblock.add(addr);
        if (info.filters.malware) sets.malware.add(addr);
        if (info.filters.family) sets.family.add(addr);
        
        // An address is only 'unfiltered' if it has no filtering flags AND
        // at least one source explicitly marked it as unfiltered.
        if (!info.filters.ads && !info.filters.malware && !info.filters.family && info.filters.unfiltered) {
             sets.unfiltered.add(addr);
        }

        // Populate feature sets
        if (info.features.no_log) sets.no_log.add(addr);
        if (info.features.dnssec) sets.dnssec.add(addr);
        if (info.features.dns64) sets.features.dns64.add(addr);
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
