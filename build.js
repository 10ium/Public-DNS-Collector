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

// --- UTILITY FUNCTIONS ---
const IPV4_REGEX = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;

/**
 * Generates a unique key for a server based on its protocol and address (ignoring port).
 * This is the core of the de-duplication logic.
 * @param {string} protocol The protocol (e.g., 'doh', 'dot', 'unspecified' for plain IPs).
 * @param {string} address The full address string.
 * @returns {string|null} A unique key or null if the address is invalid.
 */
function generateServerKey(protocol, address) {
    let baseAddress = address.trim();
    try {
        if (baseAddress.startsWith('https://') || baseAddress.startsWith('tls://') || baseAddress.startsWith('quic://')) {
            const url = new URL(baseAddress);
            baseAddress = `${url.hostname}${url.pathname}${url.search}${url.hash}`.replace(/\/$/, "");
        } else if (baseAddress.startsWith('sdns://')) {
            return `dnscrypt:${baseAddress}`; // Ensure protocol is part of the key for sdns
        } else {
            const bracketedMatch = baseAddress.match(/^\[(.+)\](?::\d+)?$/);
            if (bracketedMatch) {
                baseAddress = bracketedMatch[1]; // IPv6
            } else {
                baseAddress = baseAddress.split(':')[0]; // IPv4 or hostname
            }
        }
        return `${protocol}:${baseAddress}`;
    } catch (e) {
        return null;
    }
}


/**
 * Aggregates servers, de-duplicates them, merges properties, and categorizes them.
 * @param {Array<object>} servers The array of all server objects.
 * @returns {object} An object containing the categorized sets of addresses.
 */
function aggregateAndCategorizeServers(servers) {
    const uniqueServersMap = new Map();

    for (const server of servers) {
        for (const address of server.addresses) {
            // Treat plain IPs as 'unspecified' protocol for key generation
            const protocols = server.protocols && server.protocols.length > 0 ? server.protocols : ['unspecified'];
            
            for (const protocol of protocols) {
                const key = generateServerKey(protocol, address);
                if (!key) continue;

                if (!uniqueServersMap.has(key)) {
                    uniqueServersMap.set(key, {
                        originalAddress: address,
                        protocol: protocol,
                        filters: { ...server.filters },
                        features: { ...server.features },
                        isIPv4: protocol === 'unspecified' && IPV4_REGEX.test(address.split(':')[0])
                    });
                } else {
                    const existing = uniqueServersMap.get(key);
                    Object.keys(server.filters).forEach(k => { if (server.filters[k]) existing.filters[k] = true; });
                    Object.keys(server.features).forEach(k => { if (server.features[k]) existing.features[k] = true; });
                }
            }
        }
    }

    const sets = {
        all: new Set(), doh: new Set(), dot: new Set(), doq: new Set(), doh3: new Set(), dnscrypt: new Set(),
        udp: new Set(), tcp: new Set(), ipv4: new Set(), ipv6: new Set(),
        adblock: new Set(), malware: new Set(), family: new Set(), unfiltered: new Set(),
        no_log: new Set(), dnssec: new Set(), dns64: new Set()
    };

    for (const info of uniqueServersMap.values()) {
        const transformedAddresses = [];
        if (info.isIPv4) {
            // Handle plain IPv4: add to ipv4.txt, and add transformed versions for other lists
            sets.ipv4.add(info.originalAddress);
            transformedAddresses.push(`udp://${info.originalAddress}`, `tcp://${info.originalAddress}`);
        } else {
            // For all other protocols, use the original address
            transformedAddresses.push(info.originalAddress);
        }

        for (const addr of transformedAddresses) {
            sets.all.add(addr);

            // Add to protocol-specific sets
            if (addr.startsWith('udp://')) sets.udp.add(addr);
            if (addr.startsWith('tcp://')) sets.tcp.add(addr);
            if (info.protocol === 'doh') sets.doh.add(addr);
            if (info.protocol === 'doh3') sets.doh3.add(addr);
            if (info.protocol === 'dot') sets.dot.add(addr);
            if (info.protocol === 'doq') sets.doq.add(addr);
            if (info.protocol === 'dnscrypt') sets.dnscrypt.add(addr);
            if (info.protocol === 'ipv6') sets.ipv6.add(addr);

            // Add to filter/feature sets
            if (info.filters.ads) sets.adblock.add(addr);
            if (info.filters.malware) sets.malware.add(addr);
            if (info.filters.family) sets.family.add(addr);
            if (info.filters.unfiltered) sets.unfiltered.add(addr);
            if (info.features.no_log) sets.no_log.add(addr);
            if (info.features.dnssec) sets.dnssec.add(addr);
            if (info.features.dns64) sets.dns64.add(addr);
        }
    }

    return sets;
}


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
                     continue;
                }

                if (source.name === 'Blacklantern') {
                    const sourceDir = path.join(SOURCES_DIR, source.name);
                    if (!fs.existsSync(sourceDir)) fs.mkdirSync(sourceDir);
                    const plainAddresses = (parsedServers[0]?.addresses || []).sort();
                    if (plainAddresses.length > 0) {
                        fs.writeFileSync(path.join(sourceDir, 'all.txt'), plainAddresses.join('\n'));
                        listFileCounts[`${source.name}/all.txt`] = plainAddresses.length;
                        fs.writeFileSync(path.join(sourceDir, 'ipv4.txt'), plainAddresses.join('\n'));
                        listFileCounts[`${source.name}/ipv4.txt`] = plainAddresses.length;
                        const udpList = plainAddresses.map(ip => `udp://${ip}`);
                        fs.writeFileSync(path.join(sourceDir, 'udp.txt'), udpList.join('\n'));
                        listFileCounts[`${source.name}/udp.txt`] = udpList.length;
                        const tcpList = plainAddresses.map(ip => `tcp://${ip}`);
                        fs.writeFileSync(path.join(sourceDir, 'tcp.txt'), tcpList.join('\n'));
                        listFileCounts[`${source.name}/tcp.txt`] = tcpList.length;
                        console.log(`    📄 فایل‌های ویژه منبع ${source.name} نوشته شدند.`);
                    }
                    allServers.push(...parsedServers);
                    continue; 
                }

                allServers.push(...parsedServers);
                console.log(`  ✅ [موفقیت] تعداد ${parsedServers.length} گروه سرور از ${source.name} با موفقیت استخراج شد.`);
                const sourceDir = path.join(SOURCES_DIR, source.name);
                if (!fs.existsSync(sourceDir)) fs.mkdirSync(sourceDir);
                const sourceSets = aggregateAndCategorizeServers(parsedServers);
                for (const [listName, addressSet] of Object.entries(sourceSets)) {
                    if(addressSet.size > 0) {
                        const sortedList = Array.from(addressSet).sort();
                        fs.writeFileSync(path.join(sourceDir, `${listName}.txt`), sortedList.join('\n'));
                        listFileCounts[`${source.name}/${listName}.txt`] = sortedList.length;
                    }
                }
            } catch (error) {
                console.error(`  ❌ [خطای پردازش] تجزیه محتوای ${source.name} با خطای جدی مواجه شد: ${error.message}\n${error.stack}`);
            }
        }
    }
    
    console.log('\n- - - - - - - - - - - - - - - - - - - - - -');
    console.log('\n📊 [تجمیع نهایی] در حال ترکیب، پاک‌سازی هوشمند و دسته‌بندی تمام داده‌ها...');
    const aggregatedSets = aggregateAndCategorizeServers(allServers);

    console.log('\n💾 [نوشتن فایل‌های تجمیعی] در حال تولید و ذخیره فایل‌های خروجی اصلی...');
    for (const [listName, addressSet] of Object.entries(aggregatedSets)) {
        if (addressSet.size > 0) {
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
