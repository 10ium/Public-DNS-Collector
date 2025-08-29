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
const IPV6_REGEX = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/i;
const HOSTNAME_REGEX = /^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][a-zA-Z0-9-]*[A-Za-z0-9])$/;

function standardizeIPv6WithPort(address) {
    if (address.startsWith('[') || !address.includes(':') || address.lastIndexOf(':') === address.indexOf(':')) {
        return address;
    }
    const lastColonIndex = address.lastIndexOf(':');
    const base = address.substring(0, lastColonIndex);
    const port = address.substring(lastColonIndex + 1);
    if (/^\d+$/.test(port) && IPV6_REGEX.test(base)) {
        return `[${base}]:${port}`;
    }
    return address;
}

function isValidDnsAddress(address) {
    if (typeof address !== 'string' || address.length === 0) return false;
    const addr = address.trim();
    if (addr.endsWith('::')) return false;
    if (addr.startsWith('https://') || addr.startsWith('tls://') || addr.startsWith('quic://') || addr.startsWith('sdns://')) {
        return true;
    }
    const bracketedMatch = addr.match(/^\[(.+)\](?::(\d+))?$/);
    if (bracketedMatch && IPV6_REGEX.test(bracketedMatch[1])) {
        return true;
    }
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
    const bracketedMatch = address.match(/^(\[.+\]):[0-9]+$/);
    if (bracketedMatch) {
        return bracketedMatch[1];
    }
    const lastColonIndex = address.lastIndexOf(':');
    if (lastColonIndex > 0 && !address.substring(0, lastColonIndex).includes(':')) {
        const portPart = address.substring(lastColonIndex + 1);
        if (/^[0-9]+$/.test(portPart)) {
            return address.substring(0, lastColonIndex);
        }
    }
    return address;
}

function processBlacklanternSource(servers) {
    const sets = {
        all: new Set(),
        ipv4: new Set(),
        tcp: new Set(),
        udp: new Set(),
    };

    for (const server of servers) {
        for (const address of server.addresses) {
            const ip = address.trim();
            if (IPV4_REGEX.test(ip)) {
                sets.ipv4.add(ip);
                const tcpAddr = `tcp://${ip}`;
                const udpAddr = `udp://${ip}`;
                sets.tcp.add(tcpAddr);
                sets.udp.add(udpAddr);
                sets.all.add(tcpAddr);
                sets.all.add(udpAddr);
            }
        }
    }
    return sets;
}

function categorizeServers(servers) {
    const addressInfoMap = new Map();
    for (const server of servers) {
        for (const address of server.addresses) {
            const cleanedAddress = address.trim();
            const standardizedAddress = standardizeIPv6WithPort(cleanedAddress);
            if (!isValidDnsAddress(standardizedAddress)) {
                continue;
            }
            const key = getAddressKey(standardizedAddress);
            if (!addressInfoMap.has(key)) {
                addressInfoMap.set(key, {
                    originalAddress: standardizedAddress,
                    protocols: new Set(),
                    filters: { ads: false, malware: false, family: false, unfiltered: false },
                    features: { no_log: false, dnssec: false, dns64: false },
                });
            }
            const info = addressInfoMap.get(key);
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

    const sets = {
        all: new Set(), doh: new Set(), dot: new Set(), doq: new Set(), doh3: new Set(), dnscrypt: new Set(),
        adblock: new Set(), malware: new Set(), family: new Set(),
        unfiltered: new Set(), ipv4: new Set(), ipv6: new Set(), dns64: new Set(),
        no_log: new Set(), dnssec: new Set(),
        // New sets for tcp and udp
        tcp: new Set(), udp: new Set(),
    };

    for (const info of addressInfoMap.values()) {
        const addr = info.originalAddress;
        sets.all.add(addr);

        // Protocol-specific lists are not changed
        if (info.protocols.has('doh') && addr.startsWith('https://')) sets.doh.add(addr);
        if (info.protocols.has('dot') && addr.startsWith('tls://')) sets.dot.add(addr);
        if (info.protocols.has('doq') && addr.startsWith('quic://')) sets.doq.add(addr);
        if (info.protocols.has('doh3') && addr.startsWith('https://')) sets.doh3.add(addr);
        if (info.protocols.has('dnscrypt') && addr.startsWith('sdns://')) sets.dnscrypt.add(addr);

        const bracketedMatch = addr.match(/^\[(.+)\]/);
        const ipAddrPart = bracketedMatch ? bracketedMatch[1] : getAddressKey(addr).replace(/\[|\]/g, '');
        const isIPv4 = IPV4_REGEX.test(ipAddrPart);

        if (isIPv4) {
            // Populate ipv4.txt with plain, port-less IPs
            sets.ipv4.add(ipAddrPart);
            
            // Create prefixed addresses for new lists and filtering lists
            const tcpAddr = `tcp://${ipAddrPart}`;
            const udpAddr = `udp://${ipAddrPart}`;

            // Populate new tcp.txt and udp.txt lists
            sets.tcp.add(tcpAddr);
            sets.udp.add(udpAddr);

            // For filtering lists, add both tcp and udp prefixed versions for IPv4 servers
            if (info.filters.ads) { sets.adblock.add(tcpAddr); sets.adblock.add(udpAddr); }
            if (info.filters.malware) { sets.malware.add(tcpAddr); sets.malware.add(udpAddr); }
            if (info.filters.family) { sets.family.add(tcpAddr); sets.family.add(udpAddr); }
            if (!info.filters.ads && !info.filters.malware && !info.filters.family && info.filters.unfiltered) {
                sets.unfiltered.add(tcpAddr);
                sets.unfiltered.add(udpAddr);
            }
        } else {
            // For non-IPv4 addresses (DoH, DoT, IPv6 etc.), add them to filtering lists as is.
            if (info.filters.ads) sets.adblock.add(addr);
            if (info.filters.malware) sets.malware.add(addr);
            if (info.filters.family) sets.family.add(addr);
            if (!info.filters.ads && !info.filters.malware && !info.filters.family && info.filters.unfiltered) {
                 sets.unfiltered.add(addr);
            }
        }
        
        // Handle other lists as before
        if (IPV6_REGEX.test(ipAddrPart)) sets.ipv6.add(addr);
        if (info.features.no_log) sets.no_log.add(addr);
        if (info.features.dnssec) sets.dnssec.add(addr);
        if (info.features.dns64) sets.dns64.add(addr);
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
                } else {
                    if (source.name !== 'Blacklantern') {
                        allServers.push(...parsedServers);
                    }
                    console.log(`  ✅ [موفقیت] تعداد ${parsedServers.length} گروه سرور از ${source.name} با موفقیت استخراج شد.`);
                    console.log(`  💾 [نوشتن فایل‌های منبع: ${source.name}] در حال تولید فایل‌های خروجی...`);
                    const sourceDir = path.join(SOURCES_DIR, source.name);
                    if (!fs.existsSync(sourceDir)) fs.mkdirSync(sourceDir);
                    
                    let sourceSets;
                    if (source.name === 'Blacklantern') {
                        sourceSets = processBlacklanternSource(parsedServers);
                    } else {
                        sourceSets = categorizeServers(parsedServers);
                    }
                    
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
    
    // --- SPECIAL: Generate port-less `all.txt` ---
    const portlessUniqueAddresses = new Map();
    for (const server of allServers) {
        for (const address of server.addresses) {
            const cleanedAddress = address.trim();
            const standardizedAddress = standardizeIPv6WithPort(cleanedAddress);
            if (isValidDnsAddress(standardizedAddress)) {
                const key = getAddressKey(standardizedAddress);
                if (!portlessUniqueAddresses.has(key)) {
                    portlessUniqueAddresses.set(key, standardizedAddress);
                }
            }
        }
    }
    const allList = Array.from(portlessUniqueAddresses.values()).sort();
    const allFilePath = path.join(OUTPUT_DIR, 'all.txt');
    fs.writeFileSync(allFilePath, allList.join('\n'));
    listFileCounts['all.txt'] = allList.length;
    console.log(`  📄 فایل ${allFilePath} با ${allList.length} آدرس منحصر به فرد (بدون در نظر گرفتن پورت) نوشته شد.`);
    // --- END SPECIAL ---
    
    for (const [listName, addressSet] of Object.entries(aggregatedSets)) {
        // We already generated the special 'all.txt', so skip the one from `aggregatedSets`.
        if(listName !== 'all' && addressSet.size > 0) {
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
