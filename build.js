import fs from 'fs';
import path from 'path';
import { fetchData } from './src/utils.js';
import * as parsers from './src/parsers/index.js';

// --- CONFIGURATION ---
const OUTPUT_DIR = 'lists';
// The master list of sources, now pointing to their respective modular parsers.
const SOURCES = [
    { name: 'DNSCrypt', url: 'https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/refs/heads/master/v3/public-resolvers.md', parser: parsers.parseDNSCrypt },
    { name: 'Paulmillr', url: 'https://raw.githubusercontent.com/paulmillr/encrypted-dns/refs/heads/master/README.md', parser: parsers.parsePaulmillr },
    { name: 'Blacklantern', url: 'https://raw.githubusercontent.com/blacklanternsecurity/public-dns-servers/refs/heads/master/nameservers.txt', parser: parsers.parseBlacklantern },
    { name: 'MutinSA', url: 'https://gist.githubusercontent.com/mutin-sa/5dcbd35ee436eb629db7872581093bc5/raw/', parser: parsers.parseMutinSA },
    { name: 'AdGuard', url: 'https://adguard-dns.io/kb/general/dns-providers/', parser: parsers.parseAdGuard },
    { name: 'Mullvad', url: 'https://mullvad.net/en/help/dns-over-https-and-dns-over-tls', parser: parsers.parseMullvad },
    { name: 'DNSPrivacyOrg', url: 'https://dnsprivacy.org/public_resolvers/', parser: parsers.parseDnsPrivacyOrg },
    { name: 'Curl', url: 'https://raw.githubusercontent.com/wiki/curl/curl/DNS-over-HTTPS.md', parser: parsers.parseCurl },
    { name: 'Thiagozs', url: 'https://gist.githubusercontent.com/thiagozs/088fd8f8129ca06df524f6711116ee8f/raw/', parser: parsers.parseThiagozs },
];

// --- MAIN EXECUTION ---
async function main() {
    console.log('🚀 [شروع] فرآیند جمع‌آوری و به‌روزرسانی لیست‌های DNS آغاز شد.');
    let allServers = [];

    // Step 1 & 2: Fetch and Parse all sources by iterating through the configuration
    for (const source of SOURCES) {
        console.log(`\n📥 [دریافت] در حال دریافت اطلاعات از منبع: ${source.name}`);
        const content = await fetchData(source.url);
        
        if (content) {
            console.log(`  🔬 [پردازش] در حال تجزیه و تحلیل محتوای دریافت شده از ${source.name}...`);
            try {
                // Await the parser, wrapping with Promise.resolve to handle both sync/async parsers
                const parsedServers = await Promise.resolve(source.parser(content));
                if (parsedServers.length === 0) {
                    console.warn(`  ⚠️ [هشدار] هیچ سروری از منبع ${source.name} استخراج نشد. ممکن است ساختار منبع تغییر کرده باشد.`);
                } else {
                    allServers.push(...parsedServers);
                    console.log(`  ✅ [موفقیت] تعداد ${parsedServers.length} گروه سرور از ${source.name} با موفقیت استخراج شد.`);
                }
            } catch (error) {
                console.error(`  ❌ [خطای پردازش] تجزیه محتوای ${source.name} با خطای جدی مواجه شد: ${error.message}\n${error.stack}`);
            }
        }
    }
    
    console.log(`\n📊 [تجمیع] مجموعاً ${allServers.length} گروه سرور از تمام منابع جمع‌آوری شد.`);
    console.log('  🧹 [پاک‌سازی] در حال حذف موارد تکراری و دسته‌بندی آدرس‌ها...');

    // Step 3 & 4: Deduplicate, Generate, and Write files including the new lists
    const addressSets = {
        doh: new Set(),
        dot: new Set(),
        dnscrypt: new Set(),
        adblock: new Set(),
        malware: new Set(),
        family: new Set(),
        unfiltered: new Set(),
        ipv4: new Set(),
        ipv6: new Set(),
        no_log: new Set(),
        dnssec: new Set(),
    };

    for (const server of allServers) {
        for (const address of server.addresses) {
            const cleanedAddress = address.trim();
            if (!cleanedAddress) continue;

            // Categorize by encrypted protocol
            if (server.protocols.includes('doh') && cleanedAddress.startsWith('https://')) addressSets.doh.add(cleanedAddress);
            if (server.protocols.includes('dot') && !cleanedAddress.startsWith('https://') && !cleanedAddress.startsWith('sdns://')) addressSets.dot.add(cleanedAddress);
            if (server.protocols.includes('dnscrypt') && cleanedAddress.startsWith('sdns://')) addressSets.dnscrypt.add(cleanedAddress);

            // Categorize by filter type (only for servers with known encrypted protocols)
            if (server.protocols.length > 0) {
                if (server.filters.ads) addressSets.adblock.add(cleanedAddress);
                if (server.filters.malware) addressSets.malware.add(cleanedAddress);
                if (server.filters.family) addressSets.family.add(cleanedAddress);
                if (server.filters.unfiltered) addressSets.unfiltered.add(cleanedAddress);
            }

            // Categorize by features (for any server type)
            if (server.features.no_log) addressSets.no_log.add(cleanedAddress);
            if (server.features.dnssec) addressSets.dnssec.add(cleanedAddress);

            // Categorize by IP version
            if (/:/.test(cleanedAddress) || server.features.ipv6) addressSets.ipv6.add(cleanedAddress);
            if (/^\d{1,3}(\.\d{1,3}){3}$/.test(cleanedAddress)) addressSets.ipv4.add(cleanedAddress);
        }
    }
    
    // Refine the ipv4 list to ensure it only contains plain DNS servers
    const encryptedAddresses = new Set([...addressSets.doh, ...addressSets.dot, ...addressSets.dnscrypt]);
    const plainIPv4s = new Set();
    for(const ip of addressSets.ipv4) {
        // A plain DNS server might have the same IP as a DoH/DoT server's base, but it's a different service.
        // We only add IPs that are explicitly from non-encrypted sources.
        const sourceServer = allServers.find(s => s.addresses.includes(ip));
        if (sourceServer && sourceServer.protocols.length === 0) {
            plainIPv4s.add(ip);
        }
    }
    addressSets.ipv4 = plainIPv4s;


    // Ensure output directory exists
    if (!fs.existsSync(OUTPUT_DIR)) {
        fs.mkdirSync(OUTPUT_DIR);
    }
    
    // Write files
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
