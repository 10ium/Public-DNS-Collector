import fs from 'fs';
import path from 'path';
import { fetchData } from './src/utils.js';
import * as parsers from './src/parsers/index.js';

// --- CONFIGURATION ---
const OUTPUT_DIR = 'lists';
const SOURCES_DIR = path.join(OUTPUT_DIR, 'sources');
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
    const serversBySource = {}; // Object to hold servers for each source

    // Step 1 & 2: Fetch and Parse all sources
    for (const source of SOURCES) {
        console.log(`\n📥 [دریافت] در حال دریافت اطلاعات از منبع: ${source.name}`);
        const content = await fetchData(source.url);
        
        if (content) {
            console.log(`  🔬 [پردازش] در حال تجزیه و تحلیل محتوای دریافت شده از ${source.name}...`);
            try {
                const parsedServers = await Promise.resolve(source.parser(content));
                if (parsedServers.length === 0) {
                    console.warn(`  ⚠️ [هشدار] هیچ سروری از منبع ${source.name} استخراج نشد. ممکن است ساختار منبع تغییر کرده باشد.`);
                    console.log(`  🔍 [اشکال‌زدایی] محتوای خام دریافت شده از ${source.name} که منجر به هشدار شد: \n--- BEGIN CONTENT ---\n${typeof content === 'string' ? content.substring(0, 1000) + '...' : JSON.stringify(content)}\n--- END CONTENT ---`);
                } else {
                    allServers.push(...parsedServers);
                    serversBySource[source.name] = parsedServers; // Store servers for this source
                    console.log(`  ✅ [موفقیت] تعداد ${parsedServers.length} گروه سرور از ${source.name} با موفقیت استخراج شد.`);
                }
            } catch (error) {
                console.error(`  ❌ [خطای پردازش] تجزیه محتوای ${source.name} با خطای جدی مواجه شد: ${error.message}\n${error.stack}`);
            }
        }
    }
    
    console.log(`\n📊 [تجمیع] مجموعاً ${allServers.length} گروه سرور از تمام منابع جمع‌آوری شد.`);
    console.log('  🧹 [پاک‌سازی] در حال حذف موارد تکراری و دسته‌بندی آدرس‌ها...');

    // Step 3 & 4: Deduplicate, Generate, and Write files
    const addressSets = {
        doh: new Set(), dot: new Set(), dnscrypt: new Set(),
        adblock: new Set(), malware: new Set(), family: new Set(),
        unfiltered: new Set(), ipv4: new Set(), ipv6: new Set(),
        no_log: new Set(), dnssec: new Set(),
    };

    for (const server of allServers) {
        for (const address of server.addresses) {
            const cleanedAddress = address.trim();
            if (!cleanedAddress) continue;
            if (server.protocols.includes('doh') && cleanedAddress.startsWith('https://')) addressSets.doh.add(cleanedAddress);
            if (server.protocols.includes('dot') && !cleanedAddress.startsWith('https://') && !cleanedAddress.startsWith('sdns://')) addressSets.dot.add(cleanedAddress);
            if (server.protocols.includes('dnscrypt') && cleanedAddress.startsWith('sdns://')) addressSets.dnscrypt.add(cleanedAddress);
            if (server.protocols.length > 0) {
                if (server.filters.ads) addressSets.adblock.add(cleanedAddress);
                if (server.filters.malware) addressSets.malware.add(cleanedAddress);
                if (server.filters.family) addressSets.family.add(cleanedAddress);
                if (server.filters.unfiltered) addressSets.unfiltered.add(cleanedAddress);
            }
            if (server.features.no_log) addressSets.no_log.add(cleanedAddress);
            if (server.features.dnssec) addressSets.dnssec.add(cleanedAddress);
            if (/:/.test(cleanedAddress) || server.features.ipv6) addressSets.ipv6.add(cleanedAddress);
            if (/^\d{1,3}(\.\d{1,3}){3}$/.test(cleanedAddress)) addressSets.ipv4.add(cleanedAddress);
        }
    }
    
    const encryptedAddresses = new Set([...addressSets.doh, ...addressSets.dot, ...addressSets.dnscrypt]);
    const plainIPv4s = new Set();
    for(const ip of addressSets.ipv4) {
        const sourceServer = allServers.find(s => s.addresses.includes(ip));
        if (sourceServer && sourceServer.protocols.length === 0) {
            plainIPv4s.add(ip);
        }
    }
    addressSets.ipv4 = plainIPv4s;

    // --- Step 5: Write Files ---
    // Ensure output directories exist
    if (!fs.existsSync(OUTPUT_DIR)) fs.mkdirSync(OUTPUT_DIR);
    if (!fs.existsSync(SOURCES_DIR)) fs.mkdirSync(SOURCES_DIR);
    
    // Write aggregated list files
    console.log('\n💾 [نوشتن فایل‌های تجمیعی] در حال تولید و ذخیره فایل‌های خروجی اصلی...');
    for (const [listName, addressSet] of Object.entries(addressSets)) {
        const sortedList = Array.from(addressSet).sort();
        const filePath = path.join(OUTPUT_DIR, `${listName}.txt`);
        fs.writeFileSync(filePath, sortedList.join('\n'));
        console.log(`  📄 فایل ${filePath} با ${sortedList.length} آدرس منحصر به فرد نوشته شد.`);
    }

    // Write per-source files
    console.log('\n💾 [نوشتن فایل‌های منبع] در حال تولید فایل‌های خروجی به تفکیک هر منبع...');
    for (const [sourceName, sourceServers] of Object.entries(serversBySource)) {
        const sourceAddresses = new Set();
        for (const server of sourceServers) {
            for (const address of server.addresses) {
                sourceAddresses.add(address.trim());
            }
        }
        const sortedList = Array.from(sourceAddresses).sort();
        const filePath = path.join(SOURCES_DIR, `${sourceName}.txt`);
        fs.writeFileSync(filePath, sortedList.join('\n'));
        console.log(`  📄 فایل ${filePath} با ${sortedList.length} آدرس منحصر به فرد نوشته شد.`);
    }

    console.log('\n🎉 [پایان] فرآیند با موفقیت به اتمام رسید.');
}

main().catch(error => {
    console.error('\n🚨 [خطای حیاتی] یک خطای پیش‌بینی‌نشده در اجرای اصلی رخ داد:', error);
    process.exit(1);
});
