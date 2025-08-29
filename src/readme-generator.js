import fs from 'fs';
import path from 'path';

// --- CONFIGURATION ---
const README_PATH = path.join(process.cwd(), 'README.md');
const LIST_DIR_URL = (repoUrl, listName) => `${repoUrl}/blob/main/lists/${listName}.txt`;
const RAW_LIST_DIR_URL = (listName) => `https://raw.githubusercontent.com/${process.env.GITHUB_REPOSITORY}/main/lists/${listName}.txt`;
const SOURCE_LIST_DIR_URL = (repoUrl, sourceName, listName) => `${repoUrl}/blob/main/lists/sources/${sourceName}/${listName}.txt`;

// --- DATA ---
// Combine all list categories into a single array for a unified table
const AGGREGATED_LISTS = [
    'all', 'doh', 'dot', 'doq', 'dnscrypt', 'ipv4', 'ipv6',
    'adblock', 'malware', 'family', 'unfiltered',
    'dnssec', 'no_log', 'dns64'
];

// Re-add the individual lists here for the source-specific table generation logic
const PRIMARY_LISTS = ['all', 'doh', 'dot', 'doq', 'dnscrypt', 'ipv4', 'ipv6'];
const FILTER_LISTS = ['adblock', 'malware', 'family', 'unfiltered'];
const FEATURE_LISTS = ['dnssec', 'no_log', 'dns64'];


const LIST_DESCRIPTIONS = {
    'all': 'لیست جامع تمام DNS ها از همه منابع و پروتکل‌ها.',
    'doh': 'سرورهای DNS over HTTPS (DoH)',
    'dot': 'سرورهای DNS over TLS (DoT)',
    'doq': 'سرورهای DNS over QUIC (DoQ)',
    'dnscrypt': 'سرورهای DNSCrypt',
    'ipv4': 'سرورهای DNS سنتی IPv4',
    'ipv6': 'سرورهای DNS سنتی IPv6',
    'adblock': 'مسدودکننده تبلیغات',
    'malware': 'مسدودکننده بدافزارها و فیشینگ',
    'family': 'محافظت از خانواده (مسدودکننده محتوای بزرگسالان)',
    'unfiltered': 'بدون فیلتر',
    'dnssec': 'پشتیبانی از DNSSEC',
    'no_log': 'ادعای عدم ثبت لاگ (No-Log Policy)',
    'dns64': 'پشتیبانی از DNS64',
};

// --- TABLE GENERATION HELPERS ---
function generateMarkdownTable(headers, rows) {
    let table = `| ${headers.join(' | ')} |\n`;
    table += `| ${headers.map(() => '---').join(' | ')} |\n`;
    rows.forEach(row => {
        table += `| ${row.join(' | ')} |\n`;
    });
    return table;
}

function generateListRows(listNames, repoUrl, listFileCounts) {
    return listNames
        .map(list => {
            const fileName = `${list}.txt`;
            const count = listFileCounts[fileName] || 0;
            if (count === 0) return null;
            const description = LIST_DESCRIPTIONS[list] || 'لیست سفارشی';
            const fileUrl = LIST_DIR_URL(repoUrl, list);
            const rawUrl = RAW_LIST_DIR_URL(list);
            return [`**${list}**`, description, `[${count}](${fileUrl})`, `[لینک خام](${rawUrl})`];
        })
        .filter(Boolean); // Remove null entries for empty lists
}

function generateSourceListRows(sources, repoUrl, listFileCounts) {
    const rows = [];
    sources.forEach(source => {
        const sourceName = source.name;
        const sourceLink = source.readmeUrl ? `[${sourceName}](${source.readmeUrl})` : sourceName;
        let isFirstRowForSource = true;

        // Note: The logic for source-specific tables still needs the categorized lists
        const allListsForSourceTable = [...PRIMARY_LISTS, ...FILTER_LISTS, ...FEATURE_LISTS];
        allListsForSourceTable.forEach(list => {
            const fileName = `${sourceName}/${list}.txt`;
            const count = listFileCounts[fileName] || 0;
            if (count > 0) {
                const fileUrl = SOURCE_LIST_DIR_URL(repoUrl, sourceName, list);
                const description = LIST_DESCRIPTIONS[list] || 'لیست سفارشی';
                rows.push([
                    isFirstRowForSource ? sourceLink : '',
                    `**${list}**`,
                    description,
                    `[${count}](${fileUrl})`
                ]);
                isFirstRowForSource = false;
            }
        });
    });
    return rows;
}


// --- MAIN README GENERATOR ---
export function generateReadme(sources, repoUrl, listFileCounts) {
    const lastUpdated = new Date().toUTCString();

    const aggregatedRows = generateListRows(AGGREGATED_LISTS, repoUrl, listFileCounts);
    const sourceRows = generateSourceListRows(sources, repoUrl, listFileCounts);
    
    const sourcesList = sources.map(source => {
        const url = source.readmeUrl || source.url;
        return url ? `* [${source.name}](${url})` : `* ${source.name}`;
    }).join('\n');

    return `<div align="center">

# 🛡️ Public DNS Collector 🛡️
### لیست‌های عمومی DNS جمع‌آوری شده

</div>

---

این مخزن به طور خودکار لیستی از سرورهای DNS عمومی را از منابع مختلف معتبر جمع‌آوری، پاک‌سازی و تجمیع می‌کند.

*آخرین به‌روزرسانی: \`${lastUpdated}\`*

## لیست‌های تجمیعی (Aggregated Lists)

این لیست‌ها نتیجه ترکیب، پاک‌سازی و حذف موارد تکراری از تمام منابع هستند.

${generateMarkdownTable(['نام لیست', 'توضیحات', 'تعداد', 'لینک دانلود'], aggregatedRows)}

## لیست‌های مبتنی بر منبع (Source-Specific Lists)

این لیست‌ها حاوی سرورهای استخراج شده از هر منبع به صورت جداگانه هستند.

${generateMarkdownTable(['منبع', 'نام لیست', 'توضیحات', 'تعداد'], sourceRows)}

## منابع داده (Data Sources)
${sourcesList}

## مشارکت
این پروژه توسط اسکریپت‌ها به طور خودکار به‌روز می‌شود. اگر منبع جدیدی می‌شناسید یا در فرآیند استخراج مشکلی مشاهده کردید، لطفاً یک [Issue](https://github.com/10ium/Public-DNS-Collector/issues) ثبت کنید.
`;
}

export function writeReadme(content) {
    try {
        fs.writeFileSync(README_PATH, content);
        console.log(`✅ فایل README.md با موفقیت به‌روز شد.`);
    } catch (error) {
        console.error(`❌ [خطا] نوشتن فایل README.md با شکست مواجه شد: ${error.message}`);
    }
}
