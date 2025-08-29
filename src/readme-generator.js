import fs from 'fs';

/**
 * Generates the content for the README.md file with a dynamic and nested structure.
 * @param {object} sources - The list of source objects with names and URLs.
 * @param {string} repoUrl - The URL of the GitHub repository.
 * @param {object} listFileCounts - An object containing counts for all generated files.
 * @returns {string} The complete Markdown content for the README file.
 */
export function generateReadme(sources, repoUrl, listFileCounts) {
    // A map for providing descriptions for known list types.
    const DESCRIPTIONS = {
        'all.txt': 'لیست جامع تمام دی ان اس ها از همه منابع و پروتکل‌ها',
        'doh.txt': 'لیست تمام سرورهای دی ان اس روی اچ تی تی پی اس',
        'dot.txt': 'لیست تمام سرورهای دی ان اس روی تی ال اس',
        'doq.txt': 'لیست تمام سرورهای دی ان اس روی کوییک',
        'doh3.txt': 'لیست تمام سرورهای دی ان اس روی اچ تی تی پی اس 3',
        'dnscrypt.txt': 'لیست تمام سرورهای دی ان اس کریپت',
        'ipv4.txt': 'لیست سرورهای دی ان اس استاندارد روی آی‌پی‌وی۴',
        'ipv6.txt': '۶لیست سرورهای دی ان اس استاندارد روی آی‌پی‌وی',
        'dns64.txt': 'لیست سرورهایی که از دی‌ان‌اس۶۴ پشتیبانی می‌کنند',
        'adblock.txt': 'لیست سرورهایی که تبلیغات را مسدود می‌کنند',
        'malware.txt': 'لیست سرورهایی که از بدافزار و فیشینگ جلوگیری می‌کنند',
        'family.txt': 'لیست سرورهایی با فیلترینگ خانواده (محتوای بزرگسالان)',
        'unfiltered.txt': 'لیست سرورهای بدون فیلترینگ خاص',
        'no_log.txt': 'لیست سرورهایی که ادعا می‌کنند لاگ کاربران را ذخیره نمی‌کنند',
        'dnssec.txt': 'لیست سرورهایی که از دی ان اس سک برای افزایش امنیت پشتیبانی می‌کنند',
    };

    // A preferred order for displaying main lists to keep the README consistent.
    const PREFERRED_MAIN_LIST_ORDER = [
        'all.txt', 'doh.txt', 'dot.txt', 'doq.txt', 'doh3.txt', 'dnscrypt.txt',
        'ipv4.txt', 'ipv6.txt',
        'adblock.txt', 'malware.txt', 'family.txt', 'unfiltered.txt',
        'no_log.txt', 'dnssec.txt', 'dns64.txt'
    ];

    const updateDate = new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC';

    let markdown = `# مجموعه DNS عمومی | Public DNS Collector\n\n`;
    markdown += `<p align="center">\n  <img src="https://www.svgrepo.com/show/491884/dns.svg" alt="Public DNS Collector Banner" width="200">\n</p>\n`;
    markdown += `<div align="center">\n\n**یک مخزن جامع برای جمع‌آوری، تجمیع و به‌روزرسانی خودکار لیست‌های DNS عمومی از منابع معتبر.**\n<br />\nاین پروژه توسط GitHub Actions به صورت هفتگی اجرا شده و لیست‌های زیر را به‌روز می‌کند.\n<br />\n<br />\n\n`;
    markdown += `**آخرین بروزرسانی:** ${updateDate}\n<br />\n<br />\n\n`;
    markdown += `[![GitHub last commit](https://img.shields.io/github/last-commit/${process.env.GITHUB_REPOSITORY}?style=for-the-badge&logo=github&color=blue)](https://github.com/${process.env.GITHUB_REPOSITORY}/commits/main)\n`;
    markdown += `[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/${process.env.GITHUB_REPOSITORY}/update-lists.yml?branch=main&style=for-the-badge&logo=githubactions&logoColor=white)](https://github.com/${process.env.GITHUB_REPOSITORY}/actions)\n`;
    markdown += `[![License](https://img.shields.io/github/license/${process.env.GITHUB_REPOSITORY}?style=for-the-badge&color=brightgreen)](LICENSE)\n\n</div>\n\n---\n\n`;

    markdown += `## 🗂️ لیست‌های تجمیع شده نهایی\n\n`;
    markdown += `این لیست‌ها حاصل ترکیب، پاک‌سازی و دسته‌بندی داده‌ها از **تمام منابعی که برای تجمیع فعال هستند** می‌باشند و برای استفاده عمومی توصیه می‌شوند.\n\n`;
    markdown += `| نام فایل | تعداد آدرس‌ها | توضیحات | لینک خام |\n`;
    markdown += `| :--- | :---: | ---: | :---: |\n`;

    // Dynamically discover main list files from listFileCounts
    const mainFiles = Object.keys(listFileCounts)
        .filter(key => !key.includes('/'))
        .sort((a, b) => {
            const indexA = PREFERRED_MAIN_LIST_ORDER.indexOf(a);
            const indexB = PREFERRED_MAIN_LIST_ORDER.indexOf(b);
            if (indexA !== -1 && indexB !== -1) return indexA - indexB; // Both are in preferred order
            if (indexA !== -1) return -1; // a is preferred, b is not
            if (indexB !== -1) return 1;  // b is preferred, a is not
            return a.localeCompare(b); // Neither is preferred, sort alphabetically
        });

    mainFiles.forEach(fileName => {
        const count = listFileCounts[fileName] || 0;
        const description = DESCRIPTIONS[fileName] || `لیست خودکار تولید شده برای ${fileName.replace('.txt', '')}.`;
        const rawUrl = `${repoUrl}/raw/main/lists/${fileName}`;
        markdown += `| \`${fileName}\` | **${count}** | ${description} | [لینک](${rawUrl}) |\n`;
    });
    markdown += `\n---\n\n`;

    markdown += `##  لیست‌ها بر اساس منبع | Lists by Source\n\n`;
    markdown += "در این بخش، خروجی‌های هر منبع به صورت جداگانه و فیلتر شده قرار دارند. هر منبع دارای یک فایل `all.txt` (شامل تمام آدرس‌های استخراج شده از آن منبع) و سپس لیست‌های فیلتر شده بر اساس پروتکل و ویژگی‌ها است.\n\n";

    sources.forEach(source => {
        markdown += `<details>\n<summary><h3>📂 ${source.name}</h3></summary>\n\n`;
        markdown += `| نام فایل | تعداد آدرس‌ها | لینک خام |\n`;
        markdown += `| :--- | :---: | :---: |\n`;
        
        // Dynamically discover source-specific files
        const sourceFiles = Object.keys(listFileCounts)
            .filter(key => key.startsWith(`${source.name}/`))
            .map(key => key.split('/')[1]) // get just the filename
            .sort((a, b) => {
                if (a === 'all.txt') return -1; // always list 'all.txt' first
                if (b === 'all.txt') return 1;
                return a.localeCompare(b); // sort others alphabetically
            });

        sourceFiles.forEach(fileName => {
            const fileKey = `${source.name}/${fileName}`;
            const count = listFileCounts[fileKey];
            const rawUrl = `${repoUrl}/raw/main/lists/sources/${source.name}/${fileName}`;
            markdown += `| \`${fileName}\` | **${count}** | [لینک](${rawUrl}) |\n`;
        });
        markdown += `\n</details>\n\n`;
    });
    
    markdown += `---\n\n## 📚 منابع اصلی داده‌ها\n\n`;
    sources.forEach(source => {
        const link = source.readmeUrl || source.url; // Use readmeUrl if available, otherwise fallback to url
        if (link) {
            markdown += `- **[${source.name}](${link})**\n`;
        } else {
             markdown += `- **${source.name}** (پردازشگر داخلی)\n`;
        }
    });
    markdown += `\n---\n`;
    markdown += `<p align="center">ساخته شده با ❤️ و به صورت خودکار توسط GitHub Actions</p>\n`;
    
    return markdown;
}

/**
 * Writes the generated README content to the README.md file.
 * @param {string} content - The Markdown content to write.
 */
export function writeReadme(content) {
    fs.writeFileSync('README.md', content);
    console.log('  📄 فایل README.md با موفقیت ایجاد/به‌روزرسانی شد.');
}
