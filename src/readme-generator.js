import fs from 'fs';

/**
 * Generates the content for the README.md file with a nested structure.
 * @param {object} sources - The list of source objects with names and URLs.
 * @param {string} repoUrl - The URL of the GitHub repository.
 * @param {object} listFileCounts - An object containing counts for all generated files.
 * @returns {string} The complete Markdown content for the README file.
 */
export function generateReadme(sources, repoUrl, listFileCounts) {
    const mainListFiles = [
        { name: 'doh.txt', description: 'لیست تمام سرورهای DNS-over-HTTPS.' },
        { name: 'dot.txt', description: 'لیست تمام سرورهای DNS-over-TLS.' },
        { name: 'dnscrypt.txt', description: 'لیست تمام سرورهای DNSCrypt (به صورت Stamp).' },
        { name: 'ipv4.txt', description: 'لیست سرورهای DNS استاندارد روی IPv4.' },
        { name: 'ipv6.txt', description: 'لیست تمام آدرس‌های IPv6 موجود.' },
        { name: 'adblock.txt', description: 'لیست سرورهایی که تبلیغات را مسدود می‌کنند.' },
        { name: 'malware.txt', description: 'لیست سرورهایی که از بدافزار و فیشینگ جلوگیری می‌کنند.' },
        { name: 'family.txt', description: 'لیست سرورهایی با فیلترینگ خانواده (محتوای بزرگسالان).' },
        { name: 'unfiltered.txt', description: 'لیست سرورهای بدون فیلترینگ خاص.' },
        { name: 'no_log.txt', description: 'لیست سرورهایی که ادعا می‌کنند لاگ کاربران را ذخیره نمی‌کنند.' },
        { name: 'dnssec.txt', description: 'لیست سرورهایی که از DNSSEC برای افزایش امنیت پشتیبانی می‌کنند.' },
    ];

    const sourceSubListFiles = ['all.txt', 'doh.txt', 'dot.txt', 'dnscrypt.txt', 'ipv4.txt', 'ipv6.txt', 'adblock.txt', 'malware.txt', 'family.txt', 'unfiltered.txt', 'no_log.txt', 'dnssec.txt'];

    let markdown = `# مجموعه DNS عمومی | Public DNS Collector\n\n`;
    markdown += `<p align="center">\n  <img src="https://raw.githubusercontent.com/1024-byte/resources/main/banner/Public-DNS-Collector-banner.png" alt="Public DNS Collector Banner">\n</p>\n`;
    markdown += `<div align="center">\n\n**یک مخزن جامع برای جمع‌آوری، تجمیع و به‌روزرسانی خودکار لیست‌های DNS عمومی از منابع معتبر.**\n<br />\nاین پروژه توسط GitHub Actions به صورت هفتگی اجرا شده و لیست‌های زیر را به‌روز می‌کند.\n<br />\n<br />\n\n`;
    markdown += `[![GitHub last commit](https://img.shields.io/github/last-commit/${process.env.GITHUB_REPOSITORY}?style=for-the-badge&logo=github&color=blue)](https://github.com/${process.env.GITHUB_REPOSITORY}/commits/main)\n`;
    markdown += `[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/${process.env.GITHUB_REPOSITORY}/update-lists.yml?branch=main&style=for-the-badge&logo=githubactions&logoColor=white)](https://github.com/${process.env.GITHUB_REPOSITORY}/actions)\n`;
    markdown += `[![License](https://img.shields.io/github/license/${process.env.GITHUB_REPOSITORY}?style=for-the-badge&color=brightgreen)](LICENSE)\n\n</div>\n\n---\n\n`;

    markdown += `## 🗂️ لیست‌های تجمیع شده نهایی\n\n`;
    markdown += `این لیست‌ها حاصل ترکیب، پاک‌سازی و دسته‌بندی داده‌ها از **تمام منابع** هستند و برای استفاده عمومی توصیه می‌شوند.\n\n`;
    markdown += `| نام فایل | تعداد آدرس‌ها | توضیحات | لینک خام |\n`;
    markdown += `| :--- | :---: | :--- | :---: |\n`;
    mainListFiles.forEach(file => {
        const count = listFileCounts[file.name] || 0;
        const rawUrl = `${repoUrl}/raw/main/lists/${file.name}`;
        markdown += `| \`${file.name}\` | **${count}** | ${file.description} | [لینک](${rawUrl}) |\n`;
    });
    markdown += `\n---\n\n`;

    markdown += `##  لیست‌ها بر اساس منبع | Lists by Source\n\n`;
    // Corrected Line: The problematic backtick ` is now correctly part of the string.
    markdown += "در این بخش، خروجی‌های هر منبع به صورت جداگانه و فیلتر شده قرار دارند. هر منبع دارای یک فایل `all.txt` (شامل تمام آدرس‌های استخراج شده از آن منبع) و سپس لیست‌های فیلتر شده بر اساس پروتکل و ویژگی‌ها است.\n\n";

    sources.forEach(source => {
        markdown += `<details>\n<summary><h3>📂 ${source.name}</h3></summary>\n\n`;
        markdown += `| نام فایل | تعداد آدرس‌ها | لینک خام |\n`;
        markdown += `| :--- | :---: | :---: |\n`;
        
        sourceSubListFiles.forEach(fileName => {
            const fileKey = `${source.name}/${fileName}`;
            const count = listFileCounts[fileKey];
            if (count > 0) {
                const rawUrl = `${repoUrl}/raw/main/lists/sources/${source.name}/${fileName}`;
                markdown += `| \`${fileName}\` | **${count}** | [لینک](${rawUrl}) |\n`;
            }
        });
        markdown += `\n</details>\n\n`;
    });
    
    markdown += `---\n\n## 📚 منابع اصلی داده‌ها\n\n`;
    sources.forEach(source => {
        markdown += `- **[${source.name}](${source.url})**\n`;
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
