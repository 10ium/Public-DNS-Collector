import fs from 'fs';
import path from 'path';

/**
 * Generates the content for the README.md file.
 * @param {object} sources - The list of source objects with names and URLs.
 * @param {string} repoUrl - The URL of the GitHub repository.
 * @param {object} listFileCounts - An object containing the count of addresses for each list file.
 * @returns {string} The complete Markdown content for the README file.
 */
export function generateReadme(sources, repoUrl, listFileCounts) {
    const listFiles = [
        { name: 'doh.txt', description: 'لیست تمام سرورهای DNS-over-HTTPS.' },
        { name: 'dot.txt', description: 'لیست تمام سرورهای DNS-over-TLS.' },
        { name: 'dnscrypt.txt', description: 'لیست تمام سرورهای DNSCrypt (به صورت Stamp).' },
        { name: 'ipv4.txt', description: 'لیست سرورهای DNS استاندارد روی IPv4.' },
        { name: 'ipv6.txt', description: 'لیست تمام آدرس‌های IPv6 موجود.' },
        { name: 'adblock.txt', description: 'لیست سرورهایی که تبلیغات را مسدود می‌کنند.' },
        { name: 'malware.txt', description: 'لیست سرورهایی که از بدافزار و فیشینگ جلوگیری می‌کنند.' },
        { name: 'family.txt', description: 'لیست سرورهایی با فیلترینگ خانواده (مسدودسازی محتوای بزرگسالان).' },
        { name: 'unfiltered.txt', description: 'لیست سرورهای بدون فیلترینگ خاص.' },
        { name: 'no_log.txt', description: 'لیست سرورهایی که ادعا می‌کنند لاگ کاربران را ذخیره نمی‌کنند.' },
        { name: 'dnssec.txt', description: 'لیست سرورهایی که از DNSSEC برای افزایش امنیت پشتیبانی می‌کنند.' },
    ];

    const sourceFiles = sources.map(s => `${s.name}.txt`);

    // --- Header Section ---
    let markdown = `#  koleksi DNS Umum | Public DNS Collector  DNS  koleksi umum
<p align="center">
  <img src="https://raw.githubusercontent.com/1024-byte/resources/main/banner/Public-DNS-Collector-banner.png" alt="Public DNS Collector Banner">
</p>
<div align="center">

**یک مخزن جامع برای جمع‌آوری، تجمیع و به‌روزرسانی خودکار لیست‌های DNS عمومی از منابع معتبر.**
<br />
این پروژه توسط GitHub Actions به صورت هفتگی اجرا شده و لیست‌های زیر را به‌روز می‌کند.
<br />
<br />

[![GitHub last commit](https://img.shields.io/github/last-commit/10ium/Public-DNS-Collector?style=for-the-badge&logo=github&color=blue)](https://github.com/10ium/Public-DNS-Collector/commits/main)
[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/10ium/Public-DNS-Collector/update-lists.yml?branch=main&style=for-the-badge&logo=githubactions&logoColor=white)](https://github.com/10ium/Public-DNS-Collector/actions)
[![License](https://img.shields.io/github/license/10ium/Public-DNS-Collector?style=for-the-badge&color=brightgreen)](LICENSE)

</div>

---

`;

    // --- Aggregated Lists Section ---
    markdown += `##  لیست‌های تجمیع شده\n\n`;
    markdown += `در این بخش، لیست‌های نهایی که از ترکیب تمام منابع به دست آمده‌اند، قرار دارند. این لیست‌ها بر اساس نوع پروتکل، فیلترینگ و ویژگی‌ها دسته‌بندی شده‌اند.\n\n`;
    markdown += `| نام فایل | تعداد آدرس‌ها | توضیحات | لینک خام |\n`;
    markdown += `| :--- | :---: | :--- | :---: |\n`;
    listFiles.forEach(file => {
        const count = listFileCounts[file.name] || 0;
        const rawUrl = `${repoUrl}/raw/main/lists/${file.name}`;
        markdown += `| \`${file.name}\` | **${count}** | ${file.description} | [لینک](${rawUrl}) |\n`;
    });
    markdown += `\n`;

    // --- Per-Source Lists Section ---
    markdown += `## لیست‌ها به تفکیک منبع\n\n`;
    markdown += `در این بخش، لیست آدرس‌های استخراج شده از هر منبع به صورت جداگانه قرار دارد. این کار به شفافیت و ردیابی داده‌ها کمک می‌کند.\n\n`;
    markdown += `| نام فایل | تعداد آدرس‌ها | لینک خام |\n`;
    markdown += `| :--- | :---: | :---: |\n`;
    sourceFiles.forEach(fileName => {
        const count = listFileCounts[fileName] || 0;
        const rawUrl = `${repoUrl}/raw/main/lists/sources/${fileName}`;
        markdown += `| \`${fileName}\` | **${count}** | [لینک](${rawUrl}) |\n`;
    });
    markdown += `\n`;

    // --- Sources Section ---
    markdown += `## 📚 منابع استفاده شده\n\n`;
    markdown += `این پروژه داده‌های خود را از منابع معتبر و عمومی زیر جمع‌آوری می‌کند:\n\n`;
    sources.forEach(source => {
        markdown += `- **[${source.name}](${source.url})**\n`;
    });
    markdown += `\n`;
    
    // --- Footer Section ---
    markdown += `---\n`;
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
