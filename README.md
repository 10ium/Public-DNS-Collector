#  koleksi DNS Umum | Public DNS Collector  DNS  koleksi umum
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

##  لیست‌های تجمیع شده

در این بخش، لیست‌های نهایی که از ترکیب تمام منابع به دست آمده‌اند، قرار دارند. این لیست‌ها بر اساس نوع پروتکل، فیلترینگ و ویژگی‌ها دسته‌بندی شده‌اند.

| نام فایل | تعداد آدرس‌ها | توضیحات | لینک خام |
| :--- | :---: | :--- | :---: |
| `doh.txt` | **514** | لیست تمام سرورهای DNS-over-HTTPS. | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/doh.txt) |
| `dot.txt` | **207** | لیست تمام سرورهای DNS-over-TLS. | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/dot.txt) |
| `dnscrypt.txt` | **583** | لیست تمام سرورهای DNSCrypt (به صورت Stamp). | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/dnscrypt.txt) |
| `ipv4.txt` | **6825** | لیست سرورهای DNS استاندارد روی IPv4. | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/ipv4.txt) |
| `ipv6.txt` | **624** | لیست تمام آدرس‌های IPv6 موجود. | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/ipv6.txt) |
| `adblock.txt` | **250** | لیست سرورهایی که تبلیغات را مسدود می‌کنند. | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/adblock.txt) |
| `malware.txt` | **218** | لیست سرورهایی که از بدافزار و فیشینگ جلوگیری می‌کنند. | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/malware.txt) |
| `family.txt` | **124** | لیست سرورهایی با فیلترینگ خانواده (مسدودسازی محتوای بزرگسالان). | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/family.txt) |
| `unfiltered.txt` | **819** | لیست سرورهای بدون فیلترینگ خاص. | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/unfiltered.txt) |
| `no_log.txt` | **363** | لیست سرورهایی که ادعا می‌کنند لاگ کاربران را ذخیره نمی‌کنند. | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/no_log.txt) |
| `dnssec.txt` | **527** | لیست سرورهایی که از DNSSEC برای افزایش امنیت پشتیبانی می‌کنند. | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/dnssec.txt) |

## لیست‌ها به تفکیک منبع

در این بخش، لیست آدرس‌های استخراج شده از هر منبع به صورت جداگانه قرار دارد. این کار به شفافیت و ردیابی داده‌ها کمک می‌کند.

| نام فایل | تعداد آدرس‌ها | لینک خام |
| :--- | :---: | :---: |
| `DNSCrypt.txt` | **564** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/DNSCrypt.txt) |
| `Paulmillr.txt` | **5** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Paulmillr.txt) |
| `Blacklantern.txt` | **6808** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Blacklantern.txt) |
| `MutinSA.txt` | **36** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/MutinSA.txt) |
| `AdGuard.txt` | **305** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/AdGuard.txt) |
| `Mullvad.txt` | **24** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Mullvad.txt) |
| `DNSPrivacyOrg.txt` | **16** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/DNSPrivacyOrg.txt) |
| `Curl.txt` | **414** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Curl.txt) |
| `Thiagozs.txt` | **121** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Thiagozs.txt) |

## 📚 منابع استفاده شده

این پروژه داده‌های خود را از منابع معتبر و عمومی زیر جمع‌آوری می‌کند:

- **[DNSCrypt](https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/refs/heads/master/v3/public-resolvers.md)**
- **[Paulmillr](https://raw.githubusercontent.com/paulmillr/encrypted-dns/refs/heads/master/README.md)**
- **[Blacklantern](https://raw.githubusercontent.com/blacklanternsecurity/public-dns-servers/refs/heads/master/nameservers.txt)**
- **[MutinSA](https://gist.githubusercontent.com/mutin-sa/5dcbd35ee436eb629db7872581093bc5/raw/)**
- **[AdGuard](https://adguard-dns.io/kb/general/dns-providers/)**
- **[Mullvad](https://mullvad.net/en/help/dns-over-https-and-dns-over-tls)**
- **[DNSPrivacyOrg](https://dnsprivacy.org/public_resolvers/)**
- **[Curl](https://raw.githubusercontent.com/wiki/curl/curl/DNS-over-HTTPS.md)**
- **[Thiagozs](https://gist.githubusercontent.com/thiagozs/088fd8f8129ca06df524f6711116ee8f/raw/)**

---
<p align="center">ساخته شده با ❤️ و به صورت خودکار توسط GitHub Actions</p>
