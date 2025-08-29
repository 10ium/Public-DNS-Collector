# مجموعه DNS عمومی | Public DNS Collector

<p align="center">
  <img src="https://www.svgrepo.com/show/491884/dns.svg" alt="Public DNS Collector Banner" width="200">
</p>
<div align="center">

**یک مخزن جامع برای جمع‌آوری، تجمیع و به‌روزرسانی خودکار لیست‌های DNS عمومی از منابع معتبر.**
<br />
این پروژه توسط GitHub Actions به صورت هفتگی اجرا شده و لیست‌های زیر را به‌روز می‌کند.
<br />
<br />

**آخرین بروزرسانی:** 2025-08-29 05:29:14 UTC
<br />
<br />

[![GitHub last commit](https://img.shields.io/github/last-commit/10ium/Public-DNS-Collector?style=for-the-badge&logo=github&color=blue)](https://github.com/10ium/Public-DNS-Collector/commits/main)
[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/10ium/Public-DNS-Collector/update-lists.yml?branch=main&style=for-the-badge&logo=githubactions&logoColor=white)](https://github.com/10ium/Public-DNS-Collector/actions)
[![License](https://img.shields.io/github/license/10ium/Public-DNS-Collector?style=for-the-badge&color=brightgreen)](LICENSE)

</div>

---

## 🗂️ لیست‌های تجمیع شده نهایی

این لیست‌ها حاصل ترکیب، پاک‌سازی و دسته‌بندی داده‌ها از **تمام منابعی که برای تجمیع فعال هستند** می‌باشند و برای استفاده عمومی توصیه می‌شوند.

| نام فایل | تعداد آدرس‌ها | توضیحات | لینک خام |
| :--- | :---: | ---: | :---: |
| `all.txt` | **1692** | لیست جامع تمام دی ان اس ها از همه منابع و پروتکل‌ها | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/all.txt) |
| `doh.txt` | **551** | لیست تمام سرورهای دی ان اس روی اچ تی تی پی اس | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/doh.txt) |
| `dot.txt` | **300** | لیست تمام سرورهای دی ان اس روی تی ال اس | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/dot.txt) |
| `doq.txt` | **56** | لیست تمام سرورهای دی ان اس روی کوییک | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/doq.txt) |
| `doh3.txt` | **2** | لیست تمام سرورهای دی ان اس روی اچ تی تی پی اس ۳ | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/doh3.txt) |
| `dnscrypt.txt` | **635** | لیست تمام سرورهای دی ان اس کریپت | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/dnscrypt.txt) |
| `ipv6.txt` | **24** | لیست سرورهای دی ان اس استاندارد روی آی‌پی‌وی۶ | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/ipv6.txt) |
| `adblock.txt` | **478** | لیست سرورهایی که تبلیغات را مسدود می‌کنند | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/adblock.txt) |
| `malware.txt` | **413** | لیست سرورهایی که از بدافزار و فیشینگ جلوگیری می‌کنند | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/malware.txt) |
| `family.txt` | **162** | لیست سرورهایی با فیلترینگ خانواده (محتوای بزرگسالان) | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/family.txt) |
| `unfiltered.txt` | **921** | لیست سرورهای بدون فیلترینگ خاص | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/unfiltered.txt) |
| `no_log.txt` | **378** | لیست سرورهایی که ادعا می‌کنند لاگ کاربران را ذخیره نمی‌کنند | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/no_log.txt) |
| `dnssec.txt` | **543** | لیست سرورهایی که از دی ان اس سک برای افزایش امنیت پشتیبانی می‌کنند | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/dnssec.txt) |
| `dns64.txt` | **6** | لیست سرورهایی که از دی‌ان‌اس۶۴ پشتیبانی می‌کنند | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/dns64.txt) |

---

##  لیست‌ها بر اساس منبع | Lists by Source

در این بخش، خروجی‌های هر منبع به صورت جداگانه و فیلتر شده قرار دارند. هر منبع دارای یک فایل `all.txt` (شامل تمام آدرس‌های استخراج شده از آن منبع) و سپس لیست‌های فیلتر شده بر اساس پروتکل و ویژگی‌ها است.

<details>
<summary><h3>📂 DNSCrypt</h3></summary>

| نام فایل | تعداد آدرس‌ها | لینک خام |
| :--- | :---: | :---: |
| `all.txt` | **565** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/DNSCrypt/all.txt) |
| `adblock.txt` | **17** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/DNSCrypt/adblock.txt) |
| `dnscrypt.txt` | **565** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/DNSCrypt/dnscrypt.txt) |
| `dnssec.txt` | **319** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/DNSCrypt/dnssec.txt) |
| `family.txt` | **15** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/DNSCrypt/family.txt) |
| `malware.txt` | **59** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/DNSCrypt/malware.txt) |
| `no_log.txt` | **221** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/DNSCrypt/no_log.txt) |
| `unfiltered.txt` | **492** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/DNSCrypt/unfiltered.txt) |

</details>

<details>
<summary><h3>📂 Paulmillr</h3></summary>

| نام فایل | تعداد آدرس‌ها | لینک خام |
| :--- | :---: | :---: |
| `all.txt` | **49** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Paulmillr/all.txt) |
| `adblock.txt` | **8** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Paulmillr/adblock.txt) |
| `doh.txt` | **27** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Paulmillr/doh.txt) |
| `dot.txt` | **22** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Paulmillr/dot.txt) |
| `family.txt` | **14** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Paulmillr/family.txt) |
| `malware.txt` | **30** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Paulmillr/malware.txt) |
| `unfiltered.txt` | **18** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Paulmillr/unfiltered.txt) |

</details>

<details>
<summary><h3>📂 Blacklantern</h3></summary>

| نام فایل | تعداد آدرس‌ها | لینک خام |
| :--- | :---: | :---: |
| `all.txt` | **6808** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Blacklantern/all.txt) |
| `ipv4.txt` | **6808** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Blacklantern/ipv4.txt) |
| `tcp.txt` | **6808** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Blacklantern/tcp.txt) |
| `udp.txt` | **6808** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Blacklantern/udp.txt) |

</details>

<details>
<summary><h3>📂 MutinSA</h3></summary>

| نام فایل | تعداد آدرس‌ها | لینک خام |
| :--- | :---: | :---: |
| `all.txt` | **24** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/MutinSA/all.txt) |
| `dns64.txt` | **6** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/MutinSA/dns64.txt) |
| `dnssec.txt` | **24** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/MutinSA/dnssec.txt) |
| `ipv6.txt` | **24** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/MutinSA/ipv6.txt) |
| `unfiltered.txt` | **24** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/MutinSA/unfiltered.txt) |

</details>

<details>
<summary><h3>📂 AdGuard</h3></summary>

| نام فایل | تعداد آدرس‌ها | لینک خام |
| :--- | :---: | :---: |
| `all.txt` | **497** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/AdGuard/all.txt) |
| `adblock.txt` | **196** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/AdGuard/adblock.txt) |
| `dnscrypt.txt` | **83** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/AdGuard/dnscrypt.txt) |
| `doh.txt` | **115** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/AdGuard/doh.txt) |
| `doq.txt` | **18** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/AdGuard/doq.txt) |
| `dot.txt` | **143** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/AdGuard/dot.txt) |
| `family.txt` | **49** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/AdGuard/family.txt) |
| `malware.txt` | **250** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/AdGuard/malware.txt) |
| `unfiltered.txt` | **17** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/AdGuard/unfiltered.txt) |

</details>

<details>
<summary><h3>📂 Mullvad</h3></summary>

| نام فایل | تعداد آدرس‌ها | لینک خام |
| :--- | :---: | :---: |
| `all.txt` | **28** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Mullvad/all.txt) |
| `adblock.txt` | **16** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Mullvad/adblock.txt) |
| `dnssec.txt` | **28** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Mullvad/dnssec.txt) |
| `doh.txt` | **15** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Mullvad/doh.txt) |
| `dot.txt` | **13** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Mullvad/dot.txt) |
| `family.txt` | **7** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Mullvad/family.txt) |
| `malware.txt` | **13** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Mullvad/malware.txt) |
| `no_log.txt` | **28** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Mullvad/no_log.txt) |
| `unfiltered.txt` | **13** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Mullvad/unfiltered.txt) |

</details>

<details>
<summary><h3>📂 DNSPrivacyOrg</h3></summary>

| نام فایل | تعداد آدرس‌ها | لینک خام |
| :--- | :---: | :---: |
| `all.txt` | **7** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/DNSPrivacyOrg/all.txt) |
| `adblock.txt` | **1** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/DNSPrivacyOrg/adblock.txt) |
| `dnssec.txt` | **7** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/DNSPrivacyOrg/dnssec.txt) |
| `doh.txt` | **3** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/DNSPrivacyOrg/doh.txt) |
| `doq.txt` | **1** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/DNSPrivacyOrg/doq.txt) |
| `dot.txt` | **3** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/DNSPrivacyOrg/dot.txt) |
| `malware.txt` | **2** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/DNSPrivacyOrg/malware.txt) |
| `no_log.txt` | **7** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/DNSPrivacyOrg/no_log.txt) |
| `unfiltered.txt` | **5** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/DNSPrivacyOrg/unfiltered.txt) |

</details>

<details>
<summary><h3>📂 Curl</h3></summary>

| نام فایل | تعداد آدرس‌ها | لینک خام |
| :--- | :---: | :---: |
| `all.txt` | **620** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Curl/all.txt) |
| `adblock.txt` | **241** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Curl/adblock.txt) |
| `dnssec.txt` | **122** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Curl/dnssec.txt) |
| `doh.txt` | **414** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Curl/doh.txt) |
| `doh3.txt` | **2** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Curl/doh3.txt) |
| `doq.txt` | **42** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Curl/doq.txt) |
| `dot.txt` | **164** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Curl/dot.txt) |
| `family.txt` | **90** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Curl/family.txt) |
| `malware.txt` | **74** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Curl/malware.txt) |
| `no_log.txt` | **104** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Curl/no_log.txt) |
| `unfiltered.txt` | **301** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Curl/unfiltered.txt) |

</details>

<details>
<summary><h3>📂 Thiagozs</h3></summary>

| نام فایل | تعداد آدرس‌ها | لینک خام |
| :--- | :---: | :---: |
| `all.txt` | **121** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Thiagozs/all.txt) |
| `adblock.txt` | **12** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Thiagozs/adblock.txt) |
| `dnssec.txt` | **66** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Thiagozs/dnssec.txt) |
| `doh.txt` | **121** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Thiagozs/doh.txt) |
| `family.txt` | **3** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Thiagozs/family.txt) |
| `malware.txt` | **21** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Thiagozs/malware.txt) |
| `no_log.txt` | **27** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Thiagozs/no_log.txt) |
| `unfiltered.txt` | **87** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Thiagozs/unfiltered.txt) |

</details>

---

## 📚 منابع اصلی داده‌ها

- **[DNSCrypt](https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/refs/heads/master/v3/public-resolvers.md)**
- **[Paulmillr](https://github.com/paulmillr/encrypted-dns)**
- **[Blacklantern](https://raw.githubusercontent.com/blacklanternsecurity/public-dns-servers/refs/heads/master/nameservers.txt)**
- **[MutinSA](https://gist.githubusercontent.com/mutin-sa/5dcbd35ee436eb629db7872581093bc5/raw/)**
- **[AdGuard](https://adguard-dns.io/kb/general/dns-providers/)**
- **[Mullvad](https://mullvad.net/en/help/dns-over-https-and-dns-over-tls)**
- **[DNSPrivacyOrg](https://dnsprivacy.org/public_resolvers/)**
- **[Curl](https://raw.githubusercontent.com/wiki/curl/curl/DNS-over-HTTPS.md)**
- **[Thiagozs](https://gist.githubusercontent.com/thiagozs/088fd8f8129ca06df524f6711116ee8f/raw/)**

---
<p align="center">ساخته شده با ❤️ و به صورت خودکار توسط GitHub Actions</p>
