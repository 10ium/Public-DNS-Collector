# مجموعه DNS عمومی | Public DNS Collector

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

## 🗂️ لیست‌های تجمیع شده نهایی

این لیست‌ها حاصل ترکیب، پاک‌سازی و دسته‌بندی داده‌ها از **تمام منابع** هستند و برای استفاده عمومی توصیه می‌شوند.

| نام فایل | تعداد آدرس‌ها | توضیحات | لینک خام |
| :--- | :---: | :--- | :---: |
| `doh.txt` | **728** | لیست تمام سرورهای DNS-over-HTTPS. | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/doh.txt) |
| `dot.txt` | **317** | لیست تمام سرورهای DNS-over-TLS. | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/dot.txt) |
| `dnscrypt.txt` | **657** | لیست تمام سرورهای DNSCrypt (به صورت Stamp). | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/dnscrypt.txt) |
| `ipv4.txt` | **6788** | لیست سرورهای DNS استاندارد روی IPv4. | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/ipv4.txt) |
| `ipv6.txt` | **41** | لیست تمام آدرس‌های IPv6 موجود. | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/ipv6.txt) |
| `adblock.txt` | **252** | لیست سرورهایی که تبلیغات را مسدود می‌کنند. | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/adblock.txt) |
| `malware.txt` | **227** | لیست سرورهایی که از بدافزار و فیشینگ جلوگیری می‌کنند. | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/malware.txt) |
| `family.txt` | **129** | لیست سرورهایی با فیلترینگ خانواده (محتوای بزرگسالان). | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/family.txt) |
| `unfiltered.txt` | **7646** | لیست سرورهای بدون فیلترینگ خاص. | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/unfiltered.txt) |
| `no_log.txt` | **363** | لیست سرورهایی که ادعا می‌کنند لاگ کاربران را ذخیره نمی‌کنند. | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/no_log.txt) |
| `dnssec.txt` | **527** | لیست سرورهایی که از DNSSEC برای افزایش امنیت پشتیبانی می‌کنند. | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/dnssec.txt) |

---

##  لیست‌ها بر اساس منبع | Lists by Source

در این بخش، خروجی‌های هر منبع به صورت جداگانه و فیلتر شده قرار دارند. هر منبع دارای یک فایل `all.txt` (شامل تمام آدرس‌های استخراج شده از آن منبع) و سپس لیست‌های فیلتر شده بر اساس پروتکل و ویژگی‌ها است.

<details>
<summary><h3>📂 DNSCrypt</h3></summary>

| نام فایل | تعداد آدرس‌ها | لینک خام |
| :--- | :---: | :---: |
| `all.txt` | **564** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/DNSCrypt/all.txt) |
| `dnscrypt.txt` | **564** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/DNSCrypt/dnscrypt.txt) |
| `adblock.txt` | **16** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/DNSCrypt/adblock.txt) |
| `malware.txt` | **58** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/DNSCrypt/malware.txt) |
| `family.txt` | **15** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/DNSCrypt/family.txt) |
| `unfiltered.txt` | **492** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/DNSCrypt/unfiltered.txt) |
| `no_log.txt` | **220** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/DNSCrypt/no_log.txt) |
| `dnssec.txt` | **318** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/DNSCrypt/dnssec.txt) |

</details>

<details>
<summary><h3>📂 Paulmillr</h3></summary>

| نام فایل | تعداد آدرس‌ها | لینک خام |
| :--- | :---: | :---: |
| `all.txt` | **49** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Paulmillr/all.txt) |
| `doh.txt` | **49** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Paulmillr/doh.txt) |
| `dot.txt` | **44** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Paulmillr/dot.txt) |
| `adblock.txt` | **8** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Paulmillr/adblock.txt) |
| `malware.txt` | **28** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Paulmillr/malware.txt) |
| `family.txt` | **9** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Paulmillr/family.txt) |
| `unfiltered.txt` | **18** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Paulmillr/unfiltered.txt) |

</details>

<details>
<summary><h3>📂 Blacklantern</h3></summary>

| نام فایل | تعداد آدرس‌ها | لینک خام |
| :--- | :---: | :---: |
| `all.txt` | **6808** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Blacklantern/all.txt) |
| `ipv4.txt` | **6808** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Blacklantern/ipv4.txt) |
| `unfiltered.txt` | **6808** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Blacklantern/unfiltered.txt) |

</details>

<details>
<summary><h3>📂 MutinSA</h3></summary>

| نام فایل | تعداد آدرس‌ها | لینک خام |
| :--- | :---: | :---: |
| `all.txt` | **36** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/MutinSA/all.txt) |
| `doh.txt` | **8** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/MutinSA/doh.txt) |
| `ipv4.txt` | **18** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/MutinSA/ipv4.txt) |
| `ipv6.txt` | **18** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/MutinSA/ipv6.txt) |
| `unfiltered.txt` | **36** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/MutinSA/unfiltered.txt) |
| `dnssec.txt` | **36** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/MutinSA/dnssec.txt) |

</details>

<details>
<summary><h3>📂 AdGuard</h3></summary>

| نام فایل | تعداد آدرس‌ها | لینک خام |
| :--- | :---: | :---: |
| `all.txt` | **305** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/AdGuard/all.txt) |
| `doh.txt` | **253** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/AdGuard/doh.txt) |
| `dot.txt` | **281** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/AdGuard/dot.txt) |
| `dnscrypt.txt` | **104** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/AdGuard/dnscrypt.txt) |
| `ipv4.txt` | **108** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/AdGuard/ipv4.txt) |
| `ipv6.txt` | **20** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/AdGuard/ipv6.txt) |
| `adblock.txt` | **82** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/AdGuard/adblock.txt) |
| `malware.txt` | **82** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/AdGuard/malware.txt) |
| `family.txt` | **42** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/AdGuard/family.txt) |
| `unfiltered.txt` | **27** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/AdGuard/unfiltered.txt) |

</details>

<details>
<summary><h3>📂 Mullvad</h3></summary>

| نام فایل | تعداد آدرس‌ها | لینک خام |
| :--- | :---: | :---: |
| `all.txt` | **24** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Mullvad/all.txt) |
| `doh.txt` | **24** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Mullvad/doh.txt) |
| `dot.txt` | **24** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Mullvad/dot.txt) |
| `ipv4.txt` | **6** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Mullvad/ipv4.txt) |
| `ipv6.txt` | **6** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Mullvad/ipv6.txt) |
| `adblock.txt` | **20** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Mullvad/adblock.txt) |
| `malware.txt` | **16** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Mullvad/malware.txt) |
| `family.txt` | **8** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Mullvad/family.txt) |
| `unfiltered.txt` | **4** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Mullvad/unfiltered.txt) |
| `no_log.txt` | **24** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Mullvad/no_log.txt) |
| `dnssec.txt` | **24** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Mullvad/dnssec.txt) |

</details>

<details>
<summary><h3>📂 DNSPrivacyOrg</h3></summary>

| نام فایل | تعداد آدرس‌ها | لینک خام |
| :--- | :---: | :---: |
| `all.txt` | **16** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/DNSPrivacyOrg/all.txt) |
| `doh.txt` | **13** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/DNSPrivacyOrg/doh.txt) |
| `dot.txt` | **16** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/DNSPrivacyOrg/dot.txt) |
| `ipv4.txt` | **5** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/DNSPrivacyOrg/ipv4.txt) |
| `ipv6.txt` | **5** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/DNSPrivacyOrg/ipv6.txt) |
| `adblock.txt` | **3** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/DNSPrivacyOrg/adblock.txt) |
| `unfiltered.txt` | **13** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/DNSPrivacyOrg/unfiltered.txt) |
| `no_log.txt` | **16** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/DNSPrivacyOrg/no_log.txt) |
| `dnssec.txt` | **16** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/DNSPrivacyOrg/dnssec.txt) |

</details>

<details>
<summary><h3>📂 Curl</h3></summary>

| نام فایل | تعداد آدرس‌ها | لینک خام |
| :--- | :---: | :---: |
| `all.txt` | **414** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Curl/all.txt) |
| `doh.txt` | **414** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Curl/doh.txt) |
| `adblock.txt` | **135** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Curl/adblock.txt) |
| `malware.txt` | **60** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Curl/malware.txt) |
| `family.txt` | **67** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Curl/family.txt) |
| `unfiltered.txt` | **220** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Curl/unfiltered.txt) |
| `no_log.txt` | **85** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Curl/no_log.txt) |
| `dnssec.txt` | **97** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Curl/dnssec.txt) |

</details>

<details>
<summary><h3>📂 Thiagozs</h3></summary>

| نام فایل | تعداد آدرس‌ها | لینک خام |
| :--- | :---: | :---: |
| `all.txt` | **121** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Thiagozs/all.txt) |
| `doh.txt` | **121** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Thiagozs/doh.txt) |
| `adblock.txt` | **12** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Thiagozs/adblock.txt) |
| `malware.txt` | **21** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Thiagozs/malware.txt) |
| `family.txt` | **3** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Thiagozs/family.txt) |
| `unfiltered.txt` | **87** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Thiagozs/unfiltered.txt) |
| `no_log.txt` | **27** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Thiagozs/no_log.txt) |
| `dnssec.txt` | **66** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Thiagozs/dnssec.txt) |

</details>

---

## 📚 منابع اصلی داده‌ها

- **[DNSCrypt](https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/refs/heads/master/v3/public-resolvers.md)**
- **[Paulmillr](null)**
- **[Blacklantern](https://raw.githubusercontent.com/blacklanternsecurity/public-dns-servers/refs/heads/master/nameservers.txt)**
- **[MutinSA](https://gist.githubusercontent.com/mutin-sa/5dcbd35ee436eb629db7872581093bc5/raw/)**
- **[AdGuard](https://adguard-dns.io/kb/general/dns-providers/)**
- **[Mullvad](https://mullvad.net/en/help/dns-over-https-and-dns-over-tls)**
- **[DNSPrivacyOrg](https://dnsprivacy.org/public_resolvers/)**
- **[Curl](https://raw.githubusercontent.com/wiki/curl/curl/DNS-over-HTTPS.md)**
- **[Thiagozs](https://gist.githubusercontent.com/thiagozs/088fd8f8129ca06df524f6711116ee8f/raw/)**

---
<p align="center">ساخته شده با ❤️ و به صورت خودکار توسط GitHub Actions</p>
