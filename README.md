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

**آخرین بروزرسانی:** 2026-01-04 03:09:30 UTC
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
| `all.txt` | **1945** | لیست جامع تمام دی ان اس ها از همه منابع و پروتکل‌ها | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/all.txt) |
| `doh.txt` | **500** | لیست تمام سرورهای دی ان اس روی اچ تی تی پی اس | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/doh.txt) |
| `dot.txt` | **240** | لیست تمام سرورهای دی ان اس روی تی ال اس | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/dot.txt) |
| `doq.txt` | **47** | لیست تمام سرورهای دی ان اس روی کوییک | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/doq.txt) |
| `doh3.txt` | **5** | لیست تمام سرورهای دی ان اس روی اچ تی تی پی اس ۳ | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/doh3.txt) |
| `dnscrypt.txt` | **657** | لیست تمام سرورهای دی ان اس کریپت | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/dnscrypt.txt) |
| `ipv4.txt` | **182** | لیست سرورهای دی ان اس استاندارد روی آی‌پی‌وی۴ | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/ipv4.txt) |
| `tcp.txt` | **182** | لیست سرورهای دی انی اس آی‌پی‌وی۴ با پیشوند تی سی پی | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/tcp.txt) |
| `udp.txt` | **182** | لیست سرورهای دی انی اس آی‌پی‌وی۴ با پیشوند یو دی پی | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/udp.txt) |
| `ipv6.txt` | **124** | لیست سرورهای دی ان اس استاندارد روی آی‌پی‌وی۶ | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/ipv6.txt) |
| `adblock.txt` | **525** | لیست سرورهایی که تبلیغات را مسدود می‌کنند | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/adblock.txt) |
| `malware.txt` | **522** | لیست سرورهایی که از بدافزار و فیشینگ جلوگیری می‌کنند | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/malware.txt) |
| `family.txt` | **178** | لیست سرورهایی با فیلترینگ خانواده (محتوای بزرگسالان) | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/family.txt) |
| `unfiltered.txt` | **906** | لیست سرورهای بدون فیلترینگ خاص | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/unfiltered.txt) |
| `no_log.txt` | **432** | لیست سرورهایی که ادعا می‌کنند لاگ کاربران را ذخیره نمی‌کنند | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/no_log.txt) |
| `dnssec.txt` | **627** | لیست سرورهایی که از دی ان اس سک برای افزایش امنیت پشتیبانی می‌کنند | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/dnssec.txt) |
| `dns64.txt` | **16** | لیست سرورهایی که از دی‌ان‌اس۶۴ پشتیبانی می‌کنند | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/dns64.txt) |

---

##  لیست‌ها بر اساس منبع | Lists by Source

در این بخش، خروجی‌های هر منبع به صورت جداگانه و فیلتر شده قرار دارند. هر منبع دارای یک فایل `all.txt` (شامل تمام آدرس‌های استخراج شده از آن منبع) و سپس لیست‌های فیلتر شده بر اساس پروتکل و ویژگی‌ها است.

<details>
<summary><h3>📂 DNSCrypt</h3></summary>

| نام فایل | تعداد آدرس‌ها | لینک خام |
| :--- | :---: | :---: |
| `all.txt` | **622** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/DNSCrypt/all.txt) |
| `adblock.txt` | **15** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/DNSCrypt/adblock.txt) |
| `dnscrypt.txt` | **622** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/DNSCrypt/dnscrypt.txt) |
| `dnssec.txt` | **363** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/DNSCrypt/dnssec.txt) |
| `family.txt` | **19** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/DNSCrypt/family.txt) |
| `malware.txt` | **61** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/DNSCrypt/malware.txt) |
| `no_log.txt` | **273** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/DNSCrypt/no_log.txt) |
| `unfiltered.txt` | **547** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/DNSCrypt/unfiltered.txt) |

</details>

<details>
<summary><h3>📂 Paulmillr</h3></summary>

| نام فایل | تعداد آدرس‌ها | لینک خام |
| :--- | :---: | :---: |
| `all.txt` | **51** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Paulmillr/all.txt) |
| `adblock.txt` | **8** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Paulmillr/adblock.txt) |
| `doh.txt` | **28** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Paulmillr/doh.txt) |
| `dot.txt` | **23** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Paulmillr/dot.txt) |
| `family.txt` | **14** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Paulmillr/family.txt) |
| `malware.txt` | **30** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Paulmillr/malware.txt) |
| `unfiltered.txt` | **20** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Paulmillr/unfiltered.txt) |

</details>

<details>
<summary><h3>📂 Blacklantern</h3></summary>

| نام فایل | تعداد آدرس‌ها | لینک خام |
| :--- | :---: | :---: |
| `all.txt` | **10576** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Blacklantern/all.txt) |
| `ipv4.txt` | **5288** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Blacklantern/ipv4.txt) |
| `tcp.txt` | **5288** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Blacklantern/tcp.txt) |
| `udp.txt` | **5288** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Blacklantern/udp.txt) |

</details>

<details>
<summary><h3>📂 MutinSA</h3></summary>

| نام فایل | تعداد آدرس‌ها | لینک خام |
| :--- | :---: | :---: |
| `all.txt` | **58** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/MutinSA/all.txt) |
| `dns64.txt` | **16** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/MutinSA/dns64.txt) |
| `dnssec.txt` | **58** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/MutinSA/dnssec.txt) |
| `ipv4.txt` | **18** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/MutinSA/ipv4.txt) |
| `ipv6.txt` | **22** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/MutinSA/ipv6.txt) |
| `tcp.txt` | **18** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/MutinSA/tcp.txt) |
| `udp.txt` | **18** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/MutinSA/udp.txt) |
| `unfiltered.txt` | **58** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/MutinSA/unfiltered.txt) |

</details>

<details>
<summary><h3>📂 AdGuard</h3></summary>

| نام فایل | تعداد آدرس‌ها | لینک خام |
| :--- | :---: | :---: |
| `all.txt` | **719** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/AdGuard/all.txt) |
| `adblock.txt` | **272** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/AdGuard/adblock.txt) |
| `dnscrypt.txt` | **48** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/AdGuard/dnscrypt.txt) |
| `doh.txt` | **105** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/AdGuard/doh.txt) |
| `doq.txt` | **15** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/AdGuard/doq.txt) |
| `dot.txt` | **107** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/AdGuard/dot.txt) |
| `family.txt` | **66** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/AdGuard/family.txt) |
| `ipv4.txt` | **168** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/AdGuard/ipv4.txt) |
| `ipv6.txt` | **108** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/AdGuard/ipv6.txt) |
| `malware.txt` | **355** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/AdGuard/malware.txt) |
| `tcp.txt` | **168** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/AdGuard/tcp.txt) |
| `udp.txt` | **168** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/AdGuard/udp.txt) |
| `unfiltered.txt` | **24** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/AdGuard/unfiltered.txt) |

</details>

<details>
<summary><h3>📂 Mullvad</h3></summary>

| نام فایل | تعداد آدرس‌ها | لینک خام |
| :--- | :---: | :---: |
| `all.txt` | **39** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Mullvad/all.txt) |
| `adblock.txt` | **25** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Mullvad/adblock.txt) |
| `dnssec.txt` | **39** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Mullvad/dnssec.txt) |
| `doh.txt` | **15** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Mullvad/doh.txt) |
| `dot.txt` | **6** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Mullvad/dot.txt) |
| `family.txt` | **10** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Mullvad/family.txt) |
| `ipv4.txt` | **6** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Mullvad/ipv4.txt) |
| `ipv6.txt` | **6** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Mullvad/ipv6.txt) |
| `malware.txt` | **20** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Mullvad/malware.txt) |
| `no_log.txt` | **39** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Mullvad/no_log.txt) |
| `tcp.txt` | **6** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Mullvad/tcp.txt) |
| `udp.txt` | **6** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Mullvad/udp.txt) |
| `unfiltered.txt` | **14** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Mullvad/unfiltered.txt) |

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
| `all.txt` | **552** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Curl/all.txt) |
| `adblock.txt` | **203** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Curl/adblock.txt) |
| `dnssec.txt` | **117** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Curl/dnssec.txt) |
| `doh.txt` | **371** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Curl/doh.txt) |
| `doh3.txt` | **5** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Curl/doh3.txt) |
| `doq.txt` | **35** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Curl/doq.txt) |
| `dot.txt` | **146** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Curl/dot.txt) |
| `family.txt` | **82** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Curl/family.txt) |
| `malware.txt` | **71** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Curl/malware.txt) |
| `no_log.txt` | **95** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Curl/no_log.txt) |
| `unfiltered.txt` | **271** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Curl/unfiltered.txt) |

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
