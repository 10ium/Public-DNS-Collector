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

این لیست‌ها حاصل ترکیب، پاک‌سازی و دسته‌بندی داده‌ها از **تمام منابعی که برای تجمیع فعال هستند** می‌باشند و برای استفاده عمومی توصیه می‌شوند.

| نام فایل | تعداد آدرس‌ها | توضیحات | لینک خام |
| :--- | :---: | :--- | :---: |
| `doh.txt` | **777** | لیست تمام سرورهای DNS-over-HTTPS. | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/doh.txt) |
| `dot.txt` | **661** | لیست تمام سرورهای DNS-over-TLS. | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/dot.txt) |
| `doq.txt` | **169** | لیست تمام سرورهای DNS-over-QUIC. | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/doq.txt) |
| `doh3.txt` | **6** | لیست تمام سرورهای DNS-over-HTTP/3. | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/doh3.txt) |
| `dnscrypt.txt` | **655** | لیست تمام سرورهای DNSCrypt (به صورت Stamp). | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/dnscrypt.txt) |
| `ipv4.txt` | **179** | لیست سرورهای DNS استاندارد روی IPv4. | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/ipv4.txt) |
| `ipv6.txt` | **143** | لیست تمام آدرس‌های IPv6 موجود. | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/ipv6.txt) |
| `adblock.txt` | **502** | لیست سرورهایی که تبلیغات را مسدود می‌کنند. | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/adblock.txt) |
| `malware.txt` | **451** | لیست سرورهایی که از بدافزار و فیشینگ جلوگیری می‌کنند. | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/malware.txt) |
| `family.txt` | **167** | لیست سرورهایی با فیلترینگ خانواده (محتوای بزرگسالان). | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/family.txt) |
| `unfiltered.txt` | **940** | لیست سرورهای بدون فیلترینگ خاص. | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/unfiltered.txt) |
| `no_log.txt` | **384** | لیست سرورهایی که ادعا می‌کنند لاگ کاربران را ذخیره نمی‌کنند. | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/no_log.txt) |
| `dnssec.txt` | **565** | لیست سرورهایی که از DNSSEC برای افزایش امنیت پشتیبانی می‌کنند. | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/dnssec.txt) |
| `dns64.txt` | **12** | لیست سرورهایی که از DNS64 پشتیبانی می‌کنند. | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/dns64.txt) |

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
| `unfiltered.txt` | **6808** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Blacklantern/unfiltered.txt) |

</details>

<details>
<summary><h3>📂 MutinSA</h3></summary>

| نام فایل | تعداد آدرس‌ها | لینک خام |
| :--- | :---: | :---: |
| `all.txt` | **40** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/MutinSA/all.txt) |
| `dns64.txt` | **12** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/MutinSA/dns64.txt) |
| `dnssec.txt` | **40** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/MutinSA/dnssec.txt) |
| `ipv4.txt` | **18** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/MutinSA/ipv4.txt) |
| `ipv6.txt` | **22** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/MutinSA/ipv6.txt) |
| `unfiltered.txt` | **40** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/MutinSA/unfiltered.txt) |

</details>

<details>
<summary><h3>📂 AdGuard</h3></summary>

| نام فایل | تعداد آدرس‌ها | لینک خام |
| :--- | :---: | :---: |
| `all.txt` | **595** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/AdGuard/all.txt) |
| `adblock.txt` | **215** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/AdGuard/adblock.txt) |
| `dnscrypt.txt` | **100** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/AdGuard/dnscrypt.txt) |
| `doh.txt` | **115** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/AdGuard/doh.txt) |
| `doq.txt` | **18** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/AdGuard/doq.txt) |
| `dot.txt` | **157** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/AdGuard/dot.txt) |
| `family.txt` | **53** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/AdGuard/family.txt) |
| `ipv4.txt` | **165** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/AdGuard/ipv4.txt) |
| `ipv6.txt` | **127** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/AdGuard/ipv6.txt) |
| `malware.txt` | **282** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/AdGuard/malware.txt) |
| `unfiltered.txt` | **19** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/AdGuard/unfiltered.txt) |

</details>

<details>
<summary><h3>📂 Mullvad</h3></summary>

| نام فایل | تعداد آدرس‌ها | لینک خام |
| :--- | :---: | :---: |
| `all.txt` | **33** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Mullvad/all.txt) |
| `adblock.txt` | **20** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Mullvad/adblock.txt) |
| `dnssec.txt` | **33** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Mullvad/dnssec.txt) |
| `doh.txt` | **33** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Mullvad/doh.txt) |
| `dot.txt` | **24** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Mullvad/dot.txt) |
| `family.txt` | **8** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Mullvad/family.txt) |
| `ipv4.txt` | **6** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Mullvad/ipv4.txt) |
| `ipv6.txt` | **6** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Mullvad/ipv6.txt) |
| `malware.txt` | **16** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Mullvad/malware.txt) |
| `no_log.txt` | **33** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Mullvad/no_log.txt) |
| `unfiltered.txt` | **13** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Mullvad/unfiltered.txt) |

</details>

<details>
<summary><h3>📂 DNSPrivacyOrg</h3></summary>

| نام فایل | تعداد آدرس‌ها | لینک خام |
| :--- | :---: | :---: |
| `all.txt` | **8** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/DNSPrivacyOrg/all.txt) |
| `dnssec.txt` | **8** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/DNSPrivacyOrg/dnssec.txt) |
| `doh.txt` | **6** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/DNSPrivacyOrg/doh.txt) |
| `doq.txt` | **1** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/DNSPrivacyOrg/doq.txt) |
| `dot.txt` | **7** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/DNSPrivacyOrg/dot.txt) |
| `malware.txt` | **1** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/DNSPrivacyOrg/malware.txt) |
| `no_log.txt` | **8** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/DNSPrivacyOrg/no_log.txt) |
| `unfiltered.txt` | **7** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/DNSPrivacyOrg/unfiltered.txt) |

</details>

<details>
<summary><h3>📂 Curl</h3></summary>

| نام فایل | تعداد آدرس‌ها | لینک خام |
| :--- | :---: | :---: |
| `all.txt` | **619** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Curl/all.txt) |
| `adblock.txt` | **241** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Curl/adblock.txt) |
| `dnscrypt.txt` | **3** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Curl/dnscrypt.txt) |
| `dnssec.txt` | **122** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Curl/dnssec.txt) |
| `doh.txt` | **619** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Curl/doh.txt) |
| `doh3.txt` | **6** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Curl/doh3.txt) |
| `doq.txt` | **154** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Curl/doq.txt) |
| `dot.txt` | **498** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Curl/dot.txt) |
| `family.txt` | **90** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Curl/family.txt) |
| `malware.txt` | **73** | [لینک](https://github.com/10ium/Public-DNS-Collector/raw/main/lists/sources/Curl/malware.txt) |
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
- **Paulmillr** (پردازشگر داخلی)
- **[Blacklantern](https://raw.githubusercontent.com/blacklanternsecurity/public-dns-servers/refs/heads/master/nameservers.txt)**
- **[MutinSA](https://gist.githubusercontent.com/mutin-sa/5dcbd35ee436eb629db7872581093bc5/raw/)**
- **[AdGuard](https://adguard-dns.io/kb/general/dns-providers/)**
- **[Mullvad](https://mullvad.net/en/help/dns-over-https-and-dns-over-tls)**
- **[DNSPrivacyOrg](https://dnsprivacy.org/public_resolvers/)**
- **[Curl](https://raw.githubusercontent.com/wiki/curl/curl/DNS-over-HTTPS.md)**
- **[Thiagozs](https://gist.githubusercontent.com/thiagozs/088fd8f8129ca06df524f6711116ee8f/raw/)**

---
<p align="center">ساخته شده با ❤️ و به صورت خودکار توسط GitHub Actions</p>
