<div align="center">

# 🛡️ Public DNS Collector 🛡️
### لیست‌های عمومی DNS جمع‌آوری شده

</div>

---

این مخزن به طور خودکار لیستی از سرورهای DNS عمومی را از منابع مختلف معتبر جمع‌آوری، پاک‌سازی و تجمیع می‌کند.

*آخرین به‌روزرسانی: `Fri, 29 Aug 2025 01:27:35 GMT`*

## لیست‌های تجمیعی (Aggregated Lists)

این لیست‌ها نتیجه ترکیب، پاک‌سازی و حذف موارد تکراری از تمام منابع هستند.

### پروتکل‌ها و IPها
| نام لیست | توضیحات | تعداد | لینک دانلود |
| --- | --- | --- | --- |
| **all** | لیست جامع تمام DNS ها از همه منابع و پروتکل‌ها . | [1769](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/all.txt) | [لینک خام](https://raw.githubusercontent.com/10ium/Public-DNS-Collector/main/lists/all.txt) |
| **doh** | سرورهای DNS over HTTPS (DoH) | [543](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/doh.txt) | [لینک خام](https://raw.githubusercontent.com/10ium/Public-DNS-Collector/main/lists/doh.txt) |
| **dot** | سرورهای DNS over TLS (DoT) | [259](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/dot.txt) | [لینک خام](https://raw.githubusercontent.com/10ium/Public-DNS-Collector/main/lists/dot.txt) |
| **doq** | سرورهای DNS over QUIC (DoQ) | [55](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/doq.txt) | [لینک خام](https://raw.githubusercontent.com/10ium/Public-DNS-Collector/main/lists/doq.txt) |
| **dnscrypt** | سرورهای DNSCrypt | [602](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/dnscrypt.txt) | [لینک خام](https://raw.githubusercontent.com/10ium/Public-DNS-Collector/main/lists/dnscrypt.txt) |
| **ipv4** | سرورهای DNS سنتی IPv4 | [186](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/ipv4.txt) | [لینک خام](https://raw.githubusercontent.com/10ium/Public-DNS-Collector/main/lists/ipv4.txt) |
| **ipv6** | سرورهای DNS سنتی IPv6 | [124](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/ipv6.txt) | [لینک خام](https://raw.githubusercontent.com/10ium/Public-DNS-Collector/main/lists/ipv6.txt) |


### لیست‌های فیلترینگ
| نام لیست | توضیحات | تعداد | لینک دانلود |
| --- | --- | --- | --- |
| **adblock** | مسدودکننده تبلیغات | [495](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/adblock.txt) | [لینک خام](https://raw.githubusercontent.com/10ium/Public-DNS-Collector/main/lists/adblock.txt) |
| **malware** | مسدودکننده بدافزارها و فیشینگ | [441](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/malware.txt) | [لینک خام](https://raw.githubusercontent.com/10ium/Public-DNS-Collector/main/lists/malware.txt) |
| **family** | محافظت از خانواده (مسدودکننده محتوای بزرگسالان) | [163](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/family.txt) | [لینک خام](https://raw.githubusercontent.com/10ium/Public-DNS-Collector/main/lists/family.txt) |
| **unfiltered** | بدون فیلتر | [862](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/unfiltered.txt) | [لینک خام](https://raw.githubusercontent.com/10ium/Public-DNS-Collector/main/lists/unfiltered.txt) |


### لیست‌های مبتنی بر ویژگی‌ها
| نام لیست | توضیحات | تعداد | لینک دانلود |
| --- | --- | --- | --- |
| **dnssec** | پشتیبانی از DNSSEC | [564](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/dnssec.txt) | [لینک خام](https://raw.githubusercontent.com/10ium/Public-DNS-Collector/main/lists/dnssec.txt) |
| **no_log** | ادعای عدم ثبت لاگ (No-Log Policy) | [383](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/no_log.txt) | [لینک خام](https://raw.githubusercontent.com/10ium/Public-DNS-Collector/main/lists/no_log.txt) |
| **dns64** | پشتیبانی از DNS64 | [12](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/dns64.txt) | [لینک خام](https://raw.githubusercontent.com/10ium/Public-DNS-Collector/main/lists/dns64.txt) |


## لیست‌های مبتنی بر منبع (Source-Specific Lists)

این لیست‌ها حاوی سرورهای استخراج شده از هر منبع به صورت جداگانه هستند.

| منبع | نام لیست | توضیحات | تعداد |
| --- | --- | --- | --- |
| DNSCrypt | **all** | لیست جامع تمام DNS ها از همه منابع و پروتکل‌ها . | [565](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/DNSCrypt/all.txt) |
|  | **dnscrypt** | سرورهای DNSCrypt | [565](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/DNSCrypt/dnscrypt.txt) |
|  | **adblock** | مسدودکننده تبلیغات | [17](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/DNSCrypt/adblock.txt) |
|  | **malware** | مسدودکننده بدافزارها و فیشینگ | [59](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/DNSCrypt/malware.txt) |
|  | **family** | محافظت از خانواده (مسدودکننده محتوای بزرگسالان) | [15](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/DNSCrypt/family.txt) |
|  | **unfiltered** | بدون فیلتر | [492](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/DNSCrypt/unfiltered.txt) |
|  | **dnssec** | پشتیبانی از DNSSEC | [319](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/DNSCrypt/dnssec.txt) |
|  | **no_log** | ادعای عدم ثبت لاگ (No-Log Policy) | [221](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/DNSCrypt/no_log.txt) |
| [Paulmillr](https://github.com/paulmillr/encrypted-dns) | **all** | لیست جامع تمام DNS ها از همه منابع و پروتکل‌ها . | [49](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/Paulmillr/all.txt) |
|  | **doh** | سرورهای DNS over HTTPS (DoH) | [27](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/Paulmillr/doh.txt) |
|  | **dot** | سرورهای DNS over TLS (DoT) | [22](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/Paulmillr/dot.txt) |
|  | **adblock** | مسدودکننده تبلیغات | [8](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/Paulmillr/adblock.txt) |
|  | **malware** | مسدودکننده بدافزارها و فیشینگ | [30](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/Paulmillr/malware.txt) |
|  | **family** | محافظت از خانواده (مسدودکننده محتوای بزرگسالان) | [14](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/Paulmillr/family.txt) |
|  | **unfiltered** | بدون فیلتر | [18](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/Paulmillr/unfiltered.txt) |
| Blacklantern | **all** | لیست جامع تمام DNS ها از همه منابع و پروتکل‌ها . | [6808](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/Blacklantern/all.txt) |
|  | **ipv4** | سرورهای DNS سنتی IPv4 | [6808](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/Blacklantern/ipv4.txt) |
|  | **unfiltered** | بدون فیلتر | [6808](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/Blacklantern/unfiltered.txt) |
| MutinSA | **all** | لیست جامع تمام DNS ها از همه منابع و پروتکل‌ها . | [40](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/MutinSA/all.txt) |
|  | **ipv4** | سرورهای DNS سنتی IPv4 | [18](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/MutinSA/ipv4.txt) |
|  | **ipv6** | سرورهای DNS سنتی IPv6 | [22](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/MutinSA/ipv6.txt) |
|  | **unfiltered** | بدون فیلتر | [40](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/MutinSA/unfiltered.txt) |
|  | **dnssec** | پشتیبانی از DNSSEC | [40](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/MutinSA/dnssec.txt) |
|  | **dns64** | پشتیبانی از DNS64 | [12](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/MutinSA/dns64.txt) |
| AdGuard | **all** | لیست جامع تمام DNS ها از همه منابع و پروتکل‌ها . | [563](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/AdGuard/all.txt) |
|  | **doh** | سرورهای DNS over HTTPS (DoH) | [107](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/AdGuard/doh.txt) |
|  | **dot** | سرورهای DNS over TLS (DoT) | [109](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/AdGuard/dot.txt) |
|  | **doq** | سرورهای DNS over QUIC (DoQ) | [17](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/AdGuard/doq.txt) |
|  | **dnscrypt** | سرورهای DNSCrypt | [50](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/AdGuard/dnscrypt.txt) |
|  | **ipv4** | سرورهای DNS سنتی IPv4 | [172](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/AdGuard/ipv4.txt) |
|  | **ipv6** | سرورهای DNS سنتی IPv6 | [108](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/AdGuard/ipv6.txt) |
|  | **adblock** | مسدودکننده تبلیغات | [209](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/AdGuard/adblock.txt) |
|  | **malware** | مسدودکننده بدافزارها و فیشینگ | [275](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/AdGuard/malware.txt) |
|  | **family** | محافظت از خانواده (مسدودکننده محتوای بزرگسالان) | [49](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/AdGuard/family.txt) |
|  | **unfiltered** | بدون فیلتر | [18](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/AdGuard/unfiltered.txt) |
| Mullvad | **all** | لیست جامع تمام DNS ها از همه منابع و پروتکل‌ها . | [33](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/Mullvad/all.txt) |
|  | **doh** | سرورهای DNS over HTTPS (DoH) | [15](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/Mullvad/doh.txt) |
|  | **dot** | سرورهای DNS over TLS (DoT) | [6](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/Mullvad/dot.txt) |
|  | **ipv4** | سرورهای DNS سنتی IPv4 | [6](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/Mullvad/ipv4.txt) |
|  | **ipv6** | سرورهای DNS سنتی IPv6 | [6](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/Mullvad/ipv6.txt) |
|  | **adblock** | مسدودکننده تبلیغات | [20](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/Mullvad/adblock.txt) |
|  | **malware** | مسدودکننده بدافزارها و فیشینگ | [16](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/Mullvad/malware.txt) |
|  | **family** | محافظت از خانواده (مسدودکننده محتوای بزرگسالان) | [8](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/Mullvad/family.txt) |
|  | **unfiltered** | بدون فیلتر | [13](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/Mullvad/unfiltered.txt) |
|  | **dnssec** | پشتیبانی از DNSSEC | [33](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/Mullvad/dnssec.txt) |
|  | **no_log** | ادعای عدم ثبت لاگ (No-Log Policy) | [33](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/Mullvad/no_log.txt) |
| DNSPrivacyOrg | **all** | لیست جامع تمام DNS ها از همه منابع و پروتکل‌ها . | [7](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/DNSPrivacyOrg/all.txt) |
|  | **doh** | سرورهای DNS over HTTPS (DoH) | [3](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/DNSPrivacyOrg/doh.txt) |
|  | **dot** | سرورهای DNS over TLS (DoT) | [3](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/DNSPrivacyOrg/dot.txt) |
|  | **doq** | سرورهای DNS over QUIC (DoQ) | [1](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/DNSPrivacyOrg/doq.txt) |
|  | **adblock** | مسدودکننده تبلیغات | [1](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/DNSPrivacyOrg/adblock.txt) |
|  | **malware** | مسدودکننده بدافزارها و فیشینگ | [2](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/DNSPrivacyOrg/malware.txt) |
|  | **unfiltered** | بدون فیلتر | [5](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/DNSPrivacyOrg/unfiltered.txt) |
|  | **dnssec** | پشتیبانی از DNSSEC | [7](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/DNSPrivacyOrg/dnssec.txt) |
|  | **no_log** | ادعای عدم ثبت لاگ (No-Log Policy) | [7](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/DNSPrivacyOrg/no_log.txt) |
| Curl | **all** | لیست جامع تمام DNS ها از همه منابع و پروتکل‌ها . | [620](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/Curl/all.txt) |
|  | **doh** | سرورهای DNS over HTTPS (DoH) | [414](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/Curl/doh.txt) |
|  | **dot** | سرورهای DNS over TLS (DoT) | [164](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/Curl/dot.txt) |
|  | **doq** | سرورهای DNS over QUIC (DoQ) | [42](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/Curl/doq.txt) |
|  | **adblock** | مسدودکننده تبلیغات | [241](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/Curl/adblock.txt) |
|  | **malware** | مسدودکننده بدافزارها و فیشینگ | [74](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/Curl/malware.txt) |
|  | **family** | محافظت از خانواده (مسدودکننده محتوای بزرگسالان) | [90](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/Curl/family.txt) |
|  | **unfiltered** | بدون فیلتر | [301](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/Curl/unfiltered.txt) |
|  | **dnssec** | پشتیبانی از DNSSEC | [122](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/Curl/dnssec.txt) |
|  | **no_log** | ادعای عدم ثبت لاگ (No-Log Policy) | [104](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/Curl/no_log.txt) |
| Thiagozs | **all** | لیست جامع تمام DNS ها از همه منابع و پروتکل‌ها . | [121](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/Thiagozs/all.txt) |
|  | **doh** | سرورهای DNS over HTTPS (DoH) | [121](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/Thiagozs/doh.txt) |
|  | **adblock** | مسدودکننده تبلیغات | [12](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/Thiagozs/adblock.txt) |
|  | **malware** | مسدودکننده بدافزارها و فیشینگ | [21](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/Thiagozs/malware.txt) |
|  | **family** | محافظت از خانواده (مسدودکننده محتوای بزرگسالان) | [3](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/Thiagozs/family.txt) |
|  | **unfiltered** | بدون فیلتر | [87](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/Thiagozs/unfiltered.txt) |
|  | **dnssec** | پشتیبانی از DNSSEC | [66](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/Thiagozs/dnssec.txt) |
|  | **no_log** | ادعای عدم ثبت لاگ (No-Log Policy) | [27](https://github.com/10ium/Public-DNS-Collector/blob/main/lists/sources/Thiagozs/no_log.txt) |


## منابع داده (Data Sources)
* [DNSCrypt](https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/refs/heads/master/v3/public-resolvers.md)
* [Paulmillr](https://github.com/paulmillr/encrypted-dns)
* [Blacklantern](https://raw.githubusercontent.com/blacklanternsecurity/public-dns-servers/refs/heads/master/nameservers.txt)
* [MutinSA](https://gist.githubusercontent.com/mutin-sa/5dcbd35ee436eb629db7872581093bc5/raw/)
* [AdGuard](https://adguard-dns.io/kb/general/dns-providers/)
* [Mullvad](https://mullvad.net/en/help/dns-over-https-and-dns-over-tls)
* [DNSPrivacyOrg](https://dnsprivacy.org/public_resolvers/)
* [Curl](https://raw.githubusercontent.com/wiki/curl/curl/DNS-over-HTTPS.md)
* [Thiagozs](https://gist.githubusercontent.com/thiagozs/088fd8f8129ca06df524f6711116ee8f/raw/)

## مشارکت
این پروژه توسط اسکریپت‌ها به طور خودکار به‌روز می‌شود. اگر منبع جدیدی می‌شناسید یا در فرآیند استخراج مشکلی مشاهده کردید، لطفاً یک [Issue](https://github.com/10ium/Public-DNS-Collector/issues) ثبت کنید.
