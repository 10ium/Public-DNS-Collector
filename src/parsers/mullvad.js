import { JSDOM } from 'jsdom';
import { createServerObject } from '../utils.js';

/**
 * Parses DNS server information from the Mullvad DNS documentation page.
 * This parser creates separate server objects for each protocol (DoH, DoT)
 * to ensure data integrity and standardizes DoT hostnames.
 * @param {string} content The raw HTML content from the Mullvad source.
 * @returns {Array<object>} A list of server objects.
 */
export function parseMullvad(content) {
    const servers = [];
    const dom = new JSDOM(content);
    const document = dom.window.document;

    // --- مرحله ۱: استخراج نقشه فیلترها از جدول "Hostnames and content blockers" ---
    const filterMap = new Map();
    const headers = Array.from(document.querySelectorAll('h3'));
    const hostnamesHeader = headers.find(h => h.textContent.includes('Hostnames and content blockers'));

    if (hostnamesHeader) {
        let filterTable = hostnamesHeader.nextElementSibling;
        while (filterTable && filterTable.tagName !== 'TABLE') {
            filterTable = filterTable.nextElementSibling;
        }

        if (filterTable) {
            const filterRows = filterTable.querySelectorAll('tbody tr');
            filterRows.forEach(row => {
                const cells = row.querySelectorAll('td');
                if (cells.length < 7) return;

                const hostname = cells[0].textContent.trim();
                const checks = Array.from(cells).map(cell => cell.textContent.includes('✅'));

                const filters = {
                    ads: checks[1], trackers: checks[2], malware: checks[3],
                    adult: checks[4], gambling: checks[5], social: checks[6],
                };
                filterMap.set(hostname, filters);
            });
        } else {
            console.warn('  ⚠️ [Mullvad Parser] جدول فیلترینگ ("Hostnames and content blockers") پیدا نشد.');
        }
    } else {
        console.warn('  ⚠️ [Mullvad Parser] هدر جدول فیلترینگ پیدا نشد.');
    }


    // --- مرحله ۲: پردازش جدول اصلی سرورها ("IP-addresses and ports") ---
    const ipsHeader = headers.find(h => h.textContent.includes('IP-addresses and ports'));
    if (ipsHeader) {
        let ipTable = ipsHeader.nextElementSibling;
        while (ipTable && ipTable.tagName !== 'TABLE') {
            ipTable = ipTable.nextElementSibling;
        }

        if (ipTable) {
            const ipRows = ipTable.querySelectorAll('tbody tr');
            ipRows.forEach(row => {
                const cells = row.querySelectorAll('td');
                if (cells.length < 5) return;

                const hostname = cells[0].textContent.trim();
                const ipv4 = cells[1].textContent.trim();
                const ipv6 = cells[2].textContent.trim();
                const dohPort = cells[3].textContent.trim();
                const dotPort = cells[4].textContent.trim();

                if (filterMap.has(hostname)) {
                    // ایجاد یک آبجکت پایه با اطلاعات مشترک
                    const baseServer = createServerObject();
                    baseServer.provider = 'Mullvad';

                    const serverFilters = filterMap.get(hostname);
                    baseServer.filters.ads = serverFilters.ads || serverFilters.trackers;
                    baseServer.filters.malware = serverFilters.malware;
                    baseServer.filters.family = serverFilters.adult || serverFilters.gambling;
                    if (!baseServer.filters.ads && !baseServer.filters.malware && !baseServer.filters.family && !serverFilters.social) {
                        baseServer.filters.unfiltered = true;
                    }

                    baseServer.features.dnssec = true; // Mullvad likely supports DNSSEC
                    baseServer.features.no_log = true;
                    baseServer.features.ipv6 = !!ipv6;

                    // **بهبود اصلی: برای هر پروتکل یک آبجکت جداگانه بساز**

                    // اگر از DoH پشتیبانی می‌کند، یک سرور DoH بساز
                    if (dohPort) {
                        const dohServer = {
                            ...baseServer,
                            protocols: ['doh'],
                            addresses: [`https://${hostname}/dns-query`],
                        };
                        servers.push(dohServer);
                    }

                    // اگر از DoT پشتیبانی می‌کند، یک سرور DoT بساز
                    if (dotPort) {
                        const dotAddresses = [`tls://${hostname}`]; // اضافه کردن پیشوند استاندارد
                        if (ipv4) dotAddresses.push(ipv4);
                        if (ipv6) dotAddresses.push(ipv6);

                        const dotServer = {
                            ...baseServer,
                            protocols: ['dot'],
                            addresses: [...new Set(dotAddresses)],
                        };
                        servers.push(dotServer);
                    }
                }
            });
        } else {
            console.warn('  ⚠️ [Mullvad Parser] جدول IP آدرس‌ها ("IP-addresses and ports") پیدا نشد.');
        }
    } else {
        console.warn('  ⚠️ [Mullvad Parser] هدر جدول IP آدرس‌ها پیدا نشد.');
    }

    // --- مرحله ۳: پردازش سرورهای خاص DoH-Only در جدول "Using a specific DNS server" ---
    // این بخش از قبل درست کار می‌کرد و نیازی به تغییر نداشت
    const specificHeader = headers.find(h => h.textContent.includes('Using a specific DNS server'));
    if (specificHeader) {
        let specificTable = specificHeader.nextElementSibling;
        while (specificTable && specificTable.tagName !== 'TABLE') {
            specificTable = specificTable.nextElementSibling;
        }

        if (specificTable) {
            const specificRows = specificTable.querySelectorAll('tbody tr');
            specificRows.forEach(row => {
                const cells = row.querySelectorAll('td');
                if (cells.length < 1) return;

                const dohUrl = cells[0].textContent.trim();
                if (dohUrl.startsWith('https://')) {
                    const server = createServerObject();
                    server.provider = 'Mullvad';
                    server.filters.unfiltered = true;
                    server.protocols = ['doh'];
                    server.addresses = [dohUrl];
                    server.features.dnssec = true;
                    server.features.no_log = true;
                    server.features.ipv6 = false; // پشتیبانی از IPv6 برای این سرورها مشخص نیست

                    servers.push(server);
                }
            });
        } else {
            console.warn('  ⚠️ [Mullvad Parser] جدول سرورهای خاص ("Using a specific DNS server") پیدا نشد.');
        }
    } else {
        console.warn('  ⚠️ [Mullvad Parser] هدر جدول سرورهای خاص پیدا نشد.');
    }

    return servers;
}
