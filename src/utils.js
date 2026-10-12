import axios from 'axios';

/**
 * Fetches raw content from a URL.
 * @param {string} url The URL to fetch.
 * @returns {Promise<string|object|null>} The content as a string or JSON object, or null on failure.
 */
const blockedHostnamePattern = /^(localhost|127(\.\d{1,3}){3}|0\.0\.0\.0|10(\.\d{1,3}){3}|192\.168(\.\d{1,3}){2}|172\.(1[6-9]|2\d|3[0-1])(\.\d{1,3}){2}|169\.254(\.\d{1,3}){2}|\[?::1\]?)$/i;

function isSafeUrl(url) {
    try {
        const parsed = new URL(url);
        if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
            return false;
        }
        return !blockedHostnamePattern.test(parsed.hostname);
    } catch {
        return false;
    }
}

export async function fetchData(url) {
    if (!isSafeUrl(url)) {
        console.error(`  ❌ [خطای امنیتی] آدرس ${url} مجاز نیست.`);
        return null;
    }
    try {
        const response = await axios.get(url, { timeout: 15000 });
        return response.data;
    } catch (error) {
        console.error(`  ❌ [خطای دریافت] دریافت اطلاعات از ${url} با شکست مواجه شد. علت: ${error.message}`);
        return null;
    }
}

/**
 * Creates a standardized DNS server object.
 * @returns {object} A template object.
 */
export function createServerObject() {
    return {
        provider: 'Unknown',
        protocols: [],
        addresses: [],
        filters: { ads: false, malware: false, family: false, unfiltered: false },
        features: { dnssec: false, no_log: false, ipv6: false },
    };
}
