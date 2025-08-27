import axios from 'axios';

/**
 * Fetches raw content from a URL.
 * @param {string} url The URL to fetch.
 * @returns {Promise<string|object|null>} The content as a string or JSON object, or null on failure.
 */
export async function fetchData(url) {
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
