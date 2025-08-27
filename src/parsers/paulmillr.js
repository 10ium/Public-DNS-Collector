import { createServerObject } from '../utils.js';
import { fetchData } from '../utils.js';

/**
 * Parses the structured JSON data for each provider from the paulmillr/encrypted-dns source.
 * This is an async parser that fetches a list of provider JSON files and then processes each one.
 * @returns {Promise<Array<object>>} A list of server objects.
 */
export async function parsePaulmillr() {
    const servers = [];
    const repoApiUrl = 'https://api.github.com/repos/paulmillr/encrypted-dns/contents/providers';

    // Step 1: Fetch the list of provider files from the GitHub API
    const filesList = await fetchData(repoApiUrl);
    if (!filesList || !Array.isArray(filesList)) {
        console.warn('  ⚠️ [Paulmillr Parser] دریافت لیست فایل‌های provider با شکست مواجه شد.');
        return [];
    }

    const jsonFiles = filesList.filter(file => file.name.endsWith('.json'));

    // Step 2: Process each JSON file concurrently
    const promises = jsonFiles.map(async (file) => {
        try {
            const providerData = await fetchData(file.download_url);
            if (!providerData) return null;

            const server = createServerObject();
            server.provider = providerData.names?.en || providerData.name || 'Unknown';

            // --- Final Corrected Logic: Extract ONLY the ServerURLOrName ---
            if (providerData.https && providerData.https.ServerURLOrName) {
                server.protocols.push('doh');
                server.addresses.push(providerData.https.ServerURLOrName);
            }
            if (providerData.tls && providerData.tls.ServerURLOrName) {
                server.protocols.push('dot');
                server.addresses.push(providerData.tls.ServerURLOrName);
            }
            
            // Infer filtering from censorship and notes
            const notes = (providerData.notes?.en || '').toLowerCase();
            if (providerData.censorship === false) {
                server.filters.unfiltered = true;
            } else {
                if (notes.includes('malware') || server.provider.toLowerCase().includes('security') || server.provider.toLowerCase().includes('protected')) {
                    server.filters.malware = true;
                }
                if (notes.includes('ads') || server.provider.toLowerCase().includes('adblock')) {
                    server.filters.ads = true;
                }
                if (notes.includes('adult') || server.provider.toLowerCase().includes('family')) {
                    server.filters.family = true;
                }
                
                if (providerData.censorship === true && !server.filters.malware && !server.filters.ads && !server.filters.family) {
                    server.filters.ads = true; // General fallback for "censorship=true"
                }
            }

            if (server.addresses.length > 0) {
                server.addresses = [...new Set(server.addresses)];
                server.protocols = [...new Set(server.protocols)];
                return server;
            }
            return null;

        } catch (error) {
            console.error(`  ❌ [Paulmillr Parser] پردازش فایل ${file.name} با خطا مواجه شد: ${error.message}`);
            return null;
        }
    });

    const results = await Promise.all(promises);
    return results.filter(Boolean);
}
