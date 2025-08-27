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

            // Extract addresses and protocols
            if (providerData.https) {
                server.protocols.push('doh');
                if (providerData.https.ServerURLOrName) {
                    server.addresses.push(providerData.https.ServerURLOrName);
                }
                if (providerData.https.ServerAddresses) {
                    server.addresses.push(...providerData.https.ServerAddresses);
                }
            }
            if (providerData.tls) {
                server.protocols.push('dot');
                if (providerData.tls.ServerURLOrName) {
                    server.addresses.push(providerData.tls.ServerURLOrName);
                }
                if (providerData.tls.ServerAddresses) {
                    server.addresses.push(...providerData.tls.ServerAddresses);
                }
            }
            
            // Infer filtering from censorship and notes
            const notes = (providerData.notes?.en || '').toLowerCase();
            if (providerData.censorship === false) {
                server.filters.unfiltered = true;
            } else {
                if (notes.includes('malware')) server.filters.malware = true;
                if (notes.includes('ads')) server.filters.ads = true;
                if (notes.includes('adult') || notes.includes('family')) server.filters.family = true;
                // If censorship is true but no specific category is found, assume general adblocking
                if (!server.filters.malware && !server.filters.ads && !server.filters.family) {
                    server.filters.ads = true;
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
    return results.filter(Boolean); // Filter out any null results from failed fetches/parses
}
