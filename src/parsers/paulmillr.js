import { createServerObject } from '../utils.js';
import { fetchData } from '../utils.js';

/**
 * Parses the structured JSON data for each provider from the paulmillr/encrypted-dns source.
 * This is the definitive, async parser that fetches a list of provider JSON files and processes each one.
 * @returns {Promise<Array<object>>} A list of server objects.
 */
export async function parsePaulmillr() {
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

            const providerServers = []; // Will hold separate server objects for each protocol
            const providerName = providerData.names?.en || providerData.name || 'Unknown';
            
            // --- Determine Filters Once ---
            // This logic is common for all protocols from this provider
            const filters = {
                unfiltered: false,
                malware: false,
                ads: false,
                family: false,
            };

            if (providerData.censorship === false) {
                filters.unfiltered = true;
            } else { // Handles censorship: true or undefined
                const searchCorpus = [
                    providerData.names?.en,
                    providerData.name,
                    providerData.id,
                    providerData.profile,
                    providerData.notes?.en
                ].filter(Boolean).join(' ').toLowerCase();

                if (searchCorpus.includes('family') || searchCorpus.includes('adult content') || searchCorpus.includes('child protection')) {
                    filters.family = true;
                }
                if (searchCorpus.includes('ads') || searchCorpus.includes('ad-blocking') || searchCorpus.includes('adblock') || searchCorpus.includes('tracking') || searchCorpus.includes('noads')) {
                    filters.ads = true;
                }
                if (searchCorpus.includes('malware') || searchCorpus.includes('phishing') || searchCorpus.includes('security') || searchCorpus.includes('protected') || searchCorpus.includes('protective')) {
                    filters.malware = true;
                }
                if (providerData.censorship === true && !filters.malware && !filters.ads && !filters.family) {
                    filters.ads = true;
                    filters.malware = true;
                }
            }

            // --- Create a SEPARATE server object for DoH ---
            if (providerData.https && providerData.https.ServerURLOrName) {
                const dohServer = createServerObject();
                dohServer.provider = providerName;
                dohServer.protocols.push('doh');
                dohServer.addresses.push(providerData.https.ServerURLOrName);
                dohServer.filters = { ...filters }; // Assign a copy of the filters
                providerServers.push(dohServer);
            }

            // --- Create a SEPARATE server object for DoT ---
            if (providerData.tls && providerData.tls.ServerURLOrName) {
                const dotServer = createServerObject();
                dotServer.provider = providerName;
                dotServer.protocols.push('dot');
                dotServer.addresses.push(`tls://${providerData.tls.ServerURLOrName}`);
                dotServer.filters = { ...filters }; // Assign a copy of the filters
                providerServers.push(dotServer);
            }
            
            return providerServers;

        } catch (error) {
            console.error(`  ❌ [Paulmillr Parser] پردازش فایل ${file.name} با خطا مواجه شد: ${error.message}`);
            return null;
        }
    });

    const results = await Promise.all(promises);
    // Flatten the array of arrays and filter out any null/empty results
    return results.flat().filter(Boolean); 
}
