import { createServerObject } from '../utils.js';
import { fetchData } from '../utils.js';

/**
 * Parses the structured JSON data for each provider from the paulmillr/encrypted-dns source.
 * This is the definitive, async parser that fetches a list of provider JSON files and processes each one.
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

            // --- IMPROVED: Protocol Detection & Formatting ---
            // Add DoH (DNS over HTTPS) address if available
            if (providerData.https && providerData.https.ServerURLOrName) {
                server.protocols.push('doh');
                server.addresses.push(providerData.https.ServerURLOrName);
            }
            // Add DoT (DNS over TLS) address if available, with the required prefix
            if (providerData.tls && providerData.tls.ServerURLOrName) {
                server.protocols.push('dot');
                server.addresses.push(`tls://${providerData.tls.ServerURLOrName}`);
            }

            // If no addresses were found after checking all protocols, skip this provider
            if (server.addresses.length === 0) {
                return null;
            }
            
            // --- REVISED: Filtering Logic ---
            if (providerData.censorship === false) {
                server.filters.unfiltered = true;
            } else { // Handles censorship: true or undefined
                // Create a comprehensive text corpus by combining relevant fields to search for keywords
                const searchCorpus = [
                    providerData.names?.en,
                    providerData.name,
                    providerData.id,
                    providerData.profile,
                    providerData.notes?.en
                ].filter(Boolean).join(' ').toLowerCase();

                // Check for "family" filters
                if (searchCorpus.includes('family') || searchCorpus.includes('adult content') || searchCorpus.includes('child protection')) {
                    server.filters.family = true;
                }
                
                // Check for ad/tracking filters independently
                if (searchCorpus.includes('ads') || searchCorpus.includes('ad-blocking') || searchCorpus.includes('adblock') || searchCorpus.includes('tracking') || searchCorpus.includes('noads')) {
                    server.filters.ads = true;
                }

                // Check for security filters (malware/phishing) independently
                if (searchCorpus.includes('malware') || searchCorpus.includes('phishing') || searchCorpus.includes('security') || searchCorpus.includes('protected') || searchCorpus.includes('protective')) {
                    server.filters.malware = true;
                }

                // Fallback for providers marked with `censorship: true` but without specific keywords found.
                // This assumes a general-purpose security and ad-blocking filter.
                if (providerData.censorship === true && !server.filters.malware && !server.filters.ads && !server.filters.family) {
                    server.filters.ads = true;
                    server.filters.malware = true;
                }
            }

            // Final cleanup of collected data
            server.addresses = [...new Set(server.addresses)];
            server.protocols = [...new Set(server.protocols)];
            
            return server;

        } catch (error) {
            console.error(`  ❌ [Paulmillr Parser] پردازش فایل ${file.name} با خطا مواجه شد: ${error.message}`);
            return null;
        }
    });

    const results = await Promise.all(promises);
    return results.filter(Boolean); // Filter out any null results from failed fetches/parses
}
