# GhostVPN Reality SNI Finder

Find public HTTPS domains that may be suitable as `target` and `serverNames` for Xray REALITY. Run it **on the VPS** whose outbound network you want to measure. Requires Python 3 and no third-party packages.

## Run

```bash
git clone https://github.com/SilentGhostCodes/ghostvpn-sni-finder.git
cd ghostvpn-sni-finder
sh run.sh
```

The script detects the VPS public IPv4, ASN, prefix, and approximate country. It fetches official sites of organizations in that country from Wikidata, skips a small list of major domains, checks certificate validation, TLS 1.3, HTTP/2, redirects, ASN and GeoIP, and prints a best candidate. It saves all passed candidates to `sni-results-IP.csv`.

Country detection supports two-letter ISO country codes worldwide. For codes beyond a small built-in cache, the script asks Wikidata to resolve the code. A country must have enough listed official sites that pass the network checks; some countries may yield no candidates.

```bash
sh run.sh --server-ip 94.183.238.82 --country DE
sh run.sh --country NL                  # Dutch sites from a Netherlands VPS
sh run.sh --offset 300                 # Another batch of sites
sh run.sh --domains my-domains.txt     # One domain per line
sh run.sh --exclude excluded.txt       # One root domain per line
sh run.sh --help
```

For a single-file download, fetch `reality_sni_finder.py` from this repository and run `python3 reality_sni_finder.py`.

## How ranking works

- Matching ASN gets the highest weight. Matching approximate IP country comes next.
- TCP+TLS establishment latency and a small HTTPS download sample break ties.
- Sites that redirect to another hostname, fail TLS/certificate/HTTP checks, or resolve to a known different country are rejected.
- Small HTML pages produce no reliable speed measurement and are marked `small page`.

The script uses Wikidata for discovery and RIPEstat for ASN/approximate location. Organizational country is not necessarily the hosting country. The speed sample (at most 256 KiB per domain) measures that site's HTTPS response from the VPS; it is not VPN throughput or a popularity score. A Windows or German VPS test cannot establish reachability from Russian providers. Test finalists separately over the intended client network before changing a production profile.

No IP ranges are scanned. At most 8 public domains are contacted at once. Default is 4. The script does not change Xray or Remnawave configuration.
