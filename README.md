# GhostVPN Reality SNI Finder

Find public HTTPS domains that may be suitable as `target` and `serverNames` for Xray REALITY. Run it **on the VPS** whose outbound network you want to measure. Requires Python 3. The recommended launch command also requires `curl`; no third-party Python packages are needed.

## Install and run

Run these commands on the VPS you want to check. On Ubuntu/Debian, install the dependencies if needed:

```bash
sudo apt update
sudo apt install -y python3 git curl ca-certificates
```

First installation:

```bash
git clone https://github.com/SilentGhostCodes/ghostvpn-sni-finder.git
cd ghostvpn-sni-finder
sh run.sh --query-transport curl --discovery-timeout 60 --skip-qlever
```

This command successfully completed online discovery on the tested Netherlands and Turkey VPSs. It is the recommended starting point; availability can differ between networks.

| Option | What it does |
| --- | --- |
| `--query-transport curl` | Sends SPARQL queries using curl over IPv4 and HTTP/1.1. |
| `--discovery-timeout 60` | Allows up to 60 seconds for a curl query. Also applies to query diagnostics. |
| `--skip-qlever` | Skips the QLever endpoints that timed out on the tested VPSs. Wikidata remains enabled. |

Running just `sh run.sh` still selects the Python query client. The command above explicitly selects curl. `--timeout` separately controls ordinary API connections and candidate-site checks; it does not set the SPARQL discovery timeout.

## Update an existing installation

Do not clone the repository again inside its existing directory. If installed in your home directory:

```bash
cd ~/ghostvpn-sni-finder
git pull --ff-only
sh run.sh --query-transport curl --discovery-timeout 60 --skip-qlever
```

## Discovery

The script detects the VPS public IPv4, ASN, prefix, and approximate country. It fetches websites from Wikidata's public SPARQL service, independent QLever endpoints, or OpenStreetMap, skips a small list of major domains, checks certificate validation, TLS 1.3, HTTP/2, redirects, ASN and GeoIP, and prints a best candidate. It saves all passed candidates to `sni-results-IP.csv`.

Country detection supports two-letter ISO country codes worldwide. Country lookup and website discovery use a single SPARQL query, avoiding two consecutive requests for countries such as Turkey. A country must have enough listed official sites that pass the network checks; some countries may yield no candidates.

The API client identifies the project with a descriptive User-Agent, accepts SPARQL JSON, and, when using the Python transport, retains response cookies during each run. Successful SPARQL results are cached for 24 hours in `~/.cache/ghostvpn-sni-finder`, so repeating the same search does not make another query. Candidate websites are still rechecked on every run. These measures reduce unnecessary requests; they cannot remove a rate limit imposed by a service.

Wikidata may temporarily return HTTP 429/502. Without `--skip-qlever`, the script tries two published QLever addresses. With that option, both are skipped. After an HTTP 429/502/503/504 response and no successful alternative, the script can retry Wikidata once. For HTTP 429 it waits for `Retry-After` when the delay is at most 65 seconds; longer delays are not retried during that run. If discovery is still down, it asks OpenStreetMap for a bounded sample of website tags within 30 km of the server's approximate GeoIP coordinates. This automatic fallback works for any country with suitable GeoIP coordinates and mapped websites, including Turkey. It also includes small built-in candidate lists for `NL`, `DE`, or `TR` where available. If no candidates are found, save one domain per line in `my-domains.txt` and run `sh run.sh --domains my-domains.txt`. No service is guaranteed to be reachable from every VPS.

## More launch examples

Override the search country (two-letter ISO code):

```bash
sh run.sh --query-transport curl --discovery-timeout 60 --skip-qlever --country TR
```

Request another batch of websites:

```bash
sh run.sh --query-transport curl --discovery-timeout 60 --skip-qlever --offset 300
```

Exclude domains listed in a file:

```bash
sh run.sh --query-transport curl --discovery-timeout 60 --skip-qlever --exclude excluded.txt
```

Use your own domain list instead of online discovery:

```bash
sh run.sh --domains my-domains.txt
```

Test Wikidata with the same transport and timeout, without scanning candidate websites:

```bash
sh run.sh --diagnose --query-transport curl --discovery-timeout 60 --skip-qlever
```

Diagnostics bypass the discovery cache. Remove `--skip-qlever` to test QLever too. HTTP errors include `Retry-After` when provided. A small diagnostic query succeeding does not guarantee a larger discovery query will succeed.

Show all options:

```bash
sh run.sh --help
```

For a single-file download, fetch `reality_sni_finder.py` from this repository and run:

```bash
python3 reality_sni_finder.py --query-transport curl --discovery-timeout 60 --skip-qlever
```

## How ranking works

- Matching ASN gets the highest weight. Matching approximate IP country comes next.
- TCP+TLS establishment latency and a small HTTPS download sample break ties.
- Sites that redirect to another hostname, fail TLS/certificate/HTTP checks, or resolve to a known different country are rejected.
- Small HTML pages produce no reliable speed measurement and are marked `small page`.

The script uses Wikidata (via Wikimedia or QLever) or OpenStreetMap for discovery, and RIPEstat for ASN/approximate location. Organizational country and GeoIP city are not necessarily the physical hosting location. The speed sample (at most 256 KiB per domain) measures that site's HTTPS response from the VPS; it is not VPN throughput or a popularity score. A Windows or German VPS test cannot establish reachability from Russian providers. Test finalists separately over the intended client network before changing a production profile.

No IP ranges are scanned. At most 8 public domains are contacted at once. Default is 4. OpenStreetMap fallback makes one location-bound website query; it is not an exhaustive country search. The script does not change Xray or Remnawave configuration.
