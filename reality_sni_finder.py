#!/usr/bin/env python3
"""Find REALITY target/SNI candidates from the server itself. Python 3, stdlib only."""

import argparse
import concurrent.futures
import csv
import email.utils
import email.parser
import hashlib
import http.cookiejar
import ipaddress
import io
import json
import math
import random
import shutil
import socket
import ssl
import subprocess
import sys
import time
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


# Offline starting points when Wikidata Query Service is overloaded. These are
# only candidates; every domain must still pass the regular network checks.
FALLBACK_DOMAINS = {
    "NL": [
        "www.kerkrade.nl", "www.heerlen.nl", "www.gemeentemaastricht.nl",
        "www.sittard-geleen.nl", "www.landgraaf.nl", "www.brunssum.nl",
        "www.roermond.nl", "www.venlo.nl", "www.weert.nl",
        "www.eindhoven.nl", "www.tilburg.nl", "www.breda.nl",
        "www.delft.nl", "www.leiden.nl", "www.haarlem.nl",
        "www.enschede.nl", "www.deventer.nl", "www.zwolle.nl",
        "www.arnhem.nl", "www.nijmegen.nl", "www.groningen.nl",
        "www.wageningen.nl", "www.middelburg.nl", "www.leeuwarden.nl",
    ],
    "DE": [
        "www.bielefeld.de", "www.muenster.de", "www.dortmund.de",
        "www.bochum.de", "www.essen.de", "www.duisburg.de",
        "www.bonn.de", "www.aachen.de", "www.wuppertal.de",
        "www.krefeld.de", "www.duesseldorf.de", "www.dresden.de",
    ],
    "TR": [
        "www.ankara.bel.tr", "www.yenimahalle.bel.tr", "www.cankaya.bel.tr",
        "www.mamak.bel.tr", "www.kecioren.bel.tr", "www.ankara.edu.tr",
        "www.hacettepe.edu.tr", "www.gazi.edu.tr", "www.odtu.edu.tr",
        "www.tubitak.gov.tr", "www.etu.edu.tr", "www.etimesgut.bel.tr",
    ],
}
LARGE_DOMAINS = {
    "google.com", "google.de", "youtube.com", "facebook.com", "instagram.com",
    "cloudflare.com", "hetzner.com", "netcup.com", "microsoft.com",
    "amazon.com", "wikipedia.org", "wikimedia.org", "apple.com",
}
HEADERS = {"User-Agent": "GhostVPN-SNI-Finder/1.1 (+https://github.com/SilentGhostCodes/ghostvpn-sni-finder)"}
RIPE = "https://stat.ripe.net/data/"
WIKIDATA = "https://query.wikidata.org/sparql"
QLEVER_ENDPOINTS = (
    "https://qlever.dev/api/wikidata",
    "https://qlever.cs.uni-freiburg.de/api/wikidata",
)
OVERPASS = "https://overpass.private.coffee/api/interpreter"
SPARQL_PREFIXES = (
    "PREFIX wd: <http://www.wikidata.org/entity/> "
    "PREFIX wdt: <http://www.wikidata.org/prop/direct/> "
)
BYTES_TO_READ = 256 * 1024
API_SESSION = urllib.request.build_opener(
    urllib.request.ProxyHandler({}),
    urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
)
CACHE_DIR = Path.home() / ".cache" / "ghostvpn-sni-finder"
CACHE_TTL = 24 * 60 * 60
QUERY_TRANSPORT = "python"


def request_json(url, timeout, accept="application/json"):
    request = urllib.request.Request(url, headers={**HEADERS, "Accept": accept})
    with API_SESSION.open(request, timeout=timeout) as response:
        return json.load(response)


def request_query_json(url, timeout):
    """Optional curl transport matching the successful VPS IPv4 diagnostic."""
    if QUERY_TRANSPORT != "curl":
        return request_json(url, timeout, "application/sparql-results+json")
    with tempfile.TemporaryDirectory(prefix="sni-query-") as directory:
        body = Path(directory) / "body"
        headers = Path(directory) / "headers"
        command = [
            "curl", "-q", "-4", "--http1.1", "--silent", "--show-error",
            "--globoff", "--connect-timeout", str(min(timeout, 10)),
            "--max-time", str(timeout),
            "--user-agent", HEADERS["User-Agent"],
            "--header", "Accept: application/sparql-results+json",
            "--dump-header", str(headers), "--output", str(body),
            "--write-out", "%{http_code}", "--url", url,
        ]
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=timeout + 5)
        except subprocess.TimeoutExpired as error:
            raise OSError(f"curl query timed out after {timeout}s") from error
        if result.returncode:
            raise OSError(result.stderr.strip() or f"curl exit code {result.returncode}")
        status = int(result.stdout.strip())
        payload = body.read_bytes()
        if status != 200:
            # Take the last HTTP header block (a proxy may add a CONNECT response).
            blocks = headers.read_text(encoding="iso-8859-1").strip().split("\n\n")
            header_text = blocks[-1].partition("\n")[2]
            parsed_headers = email.parser.Parser().parsestr(header_text)
            raise urllib.error.HTTPError(url, status, "Query request failed", parsed_headers, io.BytesIO(payload))
        return json.loads(payload)


def query_cache_path(query):
    return CACHE_DIR / (hashlib.sha256(query.encode("utf-8")).hexdigest() + ".json")


def cached_bindings(query):
    path = query_cache_path(query)
    try:
        if not 0 <= time.time() - path.stat().st_mtime < CACHE_TTL:
            return None
        value = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(value, list) and all(isinstance(row, dict) for row in value):
            return value
    except (OSError, ValueError):
        pass
    return None


def fetch_bindings(url, timeout, query):
    rows = request_query_json(url, timeout)["results"]["bindings"]
    if not isinstance(rows, list):
        raise ValueError("Unexpected SPARQL result format")
    temporary = None
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=CACHE_DIR, delete=False) as output:
            temporary = Path(output.name)
            json.dump(rows, output)
        temporary.replace(query_cache_path(query))
    except OSError:
        pass  # A read-only home directory must not prevent discovery.
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
    return rows


def retry_after_delay(error):
    value = error.headers.get("Retry-After", "") if error.headers else ""
    try:
        return int(value)
    except (TypeError, ValueError):
        try:
            return int(email.utils.parsedate_to_datetime(value).timestamp() - time.time()) + 1
        except (TypeError, ValueError, OverflowError, IndexError):
            return 60


def sparql_bindings(query, timeout, skip_qlever=False):
    cached = cached_bindings(query)
    if cached is not None:
        print("Using cached discovery results (up to 24 hours old); sites will be checked again.", flush=True)
        return cached
    encoded = urllib.parse.urlencode({"query": SPARQL_PREFIXES + query})
    wikidata_url = WIKIDATA + "?" + encoded + "&format=json"
    print(f"Querying Wikidata via {QUERY_TRANSPORT}; timeout {timeout}s...", flush=True)
    try:
        return fetch_bindings(wikidata_url, timeout, query)
    except (OSError, ValueError, KeyError) as primary:
        print(f"Wikidata Query Service unavailable ({primary}).", flush=True)
        alternatives = []
        for endpoint in (() if skip_qlever else QLEVER_ENDPOINTS):
            print(f"Trying {endpoint}...", flush=True)
            try:
                return fetch_bindings(endpoint + "?" + encoded, min(timeout, 20), query)
            except (OSError, ValueError, KeyError) as error:
                alternatives.append(str(error))
        # Only one repeat request, respecting the service's rate-limit header.
        if isinstance(primary, urllib.error.HTTPError) and primary.code in (429, 502, 503, 504):
            delay = retry_after_delay(primary) if primary.code == 429 else 5
            if 0 <= delay <= 65:
                print(f"Other query endpoints unavailable; retrying Wikidata in {delay}s...", flush=True)
                time.sleep(delay)
                try:
                    return fetch_bindings(wikidata_url, timeout, query)
                except (OSError, ValueError, KeyError) as error:
                    primary = error
        raise OSError(f"Wikidata: {primary}; QLever: {'; '.join(alternatives) or 'skipped'}")


def network_info(ip, timeout):
    url = RIPE + "network-info/data.json?" + urllib.parse.urlencode({"resource": ip})
    data = request_json(url, timeout)["data"]
    return [str(asn) for asn in data.get("asns", [])], data.get("prefix", "")


def location(ip, timeout):
    url = RIPE + "maxmind-geo-lite/data.json?" + urllib.parse.urlencode({"resource": ip})
    data = request_json(url, timeout)["data"]
    for resource in data.get("located_resources", []):
        for loc in resource.get("locations", []):
            country = loc.get("country", "")
            if isinstance(country, str) and len(country) == 2 and country.isalpha():
                return country.upper(), loc.get("city", "") or ""
    return "", ""


def normalize(value):
    value = value.strip()
    if not value or value.startswith("#"):
        return ""
    try:
        parsed = urllib.parse.urlsplit(value if "://" in value else "https://" + value)
        domain = (parsed.hostname or "").rstrip(".").lower().encode("idna").decode("ascii")
        if parsed.username or parsed.password or parsed.port not in (None, 443):
            return ""
        if "." not in domain or any(part == "" for part in domain.split(".")):
            return ""
    except (ValueError, UnicodeError):
        return ""
    try:
        ipaddress.ip_address(domain)
        return ""
    except ValueError:
        return domain


def blocked(domain, excluded):
    return any(domain == root or domain.endswith("." + root) for root in excluded)


def discover_osm(server_ip, country, limit, timeout):
    """Fetch a small sample of websites mapped near the VPS's GeoIP city."""
    url = RIPE + "maxmind-geo-lite/data.json?" + urllib.parse.urlencode({"resource": server_ip})
    data = request_json(url, timeout)["data"]
    point = None
    for resource in data.get("located_resources", []):
        for loc in resource.get("locations", []):
            if loc.get("country", "").upper() != country:
                continue
            try:
                lat, lon = float(loc["latitude"]), float(loc["longitude"])
                if math.isfinite(lat) and math.isfinite(lon) and -90 <= lat <= 90 and -180 <= lon <= 180:
                    point = (lat, lon)
                    break
            except (KeyError, TypeError, ValueError):
                pass
        if point:
            break
    if not point:
        return []
    lat, lon = point
    result_limit = min(limit, 400)
    query = (
        f"[out:json][timeout:25];(nwr[\"website\"](around:30000,{lat},{lon});"
        f"nwr[\"contact:website\"](around:30000,{lat},{lon}););out tags {result_limit};"
    )
    url = OVERPASS + "?" + urllib.parse.urlencode({"data": query})
    elements = request_json(url, max(timeout, 30))["elements"]
    websites = set()
    for item in elements:
        tags = item.get("tags", {})
        for key in ("website", "contact:website"):
            for value in tags.get(key, "").split(";"):
                if value.strip():
                    websites.add(value.strip())
    print(f"OpenStreetMap: {len(websites)} websites mapped within 30 km of "
          f"GeoIP coordinates {lat:.2f}, {lon:.2f} (approximate).", flush=True)
    return sorted(websites)


def discover(country, limit, offset, timeout, server_ip=None, discovery_timeout=60, skip_qlever=False):
    try:
        query = (
            "SELECT DISTINCT ?website WHERE { "
            f'?country wdt:P297 "{country}" . '
            "?org wdt:P17 ?country ; wdt:P856 ?website . "
            'FILTER(STRSTARTS(STR(?website), "https://")) '
            f"}} LIMIT {limit} OFFSET {offset}"
        )
        rows = sparql_bindings(query, discovery_timeout, skip_qlever)
        return [item["website"]["value"] for item in rows]
    except (urllib.error.URLError, OSError) as error:
        if server_ip:
            print(f"SPARQL discovery unavailable ({error}); trying OpenStreetMap...", flush=True)
            try:
                sites = discover_osm(server_ip, country, limit, timeout)
                if sites:
                    return sites + FALLBACK_DOMAINS.get(country, [])
            except (OSError, ValueError, KeyError) as osm_error:
                print(f"OpenStreetMap unavailable ({osm_error}).", flush=True)
        fallback = FALLBACK_DOMAINS.get(country)
        if not fallback:
            raise ValueError(
                f"Automatic discovery unavailable ({error}); pass --domains sites.txt "
                "or retry after the service recovers"
            ) from error
        print(f"Online discovery unavailable ({error}); checking {len(fallback)} built-in "
              f"{country} candidate domains instead.", flush=True)
        return fallback


def diagnose_sources(timeout, skip_qlever=False):
    query = SPARQL_PREFIXES + 'SELECT ?country WHERE { ?country wdt:P297 "TR" . } LIMIT 1'
    encoded = urllib.parse.urlencode({"query": query, "format": "json"})
    passed = 0
    for endpoint in (WIKIDATA,) + (() if skip_qlever else QLEVER_ENDPOINTS):
        print(f"\nTesting {endpoint} via {QUERY_TRANSPORT}; timeout {timeout}s", flush=True)
        start = time.monotonic()
        try:
            data = request_query_json(endpoint + "?" + encoded, timeout)
            rows = data["results"]["bindings"]
            print(f"OK: {len(rows)} result(s), {time.monotonic() - start:.1f}s")
            passed += 1
        except urllib.error.HTTPError as error:
            retry = error.headers.get("Retry-After", "not provided") if error.headers else "not provided"
            print(f"HTTP {error.code}; Retry-After: {retry}; {time.monotonic() - start:.1f}s")
            try:
                print(error.read(300).decode("utf-8", errors="replace"))
            except OSError:
                pass
        except (OSError, ValueError, KeyError) as error:
            print(f"Failed after {time.monotonic() - start:.1f}s: {error}")
    return 0 if passed else 2


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


HTTP = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())


def sample_download(domain, timeout):
    url = f"https://{domain}/"
    redirected = False
    for _ in range(2):
        req = urllib.request.Request(url, headers={
            **HEADERS, "Range": f"bytes=0-{BYTES_TO_READ - 1}", "Accept-Encoding": "identity"
        })
        try:
            start = time.monotonic()
            with HTTP.open(req, timeout=timeout) as response:
                status = response.status
                chunks = 0
                deadline = time.monotonic() + timeout
                while chunks < BYTES_TO_READ and time.monotonic() < deadline:
                    block = response.read(min(32768, BYTES_TO_READ - chunks))
                    if not block:
                        break
                    chunks += len(block)
                seconds = max(time.monotonic() - start, 0.001)
            if status >= 400:
                return None
            # Small HTML pages are not a useful throughput benchmark.
            speed = round(chunks / seconds / 1024) if chunks >= 16384 else 0
            return status, redirected, chunks, speed
        except urllib.error.HTTPError as error:
            if error.code not in (301, 302, 303, 307, 308):
                return None
            next_url = urllib.parse.urljoin(url, error.headers.get("Location", ""))
            parsed = urllib.parse.urlsplit(next_url)
            if parsed.scheme != "https" or parsed.hostname != domain or parsed.port not in (None, 443):
                return None
            url, redirected = next_url, True
        except (OSError, ValueError):
            return None
    return None


def check(domain, timeout):
    try:
        addresses = socket.getaddrinfo(domain, 443, socket.AF_INET, socket.SOCK_STREAM)
        ips = list(dict.fromkeys(item[4][0] for item in addresses))
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.set_alpn_protocols(["h2"])
        for ip in ips[:3]:
            try:
                start = time.monotonic()
                with socket.create_connection((ip, 443), timeout=timeout) as raw:
                    with context.wrap_socket(raw, server_hostname=domain) as tls:
                        if tls.version() != "TLSv1.3" or tls.selected_alpn_protocol() != "h2":
                            continue
                        handshake_ms = round((time.monotonic() - start) * 1000)
                sample = sample_download(domain, timeout)
                if sample is None:
                    continue
                status, redirected, size, speed = sample
                return {"domain": domain, "ip": ip, "tls_ms": handshake_ms,
                        "http": status, "redirect": "same host" if redirected else "no",
                        "sample_bytes": size, "sample_kibs": speed}
            except (OSError, ssl.SSLError, ValueError):
                pass
    except (OSError, ValueError):
        pass
    return None


def read_domains(filename):
    with open(filename, encoding="utf-8-sig", newline="") as source:
        if filename.lower().endswith(".csv"):
            return [row["domain"] for row in csv.DictReader(source) if row.get("domain")]
        return source.readlines()


def score(row, country):
    # Network affinity and a verified country are stronger signals than a small page's throughput.
    same_network = 100 if row["same_asn"] == "yes" else 0
    same_country = 35 if row["site_country"] == country else 0
    tls = max(0, 30 - row["tls_ms"] / 10)
    sample = min(row["sample_kibs"] / 100, 15)
    redirect = -5 if row["redirect"] != "no" else 0
    return round(same_network + same_country + tls + sample + redirect, 1)


def main():
    global QUERY_TRANSPORT
    parser = argparse.ArgumentParser(description="Discover and compare REALITY target/SNI candidates from a VPS")
    parser.add_argument("--server-ip", help="Public IPv4; detected automatically when omitted")
    parser.add_argument("--country", help="Override detected country with a two-letter ISO code, e.g. NL")
    parser.add_argument("--domains", help="Use newline-separated domains or a previous result CSV")
    parser.add_argument("--exclude", help="Newline-separated domains to exclude")
    parser.add_argument("--limit", type=int, default=300, help="Wikidata records to fetch (default 300)")
    parser.add_argument("--offset", type=int, default=0, help="Fetch another batch if results are sparse")
    parser.add_argument("--workers", type=int, default=4, help="Concurrent checks (default 4, max 8)")
    parser.add_argument("--timeout", type=int, default=7, help="Timeout per connection in seconds")
    parser.add_argument("--discovery-timeout", type=int, default=60,
                        help="Query timeout for discovery and --diagnose (default 60, range 20..120)")
    parser.add_argument("--query-transport", choices=("python", "curl"), default="python",
                        help="SPARQL client: Python (default) or curl over IPv4/HTTP1.1")
    parser.add_argument("--skip-qlever", action="store_true", help="Skip QLever when unreachable from this VPS")
    parser.add_argument("--top", type=int, default=15, help="How many results to print")
    parser.add_argument("--output", help="Output CSV, default sni-results-IP.csv")
    parser.add_argument("--diagnose", action="store_true", help="Test query APIs once and print HTTP errors/Retry-After")
    args = parser.parse_args()

    if not (1 <= args.limit <= 2000 and 0 <= args.offset <= 100000 and
            1 <= args.workers <= 8 and 2 <= args.timeout <= 30 and 1 <= args.top <= 100 and
            20 <= args.discovery_timeout <= 120):
        parser.error("Limit, offset, workers, timeout or top is outside its allowed range")
    QUERY_TRANSPORT = args.query_transport
    if QUERY_TRANSPORT == "curl" and not shutil.which("curl"):
        parser.error("curl is required for --query-transport curl; install it or use --query-transport python")
    if args.diagnose:
        return diagnose_sources(args.discovery_timeout, args.skip_qlever)
    try:
        if args.server_ip:
            server_ip = args.server_ip
        else:
            try:
                server_ip = request_json("https://api.ipify.org?format=json", args.timeout)["ip"]
            except (OSError, ValueError, KeyError):
                server_ip = input("Public IPv4 of this server: ").strip()
        ipaddress.IPv4Address(server_ip)
        server_asns, prefix = network_info(server_ip, args.timeout)
        detected_country, city = location(server_ip, args.timeout)
        country = (args.country or detected_country).upper()
        if not args.domains and (len(country) != 2 or not country.isalpha()):
            raise ValueError("Country could not be detected; pass an ISO code, e.g. --country NL")
        print(f"Server: {server_ip} | ASN: {','.join(server_asns) or '?'} | prefix: {prefix or '?'}")
        print(f"GeoIP: {detected_country or '?'} {city or ''} | search country: {country or '?'}")

        candidates = read_domains(args.domains) if args.domains else discover(
            country, args.limit, args.offset, args.timeout, server_ip,
            args.discovery_timeout, args.skip_qlever
        )
        excluded = set(LARGE_DOMAINS)
        if args.exclude:
            excluded.update(x for entry in read_domains(args.exclude) if (x := normalize(entry)))
        domains = sorted({x for entry in candidates if (x := normalize(entry)) and not blocked(x, excluded)})
        random.Random(2026 + args.offset).shuffle(domains)
        print(f"Checking {len(domains)} public domains from this server...", flush=True)
        found = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
            tasks = [executor.submit(check, domain, args.timeout) for domain in domains]
            for number, task in enumerate(concurrent.futures.as_completed(tasks), 1):
                candidate = task.result()
                if candidate:
                    found.append(candidate)
                if number % 50 == 0:
                    print(f"Checked {number}/{len(domains)}; passed: {len(found)}", flush=True)
        if not found:
            print("No candidates passed. Try --offset 300 or pass --domains sites.txt")
            return 1

        print(f"Checking ASN and GeoIP for {len(found)} successful targets...", flush=True)
        for row in found:
            try:
                row_asns, _ = network_info(row["ip"], args.timeout)
                row["asns"] = ",".join(row_asns)
            except (OSError, ValueError, KeyError):
                row["asns"] = "unknown"
            try:
                row["site_country"], _ = location(row["ip"], args.timeout)
            except (OSError, ValueError, KeyError):
                row["site_country"] = ""
            row["same_asn"] = "yes" if set(server_asns) & set(row["asns"].split(",")) else "no"
        found = [row for row in found if not country or row["site_country"] in (country, "")]
        if not found:
            print("All suitable TLS sites resolved outside the requested country.")
            return 1
        for row in found:
            row["score"] = score(row, country)
        found.sort(key=lambda row: (-row["score"], row["domain"]))

        filename = args.output or f"sni-results-{server_ip.replace('.', '-')}.csv"
        fields = ["domain", "ip", "asns", "same_asn", "site_country", "tls_ms",
                  "sample_kibs", "sample_bytes", "http", "redirect", "score"]
        with Path(filename).open("w", newline="", encoding="utf-8-sig") as output:
            writer = csv.DictWriter(output, fieldnames=fields)
            writer.writeheader()
            writer.writerows(found)

        for row in found[:args.top]:
            speed = f"{row['sample_kibs']} KiB/s" if row["sample_kibs"] else "small page"
            print(f"{row['domain']:<42} AS{row['asns']:<10} {row['tls_ms']:>4} ms  "
                  f"{speed:<14} score={row['score']}")
        best = found[0]
        print("\nBEST CANDIDATE (verify it separately from Russia):")
        print(f"  target:      {best['domain']}:443")
        print(f"  serverNames: [\"{best['domain']}\"]")
        print(f"  IP/ASN:      {best['ip']} / AS{best['asns']}")
        print(f"  TLS latency: {best['tls_ms']} ms; sample download: {best['sample_kibs']} KiB/s")
        print(f"Full results: {Path(filename).resolve()}")
        print("Sample HTTP speed is not VPN throughput; Russian reachability needs a Russian network test.")
        return 0
    except (OSError, ValueError, KeyError, urllib.error.URLError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
