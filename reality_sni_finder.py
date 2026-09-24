#!/usr/bin/env python3
"""Find REALITY target/SNI candidates from the server itself. Python 3, stdlib only."""

import argparse
import concurrent.futures
import csv
import email.utils
import ipaddress
import json
import random
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


KNOWN_COUNTRIES = {"DE": "Q183", "NL": "Q55", "FI": "Q33", "SE": "Q34", "US": "Q30"}
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
}
LARGE_DOMAINS = {
    "google.com", "google.de", "youtube.com", "facebook.com", "instagram.com",
    "cloudflare.com", "hetzner.com", "netcup.com", "microsoft.com",
    "amazon.com", "wikipedia.org", "wikimedia.org", "apple.com",
}
HEADERS = {"User-Agent": "GhostVPN-SNI-Finder/1.0 (personal target research)"}
RIPE = "https://stat.ripe.net/data/"
WIKIDATA = "https://query.wikidata.org/sparql"
BYTES_TO_READ = 256 * 1024


def request_json(url, timeout):
    request = urllib.request.Request(url, headers={**HEADERS, "Accept": "application/json"})
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=timeout) as response:
        return json.load(response)


def wikidata_json(url, timeout):
    try:
        return request_json(url, timeout)
    except urllib.error.HTTPError as error:
        if error.code != 429:
            raise
        retry_after = error.headers.get("Retry-After", "") if error.headers else ""
        try:
            delay = int(retry_after)
        except (TypeError, ValueError):
            try:
                delay = int(email.utils.parsedate_to_datetime(retry_after).timestamp() - time.time()) + 1
            except (TypeError, ValueError, OverflowError, IndexError):
                delay = 60
        # Respect long Retry-After values without keeping a terminal blocked indefinitely.
        if not 0 <= delay <= 65:
            raise
        print(f"Wikidata rate limit (HTTP 429); waiting {delay} seconds before one retry...", flush=True)
        time.sleep(delay)
        return request_json(url, timeout)


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


def country_qid(country, timeout):
    if country in KNOWN_COUNTRIES:
        return KNOWN_COUNTRIES[country]
    query = f'SELECT ?country WHERE {{ ?country wdt:P297 "{country}" . }} LIMIT 1'
    url = WIKIDATA + "?" + urllib.parse.urlencode({"query": query, "format": "json"})
    rows = wikidata_json(url, max(30, timeout))["results"]["bindings"]
    if not rows:
        raise ValueError(f"No country in Wikidata for ISO code {country}; try --domains sites.txt")
    qid = rows[0]["country"]["value"].rsplit("/", 1)[-1]
    if not qid.startswith("Q") or not qid[1:].isdigit():
        raise ValueError(f"Unexpected Wikidata country identifier: {qid}")
    return qid


def discover(country, limit, offset, timeout):
    try:
        qid = country_qid(country, timeout)
        query = (
            "SELECT DISTINCT ?website WHERE { "
            f"?org wdt:P17 wd:{qid} ; wdt:P856 ?website . "
            'FILTER(STRSTARTS(STR(?website), "https://")) '
            f"}} LIMIT {limit} OFFSET {offset}"
        )
        url = WIKIDATA + "?" + urllib.parse.urlencode({"query": query, "format": "json"})
        data = wikidata_json(url, max(40, timeout))
        return [item["website"]["value"] for item in data["results"]["bindings"]]
    except (urllib.error.URLError, OSError) as error:
        fallback = FALLBACK_DOMAINS.get(country)
        if not fallback:
            raise ValueError(
                f"Wikidata discovery unavailable ({error}); pass --domains sites.txt "
                "or retry after the service recovers"
            ) from error
        print(f"Wikidata unavailable ({error}); checking {len(fallback)} built-in "
              f"{country} candidate domains instead.", flush=True)
        return fallback


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
    parser = argparse.ArgumentParser(description="Discover and compare REALITY target/SNI candidates from a VPS")
    parser.add_argument("--server-ip", help="Public IPv4; detected automatically when omitted")
    parser.add_argument("--country", help="Override detected country with a two-letter ISO code, e.g. NL")
    parser.add_argument("--domains", help="Use newline-separated domains or a previous result CSV")
    parser.add_argument("--exclude", help="Newline-separated domains to exclude")
    parser.add_argument("--limit", type=int, default=300, help="Wikidata records to fetch (default 300)")
    parser.add_argument("--offset", type=int, default=0, help="Fetch another batch if results are sparse")
    parser.add_argument("--workers", type=int, default=4, help="Concurrent checks (default 4, max 8)")
    parser.add_argument("--timeout", type=int, default=7, help="Timeout per connection in seconds")
    parser.add_argument("--top", type=int, default=15, help="How many results to print")
    parser.add_argument("--output", help="Output CSV, default sni-results-IP.csv")
    args = parser.parse_args()

    if not (1 <= args.limit <= 2000 and 0 <= args.offset <= 100000 and
            1 <= args.workers <= 8 and 2 <= args.timeout <= 30 and 1 <= args.top <= 100):
        parser.error("Limit, offset, workers, timeout or top is outside its allowed range")
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
            country, args.limit, args.offset, args.timeout
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
