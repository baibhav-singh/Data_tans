"""
phishfeed_pipeline.py — end-to-end phishing feed processor.

Stage 1 – Collect  : deduplicate raw phishfeed.txt → phishfeed_deduped.txt + brand_stats.json
Stage 2 – Parse    : filter by Brands.txt, download SSL certs and web pages
Stage 3 – Classify : score each URL with the saved impersonation classifier
"""

import csv
import json
import mimetypes
import os
import pickle
import re
import shutil
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlparse
import requests

# Force UTF-8 output so brand names with non-ASCII characters don't crash on
# Windows consoles that default to CP1252.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# ── paths ─────────────────────────────────────────────────────────────────────

BASE_DIR     = Path(__file__).parent
RAW_FEED     = BASE_DIR / "phishfeed.txt"
DEDUPED_FEED = BASE_DIR / "phishfeed_deduped.txt"
BRAND_STATS  = BASE_DIR / "brand_stats.json"
BRANDS_FILE  = BASE_DIR / "Brands.txt"
OUTPUT_DIR   = BASE_DIR / "phishfeed_output"
MODEL_FILE   = BASE_DIR / "impersonation_classifier.pkl"

KEY_FIELD   = "Page URL"
BRAND_FIELD = "Target Brands"

URLSCAN_API_KEY  = os.environ.get("URLSCAN_API_KEY", "24f3cc85-3f1d-46bc-af15-ca2bc930a1c1")
URLSCAN_FEED_URL = "https://urlscan.io/api/v1/pro/phishfeed?q=date:%3Enow-24h"
URLSCAN_MAX_PAGES   = 20
URLSCAN_RETRY_WAIT  = 3
URLSCAN_MAX_RETRIES = 4

# ─────────────────────────────────────────────────────────────────────────────
# Shared utilities
# ─────────────────────────────────────────────────────────────────────────────

def _banner(title: str) -> None:
    print(f"\n{'-'*60}")
    print(f"  {title}")
    print(f"{'-'*60}")


def safe_folder_name(brand: str) -> str:
    invalid = r'\/:*?"<>|'
    return "".join("_" if c in invalid else c for c in brand).strip()


def safe_filename(url: str) -> str:
    parsed = urlparse(url)
    host = parsed.hostname or "unknown"
    path = re.sub(r"[^\w\-.]", "_", parsed.path.strip("/"))
    name = f"{host}_{path}" if path else host
    return name[:80]


# ─────────────────────────────────────────────────────────────────────────────
# Stage 0 – Fetch urlscan phishing feed
# ─────────────────────────────────────────────────────────────────────────────

def _urlscan_fetch_page(url: str) -> dict:
    req = urllib.request.Request(url)
    req.add_header("Content-Type", "application/json")
    req.add_header("API-Key", URLSCAN_API_KEY)
    for attempt in range(1, URLSCAN_MAX_RETRIES + 1):
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                wait = URLSCAN_RETRY_WAIT * attempt
                print(f"  Rate limited — waiting {wait}s "
                      f"(attempt {attempt}/{URLSCAN_MAX_RETRIES})...", flush=True)
                time.sleep(wait)
            else:
                body = exc.read().decode(errors="replace")
                raise RuntimeError(f"HTTP {exc.code}: {body}") from exc
    raise RuntimeError(f"urlscan request failed after {URLSCAN_MAX_RETRIES} retries")


def collect_urlscan_feed() -> None:


# dowwloads the phishfeed from URLSCAN 

    API_KEY = "24f3cc85-3f1d-46bc-af15-ca2bc930a1c1"
# Lucene query to find results tagged with 'phishing'
    SEARCH_QUERY = 'tags:phishing' 

    url = f"https://urlscan.io/api/v1/pro/phishfeed?q=date:%3Enow-24h"
    headers = {'API-Key': API_KEY}

    
    
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
     
        with open('phishfeed.txt', 'w', encoding='utf-8',errors='ignore') as f:
        
            f.write(response.text)
            
        print(f"Successfully saved phishing URLs to phishing_feed.txt")
    else:
        print(f"Error {response.status_code}: {response.text}")



# ─────────────────────────────────────────────────────────────────────────────
# Stage 1 – Collect
# ─────────────────────────────────────────────────────────────────────────────

def collect_deduplicate() -> None:
    """Deduplicate phishfeed.txt by Page URL and write phishfeed_deduped.txt."""
    seen_urls: set[str] = set()
    kept = skipped = 0

    with (
        open(RAW_FEED, "r", encoding="utf-8", errors='ignore', newline="") as fin,
        open(DEDUPED_FEED, "w", encoding="utf-8", errors='ignore', newline="") as fout,
    ):
        reader = csv.DictReader(fin, delimiter="\t", quoting=csv.QUOTE_ALL)
        writer = csv.DictWriter(
            fout,
            fieldnames=reader.fieldnames,
            delimiter="\t",
            quoting=csv.QUOTE_ALL,
        )
        writer.writeheader()
        for row in reader:
            url = row.get(KEY_FIELD, "").strip()
            if url in seen_urls:
                skipped += 1
            else:
                seen_urls.add(url)
                writer.writerow(row)
                kept += 1

    print(f"  Input rows  : {kept + skipped:,}")
    print(f"  Unique rows : {kept:,}")
    print(f"  Duplicates  : {skipped:,}")
    print(f"  Output      : {DEDUPED_FEED}")


def collect_brand_stats() -> None:
    """Count brand occurrences in the deduped feed and write brand_stats.json."""
    counts: Counter = Counter()
    with open(DEDUPED_FEED, "r", encoding="utf-8", errors='ignore', newline="") as f:
        reader = csv.DictReader(f, delimiter="\t", quoting=csv.QUOTE_ALL)
        for row in reader:
            for brand in row.get(BRAND_FIELD, "").strip().split(","):
                brand = brand.strip()
                if brand:
                    counts[brand] += 1

    sorted_counts = dict(sorted(counts.items(), key=lambda x: (-x[1], x[0])))
    with open(BRAND_STATS, "w", encoding="utf-8") as f:
        json.dump(sorted_counts, f, indent=2)

    print(f"\n  Unique brands : {len(sorted_counts):,}")
    print(f"  Stats file    : {BRAND_STATS}")
    print("  Top 10 brands:")
    for brand, count in list(sorted_counts.items())[:10]:
        print(f"    {count:>6,}  {brand}")


# ─────────────────────────────────────────────────────────────────────────────
# Stage 2 – Parse
# ─────────────────────────────────────────────────────────────────────────────

def load_brands() -> set[str]:
    brands: set[str] = set()
    with open(BRANDS_FILE, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split("\t")
            if len(parts) >= 2 and parts[0].isdigit():
                brands.add(parts[1].strip())
            else:
                brands.add(parts[0].strip())
    return brands


def parse_feed(brands: set[str]) -> dict[str, list[dict]]:
    brand_map = {b.lower(): b for b in brands}
    results: dict[str, list[dict]] = {b: [] for b in brands}

    with open(DEDUPED_FEED, encoding="utf-8") as f:
        reader = csv.reader(f, delimiter="\t")
        header_row = next(reader)

        if header_row[0].isdigit() or header_row[0] == "":
            header_row = header_row[1:]

        try:
            brand_col = header_row.index("Target Brands")
        except ValueError:
            cleaned = [h.strip('"') for h in header_row]
            brand_col = cleaned.index("Target Brands")
            header_row = cleaned

        for row in reader:
            if not row:
                continue
            if row[0].isdigit():
                row = row[1:]
            if len(row) <= brand_col:
                continue
            cell = row[brand_col].strip().strip('"')
            canonical = brand_map.get(cell.lower())
            if canonical:
                results[canonical].append(dict(zip(header_row, row)))

    for brand, records in results.items():
        seen: set[str] = set()
        deduped: list[dict] = []
        for rec in records:
            url = rec.get("Page URL", "").strip().strip('"')
            if url not in seen:
                seen.add(url)
                deduped.append(rec)
        removed = len(records) - len(deduped)
        if removed:
            print(f"  [{brand}] Removed {removed} duplicate Page URL(s).")
        results[brand] = deduped

    return results


def write_brand_output(brand: str, records: list[dict]) -> None:
    if not records:
        print(f"  [{brand}] No matching records - skipping.")
        return
    folder = OUTPUT_DIR / safe_folder_name(brand)
    folder.mkdir(parents=True, exist_ok=True)
    out = folder / "phishfeed_filtered.tsv"
    fieldnames = list(records[0].keys())
    with open(out, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, delimiter="\t", quoting=csv.QUOTE_ALL)
        writer.writeheader()
        writer.writerows(records)
    print(f"  [{brand}] {len(records)} record(s) -> {out}")


def fetch_ssl_cert(url: str, timeout: int = 10) -> tuple[str | None, str | None]:
    """Return (pem, meta_json) or (None, error) for an HTTPS URL."""
    parsed = urlparse(url)
    if parsed.scheme.lower() != "https":
        return None, "not-https"
    host = parsed.hostname
    port = parsed.port or 443
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)
                cert_dict = ssock.getpeercert()
        pem = ssl.DER_cert_to_PEM_cert(der)

        def rdn(rdns):
            return {k: v for rdn in rdns for k, v in rdn}

        meta = {
            "host": host, "port": port,
            "subject": rdn(cert_dict.get("subject", [])),
            "issuer": rdn(cert_dict.get("issuer", [])),
            "notBefore": cert_dict.get("notBefore"),
            "notAfter": cert_dict.get("notAfter"),
            "serialNumber": cert_dict.get("serialNumber"),
            "subjectAltNames": [v for t, v in cert_dict.get("subjectAltName", []) if t == "DNS"],
            "retrieved_at": datetime.now(timezone.utc).isoformat(),
        }
        return pem, json.dumps(meta, indent=2)
    except Exception as exc:
        return None, str(exc)


def download_certs_for_brand(brand: str, records: list[dict], certs_dir: Path, workers: int = 10) -> set[str]:
    """Returns the set of URLs whose cert download failed, so page download can skip them."""
    urls = {r.get("Page URL", "").strip().strip('"') for r in records}
    https_urls = {u for u in urls if u.lower().startswith("https://")}
    if not https_urls:
        print(f"    [{brand}] No HTTPS URLs - skipping certs.")
        return set()
    certs_dir.mkdir(parents=True, exist_ok=True)
    ok = fail = skip = cached = 0
    failed_urls: set[str] = set()

    to_fetch = set()
    for url in https_urls:
        if (certs_dir / f"{safe_filename(url)}.pem").exists():
            cached += 1
        else:
            to_fetch.add(url)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(fetch_ssl_cert, url): url for url in to_fetch}
        for future in as_completed(futures):
            url = futures[future]
            pem, meta_or_err = future.result()
            stem = safe_filename(url)
            if pem is None:
                if meta_or_err == "not-https":
                    skip += 1
                else:
                    fail += 1
                    failed_urls.add(url)
                    (certs_dir / f"{stem}.error.txt").write_text(f"{url}\n{meta_or_err}\n", encoding="utf-8")
            else:
                (certs_dir / f"{stem}.pem").write_text(pem, encoding="utf-8")
                (certs_dir / f"{stem}.meta.json").write_text(meta_or_err, encoding="utf-8")
                ok += 1

    cached_str = f", {cached} already cached" if cached else ""
    print(f"    [{brand}] Certs: {ok} saved, {fail} failed, {skip} skipped (non-HTTPS){cached_str}")
    return failed_urls


def download_webpage(url: str, timeout: int = 10) -> tuple[str | None, str | None]:
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout, context=ssl_ctx) as resp:
            charset = resp.headers.get_content_charset() or "utf-8"
            return resp.read().decode(charset, errors="replace"), None
    except Exception as exc:
        return None, str(exc)


class _AssetParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__()
        self.base_url = base_url
        self.images: list[str] = []
        self.favicons: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple]) -> None:
        attr = dict(attrs)
        if tag == "img":
            src = attr.get("src") or attr.get("data-src") or attr.get("data-lazy-src")
            if src and not src.startswith("data:"):
                self.images.append(urljoin(self.base_url, src))
        elif tag == "link":
            rel = attr.get("rel", "").lower()
            if any(r in rel for r in ("icon", "shortcut icon", "apple-touch-icon")):
                href = attr.get("href")
                if href and not href.startswith("data:"):
                    self.favicons.append(urljoin(self.base_url, href))


def extract_assets(html: str, base_url: str) -> tuple[list[str], list[str]]:
    parser = _AssetParser(base_url)
    parser.feed(html)
    seen: set[str] = set()
    images, favicons = [], []
    for url in parser.images:
        if url not in seen:
            seen.add(url)
            images.append(url)
    for url in parser.favicons:
        if url not in seen:
            seen.add(url)
            favicons.append(url)
    return images, favicons


def download_binary(url: str, dest: Path, timeout: int = 10) -> str | None:
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        )
    }
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout, context=ssl_ctx) as resp:
            content_type = resp.headers.get_content_type() or ""
            data = resp.read()
        if not dest.suffix:
            ext = mimetypes.guess_extension(content_type.split(";")[0].strip()) or ""
            dest = dest.with_suffix(ext)
        dest.write_bytes(data)
        return None
    except Exception as exc:
        return str(exc)


def download_assets_for_page(html: str, page_url: str, assets_dir: Path, workers: int = 10) -> tuple[int, int, int]:
    images, favicons = extract_assets(html, page_url)
    if not images and not favicons:
        return 0, 0, 0

    img_dir = assets_dir / "images"
    fav_dir = assets_dir / "favicons"
    img_dir.mkdir(parents=True, exist_ok=True)
    fav_dir.mkdir(parents=True, exist_ok=True)

    tasks: list[tuple[str, Path]] = []
    for url in images:
        tasks.append((url, img_dir / safe_filename(url)[:120]))
    for url in favicons:
        tasks.append((url, fav_dir / safe_filename(url)[:120]))

    img_ok = fav_ok = fail = 0

    def _fetch(args):
        url, dest = args
        return url, dest, download_binary(url, dest)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        for url, dest, err in pool.map(_fetch, tasks):
            if err:
                fail += 1
            elif str(dest.parent).endswith("images"):
                img_ok += 1
            else:
                fav_ok += 1

    return img_ok, fav_ok, fail


def download_pages_for_brand(
    brand: str, records: list[dict], pages_dir: Path,
    skip_urls: set[str] = frozenset(), workers: int = 10,
) -> None:
    urls = {r.get("Page URL", "").strip().strip('"') for r in records}
    urls = {u for u in urls if u.lower().startswith(("http://", "https://"))}
    if not urls:
        print(f"    [{brand}] No Page URLs - skipping pages.")
        return
    pages_dir.mkdir(parents=True, exist_ok=True)
    pages_ok = pages_fail = pages_cached = pages_skipped = 0
    total_img = total_fav = total_asset_fail = 0

    to_fetch = set()
    for url in urls:
        if url in skip_urls:
            pages_skipped += 1
        elif (pages_dir / f"{safe_filename(url)}.html").exists():
            pages_cached += 1
        else:
            to_fetch.add(url)

    def _fetch(url):
        return url, *download_webpage(url)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_fetch, url): url for url in to_fetch}
        for future in as_completed(futures):
            url, html, err = future.result()
            stem = safe_filename(url)
            if html is None:
                pages_fail += 1
                (pages_dir / f"{stem}.error.txt").write_text(f"{url}\n{err}\n", encoding="utf-8")
            else:
                (pages_dir / f"{stem}.html").write_text(html, encoding="utf-8")
                pages_ok += 1
                img_ok, fav_ok, asset_fail = download_assets_for_page(html, url, pages_dir / stem)
                total_img += img_ok
                total_fav += fav_ok
                total_asset_fail += asset_fail

    cached_str  = f", {pages_cached} already cached" if pages_cached else ""
    skipped_str = f", {pages_skipped} skipped (cert error)" if pages_skipped else ""
    print(
        f"    [{brand}] Pages: {pages_ok} saved, {pages_fail} failed{cached_str}{skipped_str} | "
        f"Images: {total_img}, Favicons: {total_fav}, Asset errors: {total_asset_fail}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Stage 3 – Classify
# ─────────────────────────────────────────────────────────────────────────────

KNOWN_CA = {
    "digicert", "comodo", "sectigo", "let's encrypt", "globalsign",
    "geotrust", "verisign", "entrust", "godaddy", "amazon", "google",
    "microsoft", "identrust", "usertrust",
}

FEATURE_NAMES = [
    "cert_validity_days", "san_count", "has_wildcard_san", "public_key_bits",
    "domain_dot_count", "domain_length", "is_known_ca", "subject_matches_domain",
    "has_subject_o", "has_subject_ou", "signature_algorithm_enc",
    "public_key_type_enc", "issuer_c_enc", "subject_c_enc", "issuer_o_enc",
]


def _cert_field(cert_section, key: str) -> str:
    if not cert_section:
        return ""
    for item in cert_section:
        for k, v in item:
            if k == key:
                return v
    return ""


def _parse_cert_date(s: str | None) -> datetime | None:
    if not s:
        return None
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
        try:
            return datetime.strptime(s.strip(), fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def fetch_cert_for_classify(domain: str, port: int = 443, timeout: int = 10) -> tuple[dict | None, str | None]:
    """Return (cert_dict, pem) or (None, None) on failure."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert_dict = ssock.getpeercert()
                pem = ssl.DER_cert_to_PEM_cert(ssock.getpeercert(binary_form=True))
                return cert_dict, pem
    except Exception:
        pass

    # Retry without hostname verification for self-signed / mismatched certs
    try:
        ctx2 = ssl.create_default_context()
        ctx2.check_hostname = False
        ctx2.verify_mode = ssl.CERT_NONE
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with ctx2.wrap_socket(sock, server_hostname=domain) as ssock:
                cert_dict = ssock.getpeercert(binary_form=False)
                pem = ssl.DER_cert_to_PEM_cert(ssock.getpeercert(binary_form=True))
                return cert_dict, pem
    except Exception:
        return None, None


def load_cached_cert(url: str, certs_dir: Path) -> tuple[dict | None, str | None]:
    """
    Read a cert written by Stage 2 (fetch_ssl_cert).
    Returns (cert_dict, pem) in getpeercert() tuple format, or (None, None) on cache miss.
    """
    stem      = safe_filename(url)
    pem_path  = certs_dir / f"{stem}.pem"
    meta_path = certs_dir / f"{stem}.meta.json"

    if not pem_path.exists() or not meta_path.exists():
        return None, None

    try:
        pem  = pem_path.read_text(encoding="utf-8")
        meta = json.loads(meta_path.read_text(encoding="utf-8"))

        # Stage 2 stores subject/issuer as flat dicts; getpeercert() uses tuple-of-tuples
        def to_tuples(d: dict) -> tuple:
            return tuple(((k, v),) for k, v in d.items())

        cert_dict = {
            "subject":        to_tuples(meta.get("subject", {})),
            "issuer":         to_tuples(meta.get("issuer", {})),
            "notBefore":      meta.get("notBefore"),
            "notAfter":       meta.get("notAfter"),
            "serialNumber":   meta.get("serialNumber"),
            "subjectAltName": tuple(("DNS", n) for n in meta.get("subjectAltNames", [])),
        }
        return cert_dict, pem
    except Exception:
        return None, None


def _save_cert_files(domain: str, cert_dict: dict, pem: str, certs_dir: Path) -> None:
    def _convert(obj):
        if isinstance(obj, (list, tuple)):
            return [_convert(i) for i in obj]
        if isinstance(obj, dict):
            return {k: _convert(v) for k, v in obj.items()}
        return obj

    base = str(certs_dir / re.sub(r"[^\w\-.]", "_", domain))
    with open(base + ".json", "w", encoding="utf-8") as f:
        json.dump(_convert(cert_dict), f, indent=2)
    with open(base + ".pem", "w", encoding="utf-8") as f:
        f.write(pem)


def build_features(cert: dict | None, domain: str, encoders: dict) -> list:
    if cert is None:
        return [0] * 15

    subject = cert.get("subject", ())
    issuer  = cert.get("issuer", ())
    subject_cn = _cert_field(subject, "commonName")
    subject_o  = _cert_field(subject, "organizationName")
    subject_ou = _cert_field(subject, "organizationalUnitName")
    subject_c  = _cert_field(subject, "countryName")
    issuer_o   = _cert_field(issuer,  "organizationName")
    issuer_c   = _cert_field(issuer,  "countryName")

    nb = _parse_cert_date(cert.get("notBefore"))
    na = _parse_cert_date(cert.get("notAfter"))
    validity = (na - nb).days if nb and na else -1

    sans = cert.get("subjectAltName", ())
    san_names    = [v for _, v in sans]
    san_cnt      = len(san_names)
    has_wildcard = int(any("*." in n for n in san_names))

    def safe_enc(col, val):
        val = val or "unknown"
        try:
            return encoders[col].transform([val])[0]
        except ValueError:
            return -1

    return [
        validity, san_cnt, has_wildcard,
        0,                                          # public_key_bits (not in ssl dict)
        domain.count("."), len(domain),
        int(any(k in (issuer_o or "").lower() for k in KNOWN_CA)),
        int(
            bool(subject_cn) and bool(domain) and (
                domain.lower().endswith(subject_cn.lower().lstrip("*.")) or
                subject_cn.lower().lstrip("*.").endswith(domain.lower())
            )
        ),
        int(bool(subject_o.strip())),
        int(bool(subject_ou.strip())),
        safe_enc("signature_algorithm", "unknown"),  # not in ssl dict
        safe_enc("public_key_type",     "unknown"),  # not in ssl dict
        safe_enc("issuer_c",  issuer_c),
        safe_enc("subject_c", subject_c),
        safe_enc("issuer_o",  issuer_o),
    ]


def run_classifier(brand_results: dict[str, list[dict]], model, encoders: dict) -> None:
    """Classify all filtered URLs and write consolidated results to phishfeed_output/classification/."""
    all_results: list[dict] = []
    all_features: list[dict] = []

    print(f"\n{'='*105}")
    print(f"  {'#':<4}  {'Brand':<14}  {'Domain':<35}  {'Cert?':<8}  {'Confidence':>10}  {'Prediction'}")
    print(f"{'='*105}")

    classify_certs_dir = OUTPUT_DIR / "classification" / "certs"
    classify_certs_dir.mkdir(parents=True, exist_ok=True)

    i = 0
    for brand in sorted(brand_results):
        records = brand_results[brand]
        if not records:
            continue

        for rec in records:
            i += 1
            url = rec.get("Page URL", "").strip().strip('"')
            try:
                domain = urlparse(url).hostname or ""
            except Exception:
                domain = ""

            cert_ok    = "No"
            prediction = "ERROR"
            label      = -1
            confidence = None
            feats      = [0] * len(FEATURE_NAMES)

            if domain:
                brand_certs_dir = OUTPUT_DIR / safe_folder_name(brand) / "certs"
                cert_dict, pem = load_cached_cert(url, brand_certs_dir)
                if cert_dict is not None:
                    cert_ok = "Cached"
                else:
                    print(f"  [{i:>3}]  Fetching cert for {domain} ...", end="\r", flush=True)
                    cert_dict, pem = fetch_cert_for_classify(domain)
                    cert_ok = "Yes" if cert_dict is not None else "No"
                    if cert_dict and pem:
                        _save_cert_files(domain, cert_dict, pem, classify_certs_dir)
                feats = build_features(cert_dict, domain, encoders)
                label = int(model.predict([feats])[0])
                proba = model.predict_proba([feats])[0]
                confidence = float(proba[label])
                prediction = "MALICIOUS" if label == 1 else "BENIGN"

            tag      = "!!!" if label == 1 else "   "
            conf_str = f"{confidence:.1%}" if confidence is not None else "  N/A  "
            print(f"  {i:<4}  {brand:<14}  {domain:<35}  {cert_ok:<8}  {conf_str:>10}  {tag} {prediction}  {url[:55]}")

            all_results.append({
                "brand": brand, "url": url, "domain": domain,
                "cert_found": cert_ok, "prediction": prediction,
                "label": label,
                "confidence": round(confidence, 6) if confidence is not None else "",
            })
            all_features.append(
                dict(zip(FEATURE_NAMES, feats)) | {"domain": domain, "brand": brand, "prediction": prediction}
            )

    if not all_results:
        print("  No records to classify.")
        return

    valid  = [r for r in all_results if r["label"] >= 0]
    mal    = sum(1 for r in valid if r["label"] == 1)
    benign = sum(1 for r in valid if r["label"] == 0)
    conf_vals = [r["confidence"] for r in all_results if isinstance(r["confidence"], float)]
    avg_conf  = sum(conf_vals) / len(conf_vals) if conf_vals else 0.0

    print(f"\n{'='*105}")
    print(f"  Total URLs    : {len(all_results)}")
    print(f"  Cert found    : {sum(1 for r in all_results if r['cert_found'] == 'Yes')}")
    print(f"  BENIGN        : {benign}")
    print(f"  MALICIOUS     : {mal}")
    print(f"  Avg confidence: {avg_conf:.1%}")
    print(f"{'='*105}")

    classify_dir  = OUTPUT_DIR / "classification"
    results_path  = classify_dir / "results.csv"
    features_path = classify_dir / "features.csv"
    json_path     = classify_dir / "result.json"

    with open(results_path, "w", newline="",errors='ignore', encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=all_results[0].keys())
        writer.writeheader()
        writer.writerows(all_results)

    with open(features_path, "w", newline="",errors='ignore', encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=all_features[0].keys())
        writer.writeheader()
        writer.writerows(all_features)

    benign_urls = [
        {"brand": r["brand"], "url": r["url"]}
        for r in all_results if r["label"] == 0
    ]
    result_json = {
        "summary": {
            "total_urls":    len(all_results),
            "cert_found":    sum(1 for r in all_results if r["cert_found"] == "Yes"),
            "benign":        benign,
            "malicious":     mal,
            "avg_confidence": round(avg_conf, 4),
        },
        "benign_urls": benign_urls,
        "all_results":  all_results,
    }
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(result_json, f, indent=2)

    date_result_path = OUTPUT_DIR / "result.json"
    shutil.copy2(json_path, date_result_path)

    unique_brands = sorted({r["brand"] for r in all_results if r["brand"]})
    brands_path = OUTPUT_DIR / "Brands.txt"
    brands_path.write_text("\n".join(unique_brands) + "\n", encoding="utf-8")

    print(f"\n  Certificates -> {classify_certs_dir}/")
    print(f"  Features     -> {features_path}")
    print(f"  Results CSV  -> {results_path}")
    print(f"  Results JSON -> {json_path}")
    print(f"  Copied       -> {date_result_path}")
    print(f"  Brands.txt   -> {brands_path}  ({len(unique_brands)} unique brand(s))")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    global OUTPUT_DIR, BRAND_STATS
    OUTPUT_DIR  = BASE_DIR / "phishfeed_output" / datetime.now().strftime("%Y-%m-%d")
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    BRAND_STATS = OUTPUT_DIR / "brand_stats.json"
    print(f"  Output directory: {OUTPUT_DIR}")

    # Stage 0 – Fetch
    _banner("Stage 0 - Fetch: download phishing feed from urlscan.io")
    collect_urlscan_feed()

    # Stage 1 – Collect
    _banner("Stage 1 - Collect: deduplicate feed")
    if not RAW_FEED.exists():
        sys.exit(f"Error: raw feed not found at {RAW_FEED}")
    collect_deduplicate()
    shutil.copy2(DEDUPED_FEED, OUTPUT_DIR / DEDUPED_FEED.name)
    print(f"  Copied        : {DEDUPED_FEED.name} -> {OUTPUT_DIR}")
    collect_brand_stats()

    # Stage 2 – Parse
    _banner("Stage 2 - Parse: filter by brand, download certs & pages")
    if not BRANDS_FILE.exists():
        sys.exit(f"Error: '{BRANDS_FILE}' not found.")
    brands = load_brands()
    if not brands:
        sys.exit("Error: No brands loaded from Brands.txt.")
    print(f"  Brands: {', '.join(sorted(brands))}\n")

    brand_results = parse_feed(brands)
    total = 0
    active_brands: list[str] = []
    for brand in sorted(brand_results):
        records = brand_results[brand]
        write_brand_output(brand, records)
        total += len(records)
        if records:
            active_brands.append(brand)

    print(f"\n  {total} total record(s) written under '{OUTPUT_DIR}/'.")

    def _download_brand(brand: str) -> None:
        records = brand_results[brand]
        brand_dir = OUTPUT_DIR / safe_folder_name(brand)
        print(f"  [{brand}] Downloading SSL certs...")
        failed_cert_urls = download_certs_for_brand(brand, records, brand_dir / "certs")
        print(f"  [{brand}] Downloading webpages...")
        download_pages_for_brand(brand, records, brand_dir / "pages", skip_urls=failed_cert_urls)

    if active_brands:
        print(f"\n  Launching {len(active_brands)} brand thread(s) for cert + page downloads...")
        with ThreadPoolExecutor(max_workers=len(active_brands)) as pool:
            futures = {pool.submit(_download_brand, brand): brand for brand in active_brands}
            for future in as_completed(futures):
                brand = futures[future]
                exc = future.exception()
                #if exc:
                    #print(f"[{brand}] ERROR: {exc}".encode('utf-8', 'replace').decode('utf-8'))


    # Stage 3 – Classify
    _banner("Stage 3 - Classify: score URLs with impersonation classifier")
    if not MODEL_FILE.exists():
        print(f"  Model not found at {MODEL_FILE} - skipping classification.")
    else:
        with open(MODEL_FILE, "rb") as f:
            payload = pickle.load(f)
        model    = payload["model"]
        encoders = payload["encoders"]
        run_classifier(brand_results, model, encoders)

    # Zip the dated output folder
    _banner("Archiving output folder")
    zip_base = OUTPUT_DIR.parent / OUTPUT_DIR.name
    zip_path = shutil.make_archive(str(zip_base), "zip", OUTPUT_DIR.parent, OUTPUT_DIR.name)
    print(f"  Archive: {zip_path}")

    _banner("Pipeline complete")


if __name__ == "__main__":
    main()
