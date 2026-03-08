#!/usr/bin/env python3
"""
Red Hat CVE Report Generator

Author: Brandon Williams
Description: Queries the Red Hat Security Data API to retrieve CVE details.
Usage: python redhat_cve_report.py <CVE_List>

The input file should be plain text with one CVE per line, e.g.:
    CVE-2015-0409
    CVE-2015-0411
    CVE-2015-0432
"""

import json
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

API_BASE = "https://access.redhat.com/labs/securitydataapi/cve"
CVE_URL_BASE = "https://access.redhat.com/security/cve"
ERRATA_URL_BASE = "https://access.redhat.com/errata"
SEPARATOR = "-" * 99
MAX_WORKERS = 10


def fetch_cve(cve_id: str) -> tuple[str, dict | None, str | None]:
    url = f"{API_BASE}/{cve_id}.json"
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            return cve_id, json.loads(resp.read()), None
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return cve_id, None, "NOT FOUND"
        return cve_id, None, f"HTTP error {e.code}: {e.reason}"
    except urllib.error.URLError as e:
        return cve_id, None, f"Connection error: {e.reason}"
    except Exception as e:
        return cve_id, None, f"Error: {e}"


def format_date(date_str: str | None) -> str:
    if not date_str:
        return "N/A"
    try:
        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%d")
    except ValueError:
        return date_str


def format_errata_date(date_str: str | None) -> str:
    """Format errata dates to match original output style: 'January 20, 2015'."""
    if not date_str:
        return "N/A"
    try:
        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        return dt.astimezone(timezone.utc).strftime("%B %d, %Y").replace(" 0", " ")
    except ValueError:
        return date_str


def build_report(cve_id: str, data: dict) -> str:
    lines = [f"CVE URL: {CVE_URL_BASE}/{cve_id}"]

    # Impact/severity
    impact = data.get("threat_severity") or data.get("severity") or "N/A"
    lines.append(f"Impact: {impact}")

    # Public date
    lines.append(f"Public: {format_date(data.get('public_date'))}")

    # Statement
    statement = (data.get("statement") or "N/A").strip()
    lines.append(f"Statement: {statement}")

    # Details (can be a string or a list of strings)
    raw_details = data.get("details")
    if raw_details:
        if isinstance(raw_details, list):
            details = " ".join(raw_details).strip()
        else:
            details = str(raw_details).strip()
    else:
        details = "N/A"
    lines.append(f"Details: {details}")

    # Errata — deduplicated, preserving order
    lines.append("Errata List:")
    releases = data.get("affected_release") or []
    seen: set[str] = set()
    errata_lines: list[str] = []

    for rel in releases:
        advisory = rel.get("advisory", "")
        product = rel.get("product_name", "")
        package = rel.get("package", "")
        release_date = format_errata_date(rel.get("release_date"))
        errata_url = f"{ERRATA_URL_BASE}/{advisory}" if advisory else "N/A"

        # Include package name in parens to match original format
        if package:
            # Strip version suffix from package name for brevity (keep just the package base name)
            pkg_base = package.split("-")[0] if "-" in package else package
            label = f"{product} ({pkg_base})"
        else:
            label = product

        entry = f"{label} | {errata_url} | {release_date}"
        if entry not in seen:
            seen.add(entry)
            errata_lines.append(entry)

    if errata_lines:
        lines.extend(errata_lines)
    else:
        lines.append("N/A")

    return "\n".join(lines)


def process_cves(cve_list: list[str]) -> None:
    results: dict[str, tuple[dict | None, str | None]] = {}

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(fetch_cve, cve): cve for cve in cve_list}
        for future in as_completed(futures):
            cve_id, data, error = future.result()
            results[cve_id] = (data, error)

    # Print in the original input order
    for cve_id in cve_list:
        data, error = results[cve_id]
        print(f"Pulling details for {cve_id}")
        if error:
            print(error)
        else:
            print(build_report(cve_id, data))
        print(SEPARATOR)


def main() -> None:
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <CVE_List>", file=sys.stderr)
        sys.exit(1)

    cve_file = sys.argv[1]
    try:
        with open(cve_file) as f:
            cve_list = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Error: file '{cve_file}' not found.", file=sys.stderr)
        sys.exit(1)

    if not cve_list:
        print("Error: CVE list is empty.", file=sys.stderr)
        sys.exit(1)

    process_cves(cve_list)


if __name__ == "__main__":
    main()
