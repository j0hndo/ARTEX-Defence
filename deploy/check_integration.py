#!/usr/bin/env python3
"""Check a same-origin canary deployment without exposing synthetic secrets.

The default preflight stops before the token and verification stages. Use
--full-chain only when intentionally generating a canary_match event.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from hashlib import sha256
from html.parser import HTMLParser
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


PREFIX = "/sys/sso-status/"
OVERVIEW = PREFIX + "overview"
TOKEN = PREFIX + "getSSOToken"
INCIDENT = PREFIX + "incident/SUP-6148"
VERIFY = PREFIX + "verifySSOStatus"
STATUS_JS = re.compile(r"/sys/sso-status/assets/status\.[0-9a-f]{12}\.js\Z")
REVIEW_JS = re.compile(r"/sys/sso-status/assets/review\.[0-9a-f]{12}\.js\Z")
OPAQUE = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
TICKET = re.compile(r"ssot_[A-Za-z0-9_-]{20,128}\Z")
MAX_BODY = 1024 * 1024


class CheckError(Exception):
    """A deployment check failed without including secret URL material."""


class Links(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.anchors: list[str] = []
        self.scripts: list[str] = []
        self.base_href: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "base" and "href" in values and self.base_href is None:
            self.base_href = values["href"] or ""
        if tag == "a" and values.get("href"):
            self.anchors.append(values["href"] or "")
        if tag == "script" and values.get("src"):
            self.scripts.append(values["src"] or "")


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def origin_of(url: str) -> tuple[str, str, int]:
    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        username = parsed.username
        password = parsed.password
        port = parsed.port
    except ValueError:
        raise CheckError("URL is malformed") from None
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname
            or username is not None or password is not None
            or parsed.fragment):
        raise CheckError("URL must use HTTP or HTTPS without credentials or fragment")
    if port == 0:
        raise CheckError("URL has an invalid port")
    return parsed.scheme, hostname, port if port is not None else (443 if parsed.scheme == "https" else 80)


def same_origin(base_origin: tuple[str, str, int], current: str, link: str) -> str:
    try:
        target = urljoin(current, link)
    except ValueError:
        raise CheckError("Canary link is malformed") from None
    try:
        target_origin = origin_of(target)
    except CheckError as error:
        raise CheckError("non-HTTP or malformed canary link") from error
    if target_origin != base_origin:
        raise CheckError("off-origin canary link or redirect")
    return target


def gated_url(url: str, stage: str, run_id: str | None = None) -> str:
    try:
        parsed = urlsplit(url)
    except ValueError:
        raise CheckError(f"Malformed {stage} URL") from None
    paths = {
        "status": STATUS_JS,
        "token": TOKEN,
        "incident": INCIDENT,
        "review": REVIEW_JS,
        "verify": VERIFY,
    }
    expected = paths[stage]
    valid_path = (bool(expected.fullmatch(parsed.path)) if isinstance(expected, re.Pattern)
                  else parsed.path == expected)
    if not valid_path or parsed.fragment:
        raise CheckError(f"Unexpected {stage} endpoint")
    query = parse_qs(parsed.query, keep_blank_values=True)
    keys = {"run", "gate", "signature"} if stage == "verify" else {"run", "gate"}
    if set(query) != keys or any(len(values) != 1 for values in query.values()):
        raise CheckError(f"Malformed {stage} parameters")
    if not OPAQUE.fullmatch(query["run"][0]) or not OPAQUE.fullmatch(query["gate"][0]):
        raise CheckError(f"Malformed {stage} parameters")
    if run_id is not None and query["run"][0] != run_id:
        raise CheckError("Canary run changed between stages")
    if stage == "verify" and query["signature"][0] != "{sha256_hex}":
        raise CheckError("Verification template is malformed")
    return query["run"][0]


def js_string(source: str, key: str) -> str:
    marker = re.search(r"\b" + re.escape(key) + r'\s*:\s*("(?:[^"\\]|\\.)*")', source)
    if marker is None:
        raise CheckError(f"Missing {key} in canary bundle")
    try:
        value = json.loads(marker.group(1))
    except json.JSONDecodeError:
        raise CheckError(f"Malformed {key} in canary bundle") from None
    if not isinstance(value, str):
        raise CheckError(f"Malformed {key} in canary bundle")
    return value


def html_links(document: bytes) -> Links:
    try:
        parser = Links()
        parser.feed(document.decode("utf-8"))
        return parser
    except UnicodeDecodeError:
        raise CheckError("HTML response is not UTF-8") from None


def document_base(links: Links, document_url: str,
                  origin: tuple[str, str, int]) -> str:
    """Use the first HTML base href, which also controls browser link resolution."""
    if links.base_href is None:
        return document_url
    return same_origin(origin, document_url, links.base_href)


def resolved_path(document_base_url: str, link: str, kind: str) -> str:
    try:
        return urlsplit(urljoin(document_base_url, link)).path
    except ValueError:
        raise CheckError(f"Malformed {kind} link") from None


def fetch(opener, base_origin: tuple[str, str, int], url: str) -> tuple[int, bytes]:
    if origin_of(url) != base_origin:
        raise CheckError("off-origin canary request")
    request = Request(url, headers={"User-Agent": "artex-canary-integration-check/1.0"})
    try:
        response = opener.open(request, timeout=5)
    except HTTPError as error:
        response = error
    except (URLError, ValueError, OSError):
        raise CheckError("Network request failed") from None
    with response:
        status = response.status
        if 300 <= status < 400:
            location = response.headers.get("Location")
            if location:
                same_origin(base_origin, url, location)
            raise CheckError("Unexpected redirect in canary deployment")
        body = response.read(MAX_BODY + 1)
        if len(body) > MAX_BODY:
            raise CheckError("Canary response is too large")
        return status, body


def require_200(opener, origin: tuple[str, str, int], url: str, stage: str) -> bytes:
    status, body = fetch(opener, origin, url)
    if status != 200:
        raise CheckError(f"{stage} returned HTTP {status}")
    return body


def single_canary_link(links: list[str], current_url: str,
                       origin: tuple[str, str, int], expected_path: str,
                       kind: str) -> str:
    matches: list[str] = []
    for link in links:
        path = resolved_path(current_url, link, kind)
        if path != expected_path:
            continue
        matches.append(same_origin(origin, current_url, link))
    if not matches:
        raise CheckError(f"Missing {kind} canary link")
    if len(matches) != 1:
        raise CheckError(f"Multiple {kind} canary links")
    return matches[0]


def script_link(links: list[str], current_url: str,
                origin: tuple[str, str, int], pattern: re.Pattern[str],
                stage: str) -> str:
    matches: list[str] = []
    for link in links:
        path = resolved_path(current_url, link, stage)
        if pattern.fullmatch(path):
            matches.append(same_origin(origin, current_url, link))
    if len(matches) != 1:
        raise CheckError(f"Expected one {stage} canary bundle")
    return matches[0]


def run_check(base_url: str, support_path: str, full_chain: bool) -> str:
    origin = origin_of(base_url)
    base = urlsplit(base_url)
    if base.path not in {"", "/"} or base.query:
        raise CheckError("Base URL must be an origin without path or query")
    if (not support_path.startswith("/") or support_path.startswith("//")
            or "?" in support_path or "#" in support_path or "\\" in support_path):
        raise CheckError("Support path must be an absolute local path")
    opener = build_opener(ProxyHandler({}), NoRedirect())
    support_url = same_origin(origin, base_url, support_path)
    support = html_links(require_200(opener, origin, support_url, "Support page"))
    support_base = document_base(support, support_url, origin)
    overview_url = single_canary_link(
        support.anchors, support_base, origin, OVERVIEW, "overview")
    if urlsplit(overview_url).query:
        raise CheckError("Overview link must not contain a query")
    overview = html_links(require_200(opener, origin, overview_url, "Overview"))
    overview_base = document_base(overview, overview_url, origin)
    status_url = script_link(overview.scripts, overview_base, origin, STATUS_JS, "status")
    run_id = gated_url(status_url, "status")
    try:
        status_js = require_200(opener, origin, status_url, "Status bundle").decode("utf-8")
    except UnicodeDecodeError:
        raise CheckError("Status bundle is not UTF-8") from None

    if not full_chain:
        return "Preflight passed: support link, overview, and status bundle. No verification request was sent."

    token_url = same_origin(origin, status_url, js_string(status_js, "tokenStatusPath"))
    gated_url(token_url, "token", run_id)
    try:
        token = json.loads(require_200(opener, origin, token_url, "Synthetic token"))
    except (ValueError, UnicodeDecodeError):
        raise CheckError("Synthetic token response is malformed") from None
    if not isinstance(token, dict) or not isinstance(token.get("ticket"), str) or not TICKET.fullmatch(token["ticket"]):
        raise CheckError("Synthetic ticket is malformed")
    if not isinstance(token.get("next_url"), str):
        raise CheckError("Incident link is missing")
    incident_url = same_origin(origin, token_url, token["next_url"])
    gated_url(incident_url, "incident", run_id)
    incident = html_links(require_200(opener, origin, incident_url, "Incident"))
    incident_base = document_base(incident, incident_url, origin)
    review_url = script_link(incident.scripts, incident_base, origin, REVIEW_JS, "review")
    gated_url(review_url, "review", run_id)
    try:
        review_js = require_200(opener, origin, review_url, "Review bundle").decode("utf-8")
    except UnicodeDecodeError:
        raise CheckError("Review bundle is not UTF-8") from None
    template = same_origin(origin, review_url, js_string(review_js, "verificationPathTemplate"))
    gated_url(template, "verify", run_id)
    digest = sha256(token["ticket"].encode("utf-8")).hexdigest()
    verify_url = template.replace("{sha256_hex}", digest)
    status, body = fetch(opener, origin, verify_url)
    if (status, body) not in {(200, b"verified\n"), (403, b"blocked\n")}:
        raise CheckError(f"Verification returned unexpected HTTP {status} or body")
    return (f"Full-chain check passed: verification returned HTTP {status}. "
            "Now inspect the canary_match event in the configured event log or SIEM.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True, help="First-party application origin")
    parser.add_argument("--support-path", default="/support", help="Page containing the canary overview link")
    parser.add_argument("--full-chain", action="store_true", help="Intentionally generate a canary_match event")
    args = parser.parse_args()
    try:
        print(run_check(args.base_url, args.support_path, args.full_chain))
    except CheckError as error:
        print(f"Integration check failed: {error}", file=sys.stderr)
        return 1
    except Exception:
        # Never print a traceback that could contain synthetic URLs or tickets.
        print("Integration check failed: unexpected checker error", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
