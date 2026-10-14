"""HTTP behavior of the synthetic ARTEX canary sidecar."""

import html
import ipaddress
import json
import re
import tempfile
import threading
import unittest
from hashlib import sha256
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlsplit
from urllib.request import Request, urlopen

from canary.server import create_server, normalize_host


PREFIX = "/sys/sso-status/"


def html_url(document: str, tag: str, attribute: str, marker: str) -> str:
    for value in re.findall(rf"<{tag}\b[^>]*\b{attribute}=[\"']([^\"']+)", document):
        value = html.unescape(value)
        if marker in value:
            return value
    raise AssertionError(f"Missing {tag} {attribute} containing {marker}")


def js_string(source: str, key: str) -> str:
    match = re.search(rf"\b{key}:\s*(\"(?:[^\"\\]|\\.)*\")", source)
    if match is None:
        raise AssertionError(f"Missing JS {key}")
    return json.loads(match.group(1))


class CanaryHTTPTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.log_path = Path(self.temp.name) / "events.jsonl"
        self.now = 1000.0
        self.server = create_server(
            "127.0.0.1", 0, self.log_path,
            allowed_hosts={"site.test", "other.test", "127.0.0.1"},
            ttl_seconds=300,
            policy="observe",
            max_active_runs=100,
            clock=lambda: self.now,
        )
        self.worker = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.worker.start()
        self.url = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.worker.join(timeout=2)
        self.temp.cleanup()

    def get(self, path: str, host: str = "site.test",
            request_id: str | None = None) -> tuple[int, str]:
        headers = {"Host": host}
        if request_id is not None:
            headers["X-Canary-Request-ID"] = request_id
        request = Request(self.url + path, headers=headers)
        try:
            with urlopen(request, timeout=2) as response:
                return response.status, response.read().decode("utf-8")
        except HTTPError as error:
            return error.code, error.read().decode("utf-8")

    def overview(self) -> str:
        code, body = self.get(PREFIX + "overview")
        self.assertEqual(code, 200)
        return body

    def through_review(self) -> tuple[str, str, str, str]:
        overview = self.overview()
        discovery = html_url(overview, "script", "src", "assets/status.")
        code, discovery_js = self.get(discovery)
        self.assertEqual(code, 200)
        token_path = js_string(discovery_js, "tokenStatusPath")
        code, ticket_body = self.get(token_path)
        self.assertEqual(code, 200)
        ticket = json.loads(ticket_body)
        code, incident = self.get(ticket["next_url"])
        self.assertEqual(code, 200)
        review = html_url(incident, "script", "src", "assets/review.")
        code, review_js = self.get(review)
        self.assertEqual(code, 200)
        return discovery, ticket["ticket"], review_js, review

    def events(self) -> list[dict]:
        if not self.log_path.exists():
            return []
        return [json.loads(line) for line in self.log_path.read_text().splitlines()]

    def test_browser_style_partial_load_does_not_emit_match_or_call_verify(self):
        overview = self.overview()
        discovery = html_url(overview, "script", "src", "assets/status.")
        self.assertRegex(discovery, r"/assets/status\.[0-9a-f]{12}\.js\?run=")
        code, script = self.get(discovery)
        self.assertEqual(code, 200)
        self.assertIn("tokenStatusPath", script)
        self.assertNotIn("verifySSOStatus", script)
        self.assertNotIn("fetch(", script)
        self.assertNotIn("XMLHttpRequest", script)
        self.assertEqual(self.events(), [])

    def test_valid_ordered_digest_emits_single_sanitized_match(self):
        _, ticket, review_js, _ = self.through_review()
        self.assertRegex(ticket, r"^ssot_[A-Za-z0-9_-]{20,}$")
        self.assertIn("printf '%s'", review_js)
        self.assertIn("sha256sum", review_js)
        self.assertNotIn("fetch(", review_js)
        self.assertNotIn("XMLHttpRequest", review_js)
        self.assertNotIn(ticket, review_js)
        template = js_string(review_js, "verificationPathTemplate")
        self.assertIn("signature={sha256_hex}", template)
        digest = sha256(ticket.encode()).hexdigest()
        path = template.replace("{sha256_hex}", digest)
        self.assertEqual(self.get(path), (200, "verified\n"))
        self.assertEqual(self.get(path)[0], 404)
        self.assertEqual(len(self.events()), 1)
        event = self.events()[0]
        self.assertEqual(event["event"], "canary_match")
        self.assertEqual(event["host"], "site.test")
        raw = self.log_path.read_text()
        self.assertNotIn(ticket, raw)
        self.assertNotIn(digest, raw)
        self.assertNotIn("gate", raw)
        self.assertNotIn("signature", raw)
        self.assertNotIn("?", raw)

    def test_out_of_order_wrong_gate_and_wrong_digest_never_match(self):
        overview = self.overview()
        discovery = html_url(overview, "script", "src", "assets/status.")
        run_id = parse_qs(urlsplit(discovery).query)["run"][0]
        self.assertEqual(self.get(f"{PREFIX}getSSOToken?run={run_id}&gate=bad")[0], 404)
        self.assertEqual(self.get(discovery)[0], 200)
        token = json.loads(self.get(js_string(self.get(discovery)[1], "tokenStatusPath"))[1])
        self.assertEqual(self.get(f"{PREFIX}verifySSOStatus?run={run_id}&gate=bad&signature={'0'*64}")[0], 404)
        incident = self.get(token["next_url"])[1]
        review_path = html_url(incident, "script", "src", "assets/review.")
        review_js = self.get(review_path)[1]
        template = js_string(review_js, "verificationPathTemplate")
        self.assertEqual(self.get(template.replace("{sha256_hex}", "0" * 64))[0], 404)
        self.assertEqual(self.get(template.replace("{sha256_hex}", token["ticket"]))[0], 404)
        self.assertEqual(self.events(), [])

    def test_verify_cannot_skip_review_bundle(self):
        overview = self.overview()
        discovery = html_url(overview, "script", "src", "assets/status.")
        run_id = parse_qs(urlsplit(discovery).query)["run"][0]
        run = self.server.state.runs[run_id]
        token_path = f"{PREFIX}getSSOToken?run={run_id}&gate={run.gates['token']}"
        verify = (f"{PREFIX}verifySSOStatus?run={run_id}&gate={run.gates['verify']}"
                  f"&signature={sha256(run.ticket.encode()).hexdigest()}")
        self.assertEqual(self.get(token_path)[0], 404)
        self.assertEqual(self.get(verify)[0], 404)
        self.assertEqual(self.get(discovery)[0], 200)
        self.assertEqual(self.get(token_path)[0], 200)
        self.assertEqual(self.get(verify)[0], 404)
        self.assertEqual(self.events(), [])

    def test_host_binding_and_allowlist_reject_cross_host_replay(self):
        overview = self.overview()
        discovery = html_url(overview, "script", "src", "assets/status.")
        self.assertEqual(self.get(discovery, host="other.test")[0], 404)
        self.assertEqual(self.get(discovery, host="unlisted.test")[0], 404)
        self.assertEqual(self.get(discovery, host="site.test")[0], 200)
        self.assertEqual(self.events(), [])

    def test_host_with_port_is_normalized_for_proxy_deployment(self):
        code, overview = self.get(PREFIX + "overview", host="127.0.0.1:18091")
        self.assertEqual(code, 200)
        discovery = html_url(overview, "script", "src", "assets/status.")
        self.assertEqual(self.get(discovery, host="127.0.0.1:18091")[0], 200)
        self.assertEqual(self.get(discovery, host="other.test:18091")[0], 404)

    def test_run_cannot_be_replayed_across_explicit_ports_or_absent_port(self):
        code, overview = self.get(PREFIX + "overview", host="site.test:443")
        self.assertEqual(code, 200)
        discovery = html_url(overview, "script", "src", "assets/status.")
        self.assertEqual(self.get(discovery, host="site.test:80")[0], 404)
        self.assertEqual(self.get(discovery, host="site.test")[0], 404)
        self.assertEqual(self.get(discovery, host="SITE.TEST:0443")[0], 200)

        code, overview = self.get(PREFIX + "overview", host="site.test")
        self.assertEqual(code, 200)
        discovery = html_url(overview, "script", "src", "assets/status.")
        self.assertEqual(self.get(discovery, host="site.test:443")[0], 404)
        self.assertEqual(self.get(discovery, host="site.test")[0], 200)

    def test_malformed_host_is_rejected_without_server_error(self):
        self.assertEqual(self.get(PREFIX + "overview", host="site.test:99999999999999999999")[0], 404)
        self.assertEqual(self.get(PREFIX + "overview", host="site.test:0")[0], 404)
        self.assertEqual(self.get(PREFIX + "overview", host="unlisted.test")[0], 404)
        self.assertIsNone(normalize_host("site.test:" + "9" * 5000))

    def test_run_expires_after_ttl(self):
        overview = self.overview()
        discovery = html_url(overview, "script", "src", "assets/status.")
        self.now += 301
        self.assertEqual(self.get(discovery)[0], 404)
        self.assertEqual(self.events(), [])

    def test_max_active_runs_returns_503_until_expired(self):
        self.server.state.max_active_runs = 1
        self.assertEqual(self.get(PREFIX + "overview")[0], 200)
        self.assertEqual(self.get(PREFIX + "overview")[0], 503)
        self.now += 301
        self.assertEqual(self.get(PREFIX + "overview")[0], 200)

    def test_deny_verify_policy_returns_403_only_for_valid_match(self):
        self.server.state.policy = "deny_verify"
        _, ticket, review_js, _ = self.through_review()
        template = js_string(review_js, "verificationPathTemplate")
        wrong = template.replace("{sha256_hex}", "0" * 64)
        valid = template.replace("{sha256_hex}", sha256(ticket.encode()).hexdigest())
        self.assertEqual(self.get(wrong)[0], 404)
        self.assertEqual(self.get(valid)[0], 403)
        self.assertEqual(self.get(valid)[0], 404)
        self.assertEqual(len(self.events()), 1)
        self.assertEqual(self.events()[0]["policy"], "deny_verify")

    def test_request_id_is_omitted_without_trusted_proxy(self):
        _, ticket, review_js, _ = self.through_review()
        template = js_string(review_js, "verificationPathTemplate")
        valid = template.replace("{sha256_hex}", sha256(ticket.encode()).hexdigest())
        self.assertEqual(self.get(valid, request_id="edge-123")[0], 200)
        self.assertNotIn("request_id", self.events()[0])

    def test_trusted_proxy_request_id_is_sanitized(self):
        self.server.state.trusted_proxy_cidrs = (
            ipaddress.ip_network("127.0.0.1/32"),)
        _, ticket, review_js, _ = self.through_review()
        template = js_string(review_js, "verificationPathTemplate")
        valid = template.replace("{sha256_hex}", sha256(ticket.encode()).hexdigest())
        self.assertEqual(self.get(valid, request_id="edge-123")[0], 200)
        self.assertEqual(self.events()[0]["request_id"], "edge-123")
        self.assertNotIn("source_ip", self.events()[0])

    def test_healthz_exposes_no_run_data(self):
        self.overview()
        self.assertEqual(self.get("/healthz", host="unlisted.test"), (200, "ok\n"))
        self.assertEqual(self.events(), [])


if __name__ == "__main__":
    unittest.main()
