"""Exercise the deployment checker against a real local canary server."""

import json
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from canary.server import Handler, create_server


ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "deploy" / "check_integration.py"


class ForeignHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.seen.append(self.path)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"foreign service")

    def log_message(self, *args):
        pass


class CombinedHandler(Handler):
    def do_GET(self):
        path = urlsplit(self.path).path
        self.server.seen.append(self.path)
        if path.startswith("/sys/sso-status/assets/status.") and self.server.malformed_status:
            self._send(200, b"\xff", "application/javascript; charset=utf-8")
            return
        if path.startswith("/sys/sso-status/assets/status.") and self.server.block_status:
            self._send(403, b"blocked\n", "text/plain; charset=utf-8")
            return
        if path == "/support":
            self._send(200,
                       b'<html><a href="/sys/sso-status/overview">Service status</a></html>',
                       "text/html; charset=utf-8")
            return
        if path == "/support-foreign-link":
            body = (f'<html><a href="{self.server.foreign_url}'
                    '/sys/sso-status/overview">Service status</a></html>').encode()
            self._send(200, body, "text/html; charset=utf-8")
            return
        if path == "/support-foreign-base":
            body = (f'<html><head><base href="{self.server.foreign_url}/"></head>'
                    '<body><a href="/sys/sso-status/overview">Service status</a>'
                    '</body></html>').encode()
            self._send(200, body, "text/html; charset=utf-8")
            return
        if path == "/support-local-base":
            self._send(200,
                       b'<html><head><base href="/sys/sso-status/"></head>'
                       b'<body><a href="overview">Service status</a></body></html>',
                       "text/html; charset=utf-8")
            return
        if path == "/support-foreign-redirect":
            self.send_response(302)
            self.send_header("Location", self.server.foreign_url + "/support")
            self.end_headers()
            return
        super().do_GET()


class IntegrationCheckTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.events_path = Path(self.temp.name) / "events.jsonl"
        self.foreign = ThreadingHTTPServer(("127.0.0.1", 0), ForeignHandler)
        self.foreign.seen = []
        self.foreign_worker = threading.Thread(target=self.foreign.serve_forever,
                                               daemon=True)
        self.foreign_worker.start()
        self.server = create_server(
            "127.0.0.1", 0, self.events_path,
            allowed_hosts={"127.0.0.1"}, ttl_seconds=300,
        )
        self.server.RequestHandlerClass = CombinedHandler
        self.server.seen = []
        self.server.malformed_status = False
        self.server.block_status = False
        self.server.foreign_url = f"http://127.0.0.1:{self.foreign.server_port}"
        self.worker = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.worker.start()
        self.base_url = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.worker.join(timeout=2)
        self.foreign.shutdown()
        self.foreign.server_close()
        self.foreign_worker.join(timeout=2)
        self.temp.cleanup()

    def run_check(self, *extra):
        return subprocess.run(
            [sys.executable, str(CHECKER), "--base-url", self.base_url, *extra],
            capture_output=True, text=True, timeout=10,
        )

    def events(self):
        if not self.events_path.exists():
            return []
        return [json.loads(line) for line in self.events_path.read_text().splitlines()]

    def test_preflight_stops_after_status_bundle_without_event(self):
        result = self.run_check("--support-path", "/support")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.events(), [])
        paths = [urlsplit(request).path for request in self.server.seen]
        self.assertEqual(paths[:2], ["/support", "/sys/sso-status/overview"])
        self.assertTrue(any(path.startswith("/sys/sso-status/assets/status.")
                            for path in paths))
        self.assertNotIn("/sys/sso-status/getSSOToken", paths)
        self.assertNotIn("/sys/sso-status/verifySSOStatus", paths)
        self.assertIn("Preflight passed", result.stdout)
        self.assertNotIn("?", result.stdout + result.stderr)

    def test_full_chain_emits_one_match_and_keeps_secrets_out_of_output(self):
        result = self.run_check("--support-path", "/support", "--full-chain")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(self.events()), 1)
        self.assertEqual(self.events()[0]["event"], "canary_match")
        paths = [urlsplit(request).path for request in self.server.seen]
        self.assertIn("/sys/sso-status/getSSOToken", paths)
        self.assertIn("/sys/sso-status/verifySSOStatus", paths)
        self.assertIn("inspect the canary_match event", result.stdout)
        self.assertNotIn("?", result.stdout + result.stderr)
        self.assertNotIn("ssot_", result.stdout + result.stderr)
        self.assertNotIn("signature=", result.stdout + result.stderr)
        self.assertNotIn("gate=", result.stdout + result.stderr)

    def test_full_chain_accepts_deny_verify_policy(self):
        self.server.state.policy = "deny_verify"
        result = self.run_check("--support-path", "/support", "--full-chain")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(self.events()), 1)
        self.assertEqual(self.events()[0]["status"], 403)

    def test_foreign_redirect_is_rejected_without_following(self):
        result = self.run_check("--support-path", "/support-foreign-redirect")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("off-origin", result.stderr)
        self.assertEqual(self.foreign.seen, [])
        self.assertEqual(self.events(), [])

    def test_foreign_canary_link_is_rejected_without_following(self):
        result = self.run_check("--support-path", "/support-foreign-link")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("off-origin", result.stderr)
        self.assertEqual(self.foreign.seen, [])
        self.assertEqual(self.events(), [])

    def test_foreign_html_base_cannot_turn_root_relative_link_off_origin(self):
        result = self.run_check("--support-path", "/support-foreign-base")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("off-origin", result.stderr)
        self.assertEqual(self.foreign.seen, [])
        self.assertEqual(self.events(), [])

    def test_same_origin_html_base_resolves_relative_overview_link(self):
        result = self.run_check("--support-path", "/support-local-base")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.events(), [])

    def test_malformed_status_bundle_fails_without_traceback_or_secret_url(self):
        self.server.malformed_status = True
        result = self.run_check("--support-path", "/support")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Integration check failed", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertNotIn("?", result.stdout + result.stderr)
        self.assertEqual(self.events(), [])

    def test_403_is_not_accepted_before_verification(self):
        self.server.block_status = True
        result = self.run_check("--support-path", "/support", "--full-chain")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Status bundle returned HTTP 403", result.stderr)
        self.assertEqual(self.events(), [])

    def test_malformed_base_url_does_not_echo_input_or_traceback(self):
        marker = "CANARYSECRET"
        result = subprocess.run(
            [sys.executable, str(CHECKER), "--base-url", "http://[bad/?gate=" + marker],
            capture_output=True, text=True, timeout=10,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Integration check failed", result.stderr)
        self.assertNotIn(marker, result.stderr)
        self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
