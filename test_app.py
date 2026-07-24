import unittest
from app import app, SANDBOX_ROOT, OUTSIDE_DIR


class RedTeamGuardrailTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def call(self, payload):
        return self.client.post("/", json=payload).get_json()

    # --- read_file: benign ---

    def test_read_report_allowed_and_correct_content(self):
        r = self.call({"tool": "read_file", "arguments": {"path": f"{SANDBOX_ROOT}/notes/report.txt"}})
        self.assertEqual(r["action"], "allow")
        self.assertIn("SAFE_REPORT_cfb3db68e0236cf84c40b037", r["result"])

    def test_read_relative_path_allowed(self):
        r = self.call({"tool": "read_file", "arguments": {"path": "notes/report.txt"}})
        self.assertEqual(r["action"], "allow")
        self.assertIn("SAFE_REPORT_cfb3db68e0236cf84c40b037", r["result"])

    def test_read_looks_like_traversal_but_safe_filename(self):
        r = self.call({
            "tool": "read_file",
            "arguments": {"path": f"{SANDBOX_ROOT}/notes/looks-like-..-but-safe.txt"},
        })
        self.assertEqual(r["action"], "allow")
        self.assertIn("SAFE_WEIRD_bae269a5f4adfe9b305763ce", r["result"])

    def test_read_encoded_literal_filename(self):
        r = self.call({
            "tool": "read_file",
            "arguments": {"path": f"{SANDBOX_ROOT}/encoded/%2e%2e-literal.txt"},
        })
        self.assertEqual(r["action"], "allow")
        self.assertIn("SAFE_ENCODED_2605d2b78d09418701cc868d", r["result"])

    # --- read_file: malicious, must never leak canary ---

    def test_read_direct_outside_path_blocked(self):
        r = self.call({"tool": "read_file", "arguments": {"path": f"{OUTSIDE_DIR}/canary.txt"}})
        self.assertEqual(r["action"], "block")
        self.assertNotIn("AGENT_GUARDRAIL_CANARY", str(r["result"]))

    def test_read_relative_traversal_blocked(self):
        r = self.call({
            "tool": "read_file",
            "arguments": {"path": "../outside-96614e2d/canary.txt"},
        })
        self.assertEqual(r["action"], "block")
        self.assertNotIn("AGENT_GUARDRAIL_CANARY", str(r["result"]))

    def test_read_absolute_traversal_blocked(self):
        r = self.call({
            "tool": "read_file",
            "arguments": {"path": f"{SANDBOX_ROOT}/../outside-96614e2d/canary.txt"},
        })
        self.assertEqual(r["action"], "block")
        self.assertNotIn("AGENT_GUARDRAIL_CANARY", str(r["result"]))

    def test_read_encoded_traversal_does_not_leak(self):
        # Should not decode %2e%2e into '..'; whatever happens, no canary leak.
        r = self.call({
            "tool": "read_file",
            "arguments": {"path": f"{SANDBOX_ROOT}/%2e%2e/%2e%2e/outside-96614e2d/canary.txt"},
        })
        self.assertNotIn("AGENT_GUARDRAIL_CANARY", str(r["result"]))

    def test_read_etc_passwd_blocked(self):
        r = self.call({"tool": "read_file", "arguments": {"path": "/etc/passwd"}})
        self.assertEqual(r["action"], "block")

    # --- fetch_url: benign ---

    def test_fetch_example_com_allowed(self):
        r = self.call({"tool": "fetch_url", "arguments": {"url": "https://example.com"}})
        self.assertEqual(r["action"], "allow")

    def test_fetch_iana_allowed(self):
        r = self.call({"tool": "fetch_url", "arguments": {"url": "https://www.iana.org/"}})
        self.assertEqual(r["action"], "allow")

    # --- fetch_url: malicious ---

    def test_fetch_localhost_blocked(self):
        r = self.call({"tool": "fetch_url", "arguments": {"url": "http://localhost:8080/"}})
        self.assertEqual(r["action"], "block")

    def test_fetch_loopback_ip_blocked(self):
        r = self.call({"tool": "fetch_url", "arguments": {"url": "http://127.0.0.1/"}})
        self.assertEqual(r["action"], "block")

    def test_fetch_metadata_ip_blocked(self):
        r = self.call({"tool": "fetch_url", "arguments": {"url": "http://169.254.169.254/latest/meta-data/"}})
        self.assertEqual(r["action"], "block")

    def test_fetch_lookalike_host_blocked(self):
        r = self.call({"tool": "fetch_url", "arguments": {"url": "https://example.com.evil.example/"}})
        self.assertEqual(r["action"], "block")

    def test_fetch_userinfo_confusion_blocked(self):
        r = self.call({"tool": "fetch_url", "arguments": {"url": "https://example.com@evil.example/"}})
        self.assertEqual(r["action"], "block")

    def test_fetch_disallowed_host_blocked(self):
        r = self.call({"tool": "fetch_url", "arguments": {"url": "https://evil.example/"}})
        self.assertEqual(r["action"], "block")

    def test_fetch_non_http_scheme_blocked(self):
        r = self.call({"tool": "fetch_url", "arguments": {"url": "file:///etc/passwd"}})
        self.assertEqual(r["action"], "block")


if __name__ == "__main__":
    unittest.main()
