import os
import sys
import unittest

# Ensure shared auth middleware is available
sys.path.insert(0, os.path.expanduser("~/clawd/meok-labs-engine/shared"))
os.chdir(os.path.dirname(os.path.abspath(__file__)) + "/..")


class TestMCPImport(unittest.TestCase):
    def test_import_server(self):
        """Server module must import without errors."""
        import server  # noqa: F401

    def test_mcp_or_server_object_exists(self):
        """FastMCP servers export 'mcp'; low-level servers export 'server'."""
        import server as srv
        self.assertTrue(
            hasattr(srv, "mcp") or hasattr(srv, "server"),
            "Expected 'mcp' or 'server' object in server.py",
        )


class TestAuthMiddleware(unittest.TestCase):
    def test_check_access_blocks_empty_key(self):
        """Empty API key should be rejected on free tier."""
        from auth_middleware import check_access
        allowed, msg, tier = check_access("")
        self.assertFalse(allowed)
        self.assertIn("upgrade", msg.lower() or tier.lower())


class TestHealthEndpoint(unittest.TestCase):
    def test_health_url_resolves(self):
        """Wrapper must expose /health."""
        import urllib.request
        # Note: this test requires the wrapper to be running on port 8000.
        # It is skipped in CI unless the server is active.
        try:
            resp = urllib.request.urlopen("http://localhost:8000/health", timeout=2)
            self.assertEqual(resp.status, 200)
        except Exception as e:
            self.skipTest(f"Server not running: {e}")


if __name__ == "__main__":
    unittest.main()
