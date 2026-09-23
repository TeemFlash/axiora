import json
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from http.server import BaseHTTPRequestHandler, HTTPServer

from axiora_tool_api import CommandResult
import axiora_network_tools as nt


class Context:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.commands = []
        self.targets = []
        self.messages = []
        self.responder = lambda argv: CommandResult(0, "", "")
        self.cancelled = False

    def path(self, name):
        return self.directory / name

    def save_json(self, name, data):
        self.path(name).write_text(json.dumps(data))

    def check_cancel(self):
        if self.cancelled:
            raise RuntimeError("cancelled")

    def check_target(self, target):
        self.targets.append(target)
        if target == "outside.example":
            raise ValueError("out of scope")

    def emit(self, text):
        self.messages.append(text)

    def run(self, argv, **kwargs):
        self.commands.append((argv, kwargs))
        return self.responder(argv)


NMAP_XML = '''<?xml version="1.0"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" version="7.94">
 <host><status state="up" reason="syn-ack"/><address addr="192.0.2.8" addrtype="ipv4"/>
 <address addr="00:11:22:33:44:55" addrtype="mac" vendor="Example"/>
 <hostnames><hostname name="lab.example" type="PTR"/></hostnames>
 <ports><port protocol="tcp" portid="443"><state state="open"/>
 <service name="https" product="nginx" version="1.24"/>
 <script id="ssl-heartbleed" output="VULNERABLE:&#10;  State: VULNERABLE&#10;  CVE:CVE-2014-0160"/>
 </port><port protocol="tcp" portid="445"><state state="closed"/>
 <script id="smb-vuln-ms17-010" output="NOT VULNERABLE"/>
 </port></ports></host>
 <runstats><finished exit="success"/><hosts up="1" down="0" total="1"/></runstats>
</nmaprun>'''


class NetworkToolsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.ctx = Context(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_catalog(self):
        ids = [tool.id for tool in nt.TOOLS]
        self.assertEqual(len(ids), len(set(ids)))
        for tool in nt.TOOLS:
            names = {field.name for field in tool.fields}
            self.assertTrue(set(tool.targets) <= names)
            self.assertGreater(tool.timeout, 0)

    def test_target_option_injection_rejected(self):
        for value in ("--script=all", "example.com;id", "example.com $(id)", "192.0.2.1-254", "@targets", "999.1.1.1", "example.com\n--top-ports=10"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                nt.host(value, networks=True)
        self.assertEqual(nt.host("192.0.2.8/24", networks=True), "192.0.2.0/24")
        self.assertEqual(nt.host("2001:db8::1"), "2001:db8::1")
        with self.assertRaises(ValueError):
            nt.host("10.0.0.0/8", networks=True)
        for value in ("0", "22,--script=all", "65536", "443-22", "22\n80"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                nt.ports(value)
        self.assertEqual(nt.ports("1-65535"), "1-65535")

    def test_url_validation(self):
        self.assertEqual(nt.url("https://[::1]:8443/test?a=b"), "https://[::1]:8443/test?a=b")
        for value in ("file:///tmp/a", "https://user:pass@example.com", "https://example.com:99999", "https://example.com\\@evil.test", "https://example.com/#fragment"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                nt.url(value)

    def test_nmap_parser_retains_evidence_not_version_cve_guess(self):
        parsed = nt.parse_nmap(NMAP_XML)
        self.assertEqual(parsed["assets"][0]["services"][0]["service"]["product"], "nginx")
        self.assertEqual(parsed["assets"][0]["names"], ["lab.example"])
        self.assertEqual(len(parsed["findings"]), 1)
        self.assertIn("CVE-2014-0160", parsed["findings"][0]["evidence"])
        self.assertEqual(parsed["findings"][0]["confidence"], "scanner-reported")
        for xml in ("<nmaprun>", "<root/>", "<nmaprun/>", NMAP_XML.replace('exit="success"', 'exit="error"'), '<!DOCTYPE x [<!ENTITY a "bad">]><nmaprun/>'):
            with self.subTest(xml=xml[:50]), self.assertRaises(ValueError):
                nt.parse_nmap(xml)

    def test_nmap_profile_and_xml_artifact(self):
        def respond(argv):
            self.ctx.path("nmap.xml").write_text(NMAP_XML)
            return CommandResult(0, "", "")
        self.ctx.responder = respond
        parsed = nt.nmap_run(self.ctx, {"target": "192.0.2.8", "mode": "nse", "profile": "configuration", "ports": "443"})
        argv = self.ctx.commands[0][0]
        self.assertEqual(argv[-1], "192.0.2.8")
        self.assertEqual(argv[argv.index("--script") + 1], ",".join(nt.NSE_PROFILES["configuration"]))
        self.assertEqual(self.ctx.targets, ["192.0.2.8"])
        self.assertTrue(parsed["data"]["xml"].endswith("nmap.xml"))
        with self.assertRaises(ValueError):
            nt.nmap_run(self.ctx, {"target": "192.0.2.8", "mode": "nse", "profile": "all"})

    @unittest.skipUnless(shutil.which("nmap"), "nmap is optional")
    def test_actual_nmap_loopback_http_service(self):
        from axiora_workbench import TaskContext
        class Handler(BaseHTTPRequestHandler):
            def setup(self):
                super().setup()
                self.connection.settimeout(3)
            def do_GET(self):
                body = b"Axiora local integration fixture\n"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            def log_message(self, *args):
                pass
        try:
            server = HTTPServer(("127.0.0.1", 0), Handler)
        except PermissionError as exc:
            self.skipTest(f"Local socket unavailable in sandbox: {exc}")
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            port = server.server_address[1]
            ctx = TaskContext(self.ctx.path("actual-nmap"), "127.0.0.1", timeout=60)
            parsed = nt.nmap_run(ctx, {"target": "127.0.0.1", "ports": str(port),
                                       "mode": "services", "skip_discovery": "yes", "rate": "100"})
            asset = next(row for row in parsed["assets"] if row["address"] == "127.0.0.1")
            service = next(row for row in asset["services"] if row["port"] == port)
            self.assertEqual(service["state"], "open")
            self.assertEqual(service["protocol"], "tcp")
            self.assertEqual(asset["status"], "up")
            self.assertTrue(ctx.path("nmap.xml").is_file())
            self.assertEqual(parsed["data"]["scanner"]["scanner"], "nmap")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(3)

    def test_capture_duration_and_size_bounds(self):
        with patch.object(nt, "iface", return_value="eth0"):
            for params in ({"duration": "301"}, {"duration": "0"}, {"megabytes": "1000"}, {"packets": "100001"}):
                with self.subTest(params=params), self.assertRaises(ValueError):
                    nt.capture_run(self.ctx, params)
            def respond(argv):
                if argv[0] == "dumpcap":
                    self.ctx.path("capture.pcapng").write_bytes(b"fixture")
                return CommandResult(0, "", "")
            self.ctx.responder = respond
            parsed = nt.capture_run(self.ctx, {"duration": "2", "megabytes": "4", "packets": "25", "capture_filter": "host 192.0.2.8"})
            argv, options = self.ctx.commands[0]
            self.assertIn("duration:2", argv)
            self.assertIn("filesize:4096", argv)
            self.assertEqual(argv[argv.index("-c") + 1], "25")
            self.assertEqual(argv[argv.index("-f") + 1], "host 192.0.2.8")
            self.assertEqual(options["timeout"], 17)
            self.assertEqual(parsed["data"]["packets_analyzed"], 0)

    def test_tshark_summary(self):
        rows = [
            ["1", "100.0", "192.0.2.1", "", "192.0.2.2", "", "TCP", "60", "12345", "443", "", "", "1", ""],
            ["2", "101.0", "192.0.2.2", "", "192.0.2.1", "", "DNS", "80", "", "", "53", "2000", "", "3"],
        ]
        text = "\n".join("\t".join('"' + c + '"' for c in row) for row in rows)
        data = nt.parse_packets(text)
        self.assertEqual(data["protocols"], {"TCP": 1, "DNS": 1})
        self.assertEqual(data["bytes_analyzed"], 140)
        self.assertEqual(data["tcp_retransmissions"], 1)
        self.assertEqual(data["dns_error_responses"], 1)
        self.assertEqual(data["flow_count"], 2)
        with self.assertRaises(ValueError):
            nt.parse_packets("1\t2")

    @unittest.skipUnless(shutil.which("tshark"), "tshark is optional")
    def test_actual_tshark_offline_dns_packet(self):
        from axiora_workbench import TaskContext
        # Ethernet / IPv4 / UDP / DNS NXDOMAIN: static bytes, no packet transmission.
        dns = struct.pack("!HHHHHH", 1234, 0x8183, 0, 0, 0, 0)
        udp = struct.pack("!HHHH", 53, 50000, 8 + len(dns), 0) + dns
        ipv4 = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                           socket.inet_aton("192.0.2.53"), socket.inet_aton("192.0.2.8")) + udp
        packet = bytes.fromhex("00112233445566778899aabb0800") + ipv4
        path = self.ctx.path("dns.pcap")
        path.write_bytes(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1) +
                         struct.pack("<IIII", 100, 0, len(packet), len(packet)) + packet)
        ctx = TaskContext(self.ctx.path("actual-tshark"), "127.0.0.1", timeout=20)
        parsed = nt.pcap_run(ctx, {"file": str(path), "display_filter": "dns"})
        data = parsed["data"]
        self.assertEqual(data["packets_analyzed"], 1)
        self.assertEqual(data["protocols"], {"DNS": 1})
        self.assertEqual(data["dns_error_responses"], 1)
        self.assertEqual(data["flows"][0]["source_port"], "53")

    @unittest.skipUnless(shutil.which("iperf3"), "iperf3 is optional")
    def test_actual_iperf_loopback(self):
        from axiora_workbench import TaskContext
        try:
            with socket.socket() as reserve:
                reserve.bind(("127.0.0.1", 0))
                port = reserve.getsockname()[1]
        except PermissionError as exc:
            self.skipTest(f"Local socket unavailable in sandbox: {exc}")
        server = subprocess.Popen(["iperf3", "-s", "-1", "-B", "127.0.0.1", "-p", str(port)],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            time.sleep(0.2)
            ctx = TaskContext(self.ctx.path("actual-iperf"), "127.0.0.1", timeout=15)
            parsed = nt.iperf_run(ctx, {"target": "127.0.0.1", "port": str(port), "duration": "1", "mbps": "1"})
            self.assertGreater(parsed["data"]["end"]["sum_sent"]["bits_per_second"], 0)
            server.communicate(timeout=3)
            self.assertEqual(server.returncode, 0)
        finally:
            if server.poll() is None:
                server.terminate()
            server.communicate(timeout=3)

    def test_nuclei_jsonl_evidence(self):
        fixture = {"template-id": "tls-version", "info": {"name": "TLS Version", "severity": "info", "reference": ["https://example.test/docs"]},
                   "matched-at": "https://192.0.2.8", "host": "192.0.2.8", "extracted-results": ["tls13"], "matcher-status": True}
        parsed = nt.parse_nuclei(json.dumps(fixture) + "\n")
        self.assertEqual(parsed["findings"][0]["confidence"], "template-match")
        self.assertEqual(parsed["findings"][0]["template_id"], "tls-version")
        self.assertEqual(parsed["findings"][0]["evidence"]["extracted"], ["tls13"])
        self.assertEqual(nt.parse_nuclei("")["findings"], [])
        with self.assertRaises(ValueError):
            nt.parse_nuclei(json.dumps(fixture) + "\n[truncated")
        with self.assertRaises(ValueError):
            nt.parse_nuclei('{"message":"error"}')

    def test_finding_identities_distinguish_ports_templates_and_parameters(self):
        with patch.object(socket, "create_connection"):
            parsed = nt.segmentation(self.ctx, {"matrix": json.dumps([
                {"target": "127.0.0.1", "port": 80, "expected": "closed"},
                {"target": "127.0.0.1", "port": 443, "expected": "closed"}])})
        self.assertEqual({row["port"] for row in parsed["findings"]}, {80, 443})
        fixtures = [{"template-id": name, "info": {"name": "Same title", "severity": "low"},
                     "matched-at": "http://127.0.0.1/"} for name in ("one", "two")]
        parsed = nt.parse_nuclei("\n".join(json.dumps(row) for row in fixtures))
        self.assertEqual({row["template_id"] for row in parsed["findings"]}, {"one", "two"})
        rows = nt.zap_alerts([{"alert": "Same title", "url": "http://127.0.0.1/", "pluginId": "10000", "param": parameter}
                              for parameter in ("first", "second")])
        self.assertEqual({row["parameter"] for row in rows}, {"first", "second"})
        self.assertEqual({row["plugin_id"] for row in rows}, {"10000"})

    def test_nuclei_local_template_and_flags(self):
        template = self.ctx.path("check.yaml")
        template.write_text("id: fixture")
        def respond(argv):
            self.ctx.path("nuclei.jsonl").write_text("")
            return CommandResult(0, "", "")
        self.ctx.responder = respond
        nt.nuclei_run(self.ctx, {"target": "https://example.test", "template": str(template)})
        argv = self.ctx.commands[0][0]
        for flag in ("-duc", "-ni", "-dr", "-jsonl", "-rl"):
            self.assertIn(flag, argv)
        self.assertNotIn("-headless", argv)
        self.assertEqual(argv[argv.index("-pt") + 1], "http,ssl")

    def test_testssl_severities(self):
        rows = [{"id": "TLS1_3", "ip": "192.0.2.8/443", "severity": "OK", "finding": "offered"},
                {"id": "cert_expiration", "ip": "192.0.2.8/443", "severity": "HIGH", "finding": "expired"}]
        parsed = nt.parse_testssl(json.dumps(rows))
        self.assertEqual(len(parsed["data"]["checks"]), 2)
        self.assertEqual(len(parsed["findings"]), 1)
        self.assertEqual(parsed["findings"][0]["severity"], "high")
        with self.assertRaises(ValueError):
            nt.parse_testssl("{}")

    def test_http_header_injection_and_host_override(self):
        for headers in ({"X-Test": "hello\r\nInjected: true"}, {"Host": "outside.example"}, {"Content-Length": "0"}):
            with self.subTest(headers=headers), self.assertRaises(ValueError):
                nt.http_run(self.ctx, {"target": "http://127.0.0.1", "headers": json.dumps(headers)})

    def test_http_blank_headers_after_secret_form_clear(self):
        with patch.object(nt, "http_request", return_value={"status": 200, "elapsed_ms": 1}) as request:
            nt.http_run(self.ctx, {"target": "http://127.0.0.1", "headers": "  "})
        self.assertEqual(request.call_args.args[2], {})

    def test_access_check_unexpected_success_requires_review(self):
        def response(status, body):
            raw = body.encode()
            return {"status": status, "headers": [], "body": body, "body_bytes": len(raw),
                    "body_sha256": nt.hashlib.sha256(raw).hexdigest(), "body_truncated": False}
        replies = [response(200, "protected data"), response(200, "login page")]
        with patch.object(nt, "http_request", side_effect=replies):
            parsed = nt.access_check(self.ctx, {"target": "http://127.0.0.1/private", "expected": "second_denied"})
        self.assertEqual(parsed["data"]["verdict"], "requires_review")
        self.assertEqual(parsed["findings"][0]["confidence"], "requires_review")
        self.assertFalse(parsed["data"]["comparison"]["body_hash_equal"])
        self.assertTrue(self.ctx.path("access-check.json").is_file())
        with patch.object(nt, "http_request", side_effect=replies):
            parsed = nt.access_check(self.ctx, {"target": "http://127.0.0.1/private", "expected": "compare_only"})
        self.assertEqual(parsed["findings"], [])

    def test_access_check_validates_both_contexts_before_request(self):
        with patch.object(nt, "http_request") as request:
            with self.assertRaises(ValueError):
                nt.access_check(self.ctx, {"target": "http://127.0.0.1", "second_headers": '{"Host":"outside.example"}'})
            request.assert_not_called()
            with self.assertRaises(ValueError):
                nt.access_check(self.ctx, {"target": "http://127.0.0.1", "method": "POST"})
            request.assert_not_called()

    def test_access_check_cancellation_between_roles(self):
        def reply(*args, **kwargs):
            self.ctx.cancelled = True
            return {}
        with patch.object(nt, "http_request", side_effect=reply) as request:
            with self.assertRaisesRegex(RuntimeError, "cancelled"):
                nt.access_check(self.ctx, {"target": "http://127.0.0.1"})
        self.assertEqual(request.call_count, 1)

    def test_segmentation_validates_all_before_connecting(self):
        matrix = [{"target": "127.0.0.1", "port": 22, "expected": "open"}, {"target": "outside.example", "port": 80, "expected": "closed"}]
        with patch.object(socket, "create_connection") as connect:
            with self.assertRaises(ValueError):
                nt.segmentation(self.ctx, {"matrix": json.dumps(matrix)})
            connect.assert_not_called()

    def test_segmentation_timeout_is_inconclusive(self):
        with patch.object(socket, "create_connection", side_effect=TimeoutError("timeout")):
            parsed = nt.segmentation(self.ctx, {"matrix": '[{"target":"127.0.0.1","port":22,"expected":"closed"}]'})
        self.assertEqual(parsed["data"]["checks"][0]["verdict"], "inconclusive")
        self.assertEqual(parsed["findings"], [])

    def test_local_segmentation_and_http_no_redirect(self):
        requests = []
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append(self.path)
                if self.path == "/role-protected":
                    allowed = self.headers.get("Authorization") == "Bearer local-test-role"
                    self.send_response(200 if allowed else 403)
                    self.end_headers()
                    self.wfile.write(b"protected data" if allowed else b"forbidden")
                elif self.path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", "/destination")
                    self.end_headers()
                else:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"ok":true}')
            def log_message(self, *args):
                pass
        try:
            server = HTTPServer(("127.0.0.1", 0), Handler)
        except PermissionError as exc:
            self.skipTest(f"Local socket unavailable in sandbox: {exc}")
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            port = server.server_address[1]
            parsed = nt.segmentation(self.ctx, {"matrix": json.dumps([{"target": "127.0.0.1", "port": port, "expected": "open"}])})
            self.assertEqual(parsed["data"]["checks"][0]["verdict"], "pass")
            parsed = nt.http_run(self.ctx, {"target": f"http://127.0.0.1:{port}/redirect"})
            self.assertEqual(parsed["data"]["status"], 302)
            self.assertEqual(requests, ["/redirect"])
            parsed = nt.http_run(self.ctx, {"target": f"http://127.0.0.1:{port}/api"})
            self.assertEqual(json.loads(parsed["data"]["body"]), {"ok": True})
            parsed = nt.access_check(self.ctx, {"target": f"http://127.0.0.1:{port}/role-protected",
                                                "first_headers": '{"Authorization":"Bearer local-test-role"}',
                                                "second_headers": "{}", "expected": "second_denied"})
            self.assertEqual(parsed["data"]["verdict"], "expected_http_denial")
            self.assertEqual(parsed["data"]["first_response"]["status"], 200)
            self.assertEqual(parsed["data"]["second_response"]["status"], 403)
            self.assertEqual(parsed["findings"], [])
            self.assertEqual(parsed["data"]["first_response"]["body_bytes"], len(b"protected data"))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(2)

    def test_openapi_inventory_no_requests(self):
        path = self.ctx.path("openapi.json")
        path.write_text(json.dumps({"openapi": "3.0.3", "info": {"title": "Lab"}, "paths": {"/status": {"get": {"summary": "Status", "responses": {"200": {}}}}}}))
        parsed = nt.openapi_run(self.ctx, {"file": str(path)})
        self.assertEqual(parsed["data"]["endpoints"][0]["method"], "GET")
        self.assertEqual(self.ctx.commands, [])

    def test_zap_remote_api_rejected(self):
        with self.assertRaises(ValueError):
            nt.zap_run(self.ctx, {"endpoint": "http://example.test:8090", "api_key": "secret"})

    def test_zap_scan_finishes_and_removes_context(self):
        calls = []
        def fake(base, key, component, kind, action, arguments=None):
            calls.append((component, kind, action, arguments))
            return {"scanPolicyNames": ["Default Policy"]} if action == "scanPolicyNames" else {"contextId": "1"} if action == "newContext" else {"scan": "2"} if action == "scan" else {"status": "100"} if action == "status" else {"alerts": []} if action == "alerts" else {}
        with patch.object(nt, "zap_call", side_effect=fake):
            parsed = nt.zap_run(self.ctx, {"api_key": "secret", "mode": "scan", "target": "http://127.0.0.1/app"})
        self.assertTrue(parsed["data"]["completed"])
        self.assertIn("removeContext", [call[2] for call in calls])
        access = next(call for call in calls if call[2] == "accessUrl")
        self.assertEqual(access[3]["followRedirects"], "false")
        scan = next(call for call in calls if call[2] == "scan")
        self.assertEqual(scan[3]["recurse"], "false")

    def test_zap_cancel_stops_remote_scan(self):
        calls = []
        def fake(base, key, component, kind, action, arguments=None):
            calls.append(action)
            if action == "scanPolicyNames":
                return {"scanPolicyNames": ["Default Policy"]}
            if action == "newContext":
                return {"contextId": "1"}
            if action == "scan":
                self.ctx.cancelled = True
                return {"scan": "2"}
            return {}
        with patch.object(nt, "zap_call", side_effect=fake), self.assertRaisesRegex(RuntimeError, "cancelled"):
            nt.zap_run(self.ctx, {"api_key": "secret", "mode": "scan", "target": "http://127.0.0.1/app"})
        self.assertIn("stop", calls)
        self.assertIn("removeContext", calls)


if __name__ == "__main__":
    unittest.main()
