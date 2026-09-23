import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from axiora_projects import ProjectStore
from axiora_tool_api import CommandResult, Field, Tool
from axiora_vault import SecretVault
from axiora_workbench import (CancelledError, Scope, TaskContext, TaskTimeout, Workbench,
                              execute_remote, target_identity, validate_remote, secret_parts, redact)


class ScopeTests(unittest.TestCase):
    def test_ip_network_exact_dns_and_urls(self):
        scope = Scope('192.0.2.0/24,2001:db8::/48\nexample.test')
        for value in ('192.0.2.1', '192.0.2.0/25', '2001:db8::1', 'https://example.test/path'):
            scope.check(value)
        for value in ('192.0.3.1', '192.0.0.0/16', 'evil.example.test', 'https://example.test.evil/path'):
            with self.assertRaises(ValueError):
                scope.check(value)

    def test_options_credentials_and_malformed_scope_rejected(self):
        for value in ('--script=all', 'bad;command', 'https://user:secret@example.test', 'file:///etc/passwd', 'a b'):
            with self.assertRaises(ValueError):
                target_identity(value)


class ContextTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.ctx = TaskContext(self.temp.name, '127.0.0.1/32', timeout=10)

    def test_output_artifact_and_nonzero_error(self):
        output = self.ctx.run([sys.executable, '-c', 'print("fixture")'], output_name='console.txt')
        self.assertEqual(output.stdout.strip(), 'fixture')
        self.assertEqual(self.ctx.path('console.txt').read_text(), 'fixture\n')
        self.assertEqual(self.ctx.path('console.txt').stat().st_mode & 0o777, 0o600)
        with self.assertRaisesRegex(RuntimeError, 'код 4'):
            self.ctx.run([sys.executable, '-c', 'import sys; sys.exit(4)'])

    def test_cancellation_and_timeout_stop_process(self):
        self.ctx.deadline = time.monotonic() + .2
        start = time.monotonic()
        with self.assertRaises(TaskTimeout):
            self.ctx.run([sys.executable, '-c', 'import time; time.sleep(20)'])
        self.assertLess(time.monotonic() - start, 3)
        self.assertIsNone(self.ctx.process)
        self.ctx.deadline = time.monotonic() + 5
        timer = threading.Timer(.15, self.ctx.cancelled.set)
        timer.start()
        self.addCleanup(timer.cancel)
        with self.assertRaises(CancelledError):
            self.ctx.run([sys.executable, '-c', 'import time; time.sleep(20)'])

    def test_paths_symlinks_and_output_limit(self):
        for value in ('../escape', '/tmp/escape', 'a/b'):
            with self.assertRaises(ValueError):
                self.ctx.path(value)
        self.ctx.path('link').symlink_to('/tmp')
        with self.assertRaises(ValueError):
            self.ctx.path('link')
        (Path(self.temp.name) / 'link').unlink()
        with self.assertRaisesRegex(RuntimeError, 'вывод превысил'):
            self.ctx.run([sys.executable, '-c', 'print("x"*20000)'], max_output=1024)

    def test_secret_not_in_log_or_json(self):
        self.ctx.secrets = ('very-private-pass',)
        self.ctx.run([sys.executable, '-c', 'print("very-private-pass")'], output_name='raw.txt')
        self.ctx.save_json('data.json', {'nested': [{'password': 'very-private-pass'}]})
        for path in Path(self.temp.name).iterdir():
            self.assertNotIn('very-private-pass', path.read_text())

    def test_exited_leader_does_not_leave_descendant_with_open_pipes(self):
        output = self.ctx.path('late.txt')
        child = 'import time,pathlib;time.sleep(2);pathlib.Path(' + repr(str(output)) + ').write_text("escaped")'
        parent = 'import subprocess,sys; subprocess.Popen([sys.executable,"-c",' + repr(child) + ']); print("done")'
        started = time.monotonic()
        result = self.ctx.run([sys.executable, '-c', parent])
        self.assertIn('done', result.stdout)
        self.assertLess(time.monotonic() - started, 1.5)
        self.assertFalse(output.exists())


class WorkbenchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        def run(ctx, p):
            ctx.emit('Password: ' + p.get('password', ''))
            return {'summary': 'done', 'assets': [{'id': '127.0.0.1', 'services': [22]}],
                    'findings': [{'title': '<script>fixture</script>', 'target': '127.0.0.1',
                                  'severity': 'medium', 'evidence': p.get('password', '')}], 'data': p}
        self.tool = Tool('test.check', 'Test', 'Test', '', (Field('target', 'Target', required=True),
                         Field('password', 'Password', secret=True)), (), run, ('target',))
        self.wb = Workbench(self.temp.name, tools=[self.tool], workers=1)
        self.addCleanup(self.wb.close)
        self.project = self.wb.store.projects()[0]['id']

    def wait(self, ident):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            row = self.wb.store.get_job(ident)
            if row['status'] not in ('queued', 'running'):
                return row
            time.sleep(.02)
        self.fail('Task did not finish')

    def submit(self, password='secret-pass'):
        return self.wait(self.wb.submit('test.check', {'target': '127.0.0.1', 'password': password}, self.project))

    def test_result_assets_review_and_secret_persistence(self):
        job = self.submit()
        self.assertEqual(job['status'], 'succeeded', job)
        self.assertEqual(job['params']['password'], '[SECRET]')
        self.assertNotIn('secret-pass', json.dumps(job))
        self.assertEqual(self.wb.store.assets(self.project)[0]['identity'], '127.0.0.1')
        finding = self.wb.store.findings(self.project)[0]
        self.wb.store.review_finding(finding['id'], 'confirmed', 'manual evidence')
        self.submit('another-pass')
        findings = self.wb.store.findings(self.project)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['status'], 'confirmed')
        self.assertEqual(findings[0]['note'], 'manual evidence')
        self.assertNotIn('secret-pass', self.wb.job_log(job['id']))
        self.wb.store.review_finding(finding['id'], 'fixed', 'Patched')
        self.submit()
        reopened = self.wb.store.findings(self.project)[0]
        self.assertEqual(reopened['status'], 'new')
        self.assertIn('Повторное обнаружение', reopened['note'])

    def test_scope_and_unknown_parameters_rejected_before_task(self):
        for params in ({'target': '192.0.2.1'}, {'target': '127.0.0.1', 'extra': '--bad'}):
            with self.assertRaises(ValueError):
                self.wb.submit('test.check', params, self.project)
        self.assertEqual(self.wb.jobs(), [])

    def test_url_with_comma_is_one_target(self):
        row = self.wait(self.wb.submit('test.check', {'target': 'http://127.0.0.1/a,b'}, self.project))
        self.assertEqual(row['status'], 'succeeded')

    def test_scope_snapshot_does_not_change_with_project(self):
        row = self.submit()
        self.wb.store.update_project(self.project, scope='192.0.2.0/24')
        self.assertIn('127.0.0.1', self.wb.store.get_job(row['id'])['scope'])

    def test_distinct_ports_produce_distinct_findings(self):
        row = self.submit()
        self.wb.store.ingest_result(row['id'], {'findings': [
            {'title': 'Segmentation', 'target': '127.0.0.1', 'port': 22},
            {'title': 'Segmentation', 'target': '127.0.0.1', 'port': 443}]})
        self.assertEqual(len(self.wb.store.findings(self.project)), 3)

    def test_store_has_single_owner(self):
        with self.assertRaisesRegex(RuntimeError, 'уже открыт'):
            ProjectStore(self.temp.name)

    def test_pdf_report_when_dependency_installed(self):
        import importlib.util
        if importlib.util.find_spec('reportlab') is None:
            self.skipTest('Optional reportlab not installed')
        self.submit()
        report = Path(self.wb.export_report(self.project, 'pdf'))
        self.assertTrue(report.read_bytes().startswith(b'%PDF-'))
        self.assertGreater(report.stat().st_size, 1000)

    def test_failed_adapter_never_success_or_fake_finding(self):
        def fail(ctx, p):
            raise ValueError('parse failed')
        self.wb.tools['fail'] = Tool('fail', 'Fail', '', '', (), (), fail)
        row = self.wait(self.wb.submit('fail', {}, self.project))
        self.assertEqual(row['status'], 'failed')
        self.assertEqual(self.wb.store.findings(self.project), [])

    def test_cancel_running_and_queued(self):
        def wait(ctx, p):
            while True:
                ctx.check_cancel()
                time.sleep(.01)
        self.wb.tools['wait'] = Tool('wait', 'Wait', '', '', (), (), wait)
        first = self.wb.submit('wait', {}, self.project)
        second = self.wb.submit('wait', {}, self.project)
        self.wb.cancel_all()
        self.assertEqual(self.wait(first)['status'], 'cancelled')
        self.assertEqual(self.wait(second)['status'], 'cancelled')

    def test_reports_escape_markup_and_export_evidence(self):
        self.submit()
        report = Path(self.wb.export_report(self.project, 'html'))
        self.assertIn('&lt;script&gt;fixture&lt;/script&gt;', report.read_text())
        self.assertNotIn('<script>fixture</script>', report.read_text())
        snapshot = json.loads(Path(self.wb.export_report(self.project, 'json')).read_text())
        self.assertEqual(len(snapshot['findings']), 1)
        self.assertTrue(snapshot['evidence'])
        self.assertEqual(len(snapshot['evidence'][0]['sha256']), 64)

    def test_attachment_copied_and_hashes_match(self):
        path = Path(self.temp.name) / 'source.txt'
        path.write_text('evidence')
        copied = self.wb.store.attach(self.project, path, 'note')
        path.write_text('changed source')
        self.assertEqual(Path(copied).read_text(), 'evidence')
        self.assertEqual(self.wb.store.attachments(self.project)[0]['note'], 'note')

    def test_comparison_and_project_isolation(self):
        a, b = self.submit(), self.submit()
        diff = self.wb.compare_jobs(a['id'], b['id'])
        self.assertEqual(diff['assets']['added'], [])
        other = self.wb.store.create_project('Other', '127.0.0.1')
        c = self.wait(self.wb.submit('test.check', {'target': '127.0.0.1'}, other))
        with self.assertRaises(ValueError):
            self.wb.compare_jobs(a['id'], c['id'])
        self.assertEqual(len(self.wb.jobs(other)), 1)

    def test_demo_disabled(self):
        self.wb.disabled = True
        with self.assertRaises(RuntimeError):
            self.wb.submit('test.check', {'target': '127.0.0.1'}, self.project)


class RemoteTests(unittest.TestCase):
    def test_no_shell_expansion_of_remote_path_and_bad_hosts(self):
        validate_remote({'host': 'user@host.example', 'directory': '/home/u/Axiora project'})
        for host in ('-oProxyCommand=evil', '-x@host', 'a;touch /tmp/file', '$(whoami)', 'user@-host'):
            with self.assertRaises(ValueError):
                validate_remote({'host': host, 'directory': '/tmp/app'})

    def test_worker_roundtrip_catalog_no_hardware(self):
        request = {'version': 1, 'tool': 'hardware.catalog', 'params': {}, 'scope': '127.0.0.1', 'timeout': 5}
        process = subprocess.run([sys.executable, 'axiora_remote_worker.py'], input=json.dumps(request)+'\n',
                                 text=True, capture_output=True, timeout=10,
                                 cwd=Path(__file__).resolve().parents[1])
        self.assertEqual(process.returncode, 0, process.stderr + process.stdout)
        response = json.loads(process.stdout)
        self.assertTrue(response['ok'])
        self.assertTrue(response['result']['data']['hardware'])
        self.assertTrue(response['artifacts'])

    def test_import_remote_artifacts_no_log_collision_and_omissions_visible(self):
        import hashlib
        with tempfile.TemporaryDirectory() as directory:
            ctx = TaskContext(directory, '127.0.0.1')
            ctx.log('Local log')
            data = b'Remote log'
            response = {'version': 1, 'ok': True, 'result': {'summary': 'Captured',
                        'data': {'log': '/tmp/axiora-remote-abc/artifacts/task.log',
                                 'capture': '/tmp/axiora-remote-abc/artifacts/large.pcap'}},
                        'artifacts': [{'name': 'task.log', 'base64': base64.b64encode(data).decode(),
                                       'sha256': hashlib.sha256(data).hexdigest()}],
                        'omitted_artifacts': [{'name': 'large.pcap', 'bytes': 9000000}]}
            with patch.object(ctx, 'run', return_value=CommandResult(0, json.dumps(response), '')) as run:
                result = execute_remote(ctx, {'host': 'lab', 'directory': '/opt/axiora'},
                                        'hardware.catalog', {}, '127.0.0.1', 20)
            self.assertFalse(run.call_args.kwargs['log_output'])
            self.assertIn('Local log', ctx.log_path.read_text())
            self.assertEqual(ctx.path('remote-task.log').read_text(), 'Remote log')
            self.assertEqual(result['data']['log'], str(ctx.path('remote-task.log')))
            self.assertFalse(result['remote']['evidence_complete'])
            self.assertIn('НЕПОЛНЫЕ', result['summary'])
            self.assertIn('Не передан', result['data']['capture'])

    def test_worker_cancels_when_keepalive_eof(self):
        request = {'version': 1, 'tool': 'hardware.catalog', 'params': {},
                   'scope': '127.0.0.1', 'timeout': 5, 'keepalive': True}
        process = subprocess.run([sys.executable, 'axiora_remote_worker.py'], input=json.dumps(request)+'\n',
                                 text=True, capture_output=True, timeout=10,
                                 cwd=Path(__file__).resolve().parents[1])
        response = json.loads(process.stdout)
        self.assertFalse(response['ok'])
        self.assertIn('остановлена', response['error'])


class VaultTests(unittest.TestCase):
    def test_json_header_body_atomic_secret_redaction(self):
        secrets = secret_parts('{"Authorization":"Bearer REVIEW_TOKEN","Cookie":"sid=SESSION_TOKEN; a=OTHER_TOKEN"}')
        text = 'Echo REVIEW_TOKEN SESSION_TOKEN OTHER_TOKEN'
        self.assertEqual(redact(text, secrets), 'Echo [REDACTED] [REDACTED] [REDACTED]')

    def test_backend_never_written_to_project_or_params(self):
        class Backend:
            def set_password(self, service, name, value): self.value = value
            def get_password(self, service, name): return self.value
            def delete_password(self, service, name): self.value = None
        vault = SecretVault(Backend())
        vault.set('switch', 'private-password')
        self.assertEqual(vault.get('switch'), 'private-password')
        vault.delete('switch')
        with self.assertRaises(ValueError):
            vault.get('switch')
        with self.assertRaises(ValueError):
            vault.set('../bad', 'value')


if __name__ == '__main__':
    unittest.main()
