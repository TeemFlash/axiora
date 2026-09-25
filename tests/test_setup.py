"""Exercise installer decisions without running package managers or sudo."""
import contextlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

import axiora_setup as setup


class FakeRunner:
    """Record processes and emulate only their project-local output artifacts."""

    def __init__(self, *, missing=(), installed_iperf=True, fail_import=False):
        self.calls = []
        self.missing = set(missing)
        self.installed_iperf = installed_iperf
        self.fail_import = fail_import

    def __call__(self, argv, *, input=None, capture=False, env=None):
        argv = [str(value) for value in argv]
        self.calls.append((argv, {"input": input, "capture": capture, "env": env}))
        if argv[:2] == ["apt-cache", "policy"]:
            return "".join(
                f"{name}:\n  Installed: (none)\n  Candidate: {'(none)' if name in self.missing else '1.0'}\n"
                for name in argv[2:]
            )
        if argv[0] == "dpkg-query":
            if not self.installed_iperf:
                raise subprocess.CalledProcessError(1, argv)
            return "installed"
        if argv[1:4] == ["-m", "venv", "--system-site-packages"]:
            venv = Path(argv[4])
            (venv / "bin").mkdir(parents=True, exist_ok=True)
            (venv / "bin/python").write_text("fake interpreter\n")
            (venv / "pyvenv.cfg").write_text("include-system-site-packages = true\n")
        if argv[:3] == ["nuclei", "-ut", "-ud"]:
            directory = Path(argv[3]) / "http" / "technologies"
            directory.mkdir(parents=True, exist_ok=True)
            (directory / "sample.yaml").write_text("id: test-fixture\n")
        if len(argv) > 1 and argv[1] == "-c" and self.fail_import:
            raise subprocess.CalledProcessError(1, argv)
        return ""


class InstallerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="axiora installer ")
        self.addCleanup(temporary.cleanup)
        self.project = Path(temporary.name)
        (self.project / "hardware").mkdir()
        for name in ("axiora_setup.py", "install-and-run.sh", "requirements-tools.txt",
                     "requirements-hardware.txt", "hardware/99-axiora.rules"):
            (self.project / name).write_text("test fixture\n")
        self.runner = FakeRunner()
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(setup, "command_available", return_value=True).start()
        mock.patch.object(setup.shutil, "which", side_effect=lambda name: "/usr/bin/" + name).start()
        mock.patch.object(setup.os, "geteuid", return_value=1000).start()
        mock.patch.dict(os.environ, {"DISPLAY": ":94", "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus"}).start()
        mock.patch.object(setup, "session_needs_groups", return_value=False).start()

    def installer(self, *args, model="", release=None, runner=None):
        return setup.Installer(self.project, setup.parse_args(list(args)),
                               run=runner or self.runner,
                               release=release or {"ID": "kali"}, model=model)

    def make_venv(self, installer):
        installer.python.parent.mkdir(parents=True, exist_ok=True)
        installer.python.write_text("fake interpreter\n")
        (installer.venv / "pyvenv.cfg").write_text("include-system-site-packages = true\n")

    def write_marker(self, installer):
        self.make_venv(installer)
        installer.marker.write_text(json.dumps({"fingerprint": installer.fingerprint()}))

    def test_profiles_and_pi_tools_are_separate(self):
        full = set(self.installer().plan())
        core = set(self.installer("--core").plan())
        pi = set(self.installer("--core", model="Raspberry Pi 5 Model B Rev 1.0").plan())
        self.assertLess(core, full)
        self.assertTrue({"nmap", "tshark", "python3-gi", "python3-gi-cairo"} <= core)
        self.assertIn("nuclei", full - core)
        self.assertIn("device-tree-compiler", pi - core)
        self.assertIn("swig", pi - core)
        self.assertNotIn("python3-lgpio", full)

    def test_missing_required_package_stops_before_install_or_local_writes(self):
        runner = FakeRunner(missing={"nuclei"})
        installer = self.installer(runner=runner)
        with self.assertRaisesRegex(RuntimeError, "nuclei"):
            installer.install()
        self.assertFalse(installer.venv.exists())
        self.assertFalse(installer.templates.exists())
        self.assertFalse(any("install" in argv for argv, _ in runner.calls))
        self.assertFalse(any("debconf-set-selections" in argv for argv, _ in runner.calls))

    def test_success_marker_follows_dependency_validation_and_is_private(self):
        installer = self.installer()
        check = installer.check_dependencies

        def validate():
            self.assertFalse(installer.marker.exists())
            check()

        with mock.patch.object(installer, "check_dependencies", side_effect=validate) as checked:
            installer.install()
        checked.assert_called_once_with()
        state = json.loads(installer.marker.read_text())
        self.assertEqual(state["profile"], "full")
        self.assertEqual(state["fingerprint"], installer.fingerprint())
        self.assertEqual(stat.S_IMODE(installer.marker.stat().st_mode), 0o600)
        self.assertTrue(installer.cached())

    def test_failed_reinstall_invalidates_old_success_marker(self):
        runner = FakeRunner(fail_import=True)
        installer = self.installer("--core", "--reinstall", runner=runner)
        self.write_marker(installer)
        self.assertTrue(installer.cached())
        with self.assertRaises(subprocess.CalledProcessError):
            installer.install()
        self.assertFalse(installer.marker.exists())
        self.assertFalse(installer.cached())

    def test_cache_changes_when_requirements_profile_or_hardware_change(self):
        installer = self.installer("--core")
        self.write_marker(installer)
        self.assertTrue(installer.cached())
        self.assertFalse(self.installer().cached())
        self.assertFalse(self.installer("--core", model="Raspberry Pi 5 Model B").cached())
        (self.project / "requirements-tools.txt").write_text("updated dependency\n")
        self.assertFalse(installer.cached())
        installer.marker.write_text("malformed json")
        self.assertFalse(installer.cached())

    def test_existing_iperf_daemon_preference_is_preserved(self):
        self.installer("--core").install()
        selections = next(options["input"] for argv, options in self.runner.calls
                          if "debconf-set-selections" in argv)
        self.assertIn("wireshark-common/install-setuid boolean true", selections)
        self.assertNotIn("iperf3/start_daemon", selections)

    def test_new_iperf_install_does_not_start_a_server(self):
        runner = FakeRunner(installed_iperf=False)
        self.installer("--core", runner=runner).install()
        selections = next(options["input"] for argv, options in runner.calls
                          if "debconf-set-selections" in argv)
        self.assertIn("iperf3/start_daemon boolean false", selections)

    def test_pi_python_fallback_does_not_require_optional_apt_packages(self):
        runner = FakeRunner(missing=setup.PI_PREFERRED_PACKAGES)
        installer = self.installer("--core", model="Raspberry Pi 5 Model B", runner=runner)
        installer.install()
        hardware_pip = next((argv, options) for argv, options in runner.calls
                            if str(self.project / "requirements-hardware.txt") in argv)
        self.assertEqual(hardware_pip[0][0], str(installer.python))
        self.assertEqual(hardware_pip[1]["env"]["PYPI"], "1")
        self.assertFalse(any(argv[0] == "sudo" and "pip" in argv for argv, _ in runner.calls))
        imports = next(argv[2] for argv, _ in runner.calls if argv[1:2] == ["-c"])
        self.assertIn("request_lines", imports)
        self.assertTrue(any("wireshark,dialout,axiora" in argv for argv, _ in runner.calls))

    def test_no_templates_skips_download_and_does_not_create_templates_directory(self):
        installer = self.installer("--no-templates")
        installer.install()
        self.assertFalse(installer.templates.exists())
        self.assertFalse(any(argv[0] == "nuclei" for argv, _ in self.runner.calls))
        self.assertIn("nuclei", installer.plan())

    def test_dry_run_on_unsupported_os_has_no_process_or_filesystem_mutations(self):
        installer = self.installer("--dry-run", release={"ID": "arch"})
        before = sorted(path.relative_to(self.project) for path in self.project.rglob("*"))
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(installer.execute(), 0)
        after = sorted(path.relative_to(self.project) for path in self.project.rglob("*"))
        self.assertEqual(before, after)
        self.assertEqual(self.runner.calls, [])

    def test_root_and_unsupported_os_fail_before_commands(self):
        with mock.patch.object(setup.os, "geteuid", return_value=0):
            with self.assertRaisesRegex(RuntimeError, "sudo"):
                self.installer().execute()
        with self.assertRaisesRegex(RuntimeError, "arch"):
            self.installer(release={"ID": "arch"}).execute()
        self.assertEqual(self.runner.calls, [])

    def test_run_only_requires_venv_but_skips_installation_and_os_check(self):
        installer = self.installer("--run-only", "--", "--fullscreen", release={"ID": "arch"})
        with self.assertRaisesRegex(RuntimeError, "venv"):
            installer.execute()
        self.make_venv(installer)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(installer.execute(), 0)
        self.assertEqual([argv for argv, _ in self.runner.calls],
                         [[str(installer.python), str(self.project / "axiora.py"), "--fullscreen"]])

    def test_cached_install_skips_apt_and_pip_but_checks_imports_and_launcher(self):
        installer = self.installer("--core", "--install-only")
        self.write_marker(installer)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(installer.execute(), 0)
        calls = [argv for argv, _ in self.runner.calls]
        self.assertTrue(any(argv[1:2] == ["-c"] for argv in calls))
        self.assertTrue(any(str(self.project / "install-desktop.sh") in argv for argv in calls))
        self.assertFalse(any("apt-get" in argv or "pip" in argv for argv in calls))
        self.assertFalse(any(str(self.project / "axiora.py") in argv for argv in calls))

    def test_headless_install_completes_without_attempting_gui(self):
        installer = self.installer("--core")
        with mock.patch.dict(os.environ, {}, clear=True), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(installer.execute(), 0)
        self.assertTrue(installer.cached())
        self.assertFalse(any(str(self.project / "axiora.py") in argv for argv, _ in self.runner.calls))

    def test_boot_options_rejected_before_install_when_not_applicable(self):
        for args, error in ((("--enable-rdm6300",), ValueError),
                            (("--boot-dir", "/boot"), ValueError),
                            (("--configure-pi",), RuntimeError)):
            with self.subTest(args=args), self.assertRaises(error):
                self.installer(*args).execute()
        self.assertEqual(self.runner.calls, [])

    def test_dependency_check_rejects_venv_without_system_gtk(self):
        installer = self.installer("--core")
        self.make_venv(installer)
        (installer.venv / "pyvenv.cfg").write_text("include-system-site-packages = false\n")
        with self.assertRaisesRegex(RuntimeError, "system-site-packages"):
            installer.check_dependencies()


class SetupUtilitiesTests(unittest.TestCase):
    def test_apt_candidates_include_architecture_qualifiers_and_unavailable_entries(self):
        output = """nuclei:arm64:
  Installed: (none)
  Candidate: 3.4.5-1
  Version table:
     3.4.5-1 500
        500 https://example.invalid kali/main arm64 Packages
zaproxy:
  Installed: (none)
  Candidate: (none)
"""
        self.assertEqual(setup.parse_candidates(output), {"nuclei": "3.4.5-1", "zaproxy": None})

    def test_distribution_family_detection(self):
        self.assertTrue(setup.supported_os({"ID": "kali"}))
        self.assertTrue(setup.supported_os({"ID": "derivative", "ID_LIKE": "ubuntu debian"}))
        self.assertFalse(setup.supported_os({"ID": "arch"}))

    def test_group_refresh_runs_same_user_and_preserves_only_session_environment(self):
        python = Path("/tmp/project with spaces/.venv/bin/python")
        app = Path("/tmp/project with spaces/axiora.py")
        arguments = ["--example", "$(touch forbidden); literal argument"]
        environment = {"DISPLAY": ":1", "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus",
                       "XAUTHORITY": "/tmp/authority with spaces", "AXIORA_HOME": "/tmp/state",
                       "LD_PRELOAD": "untrusted.so", "PYTHONPATH": "/tmp/untrusted"}
        command = setup.launch_command(python, app, arguments, "alice", fresh_groups=True,
                                       environment=environment)
        self.assertEqual(command[:6], ["sudo", "-H", "-u", "alice", "--", "/usr/bin/env"])
        self.assertIn("DISPLAY=:1", command)
        self.assertIn("XAUTHORITY=/tmp/authority with spaces", command)
        self.assertIn("AXIORA_HOME=/tmp/state", command)
        self.assertFalse(any(part.startswith(("LD_PRELOAD=", "PYTHONPATH=")) for part in command))
        self.assertEqual(command[-4:], [str(python), str(app), *arguments])
        self.assertNotIn("root", command)

    def test_subprocess_runner_passes_argument_list_without_shell_interpretation(self):
        argv = ["/tmp/project with spaces/python", "$(literal)", "; untouched"]
        with mock.patch.object(setup.subprocess, "run", return_value=mock.Mock(stdout="ok")) as run:
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(setup.run_command(argv, capture=True), "ok")
        positional, options = run.call_args
        self.assertEqual(positional[0], argv)
        self.assertFalse(options.get("shell", False))
        self.assertTrue(options["check"])

    def test_group_refresh_uses_process_groups_instead_of_account_membership(self):
        with mock.patch.object(setup.os, "getgroups", return_value=[100]), \
                mock.patch.object(setup.os, "getgid", return_value=100), \
                mock.patch.object(setup.grp, "getgrnam", return_value=mock.Mock(gr_gid=200)):
            self.assertTrue(setup.session_needs_groups(["wireshark"]))
        with mock.patch.object(setup.os, "getgroups", return_value=[100, 200]), \
                mock.patch.object(setup.os, "getgid", return_value=100), \
                mock.patch.object(setup.grp, "getgrnam", return_value=mock.Mock(gr_gid=200)):
            self.assertFalse(setup.session_needs_groups(["wireshark"]))

    def test_incompatible_run_only_flags_are_rejected(self):
        for option in ("--reinstall", "--configure-pi", "--install-only"):
            with self.subTest(option=option), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                setup.parse_args(["--run-only", option])


if __name__ == "__main__":
    unittest.main()
