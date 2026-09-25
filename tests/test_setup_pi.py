from pathlib import Path
import shutil
import tempfile
import unittest

from axiora_setup_pi import BEGIN, END, configure_pi, merge_boot_config, select_boot_dir


class BootConfigTests(unittest.TestCase):
    def test_append_preserves_settings_and_resets_scope(self):
        original = "# display\n[pi4]\nmax_framebuffers=2\n[none]\narm_freq=1000"
        result = merge_boot_config(original)
        self.assertTrue(result.startswith(original + "\n" + BEGIN + "\n[all]\n"))
        self.assertIn("dtoverlay=uart0-pi5\n", result)
        self.assertNotIn("uart4", result)
        self.assertEqual(merge_boot_config(result), result)

    def test_rdm_is_explicit_and_repeatable(self):
        original = "[all]\n# Keep this comment\n"
        result = merge_boot_config(original, enable_rdm=True)
        self.assertEqual(result.count("dtoverlay=uart4-pi5"), 1)
        self.assertEqual(merge_boot_config(result, enable_rdm=True), result)
        self.assertNotIn("uart4", merge_boot_config(result))

    def test_preserves_crlf_and_trailing_comments(self):
        original = "# untouched\r\n"
        first = merge_boot_config(original) + "# user note\r\n"
        self.assertEqual(merge_boot_config(first), first)
        self.assertNotIn("\n", first.replace("\r\n", ""))

    def test_rejects_malformed_or_manually_edited_block(self):
        for value in (BEGIN, END, END + "\n" + BEGIN,
                      BEGIN + "\n" + BEGIN + "\n" + END,
                      BEGIN + "\n" + END + "\n" + END,
                      "# BEGIN AXIORA MANAGED BOOT changed\n",
                      BEGIN + "\ndtoverlay=axiora-spi,touch=off\n" + END,
                      merge_boot_config("") + "arm_freq=1500\n"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                merge_boot_config(value)

    def test_rejects_conflicting_overlays_and_includes(self):
        for directive in ("dtoverlay=spi0-2cs", "dtoverlay=spi1-1cs", "dtoverlay=w5500",
                          "dtoverlay=ads7846", "dtoverlay=xpt2046", "dtoverlay=uart0-pi5",
                          "dtoverlay=uart2", "dtoverlay=uart4-pi5,ctsrts",
                          "dtoverlay=axiora-spi", "include usercfg.txt", "include=extra.txt",
                          "overlay_prefix=custom/", "os_prefix=alternate/", "device_tree=foo.dtb"):
            with self.subTest(directive=directive), self.assertRaises(ValueError):
                merge_boot_config("[all]\n" + directive + "\n")
        self.assertIn("# dtoverlay=spi0-2cs", merge_boot_config("# dtoverlay=spi0-2cs\n"))
        self.assertIn("dtoverlay=vc4-kms-v3d", merge_boot_config("dtoverlay=vc4-kms-v3d\n"))


class BootSelectionTests(unittest.TestCase):
    def make_boot(self, path):
        path.mkdir()
        (path / "overlays").mkdir()
        (path / "config.txt").write_text("[all]\n", encoding="utf-8")
        return path

    def test_candidates_aliases_and_explicit_selection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = self.make_boot(root / "one")
            second = self.make_boot(root / "two")
            alias = root / "alias"
            alias.symlink_to(first, target_is_directory=True)
            self.assertEqual(select_boot_dir(candidates=[first, alias]), first)
            with self.assertRaisesRegex(ValueError, "--boot-dir"):
                select_boot_dir(candidates=[first, second])
            self.assertEqual(select_boot_dir(second, candidates=[first, second]), second)
            with self.assertRaisesRegex(ValueError, "--boot-dir"):
                select_boot_dir(root / "missing")

    def test_configure_backs_up_and_is_idempotent_without_real_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            boot = self.make_boot(root / "boot")
            for name in ("uart0-pi5.dtbo", "uart4-pi5.dtbo"):
                (boot / "overlays" / name).write_bytes(b"uart")
            project = root / "project"
            (project / "hardware").mkdir(parents=True)
            (project / "hardware" / "axiora-spi-overlay.dts").write_text("mock dts")
            calls = []

            def run(argv, **kwargs):
                calls.append(argv)
                if argv[0] == "dtc":
                    Path(argv[argv.index("-o") + 1]).write_bytes(b"compiled-dtbo")
                else:
                    self.assertEqual(argv[:2], ["sudo", "--"])
                    if argv[2] == "cp":
                        self.assertFalse(Path(argv[-1]).exists())
                    shutil.copyfile(argv[-2], argv[-1])
                return ""

            original = (boot / "config.txt").read_bytes()
            self.assertTrue(configure_pi(project, run, boot, enable_rdm=True))
            backups = list(boot.glob("config.txt.axiora-backup-*"))
            self.assertEqual(len(backups), 1)
            self.assertEqual(backups[0].read_bytes(), original)
            self.assertEqual(calls[1][2], "cp")
            calls.clear()
            self.assertFalse(configure_pi(project, run, boot, enable_rdm=True))
            self.assertEqual([call[0] for call in calls], ["dtc"])
            self.assertEqual(len(list(boot.glob("config.txt.axiora-backup-*"))), 1)

    def test_conflict_and_missing_uart_fail_before_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            boot = self.make_boot(root / "boot")
            calls = []
            (boot / "config.txt").write_text("include config-extra.txt\n")
            with self.assertRaisesRegex(ValueError, "include"):
                configure_pi(root, lambda argv, **kwargs: calls.append(argv), boot)
            self.assertEqual(calls, [])
            (boot / "config.txt").write_text("[all]\n")
            with self.assertRaisesRegex(ValueError, "uart0-pi5"):
                configure_pi(root, lambda argv, **kwargs: calls.append(argv), boot)
            self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
