import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import axiora


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        patches = [patch.object(axiora, 'APP_DIR', str(self.home)),
                   patch.object(axiora, 'REPORT_DIR', str(self.home / 'reports')),
                   patch.object(axiora, 'HardwareService')]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)
        self.engine = axiora.Engine(axiora.DB(str(self.home / 'live.db')))
        self.addCleanup(self.engine.db.c.close)

    def test_live_never_seeds_or_generates_data(self):
        self.assertFalse(self.engine.demo)
        for _ in range(100):
            self.engine.tick()
        self.assertEqual(self.engine.total, 0)
        self.assertEqual(self.engine.devices, {})
        self.assertEqual(len(self.engine.flows), 0)
        self.assertEqual(self.engine.db.one('SELECT COUNT(*) FROM reports')[0], 0)

    def test_reports_read_full_database_and_ids_survive_deletion(self):
        for _ in range(605):
            self.engine.add_event(axiora.RFID_OK, 'mfrc522', descr='Test UID')
        self.assertEqual(len(self.engine.events), 600)
        sections = dict(self.engine.report_data('Сеанс', ['Статистика']))
        self.assertIn('Событий: 605', sections['Статистика'])
        first, path = self.engine.write_report('Сеанс', 'HTML', ['Статистика'])
        self.assertTrue(Path(path).is_file())
        self.engine.db.q('DELETE FROM reports WHERE id=?', (first,))
        second, _ = self.engine.write_report('Сеанс', 'HTML', ['Статистика'])
        self.assertNotEqual(first, second)

    def test_live_risk_is_deterministic(self):
        a = self.engine.add_event(axiora.RFID_OK, 'reader-a')
        b = self.engine.add_event(axiora.RFID_OK, 'reader-b')
        self.assertEqual(a['risk'], b['risk'])
        self.assertEqual(a['conf'], b['conf'])

    def test_report_analysis_respects_selected_period(self):
        self.engine.add_event(axiora.ANOMALY, 'old-device', ts=time.time() - 7200)
        sections = dict(self.engine.report_data('Час', ['Оценка по правилам']))
        self.assertIn('В выбранном периоде нет событий для оценки.', sections['Оценка по правилам'])

    def test_non_ascii_login_is_rejected_without_crashing(self):
        self.assertFalse(self.engine.credentials.verify('админ', 'пароль'))

    def test_demo_developer_account_and_config_are_isolated(self):
        self.engine.credentials.change('live-password-123')
        demo = axiora.Engine(axiora.DB(str(self.home / 'demo.db')), demo=True)
        self.addCleanup(demo.db.c.close)
        self.assertTrue(demo.credentials.verify('admin', 'admin'))
        self.assertTrue(self.engine.credentials.verify('admin', 'live-password-123'))
        self.assertNotEqual(demo.config_path, self.engine.config_path)


if __name__ == '__main__':
    unittest.main()
