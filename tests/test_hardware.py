import copy
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch, Mock

from axiora_auth import Credentials
from axiora_hardware import (DEFAULT_CONFIG, RDMParser, parse_nmea, crc_a, validate_config,
                             HardwareService, save_config, load_config, CC1101, MFRC522)


def nmea(body):
    checksum = 0
    for value in body.encode():
        checksum ^= value
    return f"${body}*{checksum:02X}\r\n"


class ParsingTests(unittest.TestCase):
    def test_rdm_fragmented_stream_and_checksum(self):
        parser = RDMParser()
        good = b'\x02010203040501\x03'
        self.assertEqual(parser.feed(b'noise' + good[:6]), [])
        self.assertEqual(parser.feed(good[6:] + good), ['0102030405'] * 2)
        self.assertEqual(parser.feed(b'\x020102030405FF\x03'), [])
        self.assertEqual(parser.feed(b'\x02bad' + good), ['0102030405'])

    def test_rdm_buffer_bounded(self):
        parser = RDMParser()
        parser.feed(b'x' * 100000)
        self.assertLess(len(parser.buffer), 14)

    def test_nmea_rmc_known_vector(self):
        result = parse_nmea('$GPRMC,123519,A,4807.038,N,01131.000,E,022.4,084.4,230394,003.1,W*6A')
        self.assertTrue(result['fix'])
        self.assertAlmostEqual(result['lat'], 48.1173)
        self.assertAlmostEqual(result['lon'], 11.5166667)
        self.assertAlmostEqual(result['speed'], 41.4848)

    def test_nmea_gga_south_west(self):
        result = parse_nmea(nmea('GNGGA,123519,4807.038,S,01131.000,W,1,08,0.9,545.4,M,46.9,M,,'))
        self.assertLess(result['lat'], 0)
        self.assertLess(result['lon'], 0)
        self.assertEqual(result['altitude'], 545.4)
        self.assertEqual(result['satellites'], 8)

    def test_nmea_invalid_fix_clears_coordinates(self):
        result = parse_nmea(nmea('GPRMC,123519,V,,,,,,,230394,,,N'))
        self.assertFalse(result['fix'])
        self.assertIsNone(result['lat'])
        self.assertIsNone(result['speed'])

    def test_nmea_rejects_bad_inputs(self):
        for line in ('noise', '$GPRMC,no*00', nmea('GPRMC,123519,A,4867,N,01131,E,1,0,230394'),
                     nmea('GPRMC,123519,A,4807,N,01131,E,nan,0,230394')):
            self.assertIsNone(parse_nmea(line))

    def test_iso14443_crc_known_halt_vector(self):
        self.assertEqual(crc_a([0x50, 0]), [0x57, 0xCD])


class ConfigTests(unittest.TestCase):
    def test_roundtrip_and_defaults_unchanged(self):
        original = copy.deepcopy(DEFAULT_CONFIG)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'hardware.json'
            config = load_config(path)
            config['nrf24']['channel'] = 40
            save_config(path, config)
            self.assertEqual(load_config(path)['nrf24']['channel'], 40)
        self.assertEqual(DEFAULT_CONFIG, original)

    def test_rejects_duplicate_bus_unsupported_frequency_and_nan(self):
        bad = copy.deepcopy(DEFAULT_CONFIG)
        bad['nrf24']['device'] = bad['cc1101']['device']
        with self.assertRaises(ValueError):
            validate_config(bad)
        for value in (100, 500, float('nan'), float('inf')):
            with self.assertRaises(ValueError):
                validate_config({'cc1101': {'frequency': value}})
        with self.assertRaises(ValueError):
            validate_config({'nrf24': {'channel': True}})
        with self.assertRaises(ValueError):
            validate_config({'rdm6300': {'enabled': True, 'device': ''}})

    def test_credentials_persist_and_change(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'account.json'
            account = Credentials(path)
            self.assertTrue(account.verify('admin', 'admin'))
            self.assertFalse(account.verify('admin', 'wrong'))
            account.change('new-pass-123')
            restored = Credentials(path)
            self.assertTrue(restored.verify('admin', 'new-pass-123'))
            self.assertFalse(restored.verify('admin', 'admin'))
            self.assertNotIn('new-pass-123', path.read_text())
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)


class WorkerTests(unittest.TestCase):
    def wait_for(self, predicate, timeout=2):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(.01)
        self.fail('Worker timeout')

    @patch('axiora_hardware.HardwareService.inspect')
    def test_missing_device_and_reconnect(self, inspect):
        service = HardwareService(DEFAULT_CONFIG)
        try:
            with patch('axiora_hardware.MFRC522', side_effect=OSError('disconnected')):
                service.submit('connect', 'mfrc522')
                self.wait_for(lambda: service.snapshot()['mfrc522']['status'] == 'Ошибка')
                self.assertIn('disconnected', service.snapshot()['mfrc522']['detail'])
            class FakeReader:
                def __init__(self, config):
                    self.closed = False
                def poll(self):
                    return {'uid': '01:02:03:04'}
                def close(self):
                    self.closed = True
            with patch('axiora_hardware.MFRC522', FakeReader):
                service.submit('connect', 'mfrc522')
                self.wait_for(lambda: 'uid' in service.snapshot()['mfrc522'])
                device = service.devices['mfrc522']
                service.submit('disconnect', 'mfrc522')
                self.wait_for(lambda: service.snapshot()['mfrc522']['status'] == 'Отключён')
                self.assertTrue(device.closed)
                self.assertNotIn('uid', service.snapshot()['mfrc522'])
        finally:
            self.assertTrue(service.close())

    @patch('axiora_hardware.HardwareService.inspect')
    def test_bad_send_does_not_kill_worker(self, inspect):
        service = HardwareService(DEFAULT_CONFIG)
        try:
            service.submit('send', 'cc1101', '00')
            self.wait_for(lambda: not service.events.empty())
            self.assertEqual(service.events.get_nowait()[0], 'error')
            self.assertTrue(service.thread.is_alive())
        finally:
            service.close()

    def test_mfrc_disconnect_releases_gpio_when_spi_fails(self):
        device = MFRC522.__new__(MFRC522)
        spi, reset, factory = Mock(), Mock(), Mock()
        device.spi, device.reset, device.factory = spi, reset, factory
        device.write = Mock(side_effect=OSError("SPI disappeared"))
        with self.assertRaises(OSError):
            device.close()
        spi.close.assert_called_once()
        reset.close.assert_called_once()
        factory.close.assert_called_once()

    def test_cc1101_overflow_recovers_without_packet(self):
        device = CC1101.__new__(CC1101)
        device.capture = None
        device.status = lambda reg: 0x80 if reg == 0x3B else 0x11
        calls = []
        device.receive = lambda: calls.append('flush')
        self.assertIsNone(device.poll())
        self.assertEqual(calls, ['flush'])


if __name__ == '__main__':
    unittest.main()
