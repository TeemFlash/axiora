import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

from axiora_tool_api import CommandResult
import axiora_device_tools as device


class FakeContext:
    def __init__(self, directory, outputs=None):
        self.directory = Path(directory)
        self.outputs = iter(outputs or [])
        self.calls = []

    def path(self, name):
        return self.directory / name

    def save_json(self, name, value):
        self.path(name).write_text(json.dumps(value), encoding='utf-8')

    def check_cancel(self):
        pass

    def emit(self, message):
        pass

    def run(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        return CommandResult(0, next(self.outputs, ''), '')


class DeviceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.ctx = FakeContext(self.directory.name)

    def write(self, name, data):
        path = self.ctx.path(name)
        if isinstance(data, bytes):
            path.write_bytes(data)
        else:
            path.write_text(json.dumps(data), encoding='utf-8')
        return str(path)

    def test_iw_scan_keeps_distinct_bss_and_security_evidence(self):
        scan = '''BSS 12:34:56:78:9a:bc(on wlan0)
        freq: 2412
        signal: -42.00 dBm
        capability: ESS Privacy ShortSlotTime
        SSID: Laboratory Wi-Fi
        RSN:
            * Authentication suites: PSK SAE
BSS aa:bb:cc:dd:ee:ff(on wlan0)
        freq: 5180
        SSID:
'''
        entries = device.parse_wifi_scan(scan)
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0]['bssid'], '12:34:56:78:9A:BC')
        self.assertEqual(entries[0]['signal_dbm'], -42)
        self.assertEqual(entries[0]['security'], ['RSN'])
        self.assertEqual(entries[0]['authentication'], 'PSK SAE')
        self.assertEqual(entries[1]['ssid'], '')

    def test_wifi_capture_never_switches_managed_interface(self):
        self.ctx.outputs = iter(['Interface wlan0\n\ttype managed\n'])
        with self.assertRaisesRegex(ValueError, 'monitor'):
            device.wifi_capture(self.ctx, {'interface': 'wlan0', 'seconds': '10'})
        self.assertEqual(len(self.ctx.calls), 1)

    def test_nmcli_parses_escaped_ssid_and_keeps_signal_in_percent(self):
        raw = r'12\:34\:56\:78\:9a\:bc:Lab\:AP\\West:1:2412 MHz:54 Mbit/s:82:WPA2 WPA3'
        entries = device.parse_nmcli_scan(raw)
        self.assertEqual(entries[0]['ssid'], 'Lab:AP\\West')
        self.assertEqual(entries[0]['bssid'], '12:34:56:78:9A:BC')
        self.assertEqual(entries[0]['frequency_mhz'], 2412)
        self.assertEqual(entries[0]['signal_percent'], 82)
        self.assertNotIn('signal_dbm', entries[0])
        self.ctx.outputs = iter([raw])
        device.wifi_scan(self.ctx, {'interface': 'wlan0'})
        self.assertEqual(self.ctx.calls[0][0][0], 'nmcli')
        self.assertEqual(self.ctx.calls[0][0][-2:], ['--rescan', 'yes'])
        for malformed in ('invalid:row', raw.replace(':82:', ':101:'), raw + '\\'):
            with self.assertRaises(ValueError):
                device.parse_nmcli_scan(malformed)

    def test_wifi_detailed_iw_is_explicit(self):
        self.ctx.outputs = iter(['BSS aa:bb:cc:dd:ee:ff(on wlan0)\nSSID: Lab'])
        output = device.wifi_scan(self.ctx, {'interface': 'wlan0', 'method': 'iw'})
        self.assertEqual(self.ctx.calls[0][0], ['iw', 'dev', 'wlan0', 'scan'])
        self.assertEqual(output['data']['networks'][0]['ssid'], 'Lab')

    def test_wifi_capture_is_bounded_and_preserves_argument_boundaries(self):
        self.ctx.outputs = iter(['Interface wlan1mon\n\ttype monitor\n', ''])
        device.wifi_capture(self.ctx, {'interface': 'wlan1mon', 'seconds': '7'})
        argv = self.ctx.calls[-1][0]
        self.assertIn('duration:7', argv)
        self.assertIn('filesize:32768', argv)
        self.assertEqual(argv[-1], str(self.ctx.path('wifi-monitor.pcapng')))
        for bad in ('-i', 'wlan0;whoami', 'wlan0\n', 'a' * 16):
            with self.assertRaises(ValueError):
                device.iface(bad)

    def test_bluetooth_parses_updates_without_turning_rssi_into_device_name(self):
        text = '\x1b[0;32m[NEW]\x1b[0m Device AA:BB:CC:DD:EE:FF Test beacon\n[CHG] Device AA:BB:CC:DD:EE:FF RSSI: -62\n'
        entries = device.parse_bluetooth(text)
        self.assertEqual(entries, [{'address': 'AA:BB:CC:DD:EE:FF', 'name': 'Test beacon', 'rssi_raw': '-62'}])

    def test_snmp_secrets_not_in_argv_and_config_removed_even_on_error(self):
        saved = {}
        def run(argv, **kw):
            saved['path'] = Path(kw['env']['SNMPCONFPATH'])
            config = saved['path'] / 'snmp.conf'
            self.assertEqual(config.stat().st_mode & 0o777, 0o600)
            self.assertIn('defSecurityLevel authPriv', config.read_text())
            self.assertIn('defAuthPassphrase "auth-password"', config.read_text())
            self.assertNotIn('auth-password', repr(argv))
            self.assertNotIn('privacy-password', repr(argv))
            self.assertIn('udp6:[2001:db8::10]:161', argv)
            raise RuntimeError('agent timeout')
        self.ctx.run = run
        with self.assertRaisesRegex(RuntimeError, 'agent timeout'):
            device.snmp_inventory(self.ctx, {'target': '2001:db8::10', 'username': 'monitor',
                                            'auth_password': 'auth-password', 'privacy_password': 'privacy-password'})
        self.assertFalse(saved['path'].exists())
        self.assertFalse(list(self.ctx.directory.glob('*')))

    def test_snmp_config_rejects_newline_injection(self):
        for value in ('abc\ndefVersion 1', '\x00token', ''):
            with self.assertRaises(ValueError):
                device.snmp_quoted(value)
        self.assertEqual(device.snmp_quoted('a"b\\c'), '"a\\"b\\\\c"')

    def test_ssh_uses_strict_known_hosts_and_always_disconnects(self):
        class Connection:
            disconnected = False
            def send_command(self, command, **kw):
                self.command = command
                return 'hostname switch\ninterface GigabitEthernet0/1'
            def disconnect(self):
                self.disconnected = True
        connection = Connection()
        settings = {}
        def connect(**kwargs):
            settings.update(kwargs)
            return connection
        with patch.dict('sys.modules', {'netmiko': types.SimpleNamespace(ConnectHandler=connect)}):
            output = device.ssh_device(self.ctx, {'target': '192.0.2.2', 'username': 'operator',
                                                 'platform': 'cisco_ios', 'action': 'backup', 'password': 's3cret'})
        self.assertTrue(settings['ssh_strict'])
        self.assertTrue(settings['system_host_keys'])
        self.assertTrue(connection.disconnected)
        self.assertEqual(connection.command, 'show running-config')
        self.assertEqual(self.ctx.path('running-config.txt').stat().st_mode & 0o777, 0o600)
        self.assertNotIn('s3cret', json.dumps(output))

    def test_sigrok_mapping_rejects_options_or_unknown_parameters(self):
        self.assertEqual(device.decoder_spec({'decoder': 'spi', 'mapping': 'clk=0:miso=1:mosi=2:cs=3'}),
                         'spi:clk=0:miso=1:mosi=2:cs=3')
        for mapping in ('rx=0:rx=1', 'rx=0:script=foo', 'rx=0 --continuous', 'rx=$(id)', 'rx='):
            with self.assertRaises(ValueError):
                device.decoder_spec({'decoder': 'uart', 'mapping': mapping})

    def test_sdr_iq_size_limit_prevents_unbounded_capture(self):
        with self.assertRaisesRegex(ValueError, '32 МиБ'):
            device.sdr_receive(self.ctx, {'action': 'iq_capture', 'sample_rate': '2400000', 'seconds': '30'})
        self.assertFalse(self.ctx.calls)
        device.sdr_receive(self.ctx, {'action': 'iq_capture', 'sample_rate': '250000', 'seconds': '2'})
        argv = self.ctx.calls[0][0]
        self.assertIn('-T', argv)
        self.assertIn('-w', argv)
        self.assertEqual(argv[1:3], ['-c', '0'])

    def test_sdr_offline_path_cannot_be_remote_device(self):
        path = self.write('input_433.92M_250k.cu8', b'\x80' * 32)
        device.sdr_receive(self.ctx, {'action': 'decode', 'input': path})
        argv = self.ctx.calls[0][0]
        self.assertIn('-r', argv)
        self.assertNotIn('-d', argv)
        with self.assertRaises(ValueError):
            device.sdr_receive(self.ctx, {'action': 'receive', 'device': 'rtl_tcp:example.com'})

    def test_rfid_import_compare_preserves_offsets_and_length_changes(self):
        before = self.write('card.bin', bytes(range(32)))
        modified = bytearray(range(32))
        modified[17] = 250
        after = self.write('card.json', {'data': modified.hex() + 'AB'})
        output = device.rfid_dump(self.ctx, {'input': before, 'compare': after})
        self.assertEqual(output['data']['changes'], [{'offset': 17, 'before': 17, 'after': 250},
                                                     {'offset': 32, 'before': None, 'after': 171}])
        self.assertEqual(device.load_card_dump(str(self.ctx.path('card-dump.json'))), bytes(range(32)))

    def test_sparse_rfid_blocks_are_not_silently_reindexed(self):
        path = self.write('sparse.json', {'blocks': {'4': '00' * 16}})
        with self.assertRaisesRegex(ValueError, 'последовательные'):
            device.load_card_dump(path)
        valid = self.write('ordered.json', {'blocks': {'1': '01' * 16, '0': '00' * 16}})
        self.assertEqual(device.load_card_dump(valid), b'\x00' * 16 + b'\x01' * 16)

    def test_imported_pulses_are_validated_and_never_claim_live_confirmation(self):
        pulses = [[level, value] for bit in '001101010011010100110101' for level, value in
                  ((1, 350 if bit == '0' else 1050), (0, 1050 if bit == '0' else 350))]
        path = self.write('ook.json', {'format': 'axiora-ook-v1', 'frames': [{'pulses': pulses, 'decoded': {'confirmed': True}}]})
        output = device.pulse_import(self.ctx, {'input': path})
        self.assertEqual(output['data']['frames'][0]['decoded']['hex'], '353535')
        self.assertFalse(output['data']['frames'][0]['decoded']['confirmed'])
        path = self.write('bad.json', {'format': 'axiora-ook-v1', 'frames': [{'pulses': [[1, float('nan')]]}]})
        with self.assertRaises(ValueError):
            device.pulse_import(self.ctx, {'input': path})

    def test_radio_profiles_cannot_change_devices_or_pins(self):
        output = device.radio_profile(self.ctx, {'module': 'cc1101', 'mode': 'ook_raw', 'name': '433 MHz'})
        self.assertEqual(output['data']['settings']['modulation'], 'OOK')
        self.assertNotIn('device', output['data']['settings'])
        path = self.write('bad-profile.json', {'schema': 'axiora.radio-profile.v1', 'module': 'nrf24',
                                              'settings': {'channel': 76, 'ce': 25}})
        with self.assertRaisesRegex(ValueError, 'посторонние'):
            device.radio_profile(self.ctx, {'input': path})
        with self.assertRaises(ValueError):
            device.radio_profile(self.ctx, {'module': 'cc1101', 'frequency': '10000'})

    def test_tools_have_unique_ids_and_network_destinations_are_scoped(self):
        ids = [t.id for t in device.TOOLS]
        self.assertEqual(len(ids), len(set(ids)))
        for tool_id in ('device.ssh', 'device.snmp'):
            tool = next(t for t in device.TOOLS if t.id == tool_id)
            self.assertEqual(tool.targets, ('target',))
            self.assertTrue(any(f.secret for f in tool.fields))


if __name__ == '__main__':
    unittest.main()
