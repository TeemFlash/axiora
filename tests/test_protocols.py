import copy
import unittest
from unittest.mock import Mock

from axiora_hardware import DEFAULT_CONFIG, MFRC522, CC1101, crc_a, validate_config
from axiora_protocols import classic_block, cc_registers, decode_ook, OOKFrames


def pulse_train(bits='001101010011010100110101', unit=350):
    return [[level, length * unit] for bit in bits for level, length in
            ((1, 1 if bit == '0' else 3), (0, 3 if bit == '0' else 1))]


class ProtocolTests(unittest.TestCase):
    def test_classic_sector_boundaries(self):
        self.assertEqual(classic_block(127, 0x18), 31)
        self.assertEqual(classic_block(128, 0x18), 32)
        self.assertEqual(classic_block(254, 0x18, True), 39)
        for block in (0, 3, 127, 143, 255):
            with self.assertRaises(ValueError):
                classic_block(block, 0x18, True)
        for block, sak in ((64, 0x08), (20, 0x09), (4, 0x00)):
            with self.assertRaises(ValueError):
                classic_block(block, sak)

    def test_existing_configs_gain_radio_defaults(self):
        config = validate_config({'cc1101': {'frequency': 433.92}})
        registers = cc_registers(config['cc1101'])
        self.assertEqual(registers[0x10], 0xCA)
        self.assertEqual(registers[0x11], 0x83)
        self.assertEqual(registers[0x15], 0x35)
        self.assertEqual(registers[0x12], 0x03)

    def test_radio_profiles_reject_invalid_inputs(self):
        for key, value in [('bitrate', float('nan')), ('mode', 'anything'), ('sync', '123'),
                           ('bandwidth', 1), ('modulation', 'WiFi')]:
            with self.assertRaises(ValueError):
                validate_config({'cc1101': {key: value}})
        registers = cc_registers({'mode': 'ook_raw', 'bitrate': 4.8})
        self.assertEqual(registers[0x02], 0x0D)
        self.assertEqual(registers[0x08], 0x32)
        self.assertEqual(registers[0x12], 0x30)

    def test_known_pwm_frame_and_jitter(self):
        values = pulse_train()
        for i, value in enumerate(values):
            value[1] *= .94 if i % 3 else 1.06
        result = decode_ook(values)
        self.assertEqual(result['hex'], '353535')
        self.assertEqual(result['tristate'], '01FF01FF01FF')

    def test_not_every_signal_is_a_known_protocol(self):
        for values in (pulse_train()[:-2], [[level, 350] for level, _ in pulse_train()],
                       [[1 - level, us] for level, us in pulse_train()]):
            self.assertIsNone(decode_ook(values))

    def test_stream_needs_matching_repeats(self):
        frames = OOKFrames()
        results = []
        for stamp in (1, 1.1):
            for level, duration in pulse_train() + [[1, 350]]:
                self.assertIsNone(frames.feed(level, duration, stamp))
            results.append(frames.feed(0, 10850, stamp))
        self.assertFalse(results[0]['decoded']['confirmed'])
        self.assertTrue(results[1]['decoded']['confirmed'])
        self.assertEqual(results[1]['decoded']['repeats'], 2)
        for level, duration in pulse_train('1' * 24) + [[1, 350]]:
            frames.feed(level, duration, 1.2)
        self.assertFalse(frames.feed(0, 10850, 1.2)['decoded']['confirmed'])

    def test_slow_data_pulse_is_not_mistaken_for_sync(self):
        frames = OOKFrames()
        for level, duration in pulse_train(unit=1000) + [[1, 1000]]:
            self.assertIsNone(frames.feed(level, duration, 1))
        result = frames.feed(0, 31000, 1)
        self.assertEqual(result['decoded']['hex'], '353535')

    def test_noise_memory_is_bounded(self):
        frames = OOKFrames()
        for i in range(10000):
            frames.feed(i % 2, 200, i / 1000)
        self.assertLess(len(frames.pulses), 512)


class ClassicIOTests(unittest.TestCase):
    def reader(self):
        reader = MFRC522.__new__(MFRC522)
        reader.write = Mock()
        reader.read = Mock(return_value=8)
        reader.select_card = Mock(return_value={'uid': '04:01:02:03', 'sak': 8})
        reader.authenticate = Mock()
        reader.exchange = Mock(return_value=[])
        reader._ack = Mock()
        reader._read_block = Mock(return_value=bytes(range(16)))
        return reader

    def test_read_known_key_and_crypto_cleanup(self):
        reader = self.reader()
        result = reader.memory('read', 4, 'FFFFFFFFFFFF')
        self.assertEqual(result['data'], bytes(range(16)).hex().upper())
        self.assertEqual(result['sector'], 1)
        self.assertNotIn('key', str(result))
        self.assertIn(((8, 0),), reader.write.call_args_list)

    def test_write_requires_matching_uid_and_snapshot(self):
        reader = self.reader()
        with self.assertRaisesRegex(ValueError, 'UID'):
            reader.memory('write', 4, 'FFFFFFFFFFFF', expected_uid='other', payload=bytes(16), expected_data=bytes(16))
        reader._ack.assert_not_called()
        with self.assertRaisesRegex(ValueError, 'изменилось'):
            reader.memory('write', 4, 'FFFFFFFFFFFF', expected_uid='04:01:02:03', payload=bytes(16), expected_data=bytes(16))
        reader._ack.assert_not_called()

    def test_write_checks_both_stages_and_readback(self):
        reader = self.reader()
        original, written = bytes(range(16)), bytes([0xA5] * 16)
        reader._read_block.side_effect = [original, written]
        result = reader.memory('write', 4, 'FFFFFFFFFFFF', 'B', '04:01:02:03', written, original)
        self.assertEqual(result['data'], written.hex().upper())
        self.assertEqual(reader._ack.call_args_list[0].args[0], [0xA0, 4])
        self.assertEqual(reader._ack.call_args_list[1].args[0], list(written))
        self.assertTrue(result['verified'])

    def test_bad_readback_is_not_success(self):
        reader = self.reader()
        with self.assertRaisesRegex(OSError, 'не совпала'):
            reader.memory('write', 4, 'FFFFFFFFFFFF', 'A', '04:01:02:03', bytes(16), bytes(range(16)))

    def test_trailer_and_bad_key_never_write(self):
        reader = self.reader()
        for block in (0, 3, 7):
            with self.assertRaises(ValueError):
                reader.memory('write', block, 'FFFFFFFFFFFF', 'A', '04:01:02:03', bytes(16), bytes(16))
        with self.assertRaises(ValueError):
            reader.memory('read', 4, 'wrong-key')
        reader._ack.assert_not_called()

    def test_four_bit_ack_required(self):
        reader = MFRC522.__new__(MFRC522)
        reader.exchange = Mock(return_value=[0x0A])
        reader.last_rx_bits = 8
        with self.assertRaises(OSError):
            reader._ack([0xA0, 4])
        reader.last_rx_bits = 4
        reader._ack([0xA0, 4])
        reader.exchange.return_value = [0x04]
        with self.assertRaises(OSError):
            reader._ack([0xA0, 4])

    def test_crc_error_rejected(self):
        reader = MFRC522.__new__(MFRC522)
        reader.last_rx_bits = 0
        data = list(range(16))
        reader.exchange = Mock(return_value=data + crc_a(data))
        self.assertEqual(reader._read_block(4), bytes(data))
        reader.exchange.return_value[-1] ^= 1
        with self.assertRaises(OSError):
            reader._read_block(4)


if __name__ == '__main__':
    unittest.main()
