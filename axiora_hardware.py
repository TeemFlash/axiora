"""Hardware I/O for Axiora. No GTK dependency; all I/O belongs to one worker.

SPI chip select is owned by Linux (see hardware/axiora-spi-overlay.dts).
Never open a kernel-owned Ethernet or touchscreen device through spidev.
"""
from __future__ import annotations

import copy
import glob
import json
import math
import os
from pathlib import Path
import queue
import subprocess
import threading
import time

from axiora_protocols import CC_DEFAULTS, CLASSIC_TYPES, classic_block, validate_cc, cc_registers

PINOUT = [
    (4, 7, "Не использовать для RDM6300: это TX"),
    (13, 33, "RDM6300 TX → RX UART4 (исправление схемы)"),
    (5, 29, "MFRC522 CS"), (6, 31, "HW-237 CSN"), (7, 26, "CC1101 CSN"),
    (8, 24, "W5500 CS"), (9, 21, "SPI MISO"), (10, 19, "SPI MOSI"),
    (11, 23, "SPI SCLK"), (14, 8, "TX платы → GPS RX"),
    (15, 10, "RX платы ← GPS TX"), (16, 36, "Touch CS"),
    (17, 11, "HW-237 CE"), (20, 38, "MFRC522 RST"),
    (21, 40, "Touch IRQ"), (22, 15, "HW-237 IRQ"),
    (23, 16, "CC1101 GDO0"), (24, 18, "W5500 INT"),
    (25, 22, "W5500 RST (ядро)"), (27, 13, "CC1101 GDO2"),
]
DEFAULT_CONFIG = {
    "mfrc522": {"enabled": True, "device": "/dev/spidev0.0", "reset": 20},
    "nrf24": {"enabled": True, "device": "/dev/spidev0.1", "ce": 17,
              "channel": 76, "address": "E7E7E7E7E7"},
    "cc1101": {"enabled": True, "device": "/dev/spidev0.2", "frequency": 433.92, **CC_DEFAULTS},
    "gps": {"enabled": True, "device": "/dev/ttyAMA0", "baud": 9600},
    "rdm6300": {"enabled": False, "device": "/dev/ttyAMA4", "baud": 9600},
}
NAMES = {"mfrc522": "MFRC522", "nrf24": "HW-237 / nRF24L01+", "cc1101": "CC1101",
         "gps": "GPS", "rdm6300": "RDM6300", "w5500": "W5500", "touch": "XPT2046"}


def validate_config(config):
    result = copy.deepcopy(DEFAULT_CONFIG)
    if not isinstance(config, dict) or set(config) - set(result):
        raise ValueError("Неизвестный модуль в конфигурации")
    for key, values in config.items():
        if not isinstance(values, dict) or set(values) - set(result[key]):
            raise ValueError(f"Некорректные настройки {key}")
        result[key].update(values)
    paths = []
    for key, values in result.items():
        if type(values["enabled"]) is not bool or not isinstance(values["device"], str):
            raise ValueError(f"Некорректный тип настроек {key}")
        if values["enabled"]:
            path = values["device"]
            if not path.startswith("/dev/") or ".." in path.split("/"):
                raise ValueError(f"{key}: укажите устройство /dev/…")
            if key in ("mfrc522", "nrf24", "cc1101") and not Path(path).name.startswith("spidev"):
                raise ValueError(f"{key}: требуется spidev")
            paths.append(os.path.realpath(path))
    if len(paths) != len(set(paths)):
        raise ValueError("Два модуля не могут занимать одно устройство")
    for key in ("gps", "rdm6300"):
        if result[key]["baud"] not in (4800, 9600, 19200, 38400, 57600, 115200):
            raise ValueError("Неподдерживаемая скорость UART")
    if result["rdm6300"]["baud"] != 9600:
        raise ValueError("RDM6300 использует 9600 8N1")
    if result["mfrc522"]["reset"] != 20 or result["nrf24"]["ce"] != 17:
        raise ValueError("Для данной платы RST=GPIO20, CE=GPIO17")
    nrf = result["nrf24"]
    if type(nrf["channel"]) is not int or not 0 <= nrf["channel"] <= 125:
        raise ValueError("Канал nRF24: целое число 0–125")
    try:
        if len(bytes.fromhex(nrf["address"])) != 5:
            raise ValueError()
    except (ValueError, TypeError):
        raise ValueError("Адрес nRF24: 5 байт HEX, например E7E7E7E7E7") from None
    freq = result["cc1101"]["frequency"]
    if isinstance(freq, bool) or not isinstance(freq, (int, float)) or not any(
            lo <= freq <= hi for lo, hi in ((300, 348), (387, 464), (779, 928))):
        raise ValueError("CC1101: диапазоны 300–348, 387–464 или 779–928 МГц")
    result["cc1101"].update(validate_cc(result["cc1101"]))
    return result


def load_config(path):
    if not Path(path).exists():
        return copy.deepcopy(DEFAULT_CONFIG)
    return validate_config(json.loads(Path(path).read_text(encoding="utf-8")))


def save_config(path, config):
    config = validate_config(config)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(config, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)
    return config


class RDMParser:
    """STX + 10 hex data chars + XOR checksum (2 hex chars) + ETX."""
    def __init__(self):
        self.buffer = bytearray()

    def feed(self, data):
        self.buffer.extend(data)
        tags = []
        while self.buffer:
            start = self.buffer.find(b"\x02")
            if start < 0:
                self.buffer.clear()
                break
            del self.buffer[:start]
            if len(self.buffer) < 14:
                break
            frame = self.buffer[:14]
            if frame[-1] != 3:
                del self.buffer[0]
                continue
            del self.buffer[:14]
            try:
                value = bytes.fromhex(frame[1:13].decode("ascii"))
            except (ValueError, UnicodeError):
                continue
            if len(value) == 6 and value[5] == (value[0] ^ value[1] ^ value[2] ^ value[3] ^ value[4]):
                tags.append(value[:5].hex().upper())
        return tags


def parse_nmea(line):
    """Return only checksummed, valid RMC/GGA observations. No guessed fixes."""
    try:
        sentence = line.decode("ascii").strip() if isinstance(line, bytes) else line.strip()
        body, check = sentence[1:].split("*")
        checksum = 0
        for char in body:
            checksum ^= ord(char)
        if not sentence.startswith("$") or len(check) != 2 or checksum != int(check, 16):
            return None
        parts = body.split(",")
        kind = parts[0][-3:]
        def coordinate(raw, hemi, degree_digits):
            degrees, minutes = int(raw[:degree_digits]), float(raw[degree_digits:])
            limit = 90 if degree_digits == 2 else 180
            if not math.isfinite(minutes) or not 0 <= minutes < 60 or not 0 <= degrees <= limit:
                raise ValueError("coordinate")
            number = degrees + minutes / 60
            if number > limit or hemi not in ("NS" if degree_digits == 2 else "EW"):
                raise ValueError("coordinate")
            return -number if hemi in "SW" else number
        result = {"sentence": sentence, "updated": time.time(), "type": kind, "utc": parts[1]}
        if kind == "RMC":
            result.update(fix=parts[2] == "A", date=parts[9])
            if result["fix"]:
                speed = float(parts[7] or 0) * 1.852
                if not math.isfinite(speed) or speed < 0:
                    return None
                result.update(lat=coordinate(parts[3], parts[4], 2),
                              lon=coordinate(parts[5], parts[6], 3), speed=speed)
        elif kind == "GGA":
            quality = int(parts[6])
            result.update(fix=quality > 0, quality=quality, satellites=int(parts[7] or 0))
            if result["fix"]:
                altitude = float(parts[9])
                if not math.isfinite(altitude):
                    return None
                result.update(lat=coordinate(parts[2], parts[3], 2),
                              lon=coordinate(parts[4], parts[5], 3), altitude=altitude)
        else:
            return None
        if not result["fix"]:
            result.update(lat=None, lon=None, speed=None, altitude=None)
        return result
    except (ValueError, IndexError, UnicodeError, TypeError):
        return None


def crc_a(data):
    crc = 0x6363
    for value in data:
        value ^= crc & 0xFF
        value ^= (value << 4) & 0xFF
        crc = ((crc >> 8) ^ (value << 8) ^ (value << 3) ^ (value >> 4)) & 0xFFFF
    return [crc & 255, crc >> 8]


class SPI:
    def __init__(self, path, speed=1_000_000):
        import spidev
        self.dev = spidev.SpiDev()
        try:
            self.dev.open_path(path)
            self.dev.max_speed_hz = speed
            self.dev.mode = 0
        except Exception:
            self.dev.close()
            raise

    def xfer(self, data):
        return self.dev.xfer2(list(data))

    def close(self):
        self.dev.close()


def output_pin(number, initial_value=False):
    from gpiozero import DigitalOutputDevice
    from gpiozero.pins.lgpio import LGPIOFactory
    chips = []
    for path in Path("/sys/class/gpio").glob("gpiochip*/label"):
        try:
            if "rp1" in path.read_text().lower():
                chips.append(int(path.parent.name.removeprefix("gpiochip")))
        except (ValueError, OSError):
            pass
    # Newer GPIO character-device sysfs layout.
    for path in Path("/sys/bus/gpio/devices").glob("gpiochip*/label"):
        try:
            if "rp1" in path.read_text().lower():
                chips.append(int(path.parent.name.removeprefix("gpiochip")))
        except (ValueError, OSError):
            pass
    if not chips:
        raise OSError("Не найден gpiochip RP1; нужен Raspberry Pi 5 и доступ к /dev/gpiochip*")
    factory = LGPIOFactory(chip=min(chips))
    try:
        device = DigitalOutputDevice(number, initial_value=initial_value, pin_factory=factory)
    except Exception:
        factory.close()
        raise
    return device, factory


class MFRC522:
    def __init__(self, config):
        self.spi = self.reset = self.factory = None
        try:
            self.reset, self.factory = output_pin(config["reset"])
            time.sleep(0.01)
            self.reset.on()
            time.sleep(0.05)
            self.spi = SPI(config["device"])
            self.version = self.read(0x37)
            if self.version not in (0x90, 0x91, 0x92, 0x88):
                raise OSError(f"MFRC522 VersionReg=0x{self.version:02X}; проверьте питание и CS")
            self.write(0x01, 0x0F)
            time.sleep(0.05)
            for reg, value in ((0x2A, 0x8D), (0x2B, 0x3E), (0x2C, 0), (0x2D, 30),
                               (0x15, 0x40), (0x11, 0x3D), (0x14, 0x83)):
                self.write(reg, value)
        except Exception:
            self.close()
            raise

    def read(self, reg):
        return self.spi.xfer([0x80 | (reg << 1), 0])[1]

    def write(self, reg, value):
        self.spi.xfer([reg << 1, value])

    def exchange(self, data, bits=0):
        self.write(0x01, 0)
        self.write(0x04, 0x7F)
        self.write(0x0A, 0x80)
        for value in data:
            self.write(0x09, value)
        self.write(0x0D, bits)
        self.write(0x01, 0x0C)
        self.write(0x0D, bits | 0x80)
        deadline = time.monotonic() + 0.04
        try:
            while time.monotonic() < deadline:
                irq = self.read(0x04)
                if irq & 0x01:
                    return []
                if irq & 0x30:
                    if self.read(0x06) & 0x1B:
                        return []
                    length = self.read(0x0A)
                    if length > 64:
                        raise OSError("MFRC522: неверная длина FIFO")
                    self.last_rx_bits = self.read(0x0C) & 7
                    return [self.read(0x09) for _ in range(length)]
                time.sleep(0.001)
            return []
        finally:
            self.write(0x0D, bits)

    def select_card(self):
        self.write(0x08, self.read(0x08) & ~0x08)
        if len(self.exchange([0x52], 7)) != 2:
            return None
        uid = []
        for cascade in (0x93, 0x95, 0x97):
            part = self.exchange([cascade, 0x20])
            if len(part) != 5 or part[4] != part[0] ^ part[1] ^ part[2] ^ part[3]:
                return None
            select = [cascade, 0x70] + part
            sak = self.exchange(select + crc_a(select))
            if len(sak) != 3 or sak[1:] != crc_a(sak[:1]):
                return None
            uid.extend(part[1:4] if part[0] == 0x88 else part[:4])
            if not sak[0] & 4:
                return {"uid": ":".join(f"{b:02X}" for b in uid), "sak": sak[0]}
        return None

    def poll(self):
        card = self.select_card()
        if card:
            self.exchange([0x50, 0] + crc_a([0x50, 0]))
        return card

    def authenticate(self, block, key, key_type, uid):
        self.write(0x01, 0)
        self.write(0x04, 0x7F)
        self.write(0x0A, 0x80)
        self.write(0x0D, 0)
        for value in [0x60 if key_type == 'A' else 0x61, block] + list(key) + list(uid[-4:]):
            self.write(0x09, value)
        self.write(0x01, 0x0E)
        deadline = time.monotonic() + .1
        while time.monotonic() < deadline:
            irq = self.read(0x04)
            if irq & 1:
                break
            if irq & 0x10:
                if not self.read(0x06) & 0x1B and self.read(0x08) & 8:
                    return
                break
            time.sleep(.001)
        raise PermissionError('Аутентификация не выполнена: проверьте ключ A/B, сектор и положение карты')

    def _read_block(self, block):
        command = [0x30, block]
        result = self.exchange(command + crc_a(command))
        if len(result) != 18 or self.last_rx_bits or result[-2:] != crc_a(result[:-2]):
            raise OSError('Блок не прочитан: отказ карты, потеря связи или неверная CRC')
        return bytes(result[:16])

    def _ack(self, data):
        result = self.exchange(list(data) + crc_a(data))
        if len(result) != 1 or self.last_rx_bits != 4 or result[0] & 15 != 0x0A:
            raise OSError('Карта не подтвердила запись (NAK/тайм-аут); считайте блок заново')

    def memory(self, action, block, key_hex, key_type='A', expected_uid=None,
               payload=None, expected_data=None):
        # Validate before any card I/O. Keys are used once and never returned or logged.
        try:
            key = bytes.fromhex(key_hex)
        except (ValueError, TypeError):
            raise ValueError('Ключ должен содержать 6 байт HEX') from None
        if len(key) != 6 or key_type not in ('A', 'B'):
            raise ValueError('Нужны ключ из 6 байт и тип A или B')
        if action not in ('read', 'write') or type(block) is not int or not 0 <= block <= 255:
            raise ValueError('Неверная операция или номер блока')
        if action == 'write':
            if not expected_uid or not isinstance(payload, bytes) or len(payload) != 16:
                raise ValueError('Для записи нужны UID прочитанной карты и ровно 16 байт данных')
            if not isinstance(expected_data, bytes) or len(expected_data) != 16:
                raise ValueError('Сначала считайте исходное содержимое блока')
        card = None
        try:
            card = self.select_card()
            if not card:
                raise OSError('Карта не обнаружена; приложите одну карту к MFRC522')
            sector = classic_block(block, card['sak'], writing=action == 'write')
            if expected_uid and card['uid'] != expected_uid:
                raise ValueError('UID изменился; приложена другая карта. Запись отменена')
            self.authenticate(block, key, key_type, bytes.fromhex(card['uid'].replace(':', '')))
            before = self._read_block(block)
            after = before
            if action == 'write':
                if before != expected_data:
                    raise ValueError('Содержимое блока изменилось после чтения; считайте его заново')
                self._ack([0xA0, block])
                self._ack(list(payload))
                after = self._read_block(block)
                if after != payload:
                    raise OSError('Запись отправлена, но проверка чтением не совпала; проверьте карту')
            return dict(card, action=action, block=block, sector=sector,
                        card_type=CLASSIC_TYPES[card['sak']][0], before=before.hex().upper(),
                        data=after.hex().upper(), verified=True)
        finally:
            try:
                if card:
                    self.exchange([0x50, 0] + crc_a([0x50, 0]))
            finally:
                self.write(0x01, 0)
                self.write(0x08, self.read(0x08) & ~8)
                self.write(0x0A, 0x80)  # clear authentication bytes from the FIFO

    def close(self):
        try:
            if self.spi:
                try:
                    self.write(0x14, 0)
                finally:
                    self.spi.close()
                    self.spi = None
        finally:
            try:
                if self.reset:
                    try:
                        self.reset.off()
                    finally:
                        self.reset.close()
                        self.reset = None
            finally:
                if self.factory:
                    self.factory.close()
                    self.factory = None


class NRF24:
    """1 Mbps, 2-byte CRC, fixed 32-byte payload, pipe 0, no auto ACK."""
    def __init__(self, config):
        self.spi = self.ce = self.factory = None
        try:
            self.ce, self.factory = output_pin(config["ce"])
            self.spi = SPI(config["device"])
            self.write(0, [0x0C])
            self.write(5, [config["channel"]])
            if self.read(5)[0] != config["channel"] or self.read(3)[0] not in (1, 2, 3):
                raise OSError("nRF24: нет ответа; проверьте CSN, CE и питание")
            address = list(bytes.fromhex(config["address"]))
            for reg, value in ((1, [0]), (2, [1]), (3, [3]), (4, [0]), (6, [6]),
                               (0x0A, address), (0x10, address), (0x11, [32]),
                               (0x1C, [0]), (0x1D, [0]), (7, [0x70])):
                self.write(reg, value)
            self.spi.xfer([0xE1])
            self.spi.xfer([0xE2])
            self.receive()
        except Exception:
            self.close()
            raise

    def read(self, reg, count=1):
        return self.spi.xfer([reg & 0x1F] + [0xFF] * count)[1:]

    def write(self, reg, data):
        self.spi.xfer([0x20 | reg] + data)

    def receive(self):
        self.write(0, [0x0F])
        time.sleep(0.002)
        self.ce.on()

    def poll(self):
        if self.read(0x17)[0] & 1:
            return None
        data = self.spi.xfer([0x61] + [0xFF] * 32)[1:]
        self.write(7, [0x40])
        return {"payload": bytes(data).hex().upper(), "rpd": bool(self.read(9)[0] & 1)}

    def send(self, payload):
        if not 1 <= len(payload) <= 32:
            raise ValueError("nRF24: от 1 до 32 байт")
        self.ce.off()
        try:
            self.write(0, [0x0E])
            self.write(7, [0x70])
            self.spi.xfer([0xE1])
            self.spi.xfer([0xA0] + list(payload.ljust(32, b"\0")))
            time.sleep(0.002)
            self.ce.on()
            time.sleep(0.001)
            self.ce.off()
            deadline = time.monotonic() + 0.15
            while time.monotonic() < deadline:
                if self.spi.xfer([0xFF])[0] & 0x20:
                    return "Передано 32 байта (дополнение нулями); ACK отключён, доставка не подтверждена"
                time.sleep(0.001)
            raise TimeoutError("nRF24: истекло время передачи")
        finally:
            self.receive()

    def close(self):
        if self.ce:
            self.ce.off()
            self.ce.close()
            self.ce = None
        if self.factory:
            self.factory.close()
            self.factory = None
        if self.spi:
            try:
                self.write(0, [0x0C])
            finally:
                self.spi.close()
                self.spi = None


class CC1101:
    """26 MHz crystal; configurable packet profiles or receive-only asynchronous OOK."""
    def __init__(self, config):
        self.spi = self.capture = None
        self.profile = validate_cc(config)
        self.raw = self.profile['mode'] == 'ook_raw'
        self.frequency = config['frequency'] 
        try:
            self.spi = SPI(config["device"], 500_000)
            self.spi.xfer([0x30])
            time.sleep(0.01)
            self.version = self.status(0x31)
            if self.status(0x30) != 0 or self.version in (0, 255):
                raise OSError("CC1101: неверные PARTNUM/VERSION; проверьте SPI и питание")
            freq = round(config["frequency"] * 65536 / 26)
            registers = {0: 0x0E, 2: 0x06, 3: 0x47, 4: 0xD3, 5: 0x91, 6: 60,
                         7: 0x0C, 8: 0x05, 9: 0, 0x0A: 0, 0x0B: 6, 0x0C: 0,
                         0x0D: (freq >> 16) & 255, 0x0E: (freq >> 8) & 255, 0x0F: freq & 255,
                         0x10: 0xCA, 0x11: 0x83, 0x12: 0x03, 0x13: 0x22, 0x14: 0xF8,
                         0x15: 0x35, 0x17: 0, 0x18: 0x18, 0x19: 0x16,
                         0x1B: 0x43, 0x1C: 0x40, 0x1D: 0x91,
                         0x21: 0x56, 0x22: 0x10, 0x23: 0xE9, 0x24: 0x2A, 0x25: 0,
                         0x26: 0x1F, 0x2C: 0x81, 0x2D: 0x35, 0x2E: 0x09}
            registers.update(cc_registers(config))
            for reg, value in registers.items():
                self.spi.xfer([reg, value])
            # OOK PA table: zero for low bit, configured power for high bit.
            if self.profile['modulation'] == 'OOK' or self.raw:
                self.spi.xfer([0x7E, 0, 0x50])
                self.spi.xfer([0x22, 0x11])
                self.spi.xfer([0x1B, 0x03])
                self.spi.xfer([0x1C, 0x00])
                self.spi.xfer([0x1D, 0x91])
            else:
                self.spi.xfer([0x3E, 0x50])
            if self.raw:
                from axiora_capture import EdgeCapture
                self.capture = EdgeCapture(23)
            self.receive()
        except Exception:
            self.close()
            raise

    def status(self, reg):
        return self.spi.xfer([0xC0 | reg, 0])[1]

    def receive(self):
        self.spi.xfer([0x36])
        self.spi.xfer([0x3A])
        self.spi.xfer([0x34])

    def poll(self):
        if self.capture:
            return [dict(frame, frequency=self.frequency, profile=dict(self.profile)) for frame in self.capture.poll()]
        count = self.status(0x3B)
        state = self.status(0x35) & 0x1F
        if count & 0x80 or state == 0x11:
            self.receive()
            return None
        if state != 1:  # RXOFF_MODE=IDLE: wait for the complete packet
            return None
        try:
            if count < 3:
                return None
            length = self.spi.xfer([0xBF, 0])[1]
            if not 1 <= length <= 60 or count < length + 3:
                return None
            data = self.spi.xfer([0xFF] + [0] * (length + 2))[1:]
            if not data[-1] & 0x80:
                return None
            rssi = data[-2] - 256 if data[-2] >= 128 else data[-2]
            return {"payload": bytes(data[:-2]).hex().upper(), "rssi": rssi / 2 - 74,
                    "lqi": data[-1] & 0x7F}
        finally:
            self.receive()

    def sample(self):
        value = self.status(0x34)
        return {"rssi": (value - 256 if value >= 128 else value) / 2 - 74,
                "carrier": bool(self.status(0x38) & 0x40)}

    def send(self, payload):
        if self.raw:
            raise ValueError('OOK raw — режим приёма импульсов; для передачи HEX выберите packet')
        if not 1 <= len(payload) <= 60:
            raise ValueError("CC1101: от 1 до 60 байт")
        try:
            self.spi.xfer([0x36])
            self.spi.xfer([0x3B])
            self.spi.xfer([0x7F, len(payload)] + list(payload))
            self.spi.xfer([0x35])
            time.sleep(0.005)
            deadline = time.monotonic() + 1 + (len(payload) + 12) * 8 / (self.profile["bitrate"] * 1000)
            while time.monotonic() < deadline:
                if (self.status(0x35) & 0x1F) == 1 and (self.status(0x3A) & 0x7F) == 0:
                    return f"Передано {len(payload)} байт; подтверждение от получателя не предусмотрено"
                time.sleep(0.002)
            raise TimeoutError("CC1101: истекло время передачи")
        finally:
            self.receive()

    def close(self):
        try:
            if self.capture:
                self.capture.close()
                self.capture = None
        finally:
            if self.spi:
                try:
                    self.spi.xfer([0x36])
                    self.spi.xfer([0x39])
                finally:
                    self.spi.close()
                    self.spi = None


class SerialReader:
    def __init__(self, config, kind):
        import serial
        self.kind = kind
        self.serial = serial.Serial(config["device"], config["baud"], timeout=0,
                                    write_timeout=0.2, exclusive=True)
        self.buffer = bytearray()
        self.parser = RDMParser()

    def poll(self):
        data = self.serial.read(min(self.serial.in_waiting, 4096))
        if self.kind == "rdm6300":
            return [{"uid": uid} for uid in self.parser.feed(data)]
        self.buffer.extend(data)
        result = []
        while b"\n" in self.buffer:
            line, _, rest = self.buffer.partition(b"\n")
            self.buffer = bytearray(rest)
            value = parse_nmea(line)
            if value:
                result.append(value)
        if len(self.buffer) > 8192:
            self.buffer.clear()
        return result

    def close(self):
        self.serial.close()


def read_network():
    """Actual Linux interfaces, cumulative counters and address information."""
    addresses = {}
    try:
        process = subprocess.run(["ip", "-j", "address", "show"], capture_output=True,
                                 text=True, timeout=2, check=True)
        addresses = {item["ifname"]: [a["local"] for a in item.get("addr_info", [])]
                     for item in json.loads(process.stdout)}
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    result = []
    for path in sorted(Path("/sys/class/net").glob("*")):
        try:
            driver = (path / "device/driver").resolve().name if (path / "device/driver").exists() else "—"
            result.append({"name": path.name, "state": (path / "operstate").read_text().strip(),
                           "mac": (path / "address").read_text().strip(), "driver": driver,
                           "addresses": addresses.get(path.name, []),
                           "rx": int((path / "statistics/rx_bytes").read_text()),
                           "tx": int((path / "statistics/tx_bytes").read_text())})
        except (OSError, ValueError):
            continue
    return result


def read_neighbors():
    proc = subprocess.run(["ip", "-j", "neigh", "show"], check=True, capture_output=True,
                          text=True, timeout=3)
    return [item for item in json.loads(proc.stdout) if item.get("lladdr")]


def diagnostics():
    try:
        model = Path("/proc/device-tree/model").read_text().rstrip("\0")
    except OSError:
        model = "Обычный компьютер / модель платы не определена"
    devices = glob.glob("/dev/spidev*") + glob.glob("/dev/serial*") + glob.glob("/dev/ttyAMA*") + glob.glob("/dev/ttyUSB*") + glob.glob("/dev/ttyACM*")
    return {"model": model, "devices": sorted(devices), "network": read_network(),
            "touch": [p.read_text().strip() for p in Path("/sys/class/input").glob("event*/device/name")],
            "uart_warning": "Pi 5: GPIO4=TX UART2, GPIO5=RX UART2 занят CS MFRC522. RDM6300 TX → GPIO13 (UART4 RX) или USB–UART."}


class HardwareService:
    def __init__(self, config):
        self.config = validate_config(config)
        self.commands = queue.Queue(maxsize=64)
        self.events = queue.Queue(maxsize=512)
        self.stop_event = threading.Event()
        self.lock = threading.Lock()
        self.state = {key: {"status": "Отключён", "detail": "Нажмите «Подключить»"} for key in NAMES}
        self.state["network"] = []
        self.devices = {}
        self.last_uid = {}
        self.thread = threading.Thread(target=self._run, name="axiora-hardware", daemon=True)
        self.thread.start()
        self.submit("inspect")

    def snapshot(self):
        with self.lock:
            return copy.deepcopy(self.state)

    def emit(self, kind, name, data):
        try:
            self.events.put_nowait((kind, name, data))
        except queue.Full:
            with self.lock:
                self.state["dropped_events"] = self.state.get("dropped_events", 0) + 1
            # Command completion must not disappear behind a flood of RX data.
            if kind != "data":
                try:
                    self.events.get_nowait()
                    self.events.put_nowait((kind, name, data))
                except (queue.Empty, queue.Full):
                    pass

    def update(self, name, status, detail, **data):
        with self.lock:
            old = self.state.get(name, {})
            self.state[name] = dict(old, status=status, detail=str(detail), **data)
            if name == "gps" and "updated" in data:
                stamps = dict(old.get("field_updated", {}))
                for field in ("altitude", "speed", "satellites"):
                    if field in data:
                        stamps[field] = data["updated"]
                self.state[name]["field_updated"] = stamps
        if old.get("status") != status or old.get("detail") != str(detail):
            self.emit("status", name, {"status": status, "detail": str(detail)})

    def submit(self, action, name=None, data=None):
        try:
            self.commands.put_nowait((action, name, data))
        except queue.Full:
            raise RuntimeError("Очередь команд занята; повторите через несколько секунд") from None

    def disconnect(self, name):
        device = self.devices.pop(name, None)
        try:
            if device:
                device.close()
        finally:
            with self.lock:
                self.state[name] = {}
            self.update(name, "Отключён", "Соединение закрыто")

    def connect(self, name):
        self.disconnect(name)
        config = self.config[name]
        if not config["enabled"]:
            self.update(name, "Отключён", "Модуль выключен в настройках")
            return
        self.update(name, "Подключение", config["device"])
        factory = {"mfrc522": MFRC522, "nrf24": NRF24, "cc1101": CC1101}
        device = factory[name](config) if name in factory else SerialReader(config, name)
        self.devices[name] = device
        status = "Порт открыт" if name in ("gps", "rdm6300") else "Подключён"
        self.update(name, status, config["device"] + (" • ожидаются проверенные данные" if status == "Порт открыт" else ""))

    def inspect(self):
        interfaces = read_network()
        with self.lock:
            self.state["network"] = interfaces
            self.state["network_updated"] = time.monotonic()
        wiznet = [n for n in interfaces if "w5100" in n["driver"] or "w5500" in n["driver"]]
        self.update("w5500", "Подключён" if wiznet else "Нет драйвера",
                    "; ".join(f"{n['name']} • {n['state']} • {', '.join(n['addresses']) or 'нет IP'}" for n in wiznet)
                    or "Нужен overlay и драйвер w5100-spi; CS8 / INT24 / RST25")
        touch = []
        for path in Path("/sys/class/input").glob("event*/device/name"):
            try:
                name = path.read_text().strip()
                if any(word in name.lower() for word in ("ads7846", "xpt2046", "touchscreen")):
                    touch.append(name)
            except OSError:
                pass
        self.update("touch", "Подключён" if touch else "Нет драйвера",
                    ", ".join(touch) or "XPT2046: нужен драйвер ads7846; CS16 / IRQ21. Ввод обслуживает Xfce/libinput")

    def _command(self, action, name, data):
        if action == "connect":
            self.connect(name)
        elif action == "disconnect":
            self.disconnect(name)
        elif action == "inspect":
            self.inspect()
        elif action == "neighbors":
            self.emit("neighbors", "network", read_neighbors())
        elif action == "configure":
            config = validate_config(data)
            for key in list(self.devices):
                self.disconnect(key)
            self.config = config
            self.emit("result", "system", "Настройки применены. Подключите нужные модули.")
        elif action == "send":
            if name not in ("nrf24", "cc1101") or name not in self.devices:
                raise ValueError("Сначала подключите радиомодуль")
            self.emit("result", name, self.devices[name].send(bytes.fromhex(data)))
        elif action == "memory":
            if name != "mfrc522" or name not in self.devices:
                raise ValueError("Сначала подключите MFRC522")
            result = self.devices[name].memory(**data)
            self.emit("memory", name, result)
        elif action == "sample":
            if name != "cc1101" or name not in self.devices:
                raise ValueError("Сначала подключите CC1101")
            value = self.devices[name].sample()
            self.update(name, "Подключён", f"RSSI {value['rssi']:.1f} dBm • carrier={value['carrier']}", **value)
        else:
            raise ValueError("Неизвестная команда")

    def _run(self):
        next_inspect = 0
        while not self.stop_event.is_set():
            try:
                action, name, data = self.commands.get(timeout=0.03)
            except queue.Empty:
                action = None
            if action:
                try:
                    self._command(action, name, data)
                except Exception as exc:
                    if action == "connect":
                        self.update(name, "Ошибка", exc)
                    if action == "memory":
                        self.emit("memory", name, {"error": str(exc)})
                    self.emit("error", name or "system", str(exc))
                finally:
                    data = None  # release the request (including any card key) after execution
            for name, device in list(self.devices.items()):
                try:
                    observations = device.poll()
                    if observations is None:
                        continue
                    if isinstance(observations, dict):
                        observations = [observations]
                    for value in observations:
                        if "uid" in value:
                            key = (name, value["uid"])
                            now = time.monotonic()
                            previous = self.last_uid.get(key, 0)
                            self.last_uid[key] = now
                            if now - previous < 2:
                                continue
                            self.last_uid = {k: v for k, v in self.last_uid.items() if now - v < 60}
                        self.update(name, "Подключён", "Получены данные", **value)
                        self.emit("data", name, value)
                except Exception as exc:
                    try:
                        self.disconnect(name)
                    except Exception:
                        pass
                    self.update(name, "Ошибка", exc)
                    self.emit("error", name, str(exc))
            if time.monotonic() >= next_inspect:
                try:
                    self.inspect()
                except Exception as exc:
                    self.emit("error", "system", str(exc))
                next_inspect = time.monotonic() + 3
        for name in list(self.devices):
            try:
                self.disconnect(name)
            except Exception:
                pass

    def close(self):
        self.stop_event.set()
        self.thread.join(timeout=5)
        return not self.thread.is_alive()
