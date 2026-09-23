"""Bounded device integrations for the workbench; imports do not touch hardware.

All command invocations are argument lists. Profiles and offline imports produce
artifacts, and never silently reconfigure GPIO, a network interface or a card.
"""
from __future__ import annotations

import copy
import difflib
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import stat
import tempfile
import time

from axiora_tool_api import Field, Tool
from axiora_hardware import validate_config
from axiora_protocols import OOKFrames, decode_ook


def integer(value, low, high, name):
    if isinstance(value, bool) or not re.fullmatch(r"[0-9]+", str(value)):
        raise ValueError(f"{name}: требуется целое число")
    number = int(value)
    if not low <= number <= high:
        raise ValueError(f"{name}: диапазон {low}–{high}")
    return number


def iface(value):
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.:-]{0,14}", str(value)):
        raise ValueError("Некорректное имя сетевого интерфейса")
    return str(value)


def hostname(value):
    value = str(value).strip()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        if not re.fullmatch(r"(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", value):
            raise ValueError("Нужен IP-адрес или DNS-имя без порта") from None
        if any(not part or len(part) > 63 or part.startswith('-') or part.endswith('-')
               for part in value.split('.')):
            raise ValueError("Некорректное DNS-имя")
        return value


def input_file(value, limit=16 * 1024 * 1024):
    path = Path(str(value)).expanduser().resolve(strict=True)
    if not path.is_file() or path.stat().st_size > limit:
        raise ValueError(f"Нужен обычный файл размером не более {limit // 1024} КиБ")
    return path


def result(summary, data, assets=None):
    return {"summary": summary, "data": data, "assets": assets or [], "findings": []}


def parse_wifi_scan(text):
    networks, current = [], None
    for raw in text.splitlines():
        line = raw.strip()
        match = re.match(r"BSS ([0-9a-fA-F:]{17})(?:\(|\s|$)", line)
        if match:
            current = {"bssid": match[1].upper(), "ssid": "", "security": []}
            networks.append(current)
        elif current is not None:
            if line.startswith('SSID:'):
                current['ssid'] = line[5:].strip()
            elif line.startswith('freq:'):
                try:
                    current['frequency_mhz'] = int(line.split(':', 1)[1])
                except ValueError:
                    pass
            elif line.startswith('signal:'):
                try:
                    current['signal_dbm'] = float(line.split()[1])
                except (ValueError, IndexError):
                    pass
            elif line.startswith('RSN:'):
                current['security'].append('RSN')
            elif line.startswith('WPA:'):
                current['security'].append('WPA')
            elif 'Authentication suites:' in line:
                current['authentication'] = line.split(':', 1)[1].strip()
            elif line.startswith('capability:'):
                current['privacy'] = 'Privacy' in line
    return networks


def nmcli_fields(line):
    """Split nmcli terse rows, preserving escaped colons and backslashes."""
    values, current, escaped = [], [], False
    for char in line:
        if escaped:
            current.append(char)
            escaped = False
        elif char == '\\':
            escaped = True
        elif char == ':':
            values.append(''.join(current))
            current = []
        else:
            current.append(char)
    if escaped:
        raise ValueError('Незавершённая escape-последовательность nmcli')
    values.append(''.join(current))
    return values


def parse_nmcli_scan(text):
    networks = []
    for line in text.splitlines():
        if not line:
            continue
        values = nmcli_fields(line)
        if len(values) != 7 or not re.fullmatch(r'[0-9a-fA-F:]{17}', values[0]):
            raise ValueError('Неожиданный формат результата nmcli Wi-Fi')
        bssid, ssid, channel, frequency, rate, signal, security = values
        networks.append({'bssid': bssid.upper(), 'ssid': ssid,
                         'channel': integer(channel, 1, 233, 'Wi-Fi канал'),
                         'frequency_mhz': integer(frequency.split()[0], 1, 100000, 'Wi-Fi частота'),
                         'rate': rate, 'signal_percent': integer(signal, 0, 100, 'Уровень Wi-Fi'),
                         'security': security.split() if security != '--' else [],
                         'source': 'NetworkManager'})
    return networks


def wifi_inventory(ctx, p):
    inventory = {}
    for name, argv in [('interfaces', ['iw', 'dev']), ('capabilities', ['iw', 'list']),
                       ('regulatory', ['iw', 'reg', 'get'])]:
        ctx.check_cancel()
        inventory[name] = ctx.run(argv, timeout=15, output_name=f'wifi-{name}.txt').stdout
    ctx.save_json('wifi-inventory.json', inventory)
    return result('Интерфейсы, режимы и регуляторные ограничения Wi-Fi', inventory)


def wifi_scan(ctx, p):
    interface = iface(p['interface'])
    method = p.get('method', 'NetworkManager')
    if method == 'NetworkManager':
        raw = ctx.run(['nmcli', '--terse', '--escape', 'yes', '--colors', 'no', '--wait', '30',
                       '--fields', 'BSSID,SSID,CHAN,FREQ,RATE,SIGNAL,SECURITY',
                       'device', 'wifi', 'list', 'ifname', interface, '--rescan', 'yes'],
                      timeout=35, output_name='wifi-scan.txt').stdout
        networks = parse_nmcli_scan(raw)
    elif method == 'iw':
        raw = ctx.run(['iw', 'dev', interface, 'scan'], timeout=35, output_name='wifi-scan.txt').stdout
        networks = parse_wifi_scan(raw)
    else:
        raise ValueError('Выберите NetworkManager или iw')
    ctx.save_json('wifi-networks.json', networks)
    return result(f'Найдено Wi-Fi BSS: {len(networks)}', {'networks': networks},
                  [{'id': n['bssid'], 'type': 'wifi', **n} for n in networks])


def wifi_capture(ctx, p):
    interface = iface(p['interface'])
    seconds = integer(p.get('seconds', 20), 1, 120, 'Длительность')
    info = ctx.run(['iw', 'dev', interface, 'info'], timeout=10).stdout
    if not re.search(r'^\s*type\s+monitor\s*$', info, re.M):
        raise ValueError('Выберите уже настроенный monitor-интерфейс; Axiora не меняет режим Wi-Fi автоматически')
    destination = ctx.path('wifi-monitor.pcapng')
    ctx.run(['dumpcap', '-i', interface, '-a', f'duration:{seconds}', '-a', 'filesize:32768',
             '-c', '100000', '-w', str(destination)], timeout=seconds + 15)
    return result('Запись кадров 802.11 завершена', {'interface': interface, 'capture': destination.name})


def parse_bluetooth(text):
    text = re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', text)
    devices = {}
    for match in re.finditer(r'\bDevice ([0-9A-Fa-f:]{17})\s+([^\r\n]*)', text):
        address, name = match[1].upper(), match[2].strip()
        device = devices.setdefault(address, {'address': address})
        if name.startswith('RSSI:'):
            device['rssi_raw'] = name[5:].strip()
        elif not re.match(r'\w+(?:\s+\w+)?:', name):
            device['name'] = name
    return list(devices.values())


def bluetooth_inventory(ctx, p):
    seconds = integer(p.get('seconds', 15), 1, 60, 'Длительность')
    controller = ctx.run(['bluetoothctl', 'show'], timeout=10, output_name='bluetooth-controller.txt').stdout
    raw = ctx.run(['bluetoothctl', '--timeout', str(seconds), 'scan', 'on'],
                  timeout=seconds + 10, output_name='bluetooth-scan.txt').stdout
    known = ctx.run(['bluetoothctl', 'devices'], timeout=10, output_name='bluetooth-devices.txt').stdout
    devices = parse_bluetooth(raw + '\n' + known)
    data = {'controller': controller, 'devices': devices,
            'note': 'Список включает кэш BlueZ; наличие записи не доказывает присутствие устройства сейчас.'}
    ctx.save_json('bluetooth-inventory.json', data)
    return result(f'Записей Bluetooth: {len(devices)}', data)


def lldp_inventory(ctx, p):
    raw = ctx.run(['lldpcli', '-f', 'json', 'show', 'neighbors', 'details'],
                  timeout=15, output_name='lldp.json').stdout
    data = json.loads(raw)
    return result('LLDP-соседи локальных интерфейсов', data)


def snmp_quoted(value):
    value = str(value)
    if not value or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError('SNMP: пустые значения и управляющие символы запрещены')
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'


def snmp_inventory(ctx, p):
    target = hostname(p['target'])
    port = integer(p.get('port', 161), 1, 65535, 'Порт')
    auth = p.get('auth_protocol', 'SHA')
    if auth not in ('SHA', 'SHA-256', 'SHA-512'):
        raise ValueError('SNMP: выберите SHA, SHA-256 или SHA-512')
    username = str(p['username'])
    if not re.fullmatch(r'[A-Za-z0-9_.@-]{1,64}', username):
        raise ValueError('Некорректное имя SNMPv3')
    for key in ('auth_password', 'privacy_password'):
        if len(str(p[key])) < 8:
            raise ValueError('SNMPv3: пароль не короче 8 символов')
    lines = ['defVersion 3', 'defSecurityLevel authPriv', 'defSecurityName ' + username,
             'defAuthType ' + auth, 'defPrivType AES',
             'defAuthPassphrase ' + snmp_quoted(p['auth_password']),
             'defPrivPassphrase ' + snmp_quoted(p['privacy_password'])]
    endpoint = f'udp6:[{target}]:{port}' if ':' in target else f'udp:{target}:{port}'
    outputs = {}
    # Net-SNMP configuration is outside the job directory, with no passwords in argv.
    with tempfile.TemporaryDirectory(prefix='axiora-snmp-') as config_dir:
        config = Path(config_dir) / 'snmp.conf'
        fd = os.open(config, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            stream.write('\n'.join(lines) + '\n')
        for name, oid in [('system', '.1.3.6.1.2.1.1'), ('interfaces', '.1.3.6.1.2.1.2'),
                          ('interface_details', '.1.3.6.1.2.1.31.1.1'), ('vlans', '.1.3.6.1.2.1.17.7.1.4.3')]:
            ctx.check_cancel()
            outputs[name] = ctx.run(['snmpbulkwalk', '-v3', '-On', '-t', '2', '-r', '1', '-Cr10', endpoint, oid],
                                    timeout=35, output_name=f'snmp-{name}.txt',
                                    env={'SNMPCONFPATH': config_dir}).stdout
    ctx.save_json('snmp-inventory.json', {'target': target, 'tables': outputs})
    return result('SNMPv3 authPriv: сведения об устройстве, интерфейсах и VLAN',
                  {'target': target, 'tables': outputs}, [{'id': target, 'type': 'network-device'}])


SSH_COMMANDS = {
    'cisco_ios': {'inventory': ('show version', 'show interfaces', 'show vlan brief', 'show lldp neighbors detail'),
                  'backup': ('show running-config',)},
    'cisco_nxos': {'inventory': ('show version', 'show interface', 'show vlan brief', 'show lldp neighbors detail'),
                   'backup': ('show running-config',)},
    'arista_eos': {'inventory': ('show version', 'show interfaces', 'show vlan', 'show lldp neighbors detail'),
                   'backup': ('show running-config',)},
    'juniper_junos': {'inventory': ('show version', 'show interfaces terse', 'show vlans', 'show lldp neighbors detail'),
                      'backup': ('show configuration | display set',)},
    'hp_procurve': {'inventory': ('show version', 'show interfaces brief', 'show vlans', 'show lldp info remote-device'),
                    'backup': ('show running-config',)},
}


def ssh_device(ctx, p):
    from netmiko import ConnectHandler
    target = hostname(p['target'])
    platform = p.get('platform', 'cisco_ios')
    action = p.get('action', 'inventory')
    if platform not in SSH_COMMANDS or action not in ('inventory', 'backup'):
        raise ValueError('Выберите поддерживаемую платформу и действие')
    key_file = str(input_file(p['key_file'], 65536)) if p.get('key_file') else None
    ctx.check_cancel()
    connection = ConnectHandler(device_type=platform, host=target,
                                port=integer(p.get('port', 22), 1, 65535, 'Порт'),
                                username=str(p['username']), password=p.get('password') or '',
                                key_file=key_file, use_keys=True, allow_agent=True,
                                ssh_strict=True, system_host_keys=True,
                                conn_timeout=10, auth_timeout=10, banner_timeout=10,
                                blocking_timeout=10, read_timeout_override=20,
                                fast_cli=False)
    outputs = {}
    try:
        for command in SSH_COMMANDS[platform][action]:
            ctx.check_cancel()
            output = connection.send_command(command, read_timeout=20)
            if len(output.encode('utf-8')) > 2 * 1024 * 1024:
                raise ValueError('Ответ устройства превышает 2 МиБ')
            outputs[command] = output
        if action == 'backup':
            path = ctx.path('running-config.txt')
            path.write_text(next(iter(outputs.values())) + '\n', encoding='utf-8')
            path.chmod(0o600)
        ctx.save_json('ssh-device.json', {'target': target, 'platform': platform, 'outputs': outputs})
    finally:
        connection.disconnect()
    return result('Конфигурация сохранена' if action == 'backup' else 'Диагностика сетевого устройства завершена',
                  {'target': target, 'platform': platform, 'outputs': outputs},
                  [{'id': target, 'type': 'network-device', 'platform': platform}])


def config_diff(ctx, p):
    before = input_file(p['before'], 2 * 1024 * 1024).read_text(encoding='utf-8')
    after = input_file(p['after'], 2 * 1024 * 1024).read_text(encoding='utf-8')
    lines = list(difflib.unified_diff(before.splitlines(), after.splitlines(),
                                     fromfile='before', tofile='after', lineterm=''))
    ctx.path('configuration.diff').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    return result('Конфигурации совпадают' if not lines else f'Строк в diff: {len(lines)}',
                  {'changed': bool(lines), 'diff': lines})


def uart_session(ctx, p):
    import serial
    device = str(p.get('device', '/dev/ttyUSB0'))
    path = Path(device)
    if not device.startswith('/dev/') or '..' in path.parts or not stat.S_ISCHR(path.stat().st_mode):
        raise ValueError('UART: выберите символьное устройство /dev/…')
    seconds = integer(p.get('seconds', 10), 1, 120, 'Длительность')
    baud = integer(p.get('baud', 115200), 300, 3000000, 'Скорость UART')
    tx = str(p.get('transmit', '')).encode('utf-8')
    if len(tx) > 4096:
        raise ValueError('UART: передача ограничена 4096 байтами')
    ending = p.get('line_ending', 'none')
    if ending not in ('none', 'LF', 'CR', 'CRLF'):
        raise ValueError('Некорректный конец строки')
    if tx:
        tx += {'none': b'', 'LF': b'\n', 'CR': b'\r', 'CRLF': b'\r\n'}[ending]
    started, data = time.monotonic(), bytearray()
    with serial.Serial(device, baudrate=baud, timeout=.2, write_timeout=2, exclusive=True) as port:
        if tx:
            ctx.check_cancel()
            port.write(tx)
        while time.monotonic() - started < seconds and len(data) < 2 * 1024 * 1024:
            ctx.check_cancel()
            data.extend(port.read(min(4096, 2 * 1024 * 1024 - len(data))))
    ctx.path('uart.bin').write_bytes(data)
    ctx.path('uart.txt').write_text(data.decode('utf-8', errors='replace'), encoding='utf-8')
    return result(f'UART: получено {len(data)} байт, отправлено {len(tx)} байт',
                  {'device': device, 'baud': baud, 'received': len(data), 'sent': len(tx),
                   'size_limit_reached': len(data) >= 2 * 1024 * 1024})


def decoder_spec(p):
    decoder = p.get('decoder', 'uart')
    if decoder not in ('uart', 'spi', 'i2c'):
        raise ValueError('Поддерживаются декодеры uart, spi, i2c')
    mappings = str(p.get('mapping', 'rx=0:baudrate=115200'))
    allowed = {'uart': {'rx', 'tx', 'baudrate', 'data_bits', 'parity', 'stop_bits'},
               'spi': {'clk', 'miso', 'mosi', 'cs', 'cpol', 'cpha', 'wordsize', 'bitorder'},
               'i2c': {'scl', 'sda'}}[decoder]
    seen = set()
    for item in mappings.split(':'):
        key, separator, value = item.partition('=')
        if not separator or key not in allowed or key in seen or not re.fullmatch(r'[A-Za-z0-9_.-]{1,32}', value):
            raise ValueError('Некорректные параметры декодера; используйте имя=значение через двоеточие')
        seen.add(key)
    return decoder + ':' + mappings


def logic_analyzer(ctx, p):
    action = p.get('action', 'decode')
    if action == 'inventory':
        text = ctx.run(['sigrok-cli', '--list-supported'], timeout=20, output_name='sigrok-supported.txt').stdout
        return result('Драйверы, форматы и декодеры sigrok', {'supported': text})
    if action not in ('capture', 'decode'):
        raise ValueError('Некорректное действие sigrok')
    if action == 'capture':
        driver = str(p.get('driver', 'fx2lafw'))
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}(?::conn=[A-Za-z0-9_./-]{1,100})?', driver):
            raise ValueError('Драйвер sigrok: имя или имя:conn=устройство')
        rate = integer(p.get('sample_rate', 1000000), 1000, 24000000, 'Частота дискретизации')
        samples = integer(p.get('samples', 1000000), 1, 2000000, 'Количество отсчётов')
        capture = ctx.path('logic.sr')
        ctx.run(['sigrok-cli', '--driver', driver, '--config', f'samplerate={rate}',
                 '--samples', str(samples), '--output-file', str(capture)], timeout=60)
        return result('Логические сигналы сохранены в logic.sr', {'samples': samples, 'sample_rate': rate})
    path = input_file(p['input'], 64 * 1024 * 1024)
    decoded = ctx.run(['sigrok-cli', '--input-file', str(path), '--protocol-decoders', decoder_spec(p)],
                      timeout=60, output_name='logic-decoded.txt').stdout
    return result('Декодирование логических сигналов завершено', {'decoded': decoded})


def json_lines(text):
    values = []
    for line in text.splitlines():
        try:
            value = json.loads(line)
        except (ValueError, TypeError):
            continue
        if isinstance(value, dict):
            values.append(value)
    return values


def sdr_receive(ctx, p):
    frequency = integer(p.get('frequency', 433920000), 100000, 6000000000, 'Частота, Гц')
    sample_rate = integer(p.get('sample_rate', 250000), 250000, 2400000, 'Частота дискретизации')
    argv = ['rtl_433', '-c', '0', '-f', str(frequency), '-s', str(sample_rate), '-F', 'json', '-M', 'protocol', '-M', 'level']
    action = p.get('action', 'receive')
    if action == 'decode':
        path = input_file(p['input'], 64 * 1024 * 1024)
        if path.suffix.lower() not in ('.cu8', '.cs16', '.cf32'):
            raise ValueError('SDR: входной файл должен иметь формат cu8/cs16/cf32')
        argv += ['-r', str(path)]
        timeout = 120
    elif action in ('receive', 'iq_capture'):
        seconds = integer(p.get('seconds', 15), 1, 120 if action == 'receive' else 30, 'Длительность')
        device = str(p.get('device', '0'))
        if not re.fullmatch(r'[0-9]{1,2}|:[A-Za-z0-9_-]{1,64}', device):
            raise ValueError('SDR: индекс USB 0–99 или :серийный_номер')
        argv += ['-d', device, '-T', str(seconds)]
        if action == 'iq_capture':
            if seconds * sample_rate * 2 > 32 * 1024 * 1024:
                raise ValueError('IQ-запись ограничена 32 МиБ: уменьшите длительность/частоту дискретизации')
            capture = ctx.path(f'iq_{frequency}Hz_{sample_rate}sps.cu8')
            argv += ['-w', str(capture)]
        timeout = seconds + 15
    else:
        raise ValueError('Неизвестное действие SDR')
    raw = ctx.run(argv, timeout=timeout, output_name='rtl433.jsonl').stdout
    decoded = json_lines(raw)
    ctx.save_json('radio-devices.json', decoded)
    return result(f'SDR: декодировано сообщений {len(decoded)}',
                  {'frequency_hz': frequency, 'messages': decoded,
                   'note': 'Диапазон и качество приёма зависят от SDR и антенны.'})


def load_card_dump(value):
    path = input_file(value, 65536)
    if path.suffix.lower() != '.json':
        data = path.read_bytes()
    else:
        raw = json.loads(path.read_text(encoding='utf-8'))
        if isinstance(raw, dict) and isinstance(raw.get('data'), str):
            data = bytes.fromhex(raw['data'])
        elif isinstance(raw, dict) and isinstance(raw.get('blocks'), dict):
            blocks = raw['blocks']
            try:
                indexes = sorted(int(i) for i in blocks)
            except (ValueError, TypeError):
                raise ValueError('Номера блоков должны быть целыми числами') from None
            if indexes != list(range(len(indexes))) or any(str(i) not in blocks for i in indexes):
                raise ValueError('JSON blocks: последовательные номера с нуля; частичные дампы не склеиваются')
            parts = [bytes.fromhex(blocks[str(i)]) for i in indexes]
            if any(len(block) != 16 for block in parts):
                raise ValueError('Каждый блок JSON должен содержать 16 байт HEX')
            data = b''.join(parts)
        else:
            raise ValueError('JSON дампа: {"data":"HEX"} или {"blocks":{"0":"32 HEX",…}}')
    if not data or len(data) > 65536:
        raise ValueError('Пустой или слишком большой дамп')
    return data


def rfid_dump(ctx, p):
    before = load_card_dump(p['input'])
    blocks = [before[i:i + 16].hex().upper() for i in range(0, len(before), 16)]
    data = {'size': len(before), 'sha256': hashlib.sha256(before).hexdigest(), 'blocks': blocks}
    if p.get('compare'):
        after = load_card_dump(p['compare'])
        changes = [{'offset': i, 'before': before[i] if i < len(before) else None,
                    'after': after[i] if i < len(after) else None}
                   for i in range(max(len(before), len(after)))
                   if (before[i] if i < len(before) else None) != (after[i] if i < len(after) else None)]
        data.update(compare_size=len(after), compare_sha256=hashlib.sha256(after).hexdigest(), changes=changes)
    ctx.save_json('card-dump.json', {'format': 'axiora-card-dump-v1', 'data': before.hex().upper(), **data})
    return result(f'Дамп: {len(before)} байт' + (f", изменено позиций: {len(data['changes'])}" if 'changes' in data else ''), data)


def pulse_import(ctx, p):
    raw = json.loads(input_file(p['input'], 4 * 1024 * 1024).read_text(encoding='utf-8'))
    if not isinstance(raw, dict) or raw.get('format') != 'axiora-ook-v1' or not isinstance(raw.get('frames'), list):
        raise ValueError('Нужен JSON axiora-ook-v1 с массивом frames')
    if len(raw['frames']) > 4096:
        raise ValueError('Не более 4096 кадров за импорт')
    frames = []
    for source in raw['frames']:
        ctx.check_cancel()
        if not isinstance(source, dict) or not isinstance(source.get('pulses'), list) or len(source['pulses']) > 1024:
            raise ValueError('Некорректный кадр или слишком много импульсов')
        pulses = source['pulses']
        for pulse in pulses:
            if not isinstance(pulse, list) or len(pulse) != 2 or type(pulse[0]) is not int or pulse[0] not in (0, 1):
                raise ValueError('Импульс: [уровень 0/1, длительность в мкс]')
            if type(pulse[1]) not in (int, float) or not math.isfinite(pulse[1]) or not 0 < pulse[1] <= 10000000:
                raise ValueError('Некорректная длительность импульса')
        decoded = None
        # Decode independently: importing adjacent frames cannot assert live timing/repetition.
        if len(pulses) == 48:
            decoded = decode_ook(pulses)
        else:
            stream = OOKFrames()
            for level, duration in pulses:
                frame = stream.feed(level, duration, 0)
                if frame and frame['decoded']:
                    decoded = frame['decoded']
        if decoded:
            decoded['confirmed'] = False
            decoded['note'] = 'Офлайн-кандидат; временная последовательность и повторения не подтверждены'
        frames.append({'pulses': pulses, 'decoded': decoded})
    ctx.save_json('pulses-decoded.json', {'format': 'axiora-ook-v1', 'frames': frames})
    return result(f"Импортировано кадров: {len(frames)}; PWM24-кандидатов: {sum(bool(f['decoded']) for f in frames)}",
                  {'frames': frames})


def radio_profile(ctx, p):
    name = str(p.get('name', 'Профиль')).strip()
    if not name or len(name) > 80 or any(ord(c) < 32 for c in name):
        raise ValueError('Имя профиля: 1–80 печатных символов')
    if p.get('input'):
        source = json.loads(input_file(p['input'], 65536).read_text(encoding='utf-8'))
        if not isinstance(source, dict) or source.get('schema') != 'axiora.radio-profile.v1':
            raise ValueError('Нужен axiora.radio-profile.v1')
        module, settings = source.get('module'), source.get('settings')
    else:
        module = p.get('module', 'cc1101')
        if module == 'cc1101':
            settings = {key: float(p.get(key, default)) for key, default in
                        [('frequency', 433.92), ('bitrate', 38.4), ('bandwidth', 101.6), ('deviation', 20.6)]}
            settings.update(mode=p.get('mode', 'packet'), modulation=p.get('modulation', '2-FSK'), sync=p.get('sync', 'D391'))
        elif module == 'nrf24':
            settings = {'channel': integer(p.get('channel', 76), 0, 125, 'Канал'), 'address': p.get('address', 'E7E7E7E7E7')}
        else:
            raise ValueError('Профиль поддерживает cc1101 или nrf24')
    if module not in ('cc1101', 'nrf24') or not isinstance(settings, dict):
        raise ValueError('Некорректный модуль или настройки')
    allowed = {'cc1101': {'frequency', 'mode', 'modulation', 'bitrate', 'bandwidth', 'deviation', 'sync'},
               'nrf24': {'channel', 'address'}}[module]
    if set(settings) - allowed:
        raise ValueError('Профиль содержит посторонние аппаратные настройки')
    validated = validate_config({module: copy.deepcopy(settings)})[module]
    profile = {'schema': 'axiora.radio-profile.v1', 'name': name, 'module': module,
               'settings': {k: v for k, v in validated.items() if k in allowed}}
    ctx.save_json('radio-profile.json', profile)
    return result('Профиль проверен и сохранён; примените его отдельно в настройках оборудования', profile)


CAPABILITIES = [
    {'hardware': 'Raspberry Pi 5 Ethernet', 'supported': 'Gigabit Ethernet; IP-диагностика, PCAP, сканирование через ОС', 'limits': 'Для чужого трафика нужен SPAN/TAP; скорость зависит от всей цепочки'},
    {'hardware': 'W5500', 'supported': 'Ethernet 10/100 через драйвер ядра, MACRAW захват', 'limits': 'Общая SPI-шина ограничивает пропускную способность; не заменяет Gigabit интерфейс'},
    {'hardware': 'MFRC522', 'supported': 'ISO14443A UID; Classic Mini/1K/4K блоки с известным ключом', 'limits': 'Не эмулирует карты; DESFire/Plus/NTAG память этим драйвером не реализована'},
    {'hardware': 'RDM6300', 'supported': 'Приём идентификаторов совместимых 125 кГц меток', 'limits': 'Только чтение; UART RX GPIO13, не GPIO4'},
    {'hardware': 'CC1101', 'supported': 'Пакеты 2-FSK/GFSK/OOK; импульсы OOK и PWM24-кандидаты', 'limits': 'Диапазоны 300–348/387–464/779–928 МГц; антенна/плата должны соответствовать. Не SDR/IQ'},
    {'hardware': 'nRF24L01+PA+LNA', 'supported': 'Собственные пакеты 2,4 ГГц, фиксированный профиль драйвера', 'limits': 'Не Wi-Fi, не Bluetooth, не IEEE 802.15.4'},
    {'hardware': 'NEO-6M / XPT2046', 'supported': 'GPS NMEA / сенсор через libinput', 'limits': 'GPS требует фиксации спутников; XPT2046 не контроллер дисплея'},
    {'hardware': 'Wi-Fi адаптер', 'supported': 'iw scan и monitor-PCAP при поддержке драйвером', 'limits': 'Monitor-интерфейс настраивается отдельно; захват поддерживаемых диапазонов'},
    {'hardware': 'Bluetooth адаптер', 'supported': 'BlueZ-инвентаризация', 'limits': 'Не универсальный пассивный BLE-сниффер; для этого нужен отдельный сниффер'},
    {'hardware': 'SDR RTL-SDR', 'supported': 'rtl_433 приём, офлайн IQ-декодирование и ограниченная IQ-запись', 'limits': 'Диапазон определяется тюнером и антенной; передача не реализована'},
    {'hardware': 'USB логический анализатор', 'supported': 'sigrok захват, UART/SPI/I2C декодирование', 'limits': 'Нужен поддерживаемый драйвер и совместимые уровни напряжения'},
    {'hardware': 'NFC эмулятор / IEEE 802.15.4 адаптер', 'supported': 'Требует дополнительного оборудования', 'limits': 'Драйверы эмуляции и Zigbee/Thread в Axiora не реализованы'},
]


def capability_catalog(ctx, p):
    ctx.save_json('hardware-capabilities.json', CAPABILITIES)
    return result('Возможности и ограничения аппаратных модулей', {'hardware': CAPABILITIES})


F = Field
TOOLS = [
    Tool('wifi.inventory', 'Wi-Fi: интерфейсы и возможности', 'Wi-Fi / Bluetooth', 'Режимы драйвера и регуляторные ограничения.', (), ('iw',), wifi_inventory),
    Tool('wifi.scan', 'Wi-Fi: точки доступа', 'Wi-Fi / Bluetooth', 'NetworkManager использует разрешения сеанса Xfce. Подробный iw требует CAP_NET_ADMIN. Режим интерфейса не меняется.',
         (F('interface', 'Интерфейс', 'wlan0', required=True),
          F('method', 'Метод', 'NetworkManager', 'choice', ('NetworkManager', 'iw'))), ('nmcli|iw',), wifi_scan),
    Tool('wifi.capture', 'Wi-Fi: запись 802.11', 'Wi-Fi / Bluetooth', 'Только уже настроенный monitor-интерфейс. PCAPNG до 32 МиБ.',
         (F('interface', 'Monitor-интерфейс', 'wlan1mon', required=True), F('seconds', 'Секунды', '20')), ('iw', 'dumpcap'), wifi_capture, timeout=150),
    Tool('bluetooth.inventory', 'Bluetooth: устройства', 'Wi-Fi / Bluetooth', 'Ограниченный scan BlueZ без сопряжения; также показывает кэш.',
         (F('seconds', 'Секунды', '15'),), ('bluetoothctl',), bluetooth_inventory),
    Tool('device.lldp', 'LLDP-соседи', 'Сетевое оборудование', 'Чтение сведений локального lldpd.', (), ('lldpcli',), lldp_inventory),
    Tool('device.snmp', 'SNMPv3: инвентаризация', 'Сетевое оборудование', 'authPriv/AES: system, IF-MIB, ifXTable, VLAN. Секреты только во временном 0600 конфиге.',
         (F('target', 'IP/DNS устройства', required=True), F('port', 'Порт', '161'), F('username', 'SNMPv3 пользователь', required=True),
          F('auth_protocol', 'Аутентификация', 'SHA', 'choice', ('SHA', 'SHA-256', 'SHA-512')),
          F('auth_password', 'Пароль аутентификации', required=True, secret=True),
          F('privacy_password', 'Пароль шифрования', required=True, secret=True)), ('snmpbulkwalk',), snmp_inventory, ('target',), 180),
    Tool('device.ssh', 'SSH: диагностика / конфигурация', 'Сетевое оборудование', 'Netmiko, фиксированные show-команды; проверка known_hosts обязательна.',
         (F('target', 'IP/DNS устройства', required=True), F('port', 'Порт', '22'), F('username', 'Пользователь', required=True),
          F('password', 'Пароль (или SSH agent/ключ)', secret=True), F('key_file', 'Файл приватного SSH-ключа', kind='file'),
          F('platform', 'Платформа', 'cisco_ios', 'choice', tuple(SSH_COMMANDS)),
          F('action', 'Действие', 'inventory', 'choice', ('inventory', 'backup'))), ('python:netmiko',), ssh_device, ('target',), 180),
    Tool('device.config_diff', 'Сравнение конфигураций', 'Сетевое оборудование', 'Локальный unified diff двух текстовых файлов.',
         (F('before', 'До', kind='file', required=True), F('after', 'После', kind='file', required=True)), (), config_diff),
    Tool('hardware.uart', 'UART: запись и передача текста', 'Радио / электроника', '8N1, до 2 МиБ. Непустой текст передаётся один раз при запуске. Не открывайте порт GPS/RDM одновременно с аппаратным сервисом.',
         (F('device', 'Устройство', '/dev/ttyUSB0', required=True), F('baud', 'Бод', '115200'), F('seconds', 'Секунды', '10'),
          F('transmit', 'Передать текст (пусто = только чтение)'), F('line_ending', 'Конец строки', 'none', 'choice', ('none', 'LF', 'CR', 'CRLF'))),
         ('python:serial',), uart_session, timeout=150),
    Tool('hardware.logic', 'Логический анализатор', 'Радио / электроника', 'sigrok: список возможностей, захват в SR, декодирование UART/SPI/I2C.',
         (F('action', 'Действие', 'decode', 'choice', ('inventory', 'capture', 'decode')), F('input', 'Файл SR/VCD', kind='file'),
          F('driver', 'Драйвер для захвата', 'fx2lafw'), F('sample_rate', 'Отсчётов/с', '1000000'), F('samples', 'Количество отсчётов', '1000000'),
          F('decoder', 'Декодер', 'uart', 'choice', ('uart', 'spi', 'i2c')), F('mapping', 'Каналы/параметры через :', 'rx=0:baudrate=115200')),
         ('sigrok-cli',), logic_analyzer),
    Tool('radio.sdr', 'SDR: rtl_433 / IQ', 'Радио / электроника', 'RTL-SDR приём, офлайн IQ-декодирование, IQ-запись до 32 МиБ. Без передачи.',
         (F('action', 'Действие', 'receive', 'choice', ('receive', 'decode', 'iq_capture')), F('input', 'IQ файл', kind='file'),
          F('device', 'USB индекс / :serial', '0'), F('frequency', 'Частота, Гц', '433920000'), F('sample_rate', 'Отсчётов/с', '250000'), F('seconds', 'Секунды', '15')),
         ('rtl_433',), sdr_receive, timeout=150),
    Tool('rfid.dump', 'RFID: импорт / сравнение дампов', 'Радио / электроника', 'BIN или JSON data HEX / blocks. Только офлайн, без записи карты.',
         (F('input', 'Дамп', kind='file', required=True), F('compare', 'Сравнить с дампом', kind='file')), (), rfid_dump),
    Tool('radio.pulses', 'OOK: импорт и декодирование', 'Радио / электроника', 'Чтение axiora-ook-v1; повторная проверка PWM24 без утверждения о конкретном чипе.',
         (F('input', 'Файл импульсов JSON', kind='file', required=True),), (), pulse_import),
    Tool('radio.profile', 'Радио: библиотека профилей', 'Радио / электроника', 'Создать или импортировать проверенный именованный профиль. Активное оборудование не перенастраивается.',
         (F('name', 'Название', 'Профиль'), F('input', 'Импорт профиля JSON (необязательно)', kind='file'),
          F('module', 'Модуль', 'cc1101', 'choice', ('cc1101', 'nrf24')), F('frequency', 'CC1101 МГц', '433.92'),
          F('mode', 'CC1101 режим', 'packet', 'choice', ('packet', 'ook_raw')), F('modulation', 'Модуляция', '2-FSK', 'choice', ('2-FSK', 'GFSK', 'OOK')),
          F('bitrate', 'кбит/с', '38.4'), F('bandwidth', 'Полоса кГц', '101.6'), F('deviation', 'Девиация кГц', '20.6'), F('sync', 'Sync HEX', 'D391'),
          F('channel', 'nRF канал', '76'), F('address', 'nRF адрес HEX', 'E7E7E7E7E7')), (), radio_profile),
    Tool('hardware.catalog', 'Совместимость оборудования', 'Радио / электроника', 'Точная матрица реализованных возможностей и аппаратных ограничений.', (), (), capability_catalog),
]
