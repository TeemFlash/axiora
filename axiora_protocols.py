"""Explicit protocol support. Unknown data is never labelled as a known device."""
import math
import statistics

CC_MODULATIONS = {'2-FSK': 0, 'GFSK': 1, 'OOK': 3}
CC_DEFAULTS = {'mode': 'packet', 'modulation': '2-FSK', 'bitrate': 38.4,
               'bandwidth': 101.6, 'deviation': 20.6, 'sync': 'D391'}
CLASSIC_TYPES = {0x09: ('Mini', 20), 0x08: ('1K', 64), 0x18: ('4K', 256)}


def classic_block(block, sak, writing=False):
    if sak not in CLASSIC_TYPES:
        raise ValueError('Нужна карта MIFARE Classic Mini/1K/4K; тип карты не поддерживается')
    if type(block) is not int or not 0 <= block < CLASSIC_TYPES[sak][1]:
        raise ValueError(f'Блок вне диапазона карты Classic {CLASSIC_TYPES[sak][0]}')
    trailer = block % 4 == 3 if block < 128 else (block - 128) % 16 == 15
    if writing and (block == 0 or trailer):
        raise ValueError('Запись блока производителя и sector trailer отключена; выберите блок данных')
    return block // 4 if block < 128 else 32 + (block - 128) // 16


def validate_cc(config):
    cc = dict(CC_DEFAULTS, **{k: v for k, v in config.items() if k in CC_DEFAULTS})
    if cc['mode'] not in ('packet', 'ook_raw') or cc['modulation'] not in CC_MODULATIONS:
        raise ValueError('CC1101: режим packet/ook_raw, модуляция 2-FSK/GFSK/OOK')
    for key, low, high in (('bitrate', 0.6, 100), ('bandwidth', 58, 812), ('deviation', 1.6, 100)):
        number = cc[key]
        if type(number) not in (float, int) or not math.isfinite(number) or not low <= number <= high:
            raise ValueError(f'CC1101 {key}: число от {low} до {high}')
    try:
        if len(bytes.fromhex(cc['sync'])) != 2:
            raise ValueError()
    except (ValueError, TypeError):
        raise ValueError('Sync CC1101: ровно 2 байта HEX') from None
    if cc['mode'] == 'ook_raw':
        cc['modulation'] = 'OOK'
    return cc


def cc_registers(config):
    """Quantise requested RF values to CC1101's 26 MHz register equations."""
    cc = validate_cc(config)
    rate = cc['bitrate'] * 1000
    rate_options = [(abs(26e6 * (256 + m) * 2 ** e / 2 ** 28 - rate), e, m)
                    for e in range(16) for m in range(256)]
    _, rate_e, rate_m = min(rate_options)
    bw = cc['bandwidth'] * 1000
    _, bw_e, bw_m = min((abs(26e6 / (8 * (4 + m) * 2 ** e) - bw), e, m)
                       for e in range(4) for m in range(4))
    dev = cc['deviation'] * 1000
    _, dev_e, dev_m = min((abs(26e6 * (8 + m) * 2 ** e / 2 ** 17 - dev), e, m)
                         for e in range(8) for m in range(8))
    raw = cc['mode'] == 'ook_raw'
    modulation = 3 if raw else CC_MODULATIONS[cc['modulation']]
    sync = bytes.fromhex(cc['sync'])
    return {0x04: sync[0], 0x05: sync[1], 0x10: bw_e << 6 | bw_m << 4 | rate_e,
            0x11: rate_m, 0x12: modulation << 4 | (0 if raw else 3),
            0x15: dev_e << 4 | dev_m,
            0x02: 0x0D if raw else 0x06, 0x08: 0x32 if raw else 0x05,
            0x07: 0 if raw else 0x0C, 0x17: 0x0C if raw else 0}


def decode_ook(pulses):
    """24-bit PWM family: high/low = T/3T or 3T/T. Chip cannot be inferred."""
    if len(pulses) != 48 or any(level != (1 if i % 2 == 0 else 0)
                               for i, (level, _) in enumerate(pulses)):
        return None
    unit = statistics.median(min(pulses[i][1], pulses[i + 1][1]) for i in range(0, 48, 2))
    if not 100 <= unit <= 1000:
        return None
    bits = ''
    for i in range(0, 48, 2):
        high, low = pulses[i][1] / unit, pulses[i + 1][1] / unit
        if abs(high - 1) <= .35 and abs(low - 3) <= .75:
            bits += '0'
        elif abs(high - 3) <= .75 and abs(low - 1) <= .35:
            bits += '1'
        else:
            return None
    pairs = [bits[i:i + 2] for i in range(0, 24, 2)]
    tri = ''.join({'00': '0', '11': '1', '01': 'F'}.get(pair, '?') for pair in pairs)
    return {'format': 'PWM24 (совместим с EV1527/PT2262)', 'bits': bits,
            'hex': f'{int(bits, 2):06X}', 'unit_us': round(unit, 1),
            'tristate': tri if '?' not in tri else None}


class OOKFrames:
    """Bounded streaming frame segmentation; need two matching frames for confirmation."""
    def __init__(self):
        self.pulses = []
        self.previous = None
        self.repeats = 0
        self.previous_ts = 0

    def feed(self, level, duration, now):
        if duration <= 0:
            return None
        if level == 0 and duration >= 2500 and (not self.pulses or
                (self.pulses[-1][0] == 1 and duration >= 10 * self.pulses[-1][1])):
            pulses, self.pulses = self.pulses, []
            if not pulses:
                return None
            # A normal frame ends with a short high sync pulse then a long low gap.
            body = pulses[:-1] if len(pulses) == 49 else pulses
            decoded = decode_ook(body)
            if decoded:
                unit = decoded['unit_us']
                if not 20 <= duration / unit <= 45 or (len(pulses) == 49 and
                        not .65 <= pulses[-1][1] / unit <= 1.35):
                    decoded = None
            if decoded:
                key = decoded['bits']
                self.repeats = self.repeats + 1 if key == self.previous and now - self.previous_ts < 2 else 1
                self.previous, self.previous_ts = key, now
                decoded['repeats'] = self.repeats
                decoded['confirmed'] = self.repeats >= 2
            else:
                self.previous, self.repeats = None, 0
            return {'pulses': pulses + [[0, round(duration, 1)]], 'decoded': decoded}
        self.pulses.append([int(level), round(duration, 1)])
        if len(self.pulses) >= 512:
            pulses, self.pulses = self.pulses, []
            self.previous, self.repeats = None, 0
            return {'pulses': pulses, 'decoded': None, 'truncated': True}
        return None
