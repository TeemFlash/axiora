#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Axiora — портативная платформа мониторинга киберобстановки.

Интерфейс рассчитан на сенсорный дисплей 5" (по умолчанию 800x480, ~187 PPI):
все элементы управления не меньше 48-56 px (7-8 мм), крупный шрифт, без наведения.

Запуск:   python3 axiora.py [--fullscreen] [--size=1024x600]
Логин:    admin / admin
Данные:   ~/.axiora/live/ (реальные данные), ~/.axiora/demo/ (--demo)
"""

import argparse
import base64
import queue
import uuid
import datetime
import glob
import json
import os
import random
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# CLI diagnostics work without a graphical session or PyGObject.
if __name__ == "__main__" and "--diagnose" in sys.argv:
    from axiora_hardware import diagnostics
    print(json.dumps(diagnostics(), ensure_ascii=False, indent=2))
    raise SystemExit(0)

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk, Gdk, GLib, Pango  # noqa: E402

from axiora_auth import Credentials
from axiora_hardware import HardwareService, load_config
from axiora_pages import HardwarePages
from axiora_workbench import Workbench
from axiora_workbench_pages import WorkbenchPages

APP_NAME = "Axiora"
VALID_LOGIN = "admin"

APP_DIR = os.environ.get("AXIORA_HOME", os.path.join(os.path.expanduser("~"), ".axiora"))
REPORT_DIR = os.path.join(APP_DIR, "reports")

SCREEN_W, SCREEN_H = 800, 480   # 5" сенсорный дисплей
CHAIN_GAP = 120                 # секунд между событиями одной цепочки

# ────────────────────────────────────────────────────────────── цвета
BLUE = "#1479c4"
BLUE_DARK = "#0f63a0"
INK = "#17324a"
MUTED = "#5a6b80"
TINT = "#f5f9fc"
LINE = "#d7e3ee"
GREEN = "#25794a"
AMBER = "#9c6b00"
ORANGE = "#b85c1d"
RED = "#d93636"
GREY = "#5a6b80"

COLOR_MAP = {
    "LOW": GREEN, "MEDIUM": AMBER, "HIGH": ORANGE, "CRITICAL": RED,
    "Онлайн": GREEN, "Норма": GREEN, "Активен": GREEN, "Известный": GREEN, "Включено": GREEN,
    "Демо": BLUE, "Новое": BLUE, "Повтор": BLUE, "В работе": AMBER, "Новый": AMBER,
    "Закрыто": GREY, "Выключено": GREY, "INFO": GREY, "WARN": AMBER, "ERROR": RED,
    "Не подключён": AMBER,
}

# ────────────────────────────────────────────────────────────── CSS (белый + голубой, Times New Roman)
CSS = b"""
* {
    font-family: "DejaVu Sans", "Liberation Sans", sans-serif;
    font-size: 16px;
}
window, .root, dialog { background-color: #ffffff; }
label { color: #17324a; background-color: transparent; }
.muted { color: #5a6b80; }
.small { font-size: 13px; color: #5a6b80; }
.logo { font-size: 36px; font-weight: bold; letter-spacing: 6px; color: #1479c4; }
.h1 { font-size: 20px; font-weight: bold; color: #0f63a0; }
.error { color: #d93636; }

entry {
    background-color: #ffffff; color: #17324a; border: 2px solid #d7e3ee; border-radius: 6px;
    padding: 0 12px; min-height: 48px;
}
spinbutton, spinbutton entry { color: #17324a; background-color: #ffffff; }
entry:focus { border-color: #1479c4; }

button {
    background-image: none; background-color: #f5f9fc; color: #2c4560;
    border: 1px solid #d7e3ee; border-radius: 6px; padding: 0 18px;
    min-height: 48px; min-width: 56px;
}
button:active { background-color: #e3eefa; }
button label { color: inherit; font-weight: bold; }
button.primary { background-color: #1479c4; border-color: #1479c4; color: #ffffff; min-height: 52px; }
button.primary label { color: #ffffff; }
button.primary:active { background-color: #0f63a0; }
button.primary:disabled { background-color: #8fbfe3; border-color: #8fbfe3; }
button.ghost { background-color: #ffffff; }
button:checked { background-color: #1479c4; border-color: #1479c4; color: #ffffff; }
button:checked label { color: #ffffff; }
button:disabled { opacity: 0.55; }

.topbar { background-color: #1479c4; padding: 0 12px; }
.topbar label { color: #ffffff; }
.topbar .brand { font-size: 22px; font-weight: bold; letter-spacing: 4px; }
.topbar button { background-color: #ffffff; color: #0f63a0; border: none; min-height: 40px; padding: 0 14px; }
.topbar button label { color: #0f63a0; }

.banner { background-color: #fdf3e7; border-bottom: 2px solid #b85c1d; padding: 4px 12px; }
.banner label { color: #b85c1d; font-weight: bold; }
.banner button { min-height: 40px; }

.nav { background-color: #f5f9fc; border-right: 1px solid #d7e3ee; }
.nav row { background-color: #f5f9fc; min-height: 56px; padding: 0 12px; border-left: 4px solid transparent; }
.nav row label { color: #17324a; font-weight: bold; }
.nav row:selected { background-color: #e3eefa; border-left: 4px solid #1479c4; }
.nav row:selected label { color: #1479c4; }
.badge { background-color: #d93636; border-radius: 10px; padding: 0 7px; }
.badge label, label.badge { color: #ffffff; font-size: 13px; font-weight: bold; }

.statusbar { background-color: #f5f9fc; border-top: 1px solid #d7e3ee; padding: 3px 12px; }
.statusbar label { font-size: 13px; color: #5a6b80; }
.statusbar .toast { color: #1479c4; font-weight: bold; }

.card { background-color: #f5f9fc; border: 1px solid #d7e3ee; border-radius: 8px; padding: 10px 12px; }
.stat-value { font-size: 26px; font-weight: bold; color: #1479c4; }
.stat-title { font-size: 13px; color: #5a6b80; }
.kv-key { color: #5a6b80; }
.kv-val { color: #17324a; font-weight: bold; }
.big-number { font-size: 46px; font-weight: bold; }

.dlg { border: 2px solid #1479c4; background-color: #ffffff; }
.dlg-title { background-color: #1479c4; padding: 10px 14px; }
.dlg-title label { color: #ffffff; font-size: 18px; font-weight: bold; }

treeview { background-color: #ffffff; color: #17324a; }
treeview:selected { background-color: #d7e3ee; color: #17324a; }
treeview header button {
    background-image: none; background-color: #f5f9fc; color: #0f63a0; border: none;
    border-bottom: 2px solid #d7e3ee; border-radius: 0; min-height: 34px; padding: 0 8px;
}
treeview header button label { font-size: 14px; }

notebook { background-color: #ffffff; }
notebook > header { background-color: #ffffff; border-bottom: 2px solid #d7e3ee; }
notebook > header > tabs > tab {
    min-height: 44px; padding: 0 16px; background-color: transparent; border: none;
    border-bottom: 3px solid transparent;
}
notebook > header > tabs > tab label { color: #5a6b80; font-weight: bold; }
notebook > header > tabs > tab:checked { border-bottom: 3px solid #1479c4; }
notebook > header > tabs > tab:checked label { color: #1479c4; }
notebook > stack { background-color: #ffffff; }

progressbar trough { background-color: #f5f9fc; border: 1px solid #d7e3ee; min-height: 16px; border-radius: 8px; }
progressbar progress { background-color: #1479c4; background-image: none; min-height: 16px; border-radius: 8px; }
progressbar text { color: #17324a; font-size: 13px; }

switch { background-color: #d7e3ee; background-image: none; border: none; border-radius: 18px; min-width: 76px; min-height: 36px; }
switch:checked { background-color: #1479c4; }
switch slider { background-color: #ffffff; background-image: none; border: 1px solid #d7e3ee; border-radius: 16px; min-width: 32px; min-height: 32px; }

scale trough { background-color: #d7e3ee; min-height: 8px; border-radius: 4px; }
scale highlight { background-color: #1479c4; border-radius: 4px; }
scale slider { background-color: #ffffff; border: 2px solid #1479c4; background-image: none; min-width: 34px; min-height: 34px; border-radius: 17px; }

scrollbar { background-color: transparent; }
scrollbar slider { min-width: 12px; min-height: 12px; background-color: #a9c9e6; border-radius: 6px; border: none; }
"""

# ────────────────────────────────────────────────────────────── модель данных
SEV_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
SRC_W = {"NETWORK": 70, "IOT": 65, "RFID": 55, "RADIO": 45, "SYSTEM": 40}
SOURCES = ["NETWORK", "IOT", "RFID", "RADIO", "SYSTEM"]

NEW_DEV = "Новое устройство в сети"
NEW_DST = "Новое направление соединений"
TRAFFIC = "Рост объёма трафика"
AUTH = "Повторные ошибки аутентификации"
ANOMALY = "Сетевая аномалия"
REPEAT = "Повторяющиеся соединения"
PORT = "Необычный порт на устройстве"
NORMAL = "Штатная активность"
RFID_OK, RFID_UNK, RFID_REP = "Считывание RFID", "Неизвестный RFID-идентификатор", "Повторное считывание RFID"
SIG_NEW, SIG_REP = "Новый радиосигнал", "Повтор радиосигнала"
IFACE = "Смена состояния интерфейса"

# тип события -> (источник, вес аномальности, признак, описание)
TYPES = {
    NORMAL: ("NETWORK", 5, "", "Обычная активность устройства в пределах профиля."),
    NEW_DEV: ("NETWORK", 30, "NEW DEVICE", "Устройство впервые появилось в сети."),
    NEW_DST: ("NETWORK", 55, "NEW DESTINATION", "Обращение к адресу, которого нет в профиле устройства."),
    TRAFFIC: ("NETWORK", 60, "HIGH TRAFFIC VOLUME", "Объём передаваемых данных многократно выше нормы."),
    AUTH: ("SYSTEM", 65, "AUTH ERRORS", "Серия повторяющихся ошибок аутентификации."),
    ANOMALY: ("NETWORK", 80, "UNUSUAL CONNECTION RATE", "Необычная частота соединений и новый адрес назначения."),
    REPEAT: ("NETWORK", 88, "REPEATED CONNECTIONS", "Регулярно повторяющиеся соединения с подозрительным адресом."),
    PORT: ("IOT", 70, "UNUSUAL PORT", "Устройство использует порт, не входящий в его профиль."),
    RFID_OK: ("RFID", 8, "", "Считана известная карта."),
    RFID_UNK: ("RFID", 50, "UNKNOWN RFID", "Считана карта, отсутствующая в списке известных."),
    RFID_REP: ("RFID", 28, "REPEATED RFID", "Одна и та же карта считана повторно за короткое время."),
    SIG_NEW: ("RADIO", 30, "NEW SIGNAL", "Обнаружен сигнал с ранее не встречавшимся идентификатором."),
    SIG_REP: ("RADIO", 12, "", "Повторный приём известного сигнала."),
    IFACE: ("SYSTEM", 5, "", "Изменилось состояние сетевого интерфейса."),
}

SEED_DEVICES = [
    dict(name="Router", ip="192.168.1.1", mac="F4:EC:38:00:A1:01", type="Router",
         dst=["8.8.8.8", "1.1.1.1"], port=[53, 443], rate=30, vol=40.0),
    dict(name="Laptop-Lab", ip="192.168.1.10", mac="3C:52:82:7B:0E:44", type="Laptop",
         dst=["192.168.1.1", "93.184.216.34"], port=[443, 80], rate=20, vol=12.0),
    dict(name="Camera-01", ip="192.168.1.20", mac="00:1A:79:3C:5E:10", type="Camera",
         dst=["192.168.1.1", "10.0.0.20"], port=[554, 443], rate=6, vol=8.0),
    dict(name="Controller-02", ip="192.168.1.30", mac="00:0C:29:8E:71:2B", type="Controller",
         dst=["10.0.0.5"], port=[502], rate=3, vol=0.2),
    dict(name="RPi-Node", ip="192.168.1.40", mac="D8:3A:DD:12:44:9F", type="Raspberry Pi",
         dst=["192.168.1.1"], port=[123, 22], rate=2, vol=0.1),
    dict(name="Smart-Plug", ip="192.168.1.50", mac="50:02:91:6A:33:C8", type="Smart Device",
         dst=["192.168.1.1"], port=[443], rate=2, vol=0.1),
]
DISCOVERABLE = [
    dict(name="IoT-Sensor-01", ip="192.168.1.15", mac="B8:27:EB:4A:19:C3", type="Sensor",
         dst=["10.0.0.5", "10.0.0.10"], port=[1883, 443], rate=4, vol=1.2),
    dict(name="Printer-01", ip="192.168.1.60", mac="00:80:77:5B:12:9A", type="Printer",
         dst=["192.168.1.1"], port=[631, 9100], rate=1, vol=0.3),
    dict(name="Unknown-77", ip="192.168.1.77", mac="9C:B6:D0:1F:5A:70", type="Unknown",
         dst=["192.168.1.1"], port=[5353], rate=1, vol=0.05),
]
RESERVED_DEVICE = "IoT-Sensor-01"   # обнаруживается сценарием, а не сканированием

KNOWN_UIDS = ["04:7C:11:E8", "04:19:A3:5D", "04:B2:60:C1"]
SIGNAL_FREQ = ["433.92 MHz", "868.30 MHz", "315.00 MHz"]

SCENARIOS = {
    "Инцидент в локальной сети": (
        "Новое устройство, необычные соединения и рост трафика",
        [(NEW_DEV, "IoT-Sensor-01"), (NEW_DST, "IoT-Sensor-01"), (TRAFFIC, "IoT-Sensor-01"),
         (AUTH, "IoT-Sensor-01"), (ANOMALY, "IoT-Sensor-01"), (REPEAT, "IoT-Sensor-01")]),
    "Аномалия камеры": (
        "Необычный порт и рост трафика на камере",
        [(PORT, "Camera-01"), (TRAFFIC, "Camera-01"), (REPEAT, "Camera-01")]),
    "Штатная работа": (
        "Обычная активность без инцидентов",
        [(NORMAL, d) for d in ["Router", "Laptop-Lab", "Camera-01", "Controller-02", "RPi-Node",
                               "Smart-Plug", "Router", "Laptop-Lab"]]),
}

DEFAULT_SETTINGS = {"threshold": "65", "intensity": "Средняя", "web": "0", "fullscreen": "0"}
INTENSITY = {"Низкая": 0.5, "Средняя": 1.0, "Высокая": 2.0}


def sev_from_risk(r):
    return "LOW" if r < 30 else "MEDIUM" if r < 55 else "HIGH" if r < 80 else "CRITICAL"


def fmt_t(ts):
    return time.strftime("%H:%M:%S", time.localtime(ts))


def fmt_dt(ts):
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))


def ago(ts):
    d = max(0, int(time.time() - ts))
    return f"{d} с" if d < 60 else f"{d // 60} мин" if d < 3600 else f"{d // 3600} ч"


def fmt_int(n):
    return f"{n:,}".replace(",", " ")


def fmt_bytes(n):
    return f"{n} Б" if n < 1024 else f"{n / 1024:.0f} КБ" if n < 1048576 else f"{n / 1048576:.1f} МБ"


def advice(prio, device):
    if prio == "CRITICAL":
        return f"Немедленно проверить {device} и изолировать его сегмент сети."
    if prio == "HIGH":
        return f"Проверить {device}: поведение существенно отклоняется от профиля."
    if prio == "MEDIUM":
        return f"Продолжить наблюдение за {device}."
    return "Отклонений, требующих действий, нет."


# ────────────────────────────────────────────────────────────── база данных
class DB:
    def __init__(self, path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.path = path
        self.c = sqlite3.connect(path)
        self.c.executescript("""
        CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY, ts REAL, source TEXT, type TEXT, device TEXT,
            sev TEXT, risk INTEGER, conf INTEGER, related TEXT, descr TEXT, weight INTEGER, factors TEXT);
        CREATE TABLE IF NOT EXISTS alerts(id TEXT PRIMARY KEY, ts REAL, title TEXT, sev TEXT, status TEXT,
            events TEXT);
        CREATE TABLE IF NOT EXISTS reports(id TEXT PRIMARY KEY, ts REAL, period TEXT, fmt TEXT, path TEXT,
            size INTEGER);
        CREATE TABLE IF NOT EXISTS logs(ts REAL, level TEXT, msg TEXT);
        CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
        """)
        self.c.commit()

    def q(self, sql, args=()):
        cur = self.c.execute(sql, args)
        self.c.commit()
        return cur

    def rows(self, sql, args=()):
        return self.c.execute(sql, args).fetchall()

    def one(self, sql, args=()):
        return self.c.execute(sql, args).fetchone()

    def size(self):
        try:
            return os.path.getsize(self.path)
        except OSError:
            return 0


EV_COLS = "id,ts,source,type,device,sev,risk,conf,related,descr,weight,factors"


def ev_from_row(r):
    return dict(id=r[0], ts=r[1], source=r[2], type=r[3], device=r[4], sev=r[5], risk=r[6], conf=r[7],
                related=json.loads(r[8] or "[]"), descr=r[9], weight=r[10],
                factors=json.loads(r[11] or "{}"))


# ────────────────────────────────────────────────────────────── движок
class Engine:
    """Собирает события, оценивает риск, ищет цепочки, создаёт тревоги."""

    def __init__(self, db, demo=False, config_path=None):
        self.demo = demo
        self.hardware = None
        settings_dir = os.path.join(APP_DIR, 'demo') if demo else APP_DIR
        self.config_path = config_path or os.path.join(settings_dir, "hardware.json")
        self.hardware_config = load_config(self.config_path)
        self.credentials = Credentials(os.path.join(settings_dir, "account.json"))
        self.hardware_messages = deque(maxlen=200)
        self.capture_history = deque(maxlen=64)
        self._network_counters = {}
        self._network_ts = None
        self.network_rate = 0
        self.db = db
        self.started = time.time()
        self.ver = {}
        self.listeners = []
        self.monitoring = True
        self.devices = {}
        for d in (SEED_DEVICES if demo else []):
            self.devices[d["name"]] = dict(d, last=self.started - random.randint(3, 90))
        self.pool = [dict(d) for d in DISCOVERABLE] if demo else []
        self.flows = deque(maxlen=80)
        self.rfid = deque(maxlen=30)
        self.signals = deque(maxlen=30)
        self.seen_signals = set()
        self.traffic = deque([0] * 60, maxlen=60)
        self.ev_rate = deque([0] * 60, maxlen=60)
        self._tb = 0
        self._te = 0
        self.total_flows = 0
        self.total_bytes = 0
        self.settings = dict(DEFAULT_SETTINGS)
        for k, v in db.rows("SELECT key,value FROM settings"):
            self.settings[k] = v
        self.logs = deque(maxlen=300)
        first_run = demo and not db.one("SELECT COUNT(*) FROM events")[0]
        if first_run:
            self.seed_history()
        self.load()
        if first_run:                     # два архивных отчёта, чтобы архив не был пустым
            for age, period in ((2 * 3600, "Час"), (1200, "Сегодня")):
                self.write_report(period, "HTML" if age > 3600 else "Markdown", REPORT_SECTIONS,
                                  now=time.time() - age)
        self.log("INFO", "System started")
        self.log("INFO", "Демонстрационный режим" if demo else "Рабочий режим: только реальные данные")
        if not demo:
            self.hardware = HardwareService(self.hardware_config)

    # ---- служебное
    def bump(self, name):
        self.ver[name] = self.ver.get(name, 0) + 1

    def notify(self, kind, payload):
        for cb in list(self.listeners):
            cb(kind, payload)

    def set(self, key, value):
        self.settings[key] = str(value)
        self.db.q("INSERT OR REPLACE INTO settings VALUES(?,?)", (key, str(value)))

    def log(self, level, msg, ts=None):
        ts = ts or time.time()
        self.logs.append((ts, level, msg))
        self.db.q("INSERT INTO logs VALUES(?,?,?)", (ts, level, msg))
        self.bump("logs")

    # ---- начальные данные (первый запуск): история за последние часы
    def seed_history(self):
        now = time.time()
        choices = [(NORMAL, 60), (NEW_DST, 6), (TRAFFIC, 4), (PORT, 3), (RFID_OK, 8), (RFID_UNK, 3),
                   (SIG_NEW, 4), (SIG_REP, 5), (AUTH, 3), (IFACE, 2)]
        names = [d["name"] for d in SEED_DEVICES]
        stamps = sorted(now - random.uniform(900, 6 * 3600) for _ in range(260))
        strong = set(random.sample([i for i, _ in enumerate(stamps)], 3))
        alert_n = 0
        for i, ts in enumerate(stamps):
            etype = random.choices([c[0] for c in choices], [c[1] for c in choices])[0]
            source, w, _flag, descr = TYPES[etype]
            device = ("RFID-01" if source == "RFID" else random.choice(SIGNAL_FREQ) if source == "RADIO"
                      else random.choice(names))
            risk = round(0.3 * w + (4 if w >= 25 else 0) + 0.1 * SRC_W[source] + 0.15 * w * 0.9
                         + random.randint(-2, 2))
            if i in strong:
                etype, source, w = ANOMALY, "NETWORK", 80
                descr = TYPES[ANOMALY][3]
                device = random.choice(names)
                risk = random.randint(66, 74)
            risk = max(1, min(99, risk))
            ev = dict(id=f"EVT-{i + 1:04d}", ts=ts, source=source, type=etype, device=device,
                      sev=sev_from_risk(risk), risk=risk, conf=random.randint(62, 92), related=[],
                      descr=descr, weight=w, factors=dict(anomaly=w, frequency=20, correlation=0,
                                                          source=SRC_W[source], behaviour=round(w * 0.9)))
            self._insert_event(ev)
            if i in strong:
                alert_n += 1
                self.db.q("INSERT INTO alerts VALUES(?,?,?,?,?,?)",
                          (f"ALR-{alert_n:03d}", ts, f"{etype}: {device}", ev["sev"], "Закрыто",
                           json.dumps([ev["id"]])))
        for lv, msg, off in [("INFO", "System started", 6 * 3600), ("INFO", "Network interface initialized",
                                                                    6 * 3600 - 60),
                             ("INFO", "Analysis completed", 3 * 3600)]:
            self.db.q("INSERT INTO logs VALUES(?,?,?)", (now - off, lv, msg))
        self.db.q("INSERT OR REPLACE INTO settings VALUES('seeded','1')")
        self.seeded_now = True

    def _insert_event(self, ev):
        self.db.q("INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                  (ev["id"], ev["ts"], ev["source"], ev["type"], ev["device"], ev["sev"], ev["risk"],
                   ev["conf"], json.dumps(ev["related"]), ev["descr"], ev["weight"],
                   json.dumps(ev["factors"])))

    def load(self):
        rows = self.db.rows(f"SELECT {EV_COLS} FROM events ORDER BY ts DESC LIMIT 600")
        self.events = [ev_from_row(r) for r in reversed(rows)]
        self.alerts = [dict(id=r[0], ts=r[1], title=r[2], sev=r[3], status=r[4], events=json.loads(r[5] or "[]"))
                       for r in self.db.rows("SELECT id,ts,title,sev,status,events FROM alerts "
                                             "ORDER BY ts DESC LIMIT 200")]
        for r in reversed(self.db.rows("SELECT ts,level,msg FROM logs ORDER BY ts DESC LIMIT 300")):
            self.logs.append(r)
        self.total = self.db.one("SELECT COUNT(*) FROM events")[0]
        self.n_anom = self.db.one("SELECT COUNT(*) FROM events WHERE weight>=50")[0]
        self.next_evt = max([int(r[0][4:]) for r in self.db.rows("SELECT id FROM events")] or [0]) + 1
        self.next_alert = max([int(r[0][4:]) for r in self.db.rows("SELECT id FROM alerts")] or [0]) + 1
        for e in self.events:            # устройства, обнаруженные в прошлых сеансах
            if e["type"] == NEW_DEV:
                for p in list(self.pool):
                    if p["name"] == e["device"]:
                        self.devices[p["name"]] = dict(p, last=e["ts"])
                        self.pool.remove(p)

    # ---- события и анализ
    def add_event(self, etype, device, descr=None, ts=None, persist=True):
        source, weight, _flag, default_descr = TYPES[etype]
        now = ts or time.time()
        significant = weight >= 25
        recent = [e for e in self.events if significant and e["device"] == device and e["weight"] >= 25
                  and 0 <= now - e["ts"] < CHAIN_GAP]
        chain = len(recent) + 1 if significant else 0
        freq = min(100, 20 * chain) if significant else 0
        corr = min(100, 25 * chain) if chain >= 2 else 0
        beh = min(100, weight * 0.9 + 5 * len(recent))
        srcw = SRC_W.get(source, 50)
        risk = round(0.30 * weight + 0.20 * freq + 0.25 * corr + 0.10 * srcw + 0.15 * beh)
        risk = max(1, min(99, risk + (random.randint(-2, 2) if self.demo else 0)))
        ev = dict(id=f"EVT-{self.next_evt:04d}", ts=now, source=source, type=etype, device=device,
                  sev=sev_from_risk(risk), risk=risk, conf=min(97, 58 + 7 * len(recent) + (random.randint(0, 6) if self.demo else 0)),
                  related=[e["id"] for e in recent[-3:]], descr=descr or default_descr, weight=weight,
                  factors=dict(anomaly=weight, frequency=freq, correlation=corr, source=srcw,
                               behaviour=round(beh)))
        self.next_evt += 1
        self.events.append(ev)
        if len(self.events) > 600:
            self.events.pop(0)
        self.total += 1
        if weight >= 50:
            self.n_anom += 1
        self._insert_event(ev)
        self._te += 1
        if device in self.devices:
            self.devices[device]["last"] = now
        self.bump("events")
        self.log("WARN" if SEV_ORDER[ev["sev"]] >= 2 else "INFO", f"Event created: {ev['id']} ({etype})")
        if risk >= int(self.settings["threshold"]):
            self.make_alert(ev)
        self.notify("event", ev)
        return ev

    def make_alert(self, ev):
        a = dict(id=f"ALR-{self.next_alert:03d}", ts=ev["ts"], title=f"{ev['type']}: {ev['device']}",
                 sev=ev["sev"], status="Новое", events=[ev["id"]] + ev["related"])
        self.next_alert += 1
        self.alerts.insert(0, a)
        self.db.q("INSERT INTO alerts VALUES(?,?,?,?,?,?)",
                  (a["id"], a["ts"], a["title"], a["sev"], a["status"], json.dumps(a["events"])))
        self.bump("alerts")
        self.log("WARN", f"Alert generated: {a['id']}")
        self.notify("alert", a)

    def set_alert_status(self, aid, status):
        for a in self.alerts:
            if a["id"] == aid:
                a["status"] = status
        self.db.q("UPDATE alerts SET status=? WHERE id=?", (status, aid))
        self.bump("alerts")
        self.log("INFO", f"Alert {aid}: {status}")

    def open_alerts(self):
        return sum(1 for a in self.alerts if a["status"] == "Новое")

    def event_by_id(self, eid):
        for e in reversed(self.events):
            if e["id"] == eid:
                return e
        r = self.db.one(f"SELECT {EV_COLS} FROM events WHERE id=?", (eid,))
        return ev_from_row(r) if r else None

    def device_risk(self, name):
        now = time.time()
        best = 0
        for e in self.events:
            if e["device"] == name and now - e["ts"] < 600:
                best = max(best, e["risk"])
        return sev_from_risk(best) if best else "LOW"

    def state(self):
        now = time.time()
        worst = 0
        for e in self.events:
            if now - e["ts"] < 600:
                worst = max(worst, SEV_ORDER[e["sev"]])
        return [("Норма", GREEN), ("Наблюдение", AMBER), ("Внимание", ORANGE), ("Критическое", RED)][worst]

    def chains(self, horizon=1800, since=None, events=None, now=None):
        now = time.time() if now is None else now
        cur, out = {}, []
        for e in self.events if events is None else events:
            if e["weight"] < 25 or now - e["ts"] > horizon or (since and e["ts"] < since):
                continue
            c = cur.get(e["device"])
            if c and e["ts"] - c[-1]["ts"] <= CHAIN_GAP:
                c.append(e)
            else:
                if c and len(c) >= 3:
                    out.append(c)
                cur[e["device"]] = [e]
        out += [c for c in cur.values() if len(c) >= 3]
        res = []
        for c in out:
            res.append(dict(device=c[0]["device"], events=c, start=c[0]["ts"], end=c[-1]["ts"],
                            conf=round(sum(e["conf"] for e in c) / len(c)),
                            risk=max(e["risk"] for e in c),
                            prio=max((e["sev"] for e in c), key=lambda s: SEV_ORDER[s])))
        res.sort(key=lambda c: (-c["risk"], -c["end"]))
        return res

    def situation(self):
        ch = self.chains()
        now = time.time()
        if ch:
            c = ch[0]
            last = c["events"][-1]
            flags = []
            for e in c["events"]:
                fl = TYPES[e["type"]][2]
                if fl and fl not in flags:
                    flags.append(fl)
            return dict(risk=c["risk"], conf=c["conf"], prio=c["prio"], device=c["device"],
                        factors=last["factors"], chain=c, text=advice(c["prio"], c["device"]),
                        expl="Связанные признаки: " + ", ".join(flags) if flags else "")
        recent = [e for e in self.events if now - e["ts"] < 3600]
        if recent:
            e = max(recent, key=lambda x: x["risk"])
            return dict(risk=e["risk"], conf=e["conf"], prio=e["sev"], device=e["device"],
                        factors=e["factors"], chain=None, text=advice(e["sev"], e["device"]),
                        expl=e["type"])
        return dict(risk=0, conf=0, prio="LOW", device="—", factors={}, chain=None,
                    text=advice("LOW", ""), expl="")

    def metrics(self, ev):
        if not self.demo:
            return [("Наблюдение", "—", ev["descr"])]
        dev = self.devices.get(ev["device"])
        if not dev:
            return [("Событие", "—", ev["type"])]
        k = 1 + ev["weight"] / 8
        flag = TYPES[ev["type"]][2]
        new_dst = flag in ("NEW DESTINATION", "UNUSUAL CONNECTION RATE", "REPEATED CONNECTIONS")
        return [("Соединений в минуту", str(dev["rate"]), str(round(dev["rate"] * k))),
                ("Объём, МБ/мин", f"{dev['vol']}", f"{dev['vol'] * k:.1f}"),
                ("Адреса назначения", ", ".join(dev["dst"]), "+ 203.0.113.44" if new_dst else "без изменений"),
                ("Порты", ", ".join(map(str, dev["port"])), "+ 8554" if flag == "UNUSUAL PORT"
                 else "без изменений")]

    # ---- имитация активности
    def gen_flow(self):
        names = list(self.devices)
        name = random.choice(names)
        d = self.devices[name]
        hot = self.device_risk(name) in ("HIGH", "CRITICAL")
        dst = "203.0.113.44" if hot else random.choice(d["dst"])
        port = 4444 if hot else random.choice(d["port"])
        size = int(d["vol"] * 1024 * 1024 / 60 * random.uniform(0.4, 1.6) * (25 if hot else 1)) + 200
        self.flows.appendleft((time.time(), d["ip"], dst, str(port), size))
        self.total_flows += 1
        self.total_bytes += size
        self._tb += size
        d["last"] = time.time()
        self.bump("flows")

    def gen_signal(self):
        freq = random.choice(SIGNAL_FREQ)
        sid = f"0x{random.choice([0x3A91, 0x11C2, 0x77F0, random.randint(0x1000, 0xFFFF)]):04X}"
        new = sid not in self.seen_signals
        self.seen_signals.add(sid)
        self.signals.appendleft((time.time(), freq, f"-{random.randint(55, 85)} dBm", sid,
                                 "Новый" if new else "Повтор"))
        self.bump("signals")
        self.add_event(SIG_NEW if new else SIG_REP, freq, descr=f"Сигнал {sid} на {freq}")

    def rfid_read(self):
        last = self.rfid[0] if self.rfid else None
        r = random.random()
        if last and r < 0.25:
            uid = last[1]
        elif r < 0.7:
            uid = random.choice(KNOWN_UIDS)
        else:
            uid = ":".join(f"{random.randint(0, 255):02X}" for _ in range(4))
        known = uid in KNOWN_UIDS
        repeat = any(x[1] == uid and time.time() - x[0] < 60 for x in self.rfid)
        etype = RFID_REP if repeat else (RFID_OK if known else RFID_UNK)
        state = "Повтор" if repeat else ("Известный" if known else "Новый")
        self.rfid.appendleft((time.time(), uid, etype, state))
        self.bump("rfid")
        return self.add_event(etype, "RFID-01", descr=f"UID {uid}")

    def discover(self, name=None):
        cand = [p for p in self.pool if (p["name"] == name if name else p["name"] != RESERVED_DEVICE)]
        if not cand:
            if name and name in self.devices:      # повторное появление
                self.devices[name]["last"] = time.time()
                return self.add_event(NEW_DEV, name, descr="Устройство повторно появилось в сети.")
            return None
        d = cand[0]
        self.pool.remove(d)
        self.devices[d["name"]] = dict(d, last=time.time())
        self.log("INFO", f"Device detected: {d['ip']}")
        self.bump("devices")
        return self.add_event(NEW_DEV, d["name"], descr=f"Новое устройство {d['ip']} ({d['type']}).")

    def tick(self):
        self.ev_rate.append(self._te)
        self.traffic.append(round((self._tb if self.demo else self.network_rate) / 1024))
        self._te = 0
        self._tb = 0
        if not self.monitoring or not self.demo:
            return
        k = INTENSITY.get(self.settings["intensity"], 1.0)
        if random.random() < 0.8 * k:
            self.gen_flow()
        if random.random() < 0.12 * k:
            self.add_event(NORMAL, random.choice(list(self.devices)))
        if random.random() < 0.03 * k:
            etype = random.choice([NEW_DST, PORT, NEW_DST])
            dev = random.choice([n for n in self.devices if n != "Router"])
            self.add_event(etype, dev)
        if random.random() < 0.05 * k:
            self.gen_signal()

    # ---- сводки
    def hourly(self, hours=8):
        now = time.time()
        base = now - now % 3600
        out = [0] * hours
        for e in self.events:
            i = int((e["ts"] - (base - (hours - 1) * 3600)) // 3600)
            if 0 <= i < hours:
                out[i] += 1
        labels = [time.strftime("%H", time.localtime(base - (hours - 1 - i) * 3600)) for i in range(hours)]
        return out, labels

    def by_source(self):
        c = {s: 0 for s in SOURCES}
        for e in self.events:
            c[e["source"]] = c.get(e["source"], 0) + 1
        return [c[s] for s in SOURCES]

    def by_sev(self):
        c = {s: 0 for s in SEV_ORDER}
        for e in self.events:
            c[e["sev"]] += 1
        return [c[s] for s in SEV_ORDER]

    def counts(self):
        return [(t, self.db.one(f"SELECT COUNT(*) FROM {t}")[0])
                for t in ("events", "alerts", "reports", "logs", "settings")]

    def snapshot(self):
        st = self.state()[0]
        return dict(state=st, monitoring=self.monitoring, events=self.total, anomalies=self.n_anom,
                    devices=len(self.devices), open_alerts=self.open_alerts(),
                    last=[dict(id=e["id"], time=fmt_t(e["ts"]), type=e["type"], device=e["device"],
                               severity=e["sev"]) for e in list(self.events)[-10:]][::-1])

    # ---- отчёты
    def report_data(self, period, sections, now=None):
        now = now or time.time()
        lt = time.localtime(now)
        cut = {"Час": now - 3600,
               "Сегодня": time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday, 0, 0, 0, 0, 0, -1)),
               "Сеанс": self.started}[period]
        evs = [ev_from_row(r) for r in self.db.rows(
            f"SELECT {EV_COLS} FROM events WHERE ts BETWEEN ? AND ? ORDER BY ts", (cut, now))]
        alerts = self.db.rows("SELECT id FROM alerts WHERE ts BETWEEN ? AND ?", (cut, now))
        out = []
        for name in sections:
            L = []
            if name == "Общая информация":
                start = self.started if now >= self.started else (self.events[0]["ts"] if self.events else now)
                dur = max(0, int(now - start))
                L = [f"Дата: {fmt_dt(now)}", f"Период: {period}",
                     f"Длительность мониторинга: {dur // 3600:02d}:{dur % 3600 // 60:02d}:{dur % 60:02d}",
                     f"Устройств в сети: {len(self.devices)}", f"Событий за период: {len(evs)}"]
            elif name == "Статистика":
                sev = {s: sum(1 for e in evs if e["sev"] == s) for s in SEV_ORDER}
                L = [f"Событий: {len(evs)}", f"Аномалий: {sum(1 for e in evs if e['weight'] >= 50)}",
                     f"Тревог: {len(alerts)}",
                     "Приоритеты: " + ", ".join(f"{k} {v}" for k, v in sev.items())]
            elif name == "Хронология":
                sig = [e for e in evs if e["weight"] >= 25][-10:]
                L = [f"{fmt_t(e['ts'])}  {e['type']} — {e['device']} ({e['sev']})" for e in sig] \
                    or ["Значимых событий за период нет."]
            elif name == "Связанные события":
                ch = self.chains(horizon=now - cut + 1, since=cut, events=evs, now=now)
                L = [f"Цепочка {i + 1}: {c['device']}, событий {len(c['events'])}, уверенность {c['conf']}%, "
                     f"приоритет {c['prio']} ({', '.join(e['id'] for e in c['events'])})"
                     for i, c in enumerate(ch)] or ["Связанных цепочек не обнаружено."]
            elif name == "Оценка по правилам":
                if evs:
                    event = max(evs, key=lambda e: e["risk"])
                    L = [f"Максимальный риск за период: {event['risk']}/100, приоритет {event['sev']}.",
                         f"Основание: {event['id']} — {event['descr']}",
                         f"Рекомендация: {advice(event['sev'], event['device'])}"]
                else:
                    L = ["В выбранном периоде нет событий для оценки."]
                L.append("Эвристическая оценка; решение принимает оператор.")
            elif name == "Вывод":
                worst = max([SEV_ORDER[e["sev"]] for e in evs] or [0])
                L = [["Значимых отклонений не обнаружено.", "Наблюдались незначительные отклонения.",
                      "Требуется внимание оператора.", "Обнаружены критические события, требуется "
                      "немедленная проверка."][worst]]
            out.append((name, L))
        return out

    def write_report(self, period, fmt, sections, now=None):
        now = now or time.time()
        data = self.report_data(period, sections, now)
        os.makedirs(REPORT_DIR, exist_ok=True)
        rid = "RPT-" + uuid.uuid4().hex[:12].upper()
        stamp = time.strftime("%Y%m%d_%H%M%S", time.localtime(now))
        ext = "html" if fmt == "HTML" else "md"
        path = os.path.join(REPORT_DIR, f"axiora_{rid}_{stamp}.{ext}")
        title = f"Отчёт Axiora — {fmt_dt(now)}"
        if fmt == "HTML":
            body = "".join(f"<h2>{esc_html(t)}</h2><ul>{''.join(f'<li>{esc_html(x)}</li>' for x in L)}</ul>"
                           for t, L in data)
            text = ("<!DOCTYPE html><html lang='ru'><head><meta charset='utf-8'><title>%s</title><style>"
                    "body{font-family:'Times New Roman',serif;color:#0d2b4d;max-width:760px;margin:24px auto;}"
                    "h1,h2{color:#1976d2}li{margin:3px 0}</style></head><body><h1>%s</h1>%s</body></html>"
                    % (esc_html(title), esc_html(title), body))
        else:
            text = f"# {title}\n\n" + "\n".join(
                f"## {t}\n" + "\n".join(f"- {x}" for x in L) + "\n" for t, L in data)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        size = os.path.getsize(path)
        self.db.q("INSERT INTO reports VALUES(?,?,?,?,?,?)", (rid, now, period, fmt, path, size))
        self.bump("reports")
        self.log("INFO", f"Report generated: {rid}")
        return rid, path

    def report_text(self, path):
        try:
            with open(path, encoding="utf-8") as f:
                return f.read()
        except OSError:
            return "Файл отчёта не найден."


def esc_html(s):
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


REPORT_SECTIONS = ["Общая информация", "Статистика", "Хронология", "Связанные события", "Оценка по правилам", "Вывод"]


# ────────────────────────────────────────────────────────────── веб-панель (локальная)
class WebPanel:
    def __init__(self, engine):
        self.engine = engine
        self.server = None
        self.url = ""

    def start(self):
        if self.server:
            return self.url
        engine = self.engine

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                valid = False
                try:
                    auth = self.headers.get("Authorization", "")
                    if auth.startswith("Basic "):
                        user, password = base64.b64decode(auth[6:], validate=True).decode().split(":", 1)
                        valid = engine.credentials.verify(user, password)
                except (ValueError, UnicodeError):
                    pass
                if not valid:
                    self.send_response(401)
                    self.send_header("WWW-Authenticate", 'Basic realm="Axiora", charset="UTF-8"')
                    self.end_headers()
                    return
                snap = engine.snapshot()
                if self.path.startswith("/api"):
                    body, ctype = json.dumps(snap, ensure_ascii=False), "application/json; charset=utf-8"
                else:
                    rows = "".join(f"<tr><td>{e['time']}</td><td>{e['severity']}</td><td>{esc_html(e['type'])}</td>"
                                   f"<td>{esc_html(e['device'])}</td></tr>" for e in snap["last"])
                    body = ("<!DOCTYPE html><html><head><meta charset='utf-8'><meta http-equiv='refresh' content='3'>"
                            "<title>Axiora</title><style>body{font-family:'Times New Roman',serif;color:#0d2b4d;"
                            "margin:24px}h1{color:#1976d2}td,th{padding:6px 12px;border-bottom:1px solid #bbdefb;"
                            "text-align:left}</style></head><body><h1>AXIORA</h1>"
                            f"<p>Состояние: <b>{snap['state']}</b> · событий {snap['events']} · аномалий "
                            f"{snap['anomalies']} · устройств {snap['devices']} · открытых тревог "
                            f"{snap['open_alerts']}</p><table><tr><th>Время</th><th>Приоритет</th><th>Событие</th>"
                            f"<th>Устройство</th></tr>{rows}</table></body></html>")
                    ctype = "text/html; charset=utf-8"
                data = body.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        for port in range(8080, 8090):
            try:
                self.server = ThreadingHTTPServer(("127.0.0.1", port), H)
                self.url = f"http://127.0.0.1:{port}"
                break
            except OSError:
                continue
        if self.server:
            threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self.url

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server = None
            self.url = ""


# ════════════════════════════════════════════════════════════════════ ИНТЕРФЕЙС
def vbox(spacing=8):
    return Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=spacing)


def hbox(spacing=8):
    return Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=spacing)


def esc(text):
    return GLib.markup_escape_text(str(text))


def colored(text):
    color = COLOR_MAP.get(str(text))
    return f'<span foreground="{color}" weight="bold">{esc(text)}</span>' if color else esc(text)


def add_css(widget, *names):
    for n in names:
        widget.get_style_context().add_class(n)
    return widget


def lbl(text="", css=None, wrap=False, markup=False, ellipsize=False):
    label = Gtk.Label(xalign=0.0)
    (label.set_markup if markup else label.set_text)(text)
    if css:
        add_css(label, css)
    if wrap:
        label.set_line_wrap(True)
        label.set_max_width_chars(46)
        label.set_yalign(0.0)
    if ellipsize:
        label.set_ellipsize(Pango.EllipsizeMode.END)
    return label


def button(text, callback=None, kind=None):
    b = Gtk.Button(label=text)
    if kind:
        add_css(b, kind)
    if callback:
        b.connect("clicked", callback)
    return b


def kv_rows(pairs):
    grid = Gtk.Grid(column_spacing=14, row_spacing=8)
    for i, (k, v) in enumerate(pairs):
        key = lbl(k, "kv-key")
        key.set_valign(Gtk.Align.START)
        val = lbl("", "kv-val", wrap=True, markup=True)
        val.set_markup(colored(v))
        val.set_hexpand(True)
        grid.attach(key, 0, i, 1, 1)
        grid.attach(val, 1, i, 1, 1)
    return grid


def hex_rgba(cr, hexcolor, alpha=1.0):
    cr.set_source_rgba(int(hexcolor[1:3], 16) / 255, int(hexcolor[3:5], 16) / 255,
                       int(hexcolor[5:7], 16) / 255, alpha)


class Table:
    """Крупная таблица для касаний: строки ~48 px, нажатие на строку вызывает on_tap(key)."""

    def __init__(self, columns, widths=None, color_cols=(), scroll=True, height=120, on_tap=None):
        self.n = len(columns)
        self.cc = list(color_cols)
        self.store = Gtk.ListStore(*([str] * (self.n + 2 + len(self.cc))))   # значения, ключ, фон, цвета
        self.tree = Gtk.TreeView(model=self.store)
        self.tree.set_activate_on_single_click(True)
        self.tree.set_headers_clickable(False)
        self._key = None
        widths = widths or [None] * self.n
        for i, name in enumerate(columns):
            r = Gtk.CellRendererText()
            r.set_property("ypad", 13)
            r.set_property("xpad", 8)
            r.set_property("ellipsize", Pango.EllipsizeMode.END)
            col = Gtk.TreeViewColumn(name, r, text=i)
            col.add_attribute(r, "cell-background", self.n + 1)
            if i in self.cc:
                col.add_attribute(r, "foreground", self.n + 2 + self.cc.index(i))
                r.set_property("weight", 700)
            if widths[i]:
                col.set_min_width(widths[i])
                col.set_max_width(widths[i])
            else:
                col.set_expand(True)
                col.set_min_width(60)
            self.tree.append_column(col)
        if on_tap:
            self.tree.connect("row-activated", lambda t, path, c: on_tap(self.store[path][self.n]))
        if scroll:
            self.widget = Gtk.ScrolledWindow()
            self.widget.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
            self.widget.set_overlay_scrolling(False)
            self.widget.set_min_content_height(height)
            self.widget.set_vexpand(True)
            self.widget.add(self.tree)
            self.vadj = self.widget.get_vadjustment()
        else:
            self.widget = self.tree
            self.vadj = None

    def set_rows(self, rows):
        """rows: [(значения, ключ)]"""
        val = self.vadj.get_value() if self.vadj else 0
        self.store.clear()
        for i, (vals, key) in enumerate(rows):
            extras = [COLOR_MAP.get(str(vals[c]), INK) for c in self.cc]
            self.store.append([str(x) for x in vals] + [str(key), "#ffffff" if i % 2 == 0 else "#f4f9ff"] + extras)
        if self.vadj:
            GLib.idle_add(lambda: self.vadj.set_value(val) and False)

    def refresh(self, key, rows_fn):
        if key != self._key:
            self._key = key
            self.set_rows(rows_fn())

    def selected_key(self):
        model, it = self.tree.get_selection().get_selected()
        return model[it][self.n] if it else None

    def select_first(self):
        self.tree.get_selection().select_path(Gtk.TreePath.new_first())


class Chart(Gtk.DrawingArea):
    """Простые графики на cairo: line / bar."""

    def __init__(self, kind, color=BLUE, height=120, colors=None):
        super().__init__()
        self.kind, self.color, self.colors = kind, color, colors
        self.values, self.labels = [0], [""]
        self.set_size_request(-1, height)
        self.set_hexpand(True)
        self.connect("draw", self.on_draw)

    def set(self, values, labels):
        self.values, self.labels = list(values) or [0], list(labels) or [""]
        self.queue_draw()

    def on_draw(self, widget, cr):
        W, H = widget.get_allocated_width(), widget.get_allocated_height()
        pl, pr, pt, pb = 34, 6, 8, 20
        gw, gh = W - pl - pr, H - pt - pb
        n = len(self.values)
        maxv = max(max(self.values), 1) * 1.15
        cr.select_font_face("Times New Roman", 0, 0)
        cr.set_font_size(12)
        cr.set_line_width(1)
        for i in range(4):
            y = pt + gh * i / 3
            hex_rgba(cr, "#d6e8fa")
            cr.move_to(pl, y)
            cr.line_to(W - pr, y)
            cr.stroke()
            hex_rgba(cr, MUTED)
            cr.move_to(2, y + 4)
            cr.show_text(f"{maxv * (1 - i / 3):.0f}")
        if self.kind == "line":
            pts = [(pl + gw * i / max(n - 1, 1), pt + gh * (1 - v / maxv)) for i, v in enumerate(self.values)]
            cr.move_to(pts[0][0], pt + gh)
            for x, y in pts:
                cr.line_to(x, y)
            cr.line_to(pts[-1][0], pt + gh)
            cr.close_path()
            hex_rgba(cr, self.color, 0.14)
            cr.fill()
            hex_rgba(cr, self.color)
            cr.set_line_width(2)
            cr.move_to(*pts[0])
            for x, y in pts[1:]:
                cr.line_to(x, y)
            cr.stroke()
            if n <= 20:
                for x, y in pts:
                    cr.arc(x, y, 3, 0, 6.2832)
                    cr.fill()
            for (x, _), t in zip(pts, self.labels):
                if t:
                    hex_rgba(cr, MUTED)
                    cr.move_to(min(max(x - cr.text_extents(t).width / 2, pl), W - 20), H - 5)
                    cr.show_text(t)
        else:
            slot = gw / n
            bw = slot * 0.62
            for i, v in enumerate(self.values):
                x = pl + slot * i + (slot - bw) / 2
                bh = gh * v / maxv
                hex_rgba(cr, self.colors[i] if self.colors else self.color)
                cr.rectangle(x, pt + gh - bh, bw, bh)
                cr.fill()
                hex_rgba(cr, INK)
                s = str(v)
                cr.move_to(x + bw / 2 - cr.text_extents(s).width / 2, pt + gh - bh - 3)
                cr.show_text(s)
                hex_rgba(cr, MUTED)
                t = self.labels[i]
                cr.move_to(x + bw / 2 - cr.text_extents(t).width / 2, H - 5)
                cr.show_text(t)
        return False


class StatCard(Gtk.Box):
    def __init__(self, title):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        add_css(self, "card")
        self.value = lbl("0", "stat-value")
        self.pack_start(self.value, False, False, 0)
        self.pack_start(lbl(title, "stat-title"), False, False, 0)

    def set(self, text, color=None):
        self.value.set_markup(f'<span foreground="{color}">{esc(text)}</span>' if color else esc(text))


class Meter(Gtk.Box):
    def __init__(self, title):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        self.title = lbl(title, "kv-key")
        self.bar = Gtk.ProgressBar()
        self.bar.set_show_text(True)
        self.pack_start(self.title, False, False, 0)
        self.pack_start(self.bar, False, False, 0)

    def set(self, fraction, text):
        self.bar.set_fraction(max(0.0, min(1.0, fraction)))
        self.bar.set_text(text)


class Segmented(Gtk.Box):
    """Переключатель из крупных кнопок (одна активна)."""

    def __init__(self, options, active=0, on_change=None):
        super().__init__(spacing=6)
        self.set_homogeneous(True)
        self.options, self.index, self.on_change, self._busy = options, active, on_change, False
        self.buttons = []
        for i, o in enumerate(options):
            b = Gtk.ToggleButton(label=o)
            b.set_active(i == active)
            b.connect("toggled", self._toggled, i)
            self.pack_start(b, True, True, 0)
            self.buttons.append(b)

    def _toggled(self, b, i):
        if self._busy:
            return
        self._busy = True
        if b.get_active():
            for j, o in enumerate(self.buttons):
                if j != i:
                    o.set_active(False)
            self.index = i
            self._busy = False
            if self.on_change:
                self.on_change(i, self.options[i])
        else:
            b.set_active(True)
            self._busy = False

    @property
    def value(self):
        return self.options[self.index]


def read_cpu():
    with open("/proc/stat") as f:
        v = list(map(int, f.readline().split()[1:8]))
    return v[3] + v[4], sum(v)


def read_mem():
    d = {}
    with open("/proc/meminfo") as f:
        for line in f:
            k, v = line.split(":")
            d[k] = int(v.split()[0])
    return d["MemTotal"], d.get("MemAvailable", d["MemFree"])


def read_temp():
    for p in glob.glob("/sys/class/thermal/thermal_zone*/temp"):
        try:
            with open(p) as f:
                return int(f.read().strip()) / 1000
        except (OSError, ValueError):
            continue
    return None


def read_uptime():
    try:
        with open("/proc/uptime") as f:
            return int(float(f.read().split()[0]))
    except OSError:
        return 0


MENU = [("dash", "Главная"), ("hardware", "Модули"), ("net", "Сеть"), ("src", "Источники"), ("events", "События"),
        ("tools", "Инструменты"), ("ai", "Аналитика"), ("reports", "Отчёты"), ("system", "Система")]
PPI_NOTE = "5\" · 800×480 · цели касания ≥ 48 px"


class AxioraWindow(WorkbenchPages, HardwarePages, Gtk.Window):
    def __init__(self, engine, web, size=(SCREEN_W, SCREEN_H), fullscreen=False):
        super().__init__(title=APP_NAME)
        self.engine, self.web = engine, web
        self.engine.workbench = Workbench(os.path.join(APP_DIR, 'demo' if engine.demo else 'live', 'workbench'),
                                          disabled=engine.demo)
        self._last_activity = time.monotonic()
        self.connect('event', self._on_activity)
        self.win_w, self.win_h = size
        self.set_default_size(*size)
        self.set_position(Gtk.WindowPosition.CENTER)
        add_css(self, "root")
        self._toast_id = self._banner_id = 0
        self._kb = None
        self._cpu = read_cpu()
        self._scanning = self._sim_running = False
        self.refreshers = {}
        self.notebooks = {}
        engine.listeners.append(self.on_engine)

        self.stack = Gtk.Stack()
        self.stack.set_transition_type(Gtk.StackTransitionType.CROSSFADE)
        self.stack.set_hhomogeneous(False)
        self.stack.set_vhomogeneous(False)
        self.stack.set_transition_duration(200)
        self.add(self.stack)
        self.stack.add_named(self._build_login(), "login")
        self.stack.add_named(self._build_password_setup(), "setup")
        self.stack.add_named(self._build_main(), "main")
        self.stack.set_visible_child_name("login")
        if fullscreen or engine.settings.get("fullscreen") == "1":
            self.fullscreen()
        self.connect("destroy", self._on_destroy)
        self._tick_id = GLib.timeout_add(1000, self.on_tick)
        self._hardware_id = GLib.timeout_add(100, self.poll_hardware)

    def _on_destroy(self, *_):
        if self._kb and self._kb.poll() is None:
            self._kb.terminate()
        GLib.source_remove(self._tick_id)
        GLib.source_remove(self._hardware_id)
        self.web.stop()
        self.engine.workbench.close()
        if self.engine.hardware:
            self.engine.hardware.close()
        self.engine.db.c.close()
        if Gtk.main_level():
            Gtk.main_quit()

    # ═══════════════════════════════════════ вход
    def _on_activity(self, _widget, event):
        if event.type in (Gdk.EventType.KEY_PRESS, Gdk.EventType.BUTTON_PRESS,
                          Gdk.EventType.MOTION_NOTIFY, Gdk.EventType.TOUCH_BEGIN, Gdk.EventType.SCROLL):
            self._last_activity = time.monotonic()
        return False

    def _build_password_setup(self):
        root = vbox(10)
        root.set_halign(Gtk.Align.CENTER)
        root.set_valign(Gtk.Align.CENTER)
        root.set_size_request(400, -1)
        root.pack_start(lbl('Задайте рабочий пароль', 'logo'), False, False, 0)
        root.pack_start(lbl('Первый вход: минимум 10 символов.', wrap=True), False, False, 0)
        self.setup_password = Gtk.Entry(visibility=False)
        self.setup_password.set_placeholder_text('Новый пароль')
        self.setup_repeat = Gtk.Entry(visibility=False)
        self.setup_repeat.set_placeholder_text('Повторите пароль')
        for entry in (self.setup_password, self.setup_repeat):
            root.pack_start(entry, False, False, 0)
        self.setup_error = lbl('', 'error', wrap=True)
        root.pack_start(self.setup_error, False, False, 0)
        root.pack_start(button('Сохранить и войти', self.on_setup_password, 'primary'), False, False, 0)
        root.pack_start(button('Назад', self.on_logout), False, False, 0)
        return root

    def on_setup_password(self, *_):
        if self.stack.get_visible_child_name() != 'setup':
            return
        password = self.setup_password.get_text()
        if len(password) < 10 or password != self.setup_repeat.get_text():
            self.setup_error.set_text('Пароли должны совпадать и содержать минимум 10 символов')
            return
        try:
            self.engine.credentials.change(password)
        except OSError as exc:
            self.setup_error.set_text(str(exc))
            return
        self.setup_password.set_text('')
        self.setup_repeat.set_text('')
        self.setup_error.set_text('')
        self._enter_session()

    def _enter_session(self):
        self._last_activity = time.monotonic()
        self.engine.log('INFO', 'User admin logged in')
        self.user_label.set_text(VALID_LOGIN)
        self.menu_list.select_row(self.menu_list.get_row_at_index(0))
        self.stack.set_visible_child_name('main')
        self.refresh_current()

    def _build_login(self):
        outer = Gtk.Box()
        outer.set_halign(Gtk.Align.CENTER)
        outer.set_valign(Gtk.Align.CENTER)
        card = vbox(10)
        add_css(card, "card")
        card.set_size_request(400, -1)
        card.set_margin_top(10)
        card.set_margin_bottom(10)
        outer.pack_start(card, False, False, 0)
        card.pack_start(lbl(APP_NAME.upper(), "logo"), False, False, 0)
        card.pack_start(lbl("Вход в систему", "muted"), False, False, 0)
        self.entry_login = Gtk.Entry()
        self.entry_login.set_placeholder_text("Логин")
        self.entry_login.connect("activate", lambda *_: self.entry_pass.grab_focus())
        card.pack_start(self.entry_login, False, False, 0)
        self.entry_pass = Gtk.Entry()
        self.entry_pass.set_placeholder_text("Пароль")
        self.entry_pass.set_visibility(False)
        self.entry_pass.connect("activate", self.on_login)
        card.pack_start(self.entry_pass, False, False, 0)
        self.error_label = lbl("", "error")
        card.pack_start(self.error_label, False, False, 0)
        card.pack_start(button("Войти", self.on_login, "primary"), False, False, 0)
        card.pack_start(button("Экранная клавиатура", self.toggle_keyboard, "ghost"), False, False, 0)
        return outer

    def toggle_keyboard(self, *_):
        if self._kb and self._kb.poll() is None:
            self._kb.terminate()
            self._kb = None
            return
        exe = shutil.which("onboard")
        if exe:
            self._kb = subprocess.Popen([exe])
        else:
            self.error_label.set_text("Экранная клавиатура onboard не установлена")

    def on_login(self, *_):
        if self.engine.credentials.verify(self.entry_login.get_text().strip(), self.entry_pass.get_text()):
            self.error_label.set_text("")
            self.entry_pass.set_text("")
            if self._kb and self._kb.poll() is None:
                self._kb.terminate()
                self._kb = None
            if not self.engine.demo and self.engine.credentials.needs_setup():
                self.stack.set_visible_child_name('setup')
            else:
                self._enter_session()
        else:
            self.error_label.set_text("Неверный логин или пароль")
            self.entry_pass.grab_focus()

    def on_logout(self, *_):
        self.engine.log("INFO", "User admin logged out")
        self.web_switch.set_active(False)
        self.web.stop()
        self.engine.workbench.cancel_all()
        self.clear_workbench_secrets()
        self.setup_password.set_text('')
        self.setup_repeat.set_text('')
        for entry in getattr(self, 'account_entries', []):
            entry.set_text('')
        if self.engine.hardware:
            for name in self.engine.hardware_config:
                self.hw_command("disconnect", name)
        self.entry_pass.set_text("")
        if hasattr(self, 'memory_key'):
            self.memory_key.set_text('')
            self.memory_data.set_text('')
            self.memory_info.set_text('Ожидается чтение блока')
            self.clear_memory_preview()
        self.hide_banner()
        self.stack.set_visible_child_name("login")
        self.entry_login.grab_focus()

    # ═══════════════════════════════════════ каркас
    def _build_main(self):
        root = vbox(0)

        top = hbox(10)
        add_css(top, "topbar")
        top.set_size_request(-1, 48)
        top.pack_start(lbl(APP_NAME.upper(), "brand"), False, False, 0)
        top.pack_end(button("Выход", self.on_logout), False, False, 0)
        self.user_label = lbl("")
        top.pack_end(self.user_label, False, False, 6)
        self.clock = lbl("")
        top.pack_end(self.clock, False, False, 6)
        root.pack_start(top, False, False, 0)

        self.banner = hbox(10)
        add_css(self.banner, "banner")
        self.banner_label = lbl("", ellipsize=True)
        self.banner.pack_start(self.banner_label, True, True, 0)
        self.banner.pack_end(button("Открыть", lambda *_: (self.goto("events", 1), self.hide_banner())),
                             False, False, 0)
        self.banner.set_no_show_all(True)
        root.pack_start(self.banner, False, False, 0)

        status = hbox(12)
        add_css(status, "statusbar")
        self.status_label = lbl("", ellipsize=True)
        status.pack_start(self.status_label, True, True, 0)
        self.toast_label = lbl("", "toast", ellipsize=True)
        self.toast_label.set_max_width_chars(44)
        status.pack_end(self.toast_label, False, False, 0)

        body = hbox(0)
        root.pack_start(body, True, True, 0)
        root.pack_end(status, False, False, 0)

        self.menu_list = Gtk.ListBox()
        add_css(self.menu_list, "nav")
        self.menu_list.set_size_request(140, -1)
        self.menu_list.connect("row-selected", self.on_menu_selected)
        self.badges = {}
        for key, text in MENU:
            row = Gtk.ListBoxRow()
            box = hbox(4)
            box.pack_start(lbl(text), True, True, 0)
            badge = lbl("", "badge")
            badge.set_no_show_all(True)
            box.pack_end(badge, False, False, 0)
            self.badges[key] = badge
            row.add(box)
            self.menu_list.add(row)
        nav_scroll = Gtk.ScrolledWindow()
        nav_scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        nav_scroll.add(self.menu_list)
        body.pack_start(nav_scroll, False, False, 0)

        self.content = Gtk.Stack()
        self.content.set_transition_type(Gtk.StackTransitionType.CROSSFADE)
        self.content.set_transition_duration(150)
        specs = {
            "dash": [("Обзор", self.tab_dash, True)],
            "hardware": [("Модули", self.tab_hardware, True), ("Распиновка", self.tab_pinout, True),
                         ("Настройка", self.tab_hardware_config, True)],
            "net": [("Обзор", self.tab_net, True), ("Устройства", self.tab_devices, False),
                    ("Потоки", self.tab_flows, False)],
            "tools": [("Запуск", self.tab_workbench_tools, True), ("Задачи", self.tab_workbench_jobs, True),
                      ("Проекты", self.tab_workbench_projects, True), ("Находки", self.tab_workbench_findings, True),
                      ("Модули", self.tab_workbench_modules, True)],
            "src": [("RFID", self.tab_rfid, False), ("Радио", self.tab_radio, False),
                    ("Наборы", self.tab_sets, True)],
            "events": [("Журнал", self.tab_log, False), ("Тревоги", self.tab_alerts, False),
                       ("Статистика", self.tab_stats, True)],
            "ai": [("Ситуация", self.tab_situation, True), ("Аномалии", self.tab_anomalies, False),
                   ("Цепочки", self.tab_chains, False)],
            "reports": [("Создать", self.tab_report_new, True), ("Архив", self.tab_report_list, False)],
            "system": [("Состояние", self.tab_sys, True), ("Журнал", self.tab_syslog, False),
                       ("База", self.tab_db, True), ("Настройки", self.tab_settings, True), ("Учётная запись", self.tab_account, True)],
        }
        if not self.engine.demo:
            specs["net"] = [("Интерфейсы", self.tab_live_net, True), ("Соседи", self.tab_live_neighbors, True)]
            specs["src"] = [("RFID", self.tab_live_rfid, True), ("Память карт", self.tab_card_memory, True), ("2,4 ГГц", self.tab_nrf24, True),
                            ("CC1101", self.tab_cc1101, True), ("GPS", self.tab_gps, True),
                            ("Сенсор", self.tab_touch, True)]
        for key, tabs in specs.items():
            self.refreshers[key] = []
            nb = Gtk.Notebook()
            nb.set_scrollable(True)
            nb.set_show_tabs(len(tabs) > 1)
            for name, builder, scroll in tabs:
                widget, refresh = builder()
                if refresh:
                    self.refreshers[key].append(refresh)
                for side in ("top", "bottom", "start", "end"):
                    getattr(widget, f"set_margin_{side}")(8)
                if scroll:
                    sw = Gtk.ScrolledWindow()
                    sw.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
                    sw.set_overlay_scrolling(False)
                    sw.add(widget)
                    widget = sw
                nb.append_page(widget, Gtk.Label(label=name))
            nb.connect("switch-page", lambda *_: GLib.idle_add(self.refresh_current))
            self.notebooks[key] = nb
            self.content.add_named(nb, key)
        body.pack_start(self.content, True, True, 0)
        return root

    def on_menu_selected(self, _lb, row):
        if row is not None:
            self.content.set_visible_child_name(MENU[row.get_index()][0])
            self.refresh_current()

    def current(self):
        return self.content.get_visible_child_name()

    def goto(self, key, tab=None):
        idx = [k for k, _ in MENU].index(key)
        self.menu_list.select_row(self.menu_list.get_row_at_index(idx))
        if tab is not None:
            self.notebooks[key].set_current_page(tab)
        self.refresh_current()

    def refresh_current(self, *_):
        if self.stack.get_visible_child_name() != "main":
            return False
        for fn in self.refreshers.get(self.current() or "dash", []):
            fn()
        return False

    # ═══════════════════════════════════════ такт, уведомления
    def on_tick(self):
        E = self.engine
        if self.stack.get_visible_child_name() == 'main' and time.monotonic() - self._last_activity >= 600:
            self.on_logout()
        E.tick()
        self.clock.set_text(time.strftime("%d.%m  %H:%M:%S"))
        st, col = E.state()
        self.status_label.set_markup(
            f'{"ДЕМО" if E.demo else "LIVE"} • <span foreground="{col}" weight="bold">{st}</span>    '
            f'Мониторинг: {"включён" if E.monitoring else "пауза"}    Событий: {fmt_int(E.total)}    '
            f'Открытых тревог: {E.open_alerts()}')
        self.update_badges()
        self.refresh_current()
        return True

    def poll_hardware(self):
        E = self.engine
        if not E.hardware:
            return True
        for _ in range(100):
            try:
                kind, name, data = E.hardware.events.get_nowait()
            except queue.Empty:
                break
            if kind in ("error", "result"):
                text = str(data)
                E.log("ERROR" if kind == "error" else "INFO", f"{name}: {text}")
                E.hardware_messages.appendleft((time.time(), name, text))
                self.toast(f"{name}: {text}")
            elif kind == "memory":
                self.on_memory_result(data)
                if "error" not in data:
                    E.log("INFO", f"MFRC522 {data['action']}: UID {data['uid']}, блок {data['block']}")
            elif kind == "status":
                E.log("INFO", f"{name}: {data['status']} • {data['detail']}")
            elif kind == "neighbors":
                E.devices.clear()
                for item in data:
                    key = item["dst"] + "%" + item["dev"]
                    E.devices[key] = dict(name=key, ip=item["dst"], mac=item["lladdr"],
                                          type=item["dev"], last=time.time(), dst=[], port=[], rate=0, vol=0)
                E.bump("devices")
            elif kind == "data" and E.monitoring:
                if "uid" in data:
                    uid = data["uid"]
                    E.rfid.appendleft((time.time(), uid, name, "Считано"))
                    E.bump("rfid")
                    E.add_event(RFID_OK, name, descr=f"Считан UID {uid}; владелец не проверялся")
                elif "pulse_frame" in data:
                    frame = dict(data['pulse_frame'], ts=time.time(), frequency=data.get('frequency'),
                                 profile=data.get('profile'))
                    E.capture_history.appendleft(frame)
                    decoded = frame.get('decoded')
                    text = (f"PWM24 {decoded['hex']} • {decoded['unit_us']} мкс • "
                            f"{'повтор подтверждён' if decoded['confirmed'] else 'кандидат'}"
                            if decoded else f"RAW • {len(frame['pulses'])} импульсов • протокол не определён")
                    if frame.get('lost_edges_or_frames'):
                        text += f" • потери: {frame['lost_edges_or_frames']}"
                    E.hardware_messages.appendleft((time.time(), name, text))
                    if decoded and decoded['confirmed']:
                        E.add_event(SIG_REP, name, descr=text)
                elif "payload" in data:
                    text = f"RX {data['payload']}"
                    if "rssi" in data:
                        text += f" • {data['rssi']:.1f} dBm"
                    E.hardware_messages.appendleft((time.time(), name, text))
                    E.add_event(SIG_REP, name, descr=text)
        state = E.hardware.snapshot()
        now = state.get("network_updated", time.monotonic())
        counters = {n["name"]: n["rx"] + n["tx"] for n in state.get("network", []) if n["name"] != "lo"}
        elapsed = now - E._network_ts if E._network_ts is not None else 1
        if elapsed > 0:
            delta = sum(max(0, value - E._network_counters.get(key, value)) for key, value in counters.items())
            if E.monitoring:
                E.network_rate = delta / elapsed
                E.total_bytes += delta
            E._network_counters, E._network_ts = counters, now
        return True

    def update_badges(self):
        n = self.engine.open_alerts()
        b = self.badges["events"]
        b.set_text(str(n) if n else "")
        b.set_visible(n > 0)

    def on_engine(self, kind, payload):
        if kind == "alert":
            self.update_badges()
            if SEV_ORDER[payload["sev"]] >= 2:
                self.show_banner(f'Новая тревога {payload["id"]} ({payload["sev"]}): {payload["title"]}')

    def toast(self, text):
        self.toast_label.set_text(text)
        if self._toast_id:
            GLib.source_remove(self._toast_id)
        self._toast_id = GLib.timeout_add_seconds(5, self._clear_toast)

    def _clear_toast(self):
        self.toast_label.set_text("")
        self._toast_id = 0
        return False

    def show_banner(self, text):
        self.banner_label.set_text(text)
        self.banner.set_no_show_all(False)
        self.banner.show_all()
        if self._banner_id:
            GLib.source_remove(self._banner_id)
        self._banner_id = GLib.timeout_add_seconds(10, self.hide_banner)

    def hide_banner(self, *_):
        self.banner.hide()
        self._banner_id = 0
        return False

    def progress(self, bar, seconds, on_done, text=None):
        steps = max(1, int(seconds * 10))
        counter = [0]
        bar.set_fraction(0)
        if text:
            bar.set_text(text)

        def tick():
            counter[0] += 1
            bar.set_fraction(counter[0] / steps)
            if counter[0] >= steps:
                on_done()
                return False
            return True

        GLib.timeout_add(100, tick)

    # ═══════════════════════════════════════ диалоги (крупные, без рамки окна)
    def dialog(self, title, body, buttons=(("Закрыть", None),)):
        dlg = Gtk.Dialog(transient_for=self, modal=True)
        dlg.set_decorated(False)
        dlg.set_position(Gtk.WindowPosition.CENTER_ON_PARENT)
        w = self.get_allocated_width() or self.win_w
        h = self.get_allocated_height() or self.win_h
        dlg.set_default_size(min(640, w - 30), min(400, h - 30))
        frame = vbox(0)
        add_css(frame, "dlg")
        head = hbox(0)
        add_css(head, "dlg-title")
        head.pack_start(lbl(title, ellipsize=True), True, True, 0)
        frame.pack_start(head, False, False, 0)
        sw = Gtk.ScrolledWindow()
        sw.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        sw.set_overlay_scrolling(False)
        for side in ("top", "bottom", "start", "end"):
            getattr(body, f"set_margin_{side}")(12)
        sw.add(body)
        frame.pack_start(sw, True, True, 0)
        row = hbox(8)
        row.set_homogeneous(True)
        for side in ("top", "bottom", "start", "end"):
            getattr(row, f"set_margin_{side}")(10)
        for i, (text, kind) in enumerate(buttons):
            row.pack_start(button(text, lambda _b, i=i: dlg.response(i), kind), True, True, 0)
        frame.pack_end(row, False, False, 0)
        dlg.get_content_area().pack_start(frame, True, True, 0)
        dlg.show_all()
        resp = dlg.run()
        dlg.destroy()
        return resp

    def info(self, title, text):
        self.dialog(title, lbl(text, wrap=True))

    def confirm(self, title, text):
        return self.dialog(title, lbl(text, wrap=True), (("Отмена", None), ("Подтвердить", "primary"))) == 1

    def show_event(self, eid):
        e = self.engine.event_by_id(eid)
        if not e:
            return
        self.dialog(e["type"], kv_rows([
            ("ID", e["id"]), ("Время", fmt_dt(e["ts"]) + time.strftime(":%S", time.localtime(e["ts"]))),
            ("Источник", e["source"]), ("Устройство", e["device"]), ("Приоритет", e["sev"]),
            ("Risk", f"{e['risk']}/100"), ("Уверенность", f"{e['conf']}%"),
            ("Связанные", ", ".join(e["related"]) or "—"), ("Описание", e["descr"])]))

    def show_device(self, name):
        E = self.engine
        d = E.devices.get(name)
        if not d:
            return
        risk = E.device_risk(name)
        last = [e for e in E.events if e["device"] == name and e["weight"] >= 50]
        dev = f"{last[-1]['type']} ({fmt_t(last[-1]['ts'])})" if last and risk != "LOW" else "В пределах нормы"
        self.dialog(name, kv_rows([
            ("IP-адрес", d["ip"]), ("MAC-адрес", d["mac"]), ("Тип", d["type"]),
            ("Активность", f"{ago(d['last'])} назад"), ("Уровень риска", risk),
            ("Обычные адреса", ", ".join(d["dst"])), ("Обычные порты", ", ".join(map(str, d["port"]))),
            ("Профиль трафика", f"≈ {d['vol']} МБ/мин, {d['rate']} соед./мин"), ("Отклонение", dev)]))

    def show_alert(self, aid):
        E = self.engine
        a = next((x for x in E.alerts if x["id"] == aid), None)
        if not a:
            return
        body = kv_rows([("Тревога", a["id"]), ("Время", fmt_dt(a["ts"])), ("Приоритет", a["sev"]),
                        ("Статус", a["status"]), ("Описание", a["title"]),
                        ("События", ", ".join(a["events"]))])
        r = self.dialog(a["id"], body, (("Принять в работу", None), ("Закрыть тревогу", "primary"),
                                        ("Назад", None)))
        if r == 0:
            E.set_alert_status(aid, "В работе")
            self.toast(f"{aid}: принята в работу")
        elif r == 1:
            E.set_alert_status(aid, "Закрыто")
            self.toast(f"{aid}: закрыта")
        self.update_badges()

    def show_anomaly(self, eid):
        e = self.engine.event_by_id(eid)
        if not e:
            return
        rows = [(k, f"{n}  →  {c}") for k, n, c in self.engine.metrics(e)]
        self.dialog(f"{TYPES[e['type']][2] or e['type']}  ·  {e['device']}",
                    kv_rows([("Событие", e["id"]), ("Anomaly score", str(e["factors"].get("anomaly", "—")))]
                            + [("Норма → сейчас: " + k, v) for k, v in rows]))

    def show_chain(self, idx):
        ch = self.engine.chains()
        if idx >= len(ch):
            return
        c = ch[idx]
        lines = "\n".join(f"{fmt_t(e['ts'])}   {e['type']}   [{e['sev']}  {e['risk']}]" for e in c["events"])
        body = vbox(10)
        body.pack_start(kv_rows([("Устройство", c["device"]), ("Уверенность", f"{c['conf']}%"),
                                 ("Приоритет", c["prio"]), ("Risk", f"{c['risk']}/100")]), False, False, 0)
        body.pack_start(lbl(lines, wrap=True), False, False, 0)
        self.dialog("Цепочка связанных событий", body)

    # ═══════════════════════════════════════ ГЛАВНАЯ
    def tab_dash(self):
        E = self.engine
        root = vbox(8)
        cards = hbox(8)
        cards.set_homogeneous(True)
        self.d_cards = [StatCard(t) for t in ("событий", "аномалий", "устройств", "тревог открыто")]
        for c in self.d_cards:
            cards.pack_start(c, True, True, 0)
        root.pack_start(cards, False, False, 0)

        charts = hbox(8)
        charts.set_homogeneous(True)
        self.ch_hour, self.ch_traffic = Chart("bar"), Chart("line")
        for title, ch in (("События по часам", self.ch_hour), ("Трафик, КБ/с (60 с)", self.ch_traffic)):
            box = vbox(2)
            add_css(box, "card")
            box.pack_start(lbl(title, "small"), False, False, 0)
            box.pack_start(ch, False, False, 0)
            charts.pack_start(box, True, True, 0)
        root.pack_start(charts, False, False, 0)

        root.pack_start(lbl("ДЕМО: синтетические данные" if E.demo else
                            "Реальные данные • подключение: Модули • операции: Источники", "small", wrap=True), False, False, 0)
        root.pack_start(lbl("Последние события", "h1"), False, False, 0)
        tbl = Table(["Время", "Приоритет", "Событие", "Устройство"], [80, 110, None, 130], color_cols=[1],
                    scroll=False, on_tap=self.show_event)
        root.pack_start(tbl.widget, False, False, 0)

        def refresh():
            self.d_cards[0].set(fmt_int(E.total))
            self.d_cards[1].set(fmt_int(E.n_anom), AMBER)
            self.d_cards[2].set(str(len(E.devices)))
            n = E.open_alerts()
            self.d_cards[3].set(str(n), RED if n else GREEN)
            hv, hl = E.hourly()
            self.ch_hour.set(hv, hl)
            self.ch_traffic.set(list(E.traffic), [f"{60 - i}с" if i % 15 == 0 else "" for i in range(60)])
            tbl.refresh(E.ver.get("events"), lambda: [
                ((fmt_t(e["ts"]), e["sev"], e["type"], e["device"]), e["id"]) for e in reversed(E.events[-5:])])

        return root, refresh

    # ═══════════════════════════════════════ СЕТЬ
    def tab_net(self):
        E = self.engine
        root = vbox(10)
        self.mon_btn = Gtk.ToggleButton(label="Мониторинг включён")
        self.mon_btn.set_active(E.monitoring)
        self.mon_btn.set_size_request(-1, 56)
        self.mon_btn.connect("toggled", self.on_monitor)
        root.pack_start(self.mon_btn, False, False, 0)

        g = Gtk.Grid(column_spacing=8, row_spacing=8, column_homogeneous=True)
        self.n_cards = [StatCard("ETH0 · 192.168.1.2 · КБ/с"), StatCard("ETH1 · 10.10.0.1 · КБ/с"),
                        StatCard("потоков за сеанс"), StatCard("объём за сеанс")]
        for i, c in enumerate(self.n_cards):
            g.attach(c, i % 2, i // 2, 1, 1)
        root.pack_start(g, False, False, 0)
        root.pack_start(lbl("Link ETH0: онлайн     Link ETH1: онлайн     Режим: пассивный мониторинг",
                            "small"), False, False, 0)

        def refresh():
            kb = E.traffic[-1] if E.traffic else 0
            self.n_cards[0].set(f"{kb * 0.7:.0f}")
            self.n_cards[1].set(f"{kb * 0.3:.0f}")
            self.n_cards[2].set(fmt_int(E.total_flows))
            self.n_cards[3].set(fmt_bytes(E.total_bytes))

        return root, refresh

    def on_monitor(self, btn):
        E = self.engine
        E.monitoring = btn.get_active()
        btn.set_label("Мониторинг включён" if E.monitoring else "Мониторинг приостановлен")
        E.log("INFO", "Monitoring started" if E.monitoring else "Monitoring paused")
        self.toast("Мониторинг запущен" if E.monitoring else "Мониторинг приостановлен")

    def tab_devices(self):
        E = self.engine
        root = vbox(8)
        bar = hbox(8)
        self.scan_lbl = lbl("", "muted")
        bar.pack_start(self.scan_lbl, True, True, 0)
        self.scan_btn = button("Сканировать сеть", self.on_scan, "primary")
        bar.pack_end(self.scan_btn, False, False, 0)
        root.pack_start(bar, False, False, 0)
        self.scan_bar = Gtk.ProgressBar()
        root.pack_start(self.scan_bar, False, False, 0)
        tbl = Table(["Имя", "IP-адрес", "Тип", "Актив.", "Риск"], [150, 130, 110, 80, None], color_cols=[4],
                    on_tap=self.show_device)
        root.pack_start(tbl.widget, True, True, 0)

        def refresh():
            self.scan_lbl.set_text(f"Устройств в сети: {len(E.devices)}")
            tbl.refresh((E.ver.get("devices"), E.ver.get("events"), int(time.time() // 5)), lambda: [
                ((n, d["ip"], d["type"], ago(d["last"]), E.device_risk(n)), n) for n, d in E.devices.items()])

        return root, refresh

    def on_scan(self, *_):
        if self._scanning:
            return
        self._scanning = True
        self.scan_btn.set_sensitive(False)

        def done():
            self._scanning = False
            self.scan_btn.set_sensitive(True)
            self.scan_bar.set_fraction(0)
            ev = self.engine.discover()
            if ev:
                d = self.engine.devices[ev["device"]]
                self.info("Найдено новое устройство", f"{ev['device']} ({d['type']})\nIP: {d['ip']}\n"
                                                    f"MAC: {d['mac']}")
            else:
                self.toast("Сканирование завершено: новых устройств нет")
            self.refresh_current()

        self.progress(self.scan_bar, 1.6, done)

    def tab_flows(self):
        E = self.engine
        tbl = Table(["Время", "Источник", "Назначение", "Порт", "Объём"], [80, 130, 150, 70, None])

        def refresh():
            tbl.refresh(E.ver.get("flows"), lambda: [
                ((fmt_t(t), s, d, p, fmt_bytes(b)), i) for i, (t, s, d, p, b) in enumerate(E.flows)])

        root = vbox(6)
        root.pack_start(lbl("Анализируется поведение соединений, а не отдельные пакеты.", "small"),
                        False, False, 0)
        root.pack_start(tbl.widget, True, True, 0)
        return root, refresh

    # ═══════════════════════════════════════ ИСТОЧНИКИ
    def tab_rfid(self):
        E = self.engine
        root = vbox(8)
        bar = hbox(8)
        bar.pack_start(button("Считать карту", self.on_rfid, "primary"), True, True, 0)
        root.pack_start(bar, False, False, 0)
        root.pack_start(lbl("Считыватель RFID-01 · режим демонстрации: считывание создаёт событие "
                            "и передаёт его в анализ.", "small", wrap=True), False, False, 0)
        tbl = Table(["Время", "UID", "Событие", "Статус"], [80, 120, None, 100], color_cols=[3])
        root.pack_start(tbl.widget, True, True, 0)

        def refresh():
            tbl.refresh(E.ver.get("rfid"), lambda: [((fmt_t(t), uid, et, st), i)
                                                    for i, (t, uid, et, st) in enumerate(E.rfid)])

        return root, refresh

    def on_rfid(self, *_):
        ev = self.engine.rfid_read()
        self.toast(f"{ev['descr']}: {ev['type']} ({ev['sev']})")
        self.refresh_current()

    def tab_radio(self):
        E = self.engine
        root = vbox(6)
        root.pack_start(lbl(f'Wi‑Fi: {colored("Онлайн")}     Bluetooth: {colored("Онлайн")}     '
                            f'Радиомодуль: {colored("Демо")}     GPIO: {colored("Онлайн")}',
                            markup=True), False, False, 0)
        tbl = Table(["Время", "Частота", "Уровень", "ID", "Состояние"], [80, 110, 90, 90, None], color_cols=[4])
        root.pack_start(tbl.widget, True, True, 0)

        def refresh():
            tbl.refresh(E.ver.get("signals"), lambda: [((fmt_t(t), f, lv, sid, st), i)
                                                       for i, (t, f, lv, sid, st) in enumerate(E.signals)])

        return root, refresh

    def tab_sets(self):
        root = vbox(8)
        root.pack_start(lbl("Наборы событий для демонстрации и проверки анализа. Выберите набор и запустите.",
                            "small", wrap=True), False, False, 0)
        self.set_tbl = Table(["Набор", "Описание", "Событий"], [210, None, 80], scroll=False)
        self.set_tbl.set_rows([((n, d, str(len(s))), n) for n, (d, s) in SCENARIOS.items()])
        self.set_tbl.select_first()
        root.pack_start(self.set_tbl.widget, False, False, 0)
        self.sim_btn = button("Запустить выбранный набор", self.on_sim, "primary")
        root.pack_start(self.sim_btn, False, False, 0)
        self.sim_bar = Gtk.ProgressBar()
        self.sim_bar.set_show_text(True)
        self.sim_bar.set_text("Готово к запуску")
        root.pack_start(self.sim_bar, False, False, 0)
        return root, None

    def on_sim(self, *_):
        E = self.engine
        if self._sim_running:
            return
        if not E.monitoring:
            self.toast("Сначала включите мониторинг (Сеть → Обзор)")
            return
        name = self.set_tbl.selected_key() or list(SCENARIOS)[0]
        desc, steps = SCENARIOS[name]
        before = (E.n_anom, len(E.alerts), E.total)
        made = []
        self._sim_running = True
        self.sim_btn.set_sensitive(False)
        self.sim_bar.set_fraction(0)
        self.sim_bar.set_text(f"{name}: 0 / {len(steps)}")
        E.log("INFO", f"Dataset started: {name}")

        def step():
            i = len(made)
            etype, dev = steps[i]
            made.append(E.discover(dev) if etype == NEW_DEV else E.add_event(etype, dev))
            self.sim_bar.set_fraction(len(made) / len(steps))
            self.sim_bar.set_text(f"{name}: {len(made)} / {len(steps)}")
            self.refresh_current()
            if len(made) < len(steps):
                return True
            self._sim_running = False
            self.sim_btn.set_sensitive(True)
            worst = max((m["sev"] for m in made if m), key=lambda s: SEV_ORDER[s], default="LOW")
            ch = E.chains()
            E.log("INFO", "Analysis completed")
            self.info("Набор обработан",
                      f"Событий создано: {len(made)}\nАномалий выявлено: {E.n_anom - before[0]}\n"
                      f"Новых тревог: {len(E.alerts) - before[1]}\nЦепочек связанных событий: {len(ch)}\n"
                      f"Максимальный приоритет: {worst}")
            return False

        GLib.timeout_add(1100, step)

    # ═══════════════════════════════════════ СОБЫТИЯ
    def tab_log(self):
        E = self.engine
        root = vbox(8)
        self.log_filter = Segmented(["Все", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
        root.pack_start(self.log_filter, False, False, 0)
        tbl = Table(["Время", "Приоритет", "Событие", "Устройство"], [80, 110, None, 130], color_cols=[1],
                    on_tap=self.show_event)
        root.pack_start(tbl.widget, True, True, 0)

        def refresh():
            f = self.log_filter.value
            tbl.refresh((E.ver.get("events"), f), lambda: [
                ((fmt_t(e["ts"]), e["sev"], e["type"], e["device"]), e["id"])
                for e in reversed(E.events) if f == "Все" or e["sev"] == f][:120])

        return root, refresh

    def tab_alerts(self):
        E = self.engine
        tbl = Table(["Время", "Приоритет", "Предупреждение", "Статус"], [80, 110, None, 110], color_cols=[1, 3],
                    on_tap=self.show_alert)

        def refresh():
            tbl.refresh(E.ver.get("alerts"), lambda: [
                ((fmt_t(a["ts"]), a["sev"], a["title"], a["status"]), a["id"]) for a in E.alerts[:100]])

        root = vbox(6)
        root.pack_start(lbl("Нажмите на строку, чтобы принять тревогу в работу или закрыть её.", "small"),
                        False, False, 0)
        root.pack_start(tbl.widget, True, True, 0)
        return root, refresh

    def tab_stats(self):
        E = self.engine
        root = vbox(8)
        self.stat_total = lbl("", "muted")
        root.pack_start(self.stat_total, False, False, 0)
        self.ch_src = Chart("bar", height=130)
        self.ch_sev = Chart("bar", colors=[GREEN, AMBER, ORANGE, RED], height=130)
        for title, ch in (("События по источникам", self.ch_src), ("События по приоритету", self.ch_sev)):
            box = vbox(2)
            add_css(box, "card")
            box.pack_start(lbl(title, "small"), False, False, 0)
            box.pack_start(ch, False, False, 0)
            root.pack_start(box, False, False, 0)

        def refresh():
            self.stat_total.set_text(f"В памяти: {len(E.events)} последних событий; всего в базе: {fmt_int(E.total)}")
            self.ch_src.set(E.by_source(), SOURCES)
            self.ch_sev.set(E.by_sev(), list(SEV_ORDER))

        return root, refresh

    # ═══════════════════════════════════════ АНАЛИТИКА
    def tab_situation(self):
        E = self.engine
        root = vbox(8)
        top = hbox(8)
        top.set_homogeneous(True)
        self.s_risk = lbl("", "big-number", markup=True)
        risk_box = vbox(0)
        add_css(risk_box, "card")
        risk_box.pack_start(self.s_risk, False, False, 0)
        risk_box.pack_start(lbl("Risk Score", "stat-title"), False, False, 0)
        self.s_conf, self.s_prio, self.s_dev = StatCard("уверенность"), StatCard("приоритет"), StatCard("устройство")
        top.pack_start(risk_box, True, True, 0)
        side = vbox(6)
        row = hbox(6)
        row.set_homogeneous(True)
        row.pack_start(self.s_conf, True, True, 0)
        row.pack_start(self.s_prio, True, True, 0)
        side.pack_start(row, False, False, 0)
        side.pack_start(self.s_dev, False, False, 0)
        top.pack_start(side, True, True, 0)
        root.pack_start(top, False, False, 0)

        self.meters = {}
        for key, title in (("anomaly", "Anomaly Score"), ("frequency", "Event Frequency"),
                           ("correlation", "Correlation Score"), ("source", "Source Importance"),
                           ("behaviour", "Behaviour Change")):
            m = Meter(title)
            self.meters[key] = m
            root.pack_start(m, False, False, 0)
        self.s_text = lbl("", wrap=True, markup=True)
        root.pack_start(self.s_text, False, False, 4)
        root.pack_start(lbl("Эвристическая оценка по правилам, не модель AI. Процент — условный показатель связи событий.", "small"),
                        False, False, 0)

        def refresh():
            s = E.situation()
            col = COLOR_MAP[s["prio"]]
            self.s_risk.set_markup(f'<span foreground="{col}">{s["risk"]}</span><span foreground="{MUTED}" '
                                   f'size="small"> / 100</span>')
            self.s_conf.set(f"{s['conf']}%")
            self.s_prio.set(s["prio"], col)
            self.s_dev.set(s["device"])
            for k, m in self.meters.items():
                v = s["factors"].get(k, 0)
                m.set(v / 100, str(v))
            self.s_text.set_markup(f"<b>Рекомендация:</b> {esc(s['text'])}\n{esc(s['expl'])}")

        return root, refresh

    def tab_anomalies(self):
        E = self.engine
        tbl = Table(["Время", "Устройство", "Признак", "Score", "Приоритет"], [80, 130, None, 70, 110],
                    color_cols=[4], on_tap=self.show_anomaly)

        def refresh():
            tbl.refresh(E.ver.get("events"), lambda: [
                ((fmt_t(e["ts"]), e["device"], TYPES[e["type"]][2] or e["type"], e["weight"], e["sev"]), e["id"])
                for e in reversed(E.events) if e["weight"] >= 50][:100])

        root = vbox(6)
        root.pack_start(lbl("Отклонения от нормальной активности. Нажмите строку — покажет норму и текущие значения.",
                            "small", wrap=True), False, False, 0)
        root.pack_start(tbl.widget, True, True, 0)
        return root, refresh

    def tab_chains(self):
        E = self.engine
        root = vbox(6)
        self.chain_hint = lbl("", "small", wrap=True)
        root.pack_start(self.chain_hint, False, False, 0)
        tbl = Table(["Устройство", "Событий", "Уверенность", "Приоритет", "Период"], [150, 90, 120, 110, None],
                    color_cols=[3], on_tap=lambda k: self.show_chain(int(k)))
        root.pack_start(tbl.widget, True, True, 0)

        def refresh():
            ch = E.chains()
            self.chain_hint.set_text("Возможные связанные цепочки событий одного устройства (последние 30 минут)."
                                     if ch else "Цепочек пока нет: ожидаются связанные события.")
            tbl.refresh((E.ver.get("events"), len(ch)), lambda: [
                ((c["device"], len(c["events"]), f"{c['conf']}%", c["prio"],
                  f"{fmt_t(c['start'])}–{fmt_t(c['end'])}"), i) for i, c in enumerate(ch)])

        return root, refresh

    # ═══════════════════════════════════════ ОТЧЁТЫ
    def tab_report_new(self):
        E = self.engine
        root = vbox(8)
        root.pack_start(lbl("Период", "kv-key"), False, False, 0)
        self.rep_period = Segmented(["Час", "Сегодня", "Сеанс"], 1)
        root.pack_start(self.rep_period, False, False, 0)
        root.pack_start(lbl("Формат", "kv-key"), False, False, 0)
        self.rep_fmt = Segmented(["HTML", "Markdown"])
        root.pack_start(self.rep_fmt, False, False, 0)
        root.pack_start(lbl("Разделы отчёта", "kv-key"), False, False, 0)
        grid = Gtk.Grid(column_spacing=6, row_spacing=6, column_homogeneous=True)
        self.rep_secs = []
        for i, name in enumerate(REPORT_SECTIONS):
            b = Gtk.ToggleButton(label=name)
            b.set_active(True)
            grid.attach(b, i % 2, i // 2, 1, 1)
            self.rep_secs.append(b)
        root.pack_start(grid, False, False, 0)
        self.rep_btn = button("Сформировать отчёт", self.on_report, "primary")
        root.pack_start(self.rep_btn, False, False, 4)
        self.rep_bar = Gtk.ProgressBar()
        self.rep_bar.set_show_text(True)
        self.rep_bar.set_text("Готов к формированию")
        root.pack_start(self.rep_bar, False, False, 0)
        return root, None

    def on_report(self, *_):
        secs = [b.get_label() for b in self.rep_secs if b.get_active()]
        if not secs:
            self.toast("Выберите хотя бы один раздел")
            return
        period, fmt = self.rep_period.value, self.rep_fmt.value
        self.rep_btn.set_sensitive(False)

        def done():
            try:
                rid, path = self.engine.write_report(period, fmt, secs)
                self.rep_bar.set_text(f"Готово: {rid}")
                self.toast(f"Отчёт {rid} сохранён: {path}")
            except (OSError, sqlite3.Error) as exc:
                self.rep_bar.set_text("Ошибка сохранения")
                self.toast(str(exc))
            finally:
                self.rep_btn.set_sensitive(True)

        self.progress(self.rep_bar, 1.5, done, "Формирование отчёта…")

    def tab_report_list(self):
        E = self.engine
        tbl = Table(["ID", "Создан", "Формат", "Период", "Размер"], [90, 150, 100, 100, None],
                    on_tap=self.show_report)

        def refresh():
            tbl.refresh(E.ver.get("reports", 0) + 1000 * len(E.db.rows("SELECT id FROM reports")), lambda: [
                ((r[0], fmt_dt(r[1]), r[3], r[2], fmt_bytes(r[5])), r[4])
                for r in E.db.rows("SELECT id,ts,period,fmt,path,size FROM reports ORDER BY ts DESC")])

        root = vbox(6)
        root.pack_start(lbl("Нажмите на отчёт, чтобы просмотреть его.", "small"), False, False, 0)
        root.pack_start(tbl.widget, True, True, 0)
        return root, refresh

    def show_report(self, path):
        E = self.engine
        view = Gtk.TextView()
        view.set_editable(False)
        view.set_cursor_visible(False)
        view.set_wrap_mode(Gtk.WrapMode.WORD)
        view.get_buffer().set_text(E.report_text(path))
        r = self.dialog(os.path.basename(path), view, (("Закрыть", None), ("Открыть", None), ("Удалить", None)))
        if r == 1:
            exe = shutil.which("xdg-open")
            if exe:
                subprocess.Popen([exe, path])
            else:
                self.toast("xdg-open недоступен")
        elif r == 2 and self.confirm("Удалить отчёт", "Файл отчёта будет удалён без возможности восстановления."):
            try:
                os.remove(path)
            except OSError:
                pass
            E.db.q("DELETE FROM reports WHERE path=?", (path,))
            E.bump("reports")
            self.toast("Отчёт удалён")

    # ═══════════════════════════════════════ СИСТЕМА
    def tab_sys(self):
        E = self.engine
        root = vbox(8)
        self.m_cpu, self.m_ram, self.m_disk, self.m_temp = (Meter("Процессор"), Meter("Память"),
                                                            Meter("Накопитель"), Meter("Температура"))
        grid = Gtk.Grid(column_spacing=12, row_spacing=6, column_homogeneous=True)
        for i, m in enumerate((self.m_cpu, self.m_ram, self.m_disk, self.m_temp)):
            grid.attach(m, i % 2, i // 2, 1, 1)
        root.pack_start(grid, False, False, 0)
        self.uptime = lbl("", "muted")
        root.pack_start(self.uptime, False, False, 0)
        self.hw = Table(["Компонент", "Описание", "Статус"], [170, None, 120], color_cols=[2], scroll=False)
        root.pack_start(self.hw.widget, False, False, 0)

        def refresh():
            idle, total = read_cpu()
            di, dt = idle - self._cpu[0], total - self._cpu[1]
            self._cpu = (idle, total)
            cpu = 1 - di / dt if dt else 0
            self.m_cpu.set(cpu, f"{cpu * 100:.0f}%")
            tm, av = read_mem()
            self.m_ram.set(1 - av / tm, f"{(tm - av) / 1048576:.1f} / {tm / 1048576:.1f} ГБ")
            du = shutil.disk_usage("/")
            self.m_disk.set(du.used / du.total, f"{du.used / 2 ** 30:.0f} / {du.total / 2 ** 30:.0f} ГБ")
            t = read_temp()
            self.m_temp.set((t or 0) / 100, f"{t:.0f} °C" if t is not None else "нет датчика")
            up = read_uptime()
            self.uptime.set_text(f"Работает: {up // 3600} ч {up % 3600 // 60} мин   ·   Узел: {os.uname().nodename}"
                                 f"   ·   {os.uname().machine}")
            try:
                mon = Gdk.Display.get_default().get_monitor(0).get_geometry()
                disp = f"{mon.width}×{mon.height} px"
            except Exception:
                disp = "—"
            state = self.hw_state()
            self.hw.refresh((str(state), disp), lambda: [
                (("Узел", f"{os.uname().nodename}, {os.uname().machine}", "Онлайн"), "host"),
                (("Дисплей", disp, "Онлайн"), "display"),
            ] + [((key, item.get("detail", ""), item.get("status", "—")), key)
                 for key, item in state.items() if isinstance(item, dict)])

        return root, refresh

    def tab_syslog(self):
        E = self.engine
        tbl = Table(["Время", "Уровень", "Сообщение"], [80, 90, None], color_cols=[1])

        def refresh():
            tbl.refresh(E.ver.get("logs"), lambda: [((fmt_t(t), lv, m), i)
                                                    for i, (t, lv, m) in enumerate(reversed(E.logs))][:120])

        return tbl.widget, refresh

    def tab_db(self):
        E = self.engine
        root = vbox(8)
        self.db_info = lbl("", "small", wrap=True)
        root.pack_start(self.db_info, False, False, 0)
        self.db_tbl = Table(["Таблица", "Записей"], [220, None], scroll=False)
        root.pack_start(self.db_tbl.widget, False, False, 0)
        row = hbox(8)
        row.set_homogeneous(True)
        row.pack_start(button("Резервная копия", self.on_backup), True, True, 0)
        row.pack_start(button("Очистить события", self.on_clear), True, True, 0)
        root.pack_start(row, False, False, 0)

        def refresh():
            self.db_info.set_text(f"Локальная база данных: {E.db.path}  ·  размер {fmt_bytes(E.db.size())}")
            self.db_tbl.refresh((E.ver.get("events"), E.ver.get("alerts"), E.ver.get("logs"), E.ver.get("reports")),
                                lambda: [((t, fmt_int(n)), t) for t, n in E.counts()])

        return root, refresh

    def on_backup(self, *_):
        dst = os.path.join(APP_DIR, f"backup_{time.strftime('%Y%m%d_%H%M%S')}.db")
        try:
            with sqlite3.connect(dst) as target:
                self.engine.db.c.backup(target)
            self.engine.log("INFO", "Database backup created")
            self.toast(f"Копия создана: {dst}")
        except OSError as exc:
            self.toast(f"Ошибка копирования: {exc}")

    def on_clear(self, *_):
        E = self.engine
        if not self.confirm("Очистить события", "Будут удалены все события и тревоги. Продолжить?"):
            return
        E.db.q("DELETE FROM events")
        E.db.q("DELETE FROM alerts")
        E.events.clear()
        E.alerts.clear()
        E.total = E.n_anom = 0
        for name in ("events", "alerts"):
            E.bump(name)
        E.log("WARN", "Events and alerts cleared")
        self.update_badges()
        self.toast("События и тревоги удалены")

    def tab_settings(self):
        E = self.engine
        root = vbox(10)

        def row(title, control, sub=None):
            r = hbox(10)
            col = vbox(0)
            col.pack_start(lbl(title), False, False, 0)
            if sub is not None:
                self.web_lbl = sub
                col.pack_start(sub, False, False, 0)
            r.pack_start(col, True, True, 0)
            r.pack_end(control, False, False, 0)
            r.set_size_request(-1, 56)
            return r

        web_sw = self.web_switch = Gtk.Switch()
        web_sw.set_valign(Gtk.Align.CENTER)
        web_sw.set_active(False)
        web_sub = lbl(self.web.url or "Выключена", "small")
        web_sw.connect("notify::active", self.on_web)
        root.pack_start(row("Веб-панель (только на этом устройстве)", web_sw, web_sub), False, False, 0)

        fs_sw = Gtk.Switch()
        fs_sw.set_valign(Gtk.Align.CENTER)
        fs_sw.set_active(E.settings["fullscreen"] == "1")
        fs_sw.connect("notify::active", self.on_fullscreen)
        root.pack_start(row("Полноэкранный режим", fs_sw), False, False, 0)

        thr = Gtk.Scale.new_with_range(Gtk.Orientation.HORIZONTAL, 30, 95, 5)
        thr.set_value(int(E.settings["threshold"]))
        thr.set_size_request(280, 48)
        thr.set_value_pos(Gtk.PositionType.LEFT)
        thr.connect("value-changed", lambda s: (E.set("threshold", int(s.get_value())),
                                                self.toast(f"Порог тревоги: risk ≥ {int(s.get_value())}")))
        root.pack_start(row("Порог тревоги (Risk Score)", thr), False, False, 0)

        root.pack_start(lbl("Режим: демонстрация" if E.demo else "Рабочий режим • без имитации данных", "kv-key"), False, False, 0)
        opts = ["Низкая", "Средняя", "Высокая"]
        seg = Segmented(opts, opts.index(E.settings["intensity"]),
                        lambda i, v: (E.set("intensity", v), self.toast(f"Интенсивность: {v}")))
        if E.demo:
            root.pack_start(seg, False, False, 0)
        root.pack_start(lbl(f"Экран: {PPI_NOTE}", "small"), False, False, 0)
        return root, None

    def on_web(self, sw, _p):
        E = self.engine
        if sw.get_active():
            url = self.web.start()
            if not url:
                sw.set_active(False)
                self.toast("Не удалось запустить веб-панель")
                return
            E.set("web", 1)
            self.web_lbl.set_text(url)
            E.log("INFO", f"Web dashboard started: {url}")
            self.toast(f"Веб-панель: {url}")
        else:
            self.web.stop()
            E.set("web", 0)
            self.web_lbl.set_text("Выключена")
            E.log("INFO", "Web dashboard stopped")
            self.toast("Веб-панель выключена")

    def on_fullscreen(self, sw, _p):
        self.engine.set("fullscreen", 1 if sw.get_active() else 0)
        (self.fullscreen if sw.get_active() else self.unfullscreen)()


# ════════════════════════════════════════════════════════════════════ запуск
def parse_args(argv):
    parser = argparse.ArgumentParser(description="Axiora — GTK-приложение для Raspberry Pi 5 / Kali Xfce")
    parser.add_argument("--demo", action="store_true", help="изолированная демонстрация без оборудования")
    parser.add_argument("--fullscreen", action="store_true")
    parser.add_argument("--size", default="800x480", help="размер окна, например 1024x600")
    parser.add_argument("--config", help="путь к hardware.json")
    parser.add_argument("--diagnose", action="store_true", help="диагностика без GUI")
    args = parser.parse_args(argv[1:])
    try:
        size = tuple(int(value) for value in args.size.lower().split("x"))
        if len(size) != 2 or size[0] < 800 or size[1] < 480:
            raise ValueError()
    except ValueError:
        parser.error("--size должен быть вида 800x480, минимум 800×480")
    args.size = size
    return args


def main():
    global REPORT_DIR
    args = parse_args(sys.argv)
    if not Gtk.init_check()[0]:
        print("Нет графического дисплея. Запустите Axiora в сеансе Xfce или используйте --diagnose.", file=sys.stderr)
        return 1
    # Keep pre-existing prototype data untouched; it contains simulated history.
    data_dir = os.path.join(APP_DIR, "demo" if args.demo else "live")
    REPORT_DIR = os.path.join(data_dir, "reports")
    os.makedirs(REPORT_DIR, exist_ok=True)
    try:
        engine = Engine(DB(os.path.join(data_dir, "axiora.db")), args.demo, args.config)
    except (ValueError, OSError) as exc:
        print(f"Не удалось запустить Axiora: {exc}", file=sys.stderr)
        return 1
    web = WebPanel(engine)
    provider = Gtk.CssProvider()
    provider.load_from_data(CSS)
    Gtk.StyleContext.add_provider_for_screen(
        Gdk.Screen.get_default(), provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
    win = AxioraWindow(engine, web, args.size, args.fullscreen)
    win.show_all()
    win.banner.hide()
    Gtk.main()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
