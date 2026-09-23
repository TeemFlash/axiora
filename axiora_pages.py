"""GTK pages backed by HardwareService; imported lazily to keep the CLI headless."""
import copy
import json
import os
import shutil
import subprocess
import time

from gi.repository import Gtk, Gdk, GLib
from axiora_hardware import NAMES, PINOUT, save_config


def box():
    return Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)


def label(text):
    item = Gtk.Label(label=text, xalign=0)
    item.set_line_wrap(True)
    item.set_max_width_chars(65)
    return item


def button(text, callback):
    item = Gtk.Button(label=text)
    item.connect("clicked", callback)
    return item


def textview(height=130):
    view = Gtk.TextView(editable=False, cursor_visible=False, monospace=True)
    view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
    scroll = Gtk.ScrolledWindow()
    scroll.set_min_content_height(height)
    scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
    scroll.add(view)
    return view, scroll


class HardwarePages:
    def hw_command(self, action, name=None, data=None):
        if not self.engine.hardware:
            self.toast("Оборудование доступно при запуске без --demo")
            return
        try:
            self.engine.hardware.submit(action, name, data)
        except Exception as exc:
            self.toast(str(exc))

    def hw_state(self):
        return self.engine.hardware.snapshot() if self.engine.hardware else {}

    def hw_controls(self, name):
        row = Gtk.Box(spacing=6)
        row.pack_start(button("Подключить", lambda *_: self.hw_command("connect", name)), True, True, 0)
        row.pack_start(button("Отключить", lambda *_: self.hw_command("disconnect", name)), True, True, 0)
        return row

    def tab_hardware(self):
        root = box()
        root.pack_start(label("Raspberry Pi 5 • общая SPI0 • нумерация BCM"), False, False, 0)
        root.pack_start(label("RDM6300: GPIO4 — TX UART2, RX находится на GPIO5, который занят MFRC522 CS. "
                              "Используйте USB–UART либо перенесите TX считывателя на GPIO13 (pin 33), RX UART4."), False, False, 0)
        rows = {}
        for key, name in NAMES.items():
            frame = Gtk.Frame(label=name)
            body = box()
            body.set_margin_start(10)
            body.set_margin_end(10)
            body.set_margin_bottom(8)
            rows[key] = label("")
            body.pack_start(rows[key], False, False, 0)
            if key in self.engine.hardware_config:
                body.pack_start(self.hw_controls(key), False, False, 0)
            frame.add(body)
            root.pack_start(frame, False, False, 0)
        root.pack_start(button("Обновить диагностику", lambda *_: self.hw_command("inspect")), False, False, 0)
        lost = label("")
        root.pack_start(lost, False, False, 0)
        def refresh():
            state = self.hw_state()
            count = state.get("dropped_events", 0)
            lost.set_text(f"Пропущено событий из-за заполнения очереди: {count}" if count else "")
            for key, widget in rows.items():
                item = state.get(key, {})
                widget.set_text(f"{item.get('status', 'Демо')} • {item.get('detail', 'Оборудование не используется')}")
        return root, refresh

    def tab_pinout(self):
        root = box()
        root.pack_start(label("GPIO (BCM) / физический контакт / назначение"), False, False, 0)
        for gpio, physical, role in PINOUT:
            root.pack_start(label(f"GPIO{gpio:<2}  /  {physical:<2}  /  {role}"), False, False, 0)
        root.pack_start(label("Общий GND обязателен. Сигналы GPIO — 3,3 В. GPS TX → GPIO15; GPS RX ← GPIO14. "
                              "XPT2046 обслуживает драйвер ADS7846. RDM6300: перенесите TX на GPIO13, физический pin 33."), False, False, 0)
        return root, None

    def tab_hardware_config(self):
        root = box()
        root.pack_start(label("Пути устройств относятся к overlay Axiora. После сохранения соединения закрываются; "
                              "подключите модули заново. SPI CS меняются в Device Tree, а не здесь."), False, False, 0)
        controls = {}
        for key, values in self.engine.hardware_config.items():
            root.pack_start(label(NAMES[key]), False, False, 0)
            row = Gtk.Box(spacing=6)
            enabled = Gtk.CheckButton(label="Включён")
            enabled.set_active(values["enabled"])
            path = Gtk.Entry(text=values["device"], hexpand=True)
            row.pack_start(enabled, False, False, 0)
            row.pack_start(path, True, True, 0)
            root.pack_start(row, False, False, 0)
            controls[key] = {"enabled": enabled, "device": path}
            for field in ("baud", "channel", "address", "frequency", "mode", "modulation", "bitrate", "bandwidth", "deviation", "sync"):
                if field not in values:
                    continue
                row = Gtk.Box(spacing=8)
                row.pack_start(label({"baud": "Скорость UART", "channel": "Канал 0–125", "address": "Адрес HEX, 5 байт",
                                      "frequency": "Частота, МГц", "mode": "CC1101: режим",
                                      "modulation": "Модуляция пакетов", "bitrate": "Скорость, кбит/с",
                                      "bandwidth": "Полоса RX, кГц", "deviation": "Девиация, кГц",
                                      "sync": "Sync, 2 байта HEX"}[field]), True, True, 0)
                if field in ("mode", "modulation"):
                    entry = Gtk.ComboBoxText()
                    for option in (("packet", "ook_raw") if field == "mode" else ("2-FSK", "GFSK", "OOK")):
                        entry.append(option, option)
                    entry.set_active_id(values[field])
                else:
                    entry = Gtk.Entry(text=str(values[field]))
                controls[key][field] = entry
                row.pack_end(entry, False, False, 0)
                root.pack_start(row, False, False, 0)
        message = label("")
        def save(*_):
            config = copy.deepcopy(self.engine.hardware_config)
            try:
                for key, items in controls.items():
                    for field, widget in items.items():
                        value = (widget.get_active() if field == "enabled" else widget.get_active_id()
                                 if field in ("mode", "modulation") else widget.get_text().strip())
                        if field in ("baud", "channel"):
                            value = int(value)
                        elif field in ("frequency", "bitrate", "bandwidth", "deviation"):
                            value = float(value)
                        config[key][field] = value
                config = save_config(self.engine.config_path, config)
                self.engine.hardware_config = config
                controls['cc1101']['modulation'].set_active_id(config['cc1101']['modulation'])
                self.hw_command("configure", data=config)
                message.set_text("Настройки сохранены")
            except Exception as exc:
                message.set_text(str(exc))
        root.pack_start(button("Сохранить настройки модулей", save), False, False, 0)
        root.pack_start(message, False, False, 0)
        return root, None

    def tab_live_rfid(self):
        root = box()
        root.pack_start(label("MFRC522: UID карт ISO14443A, 13,56 МГц. RDM6300: идентификаторы 125 кГц. "
                              "Чтение идёт автоматически после подключения; удерживаемая карта не засоряет журнал."), False, False, 0)
        statuses = {}
        for name in ("mfrc522", "rdm6300"):
            statuses[name] = label("")
            root.pack_start(statuses[name], False, False, 0)
            root.pack_start(self.hw_controls(name), False, False, 0)
        view, scroll = textview()
        root.pack_start(scroll, True, True, 0)
        def refresh():
            state = self.hw_state()
            for name, widget in statuses.items():
                item = state.get(name, {})
                widget.set_text(f"{NAMES[name]} • {item.get('status', '—')} • {item.get('detail', '')}")
            view.get_buffer().set_text("\n".join(f"{time.strftime('%H:%M:%S', time.localtime(t))}  {uid}  {event}"
                                                for t, uid, event, _ in self.engine.rfid) or "Карты ещё не считаны")
        return root, refresh

    def tab_card_memory(self):
        root = box()
        root.pack_start(label("MIFARE Classic Mini / 1K / 4K • MFRC522. Нужен ключ соответствующего сектора. "
                              "Запись меняет один блок данных (16 байт); сначала считайте этот блок. "
                              "Блок производителя и sector trailer доступны только для чтения."), False, False, 0)
        root.pack_start(self.hw_controls("mfrc522"), False, False, 0)
        self.memory_block = Gtk.SpinButton.new_with_range(0, 255, 1)
        self.memory_block.set_value(4)
        self.memory_key_type = Gtk.ComboBoxText()
        for value in ('A', 'B'):
            self.memory_key_type.append(value, 'Key ' + value)
        self.memory_key_type.set_active(0)
        self.memory_key = Gtk.Entry(visibility=False)
        self.memory_key.set_placeholder_text("Ключ: 12 HEX-символов")
        row = Gtk.Box(spacing=6)
        row.pack_start(label("Блок"), False, False, 0)
        row.pack_start(self.memory_block, False, False, 0)
        row.pack_start(self.memory_key_type, False, False, 0)
        row.pack_start(self.memory_key, True, True, 0)
        root.pack_start(row, False, False, 0)
        root.pack_start(label("Ключ не сохраняется в настройках, базе или отчётах. "
                              "Для заводской тестовой карты часто используется FFFFFFFFFFFF."), False, False, 0)
        self.memory_read_btn = button("Считать блок", lambda *_: self.memory_request('read'))
        root.pack_start(self.memory_read_btn, False, False, 0)
        self.memory_data = Gtk.Entry()
        self.memory_data.set_placeholder_text("Данные для записи: 32 HEX-символа (16 байт)")
        root.pack_start(self.memory_data, False, False, 0)
        self.memory_write_btn = button("Записать 16 байт в считанный блок", lambda *_: self.memory_request('write'))
        self.memory_write_btn.set_sensitive(False)
        root.pack_start(self.memory_write_btn, False, False, 0)
        self.memory_info = label("Ожидается чтение блока")
        root.pack_start(self.memory_info, False, False, 0)
        self.memory_preview = None
        self.memory_busy = False
        self.memory_block.connect('value-changed', lambda *_: self.clear_memory_preview())
        self.memory_key_type.connect('changed', lambda *_: self.clear_memory_preview())
        return root, None

    def clear_memory_preview(self):
        self.memory_preview = None
        self.memory_write_btn.set_sensitive(False)

    def memory_request(self, action):
        if self.memory_busy or not self.engine.hardware:
            return
        block = self.memory_block.get_value_as_int()
        try:
            key = self.memory_key.get_text().strip()
            if len(bytes.fromhex(key)) != 6:
                raise ValueError('Нужен ключ из 6 байт HEX')
            request = dict(action=action, block=block, key_hex=key,
                           key_type=self.memory_key_type.get_active_id())
            if action == 'write':
                if not self.memory_preview or self.memory_preview['block'] != block:
                    raise ValueError('Сначала считайте выбранный блок')
                payload = bytes.fromhex(self.memory_data.get_text())
                if len(payload) != 16:
                    raise ValueError('Для записи нужны ровно 16 байт HEX')
                request.update(expected_uid=self.memory_preview['uid'], payload=payload,
                               expected_data=bytes.fromhex(self.memory_preview['data']))
            self.engine.hardware.submit('memory', 'mfrc522', request)
            self.memory_busy = True
            self.memory_read_btn.set_sensitive(False)
            self.memory_write_btn.set_sensitive(False)
            self.memory_info.set_text('Операция выполняется… держите одну карту у считывателя')
        except (ValueError, RuntimeError) as exc:
            self.memory_info.set_text(str(exc))

    def on_memory_result(self, result):
        self.memory_busy = False
        self.memory_read_btn.set_sensitive(True)
        # A completed operation must not restore secret data after logout.
        if self.stack.get_visible_child_name() != 'main':
            self.clear_memory_preview()
            return
        if 'error' in result:
            self.clear_memory_preview()
            self.memory_info.set_text(result['error'])
            return
        self.memory_preview = result
        self.memory_data.set_text(result['data'])
        self.memory_info.set_text(f"UID {result['uid']} • Classic {result['card_type']} • "
            f"сектор {result['sector']} • блок {result['block']}\n"
            f"{'Записано и проверено чтением' if result['action'] == 'write' else 'Считано'}: {result['data']}")
        from axiora_protocols import classic_block
        try:
            classic_block(result['block'], result['sak'], writing=True)
            self.memory_write_btn.set_sensitive(result['block'] == self.memory_block.get_value_as_int())
        except ValueError:
            self.memory_write_btn.set_sensitive(False)

    def export_pulses(self, *_):
        frames = list(self.engine.capture_history)
        if not frames:
            self.toast('Нет захваченных импульсов; выберите CC1101 ook_raw и подключите модуль')
            return
        chooser = Gtk.FileChooserDialog(title='Сохранить OOK-захват', transient_for=self,
                                        action=Gtk.FileChooserAction.SAVE)
        chooser.add_buttons('Отмена', Gtk.ResponseType.CANCEL, 'Сохранить', Gtk.ResponseType.OK)
        chooser.set_current_name('axiora-ook.json')
        chooser.set_do_overwrite_confirmation(True)
        try:
            if chooser.run() == Gtk.ResponseType.OK:
                with open(chooser.get_filename(), 'w', encoding='utf-8') as stream:
                    json.dump({'format': 'axiora-ook-v1', 'frames': frames}, stream, ensure_ascii=False, indent=2)
                self.toast('OOK-захват сохранён')
        except OSError as exc:
            self.toast(str(exc))
        finally:
            chooser.destroy()

    def tab_nrf24(self):
        return self.radio_page("nrf24", "nRF24L01+PA+LNA • 2,4 ГГц • 1 Мбит/с • CRC 2 байта • "
                               "пакет 32 байта • без ACK. Приём требует совпадения канала, адреса и профиля второго модуля.")

    def tab_cc1101(self):
        return self.radio_page("cc1101", "CC1101 • packet: 2-FSK/GFSK/OOK, CRC, 1–60 байт. "
                               "ook_raw: приём импульсов через GDO0/ GPIO23. "
                               "Профиль выбирается в Модули → Настройка.")

    def radio_page(self, name, description):
        root = box()
        root.pack_start(label(description), False, False, 0)
        status = label("")
        root.pack_start(status, False, False, 0)
        root.pack_start(self.hw_controls(name), False, False, 0)
        payload = Gtk.Entry()
        payload.set_placeholder_text("Пакет HEX, например 48656C6C6F")
        root.pack_start(payload, False, False, 0)
        def send(*_):
            try:
                value = bytes.fromhex(payload.get_text())
                if not 1 <= len(value) <= (32 if name == "nrf24" else 60):
                    raise ValueError("Неверная длина пакета")
                self.hw_command("send", name, value.hex())
            except ValueError as exc:
                self.toast(f"Ошибка HEX: {exc}")
        send_button = button("Передать пакет", send)
        root.pack_start(send_button, False, False, 0)
        if name == "cc1101":
            root.pack_start(button("Измерить RSSI", lambda *_: self.hw_command("sample", name)), False, False, 0)
            root.pack_start(button("Сохранить OOK-импульсы (JSON)", self.export_pulses), False, False, 0)
            root.pack_start(label("PWM24 EV1527/PT2262: распознавание формата, а не модели устройства. "
                                  "Два одинаковых кадра подтверждают повтор; остальные сигналы остаются RAW."), False, False, 0)
        view, scroll = textview()
        root.pack_start(scroll, True, True, 0)
        def refresh():
            item = self.hw_state().get(name, {})
            settings = self.engine.hardware_config[name]
            radio_config = (f"канал {settings['channel']} • адрес {settings['address']}" if name == "nrf24"
                            else f"{settings['frequency']} МГц • {settings['mode']} • "
                                 f"{settings['modulation']} • {settings['bitrate']} кбит/с")
            send_button.set_sensitive(item.get('status') == 'Подключён' and
                                      (name != 'cc1101' or settings['mode'] == 'packet'))
            status.set_text(f"{item.get('status', '—')} • {radio_config} • {item.get('detail', '')}")
            lines = [f"{time.strftime('%H:%M:%S', time.localtime(t))}  {text}" for t, source, text
                     in self.engine.hardware_messages if source == name]
            view.get_buffer().set_text("\n".join(lines[:60]) or "Принятых пакетов пока нет")
        return root, refresh

    def tab_gps(self):
        root = box()
        root.pack_start(label("NEO-6M • GPS TX → GPIO15 (pin 10), GPS RX ← GPIO14 (pin 8). "
                              "9600 8N1 по умолчанию; скорость на модуле могла быть изменена."), False, False, 0)
        root.pack_start(self.hw_controls("gps"), False, False, 0)
        info = label("")
        root.pack_start(info, False, False, 0)
        raw, scroll = textview(90)
        root.pack_start(scroll, True, True, 0)
        def refresh():
            item = self.hw_state().get("gps", {})
            fresh = time.time() - item.get("updated", 0) < 5 and item.get("status") == "Подключён"
            fix = fresh and item.get("fix") and item.get("lat") is not None and item.get("lon") is not None
            position = f"{item['lat']:.6f}, {item['lon']:.6f}" if fix else "Нет актуального определения координат"
            def current(field):
                value = item.get(field)
                age = time.time() - item.get("field_updated", {}).get(field, 0)
                return "—" if value is None or age >= 5 else f"{value:.1f}" if isinstance(value, float) else str(value)
            info.set_text(f"{item.get('status', '—')} • {item.get('detail', '')}\n\n{position}\n"
                          f"Спутники: {current('satellites') if fresh else '—'}   "
                          f"Высота: {current('altitude') if fix else '—'} м\n"
                          f"Скорость: {current('speed') if fix else '—'} км/ч   "
                          f"UTC: {item.get('utc', '—') if fresh else '—'}")
            raw.get_buffer().set_text(item.get("sentence", "Ожидание проверенных NMEA RMC/GGA"))
        return root, refresh

    def tab_touch(self):
        root = box()
        status = label("")
        root.pack_start(status, False, False, 0)
        root.pack_start(label("XPT2046 • CS16 / IRQ21 • ADS7846. Коснитесь поля. Координаты приходят от Xfce/libinput. "
                              "Мышь также работает; этот тест сам по себе не подтверждает подключение сенсора."), False, False, 0)
        area = Gtk.DrawingArea()
        area.set_size_request(-1, 150)
        area.add_events(Gdk.EventMask.BUTTON_PRESS_MASK | Gdk.EventMask.POINTER_MOTION_MASK)
        point = [None, None]
        coords = label("Ожидание касания")
        def event(_widget, ev):
            point[:] = [ev.x, ev.y]
            coords.set_text(f"X={ev.x:.0f}, Y={ev.y:.0f}")
            area.queue_draw()
            return True
        def draw(widget, cr):
            cr.set_source_rgb(0.94, 0.97, 1)
            cr.paint()
            if point[0] is not None:
                cr.set_source_rgb(0.08, 0.47, 0.77)
                cr.arc(*point, 12, 0, 6.2832)
                cr.fill()
        area.connect("draw", draw)
        area.connect("button-press-event", event)
        root.pack_start(area, True, True, 0)
        root.pack_start(coords, False, False, 0)
        def refresh():
            item = self.hw_state().get("touch", {})
            status.set_text(f"{item.get('status', '—')} • {item.get('detail', '')}")
        return root, refresh

    def tab_live_net(self):
        root = box()
        root.pack_start(label("Интерфейсы Linux, адреса и реальные счётчики RX/TX. "
                              "W5500 появляется после загрузки драйвера w5100-spi."), False, False, 0)
        view, scroll = textview(180)
        root.pack_start(scroll, True, True, 0)
        root.pack_start(button("Настроить подключения Xfce", self.open_network_settings), False, False, 0)
        def refresh():
            rows = self.hw_state().get("network", [])
            view.get_buffer().set_text("\n\n".join(
                f"{n['name']} • {n['state']} • {n['driver']}\n"
                f"IP: {', '.join(n['addresses']) or 'нет'}\nMAC: {n['mac']}\n"
                f"RX {n['rx']:,} байт / TX {n['tx']:,} байт" for n in rows) or "Ожидание данных Linux")
        return root, refresh

    def open_network_settings(self, *_):
        executable = shutil.which("nm-connection-editor")
        if executable:
            subprocess.Popen([executable])
        else:
            self.toast("Установите network-manager-gnome для nm-connection-editor")

    def tab_live_neighbors(self):
        root = box()
        root.pack_start(label("ARP/ND-кэш Linux. Здесь только соседи, уже известные системе; "
                              "это не полный список устройств сети."), False, False, 0)
        root.pack_start(button("Обновить соседей", lambda *_: self.hw_command("neighbors")), False, False, 0)
        view, scroll = textview()
        root.pack_start(scroll, True, True, 0)
        def refresh():
            view.get_buffer().set_text("\n".join(f"{n['ip']}  {n['mac']}  {n['type']}" for n in self.engine.devices.values())
                                      or "Нажмите «Обновить соседей». Кэш может быть пуст.")
        return root, refresh

    def tab_account(self):
        root = box()
        root.pack_start(label("Локальная учётная запись admin. Начальный пароль для разработки: admin."), False, False, 0)
        entries = []
        for hint in ("Текущий пароль", "Новый пароль (минимум 8 символов)", "Повторите новый пароль"):
            entry = Gtk.Entry(visibility=False)
            entry.set_placeholder_text(hint)
            root.pack_start(entry, False, False, 0)
            entries.append(entry)
        result = label("")
        def change(*_):
            old, new, repeat = [item.get_text() for item in entries]
            if not self.engine.credentials.verify("admin", old):
                result.set_text("Текущий пароль неверен")
            elif len(new) < 8 or new != repeat:
                result.set_text("Пароли должны совпадать и содержать минимум 8 символов")
            else:
                try:
                    self.engine.credentials.change(new)
                    for entry in entries:
                        entry.set_text("")
                    result.set_text("Пароль изменён")
                except OSError as exc:
                    result.set_text(str(exc))
        root.pack_start(button("Изменить пароль", change), False, False, 0)
        root.pack_start(result, False, False, 0)
        return root, None
