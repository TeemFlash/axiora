"""GTK3 pages for the persistent, asynchronous Axiora workbench.

The widgets only submit work and render stored results. Network operations and
external commands belong to workbench adapters, never GTK callbacks.
"""
import json
import threading
import time
from pathlib import Path

from gi.repository import Gio, GLib, Gtk, Pango

from axiora_pages import box, button, label, textview


STATUS = {
    "queued": "В очереди", "running": "Выполняется", "succeeded": "Готово",
    "failed": "Ошибка", "cancelled": "Остановлено", "timed_out": "Тайм-аут",
    "interrupted": "Прервано",
}
REVIEW = {"new": "Новая", "confirmed": "Подтверждена", "false_positive": "Ложное срабатывание", "fixed": "Исправлена"}


def _plain(value):
    return json.dumps(value, ensure_ascii=False, indent=2, default=str) if isinstance(value, (dict, list, tuple)) else str(value or "")


def _bounded_json(value, limit=160000):
    """Serialize only the visible prefix of a potentially large scanner result."""
    parts, remaining = [], limit
    for chunk in json.JSONEncoder(ensure_ascii=False, indent=2, default=str).iterencode(value):
        parts.append(chunk[:remaining])
        remaining -= len(chunk)
        if remaining <= 0:
            parts.append("\n… Вывод сокращён; полный результат сохранён в проекте.")
            break
    return "".join(parts)


def _text(widget):
    if isinstance(widget, Gtk.TextView):
        buf = widget.get_buffer()
        return buf.get_text(buf.get_start_iter(), buf.get_end_iter(), True)
    if isinstance(widget, Gtk.ComboBoxText):
        return widget.get_active_id() or ""
    if isinstance(widget, Gtk.CheckButton):
        return widget.get_active()
    return widget.get_text()


def _set_text(view, value):
    text = _plain(value)
    if _text(view) != text:
        view.get_buffer().set_text(text)


def _combo():
    item = Gtk.ComboBoxText()
    item.set_hexpand(True)
    for cell in item.get_cells():
        cell.set_property("ellipsize", Pango.EllipsizeMode.END)
        cell.set_property("width-chars", 24)
    return item


def _table(columns):
    model = Gtk.ListStore(*([str] * (len(columns) + 1)))
    view = Gtk.TreeView(model=model)
    for index, title in enumerate(columns, 1):
        cell = Gtk.CellRendererText(ellipsize=Pango.EllipsizeMode.END)
        col = Gtk.TreeViewColumn(title, cell, text=index)
        col.set_resizable(True)
        col.set_sizing(Gtk.TreeViewColumnSizing.FIXED)
        col.set_fixed_width(145 if index == 1 else 110)
        view.append_column(col)
    scroll = Gtk.ScrolledWindow()
    scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
    scroll.set_min_content_height(130)
    scroll.add(view)
    return model, view, scroll


def _selected(view):
    model, row = view.get_selection().get_selected()
    return model[row][0] if row is not None else None


def _replace_rows(model, view, rows):
    wanted = _selected(view)
    old = [list(row) for row in model]
    if old == rows:
        return
    model.clear()
    selected = None
    for row in rows:
        iterator = model.append(row)
        if row[0] == wanted:
            selected = iterator
    if selected is not None:
        view.get_selection().select_iter(selected)
    elif rows:
        view.get_selection().select_path(0)


class WorkbenchPages:
    @property
    def wb(self):
        return self.engine.workbench

    def _wb_message(self, widget, text):
        widget.set_text(str(text))
        return False

    def _wb_background(self, message, operation, done=None):
        """Keep filesystem exports/copies out of GTK's event loop too."""
        message.set_text("Выполняется…")
        def worker():
            try:
                result = operation()
            except Exception as exc:
                GLib.idle_add(self._wb_message, message, f"Ошибка: {exc}")
            else:
                def complete():
                    message.set_text(f"Готово: {result}")
                    if done:
                        done(result)
                    return False
                GLib.idle_add(complete)
        threading.Thread(target=worker, name="axiora-ui-file", daemon=True).start()

    def _wb_project_selector(self, root):
        root.pack_start(label("Проект и область проверки"), False, False, 0)
        combo = _combo()
        root.pack_start(combo, False, False, 0)
        scope = label("")
        root.pack_start(scope, False, False, 0)
        state = {"updating": False, "rows": None}
        def changed(*_):
            if not state["updating"] and combo.get_active_id():
                self.selected_project = combo.get_active_id()
                refresh()
        def refresh():
            rows = self.wb.store.projects()
            ids = {str(row["id"]) for row in rows}
            current = getattr(self, "selected_project", None)
            if current not in ids:
                current = str(rows[0]["id"]) if rows else None
                self.selected_project = current
            names = [(str(row["id"]), str(row["name"])) for row in rows]
            state["updating"] = True
            if names != state["rows"]:
                combo.remove_all()
                for key, name in names:
                    combo.append(key, name)
                state["rows"] = names
            combo.set_active_id(current)
            state["updating"] = False
            project = next((row for row in rows if str(row["id"]) == current), {})
            value = project.get("scope", "")
            if isinstance(value, (list, tuple)):
                value = ", ".join(value)
            scope.set_text("Цели: " + str(value or "не заданы"))
        combo.connect("changed", changed)
        refresh()
        return combo, refresh

    def _wb_open(self, path, message=None):
        try:
            Gio.AppInfo.launch_default_for_uri(Path(path).resolve().as_uri(), None)
        except Exception as exc:
            if message:
                message.set_text(str(exc))
            else:
                self.toast(str(exc))

    def _wb_choose_file(self, entry):
        dialog = Gtk.FileChooserDialog(title="Выберите файл", transient_for=self,
                                       action=Gtk.FileChooserAction.OPEN)
        dialog.add_buttons("Отмена", Gtk.ResponseType.CANCEL, "Выбрать", Gtk.ResponseType.OK)
        if dialog.run() == Gtk.ResponseType.OK:
            entry.set_text(dialog.get_filename())
        dialog.destroy()

    def clear_workbench_secrets(self):
        for item in getattr(self, "_wb_secret_widgets", []):
            try:
                if isinstance(item, Gtk.TextView):
                    item.get_buffer().set_text("")
                else:
                    item.set_text("")
            except RuntimeError:
                pass

    def tab_workbench_tools(self):
        root = box()
        _, project_refresh = self._wb_project_selector(root)
        root.pack_start(label("Выберите модуль, заполните параметры и запустите задачу. "
                              "Результаты и журнал доступны на вкладке «Задачи»."), False, False, 0)
        self.wb_tool_combo = _combo()
        for tool in sorted(self.wb.tools.values(), key=lambda item: (item.category, item.title)):
            self.wb_tool_combo.append(tool.id, f"{tool.category} / {tool.title}")
        root.pack_start(self.wb_tool_combo, False, False, 0)
        description = label("")
        availability = label("")
        root.pack_start(description, False, False, 0)
        root.pack_start(availability, False, False, 0)
        form = box()
        root.pack_start(form, False, False, 0)
        self._wb_tool_controls = {}
        self._wb_secret_widgets = []
        self.wb_timeout = Gtk.Entry(text="120")
        root.pack_start(label("Лимит времени, секунд"), False, False, 0)
        root.pack_start(self.wb_timeout, False, False, 0)
        remote_frame = Gtk.Expander(label="Удалённый исполнитель через SSH")
        remote_box = box()
        self.wb_remote_enabled = Gtk.CheckButton(label="Выполнить на удалённом узле")
        self.wb_remote_host = Gtk.Entry()
        self.wb_remote_host.set_placeholder_text("SSH alias или user@host")
        self.wb_remote_directory = Gtk.Entry()
        self.wb_remote_directory.set_placeholder_text("Абсолютный каталог Axiora на узле")
        self.wb_remote_port = Gtk.Entry(text="22")
        self.wb_remote_port.set_placeholder_text("Порт SSH")
        for child in (self.wb_remote_enabled, self.wb_remote_host, self.wb_remote_directory, self.wb_remote_port):
            remote_box.pack_start(child, False, False, 0)
        remote_box.pack_start(label("Используется заранее настроенный ключ SSH. Пути входных файлов "
                                    "относятся к удалённому узлу. Его зависимости устанавливаются отдельно."), False, False, 0)
        remote_frame.add(remote_box)
        root.pack_start(remote_frame, False, False, 0)
        message = label("")
        def selected(*_):
            self.clear_workbench_secrets()
            self._wb_secret_widgets = []
            self._wb_tool_controls = {}
            for child in form.get_children():
                form.remove(child)
                child.destroy()
            tool = self.wb.tools.get(self.wb_tool_combo.get_active_id())
            if not tool:
                return
            description.set_text(tool.description)
            self.wb_timeout.set_text(str(tool.timeout))
            for field in tool.fields:
                form.pack_start(label(field.label + (" *" if field.required else "")), False, False, 0)
                if field.kind in ("choice", "select"):
                    item = _combo()
                    for choice in field.choices:
                        key, title = choice if isinstance(choice, (tuple, list)) and len(choice) == 2 else (choice, choice)
                        item.append(str(key), str(title))
                    if not item.set_active_id(str(field.default)):
                        item.set_active(0)
                    widget = item
                elif field.kind in ("bool", "boolean", "check"):
                    item = Gtk.CheckButton(label=field.label)
                    item.set_active(str(field.default).lower() in ("true", "1", "yes"))
                    widget = item
                elif field.kind == "multiline" and not field.secret:
                    item, widget = textview(90)
                    item.set_editable(True)
                    item.set_cursor_visible(True)
                    item.get_buffer().set_text(str(field.default))
                else:
                    item = Gtk.Entry(text=str(field.default or ""))
                    item.set_hexpand(True)
                    item.set_visibility(not (field.secret or field.kind == "password"))
                    if field.kind == "file":
                        widget = Gtk.Box(spacing=6)
                        widget.pack_start(item, True, True, 0)
                        widget.pack_start(button("Файл…", lambda *_, e=item: self._wb_choose_file(e)), False, False, 0)
                    else:
                        widget = item
                if field.secret or field.kind == "password":
                    self._wb_secret_widgets.append(item)
                    if isinstance(item, Gtk.Entry):
                        item.set_placeholder_text("Значение или vault:имя")
                self._wb_tool_controls[field.name] = (field, item)
                form.pack_start(widget, False, False, 0)
            form.show_all()
            refresh()
        def launch(*_):
            try:
                tool_id = self.wb_tool_combo.get_active_id()
                if not tool_id:
                    raise ValueError("Нет доступных модулей")
                params = {}
                for name, (field, item) in self._wb_tool_controls.items():
                    value = _text(item)
                    if field.required and not str(value).strip():
                        raise ValueError(f"Заполните поле: {field.label}")
                    if field.kind in ("int", "integer") and str(value).strip():
                        value = int(value)
                    elif field.kind in ("float", "number") and str(value).strip():
                        value = float(value)
                    params[name] = value
                timeout = int(self.wb_timeout.get_text())
                if timeout <= 0:
                    raise ValueError("Лимит времени должен быть больше нуля")
                remote = None
                if self.wb_remote_enabled.get_active():
                    remote = {"host": self.wb_remote_host.get_text().strip(),
                              "directory": self.wb_remote_directory.get_text().strip()}
                    port = int(self.wb_remote_port.get_text())
                    if not 1 <= port <= 65535:
                        raise ValueError("Порт SSH должен быть от 1 до 65535")
                    if port != 22:
                        remote["port"] = port
                    if not remote["host"] or not remote["directory"].startswith("/"):
                        raise ValueError("Укажите узел SSH и абсолютный каталог Axiora")
                job = self.wb.submit(tool_id, params, self.selected_project, timeout=timeout, remote=remote)
                self.clear_workbench_secrets()
                message.set_text(f"Задача {job} поставлена в очередь. Откройте вкладку «Задачи».")
            except Exception as exc:
                message.set_text(f"Ошибка: {exc}")
        self.wb_launch_button = button("Запустить задачу", launch)
        root.pack_start(self.wb_launch_button, False, False, 0)
        root.pack_start(message, False, False, 0)
        def refresh():
            project_refresh()
            tool_id = self.wb_tool_combo.get_active_id()
            status = next((row for row in self.wb.tool_status() if row["id"] == tool_id), None)
            if status:
                missing = status.get("missing", [])
                availability.set_text("Локально: " + ("готов к запуску" if status.get("available")
                                                      else "не установлено: " + (", ".join(missing) if isinstance(missing, list) else str(missing))))
        self.wb_tool_combo.connect("changed", selected)
        self.wb_tool_combo.set_active(0)
        return root, refresh

    def tab_workbench_jobs(self):
        root = box()
        _, project_refresh = self._wb_project_selector(root)
        model, tree, scroll = _table(["Модуль", "Состояние", "Создана"])
        self.wb_jobs_tree = tree
        root.pack_start(scroll, False, False, 0)
        info = label("Выберите задачу")
        root.pack_start(info, False, False, 0)
        row = Gtk.Box(spacing=6)
        cancel = button("Остановить", lambda *_: act("cancel"))
        open_dir = button("Файлы задачи", lambda *_: act("open"))
        row.pack_start(cancel, True, True, 0)
        row.pack_start(open_dir, True, True, 0)
        root.pack_start(row, False, False, 0)
        output, output_scroll = textview(180)
        root.pack_start(output_scroll, False, False, 0)
        state = {"jobs": {}, "detail_key": None, "details_text": ""}
        def show(*_):
            job = state["jobs"].get(_selected(tree), {})
            cancel.set_sensitive(job.get("status") in ("queued", "running"))
            open_dir.set_sensitive(bool(job.get("artifact_dir")))
            if not job:
                info.set_text("Нет задач в этом проекте")
                _set_text(output, "")
                return
            info.set_text(f"{job['id']} • {STATUS.get(job.get('status'), job.get('status', ''))}\n"
                          f"{job.get('summary') or job.get('error') or ''}")
            detail_key = tuple(job.get(key) for key in ("id", "status", "finished", "progress"))
            if detail_key != state["detail_key"]:
                try:
                    selected = self.wb.store.get_job(job["id"]) if hasattr(self.wb.store, "get_job") else job
                    details = {key: selected.get(key) for key in ("tool_id", "status", "progress", "params", "result", "error")
                               if selected.get(key) is not None}
                    state["details_text"] = _bounded_json(details)
                    state["detail_key"] = detail_key
                except (OSError, ValueError) as exc:
                    state["details_text"] = f"Результат задачи недоступен: {exc}"
            log = job.get("log_tail", "")
            if hasattr(self.wb, "job_log"):
                try:
                    log = self.wb.job_log(job["id"], max_bytes=32000)
                except (OSError, ValueError) as exc:
                    log = f"Журнал недоступен: {exc}"
            _set_text(output, state["details_text"] + "\n\nЖУРНАЛ\n" + str(log)[-64000:])
        def act(action):
            job = state["jobs"].get(_selected(tree))
            if not job:
                return
            try:
                if action == "cancel":
                    self.wb.cancel(job["id"])
                else:
                    self._wb_open(job["artifact_dir"], info)
            except Exception as exc:
                info.set_text(str(exc))
        tree.get_selection().connect("changed", show)
        comparison = Gtk.Expander(label="Сравнить результаты двух задач")
        content = box()
        first, second = _combo(), _combo()
        content.pack_start(label("Ранее"), False, False, 0)
        content.pack_start(first, False, False, 0)
        content.pack_start(label("Позднее"), False, False, 0)
        content.pack_start(second, False, False, 0)
        compare_view, compare_scroll = textview(140)
        def compare(*_):
            try:
                if not first.get_active_id() or not second.get_active_id():
                    raise ValueError("Выберите две задачи")
                _set_text(compare_view, self.wb.compare_jobs(first.get_active_id(), second.get_active_id()))
            except Exception as exc:
                _set_text(compare_view, str(exc))
        content.pack_start(button("Сравнить", compare), False, False, 0)
        content.pack_start(compare_scroll, False, False, 0)
        comparison.add(content)
        root.pack_start(comparison, False, False, 0)
        previous = [None]
        def refresh():
            project_refresh()
            jobs = self.wb.jobs(project_id=self.selected_project, include_results=False)
            state["jobs"] = {str(job["id"]): job for job in jobs}
            rows = []
            for job in jobs:
                created = job.get("created")
                stamp = time.strftime("%d.%m %H:%M:%S", time.localtime(created)) if isinstance(created, (int, float)) else str(created or "")
                tool = self.wb.tools.get(job.get("tool_id"))
                rows.append([str(job["id"]), tool.title if tool else str(job.get("tool_id", "")), STATUS.get(job.get("status"), str(job.get("status", ""))), stamp])
            _replace_rows(model, tree, rows)
            ids = [(str(job["id"]), f"{job.get('tool_id')} • {str(job['id'])[:12]}") for job in jobs]
            if ids != previous[0]:
                for index, combo in enumerate((first, second)):
                    current = combo.get_active_id()
                    combo.remove_all()
                    for key, title in ids:
                        combo.append(key, title)
                    if not current or not combo.set_active_id(current):
                        combo.set_active(min(index, len(ids) - 1))
                previous[0] = ids
            show()
        refresh()
        return root, refresh

    def tab_workbench_projects(self):
        root = box()
        project_combo, project_refresh = self._wb_project_selector(root)
        name = Gtk.Entry()
        scope, scope_scroll = textview(75)
        scope.set_editable(True)
        scope.set_cursor_visible(True)
        notes, notes_scroll = textview(85)
        notes.set_editable(True)
        notes.set_cursor_visible(True)
        for title, widget in (("Название", name), ("Область: IP, CIDR, имена узлов; по одному на строку", scope_scroll), ("Заметки", notes_scroll)):
            root.pack_start(label(title), False, False, 0)
            root.pack_start(widget, False, False, 0)
        state = {"editing": None, "loaded": object()}
        message = label("")
        def load():
            if state["loaded"] == self.selected_project:
                return
            project = next((row for row in self.wb.store.projects() if str(row["id"]) == self.selected_project), {})
            state["loaded"] = self.selected_project
            state["editing"] = project.get("id")
            name.set_text(project.get("name", ""))
            value = project.get("scope", "")
            _set_text(scope, "\n".join(value) if isinstance(value, (tuple, list)) else value)
            _set_text(notes, project.get("notes", ""))
        def new(*_):
            state["editing"] = None
            name.set_text("")
            _set_text(scope, "")
            _set_text(notes, "")
            message.set_text("Заполните название и область нового проекта, затем сохраните.")
            name.grab_focus()
        def save(*_):
            try:
                fields = {"name": name.get_text().strip(), "scope": _text(scope), "notes": _text(notes)}
                if not fields["name"]:
                    raise ValueError("Введите название проекта")
                if state["editing"]:
                    self.wb.store.update_project(state["editing"], **fields)
                    project_id = state["editing"]
                else:
                    project_id = self.wb.store.create_project(**fields)
                self.selected_project = str(project_id)
                state["editing"] = project_id
                state["loaded"] = self.selected_project
                project_refresh()
                message.set_text("Проект сохранён")
            except Exception as exc:
                message.set_text(str(exc))
        actions = Gtk.Box(spacing=6)
        actions.pack_start(button("Новый проект", new), True, True, 0)
        actions.pack_start(button("Сохранить проект", save), True, True, 0)
        root.pack_start(actions, False, False, 0)
        root.pack_start(message, False, False, 0)
        attachments = Gtk.Expander(label="Вложения и отчёты")
        body = box()
        path = Gtk.Entry()
        path.set_placeholder_text("Путь к файлу для добавления в проект")
        body.pack_start(path, False, False, 0)
        body.pack_start(button("Выбрать файл…", lambda *_: self._wb_choose_file(path)), False, False, 0)
        attachment_note = Gtk.Entry()
        attachment_note.set_placeholder_text("Комментарий к вложению")
        body.pack_start(attachment_note, False, False, 0)
        def attach(*_):
            project_id, source, note = self.selected_project, path.get_text(), attachment_note.get_text()
            if not source:
                message.set_text("Выберите файл")
                return
            self._wb_background(message, lambda: self.wb.store.attach(project_id, source, note=note))
        body.pack_start(button("Скопировать файл в проект", attach), False, False, 0)
        attached_view, attached_scroll = textview(100)
        body.pack_start(attached_scroll, False, False, 0)
        report_row = Gtk.Box(spacing=6)
        exported = {"path": None}
        for fmt in ("html", "json", "pdf"):
            def export(*_, format=fmt):
                project_id = self.selected_project
                self._wb_background(message, lambda: self.wb.export_report(project_id, format=format),
                                    lambda value: exported.update(path=str(value)))
            report_row.pack_start(button(fmt.upper(), export), True, True, 0)
        body.pack_start(report_row, False, False, 0)
        body.pack_start(button("Открыть последний отчёт", lambda *_: self._wb_open(exported["path"], message)
                               if exported["path"] else message.set_text("Сначала сформируйте отчёт")), False, False, 0)
        attachments.add(body)
        root.pack_start(attachments, False, False, 0)
        inventory = Gtk.Expander(label="Устройства проекта")
        inventory_body = box()
        asset_model, asset_tree, asset_scroll = _table(["Устройство", "Имя", "Обновлено"])
        asset_view, asset_detail_scroll = textview(110)
        inventory_body.pack_start(asset_scroll, False, False, 0)
        inventory_body.pack_start(asset_detail_scroll, False, False, 0)
        inventory.add(inventory_body)
        root.pack_start(inventory, False, False, 0)
        asset_rows = {}
        def select_asset(*_):
            _set_text(asset_view, asset_rows.get(_selected(asset_tree), "Устройства ещё не обнаружены"))
        asset_tree.get_selection().connect("changed", select_asset)
        def refresh():
            project_refresh()
            load()
            rows = self.wb.store.attachments(self.selected_project)
            _set_text(attached_view, rows or "Вложений пока нет")
            if hasattr(self.wb.store, "assets"):
                assets = self.wb.store.assets(self.selected_project)
                asset_rows.clear()
                asset_rows.update({str(row["id"]): row for row in assets})
                table_rows = []
                for row in assets:
                    data = row.get("data", {})
                    updated = row.get("updated")
                    stamp = time.strftime("%d.%m %H:%M:%S", time.localtime(updated)) if isinstance(updated, (int, float)) else str(updated or "")
                    names = data.get("hostname") or data.get("hostnames") or data.get("names") or data.get("name") or ""
                    if isinstance(names, list):
                        names = ", ".join(str(name) for name in names)
                    table_rows.append([str(row["id"]), str(row.get("identity", "")), str(names), stamp])
                _replace_rows(asset_model, asset_tree, table_rows)
                select_asset()
        project_combo.connect("changed", lambda *_: load())
        refresh()
        return root, refresh

    def tab_workbench_findings(self):
        root = box()
        _, project_refresh = self._wb_project_selector(root)
        root.pack_start(label("Находки содержат исходные доказательства и рекомендации. "
                              "Подтверждение и повторная проверка фиксируются отдельно от результата сканера."), False, False, 0)
        model, tree, scroll = _table(["Находка", "Уровень", "Статус"])
        self.wb_findings_tree = tree
        root.pack_start(scroll, False, False, 0)
        details, details_scroll = textview(150)
        root.pack_start(details_scroll, False, False, 0)
        review = _combo()
        for key, title in REVIEW.items():
            review.append(key, title)
        root.pack_start(review, False, False, 0)
        note = Gtk.Entry()
        note.set_placeholder_text("Комментарий проверяющего")
        root.pack_start(note, False, False, 0)
        message = label("")
        state = {"findings": {}, "editing": None}
        def selected(*_):
            current = _selected(tree)
            finding = state["findings"].get(current)
            _set_text(details, finding or "Находок пока нет")
            if current == state["editing"] or not current:
                return
            state["editing"] = current
            review.set_active_id(finding.get("status", "new"))
            note.set_text(str(finding.get("review_note", finding.get("note", "")) or ""))
        def save(*_):
            try:
                current = _selected(tree)
                if not current:
                    raise ValueError("Выберите находку")
                self.wb.store.review_finding(current, review.get_active_id() or "new", note=note.get_text())
                message.set_text("Результат проверки сохранён")
                refresh()
            except Exception as exc:
                message.set_text(str(exc))
        root.pack_start(button("Сохранить проверку", save), False, False, 0)
        root.pack_start(message, False, False, 0)
        tree.get_selection().connect("changed", selected)
        def refresh():
            project_refresh()
            rows = self.wb.store.findings(self.selected_project)
            state["findings"] = {str(row["id"]): row for row in rows}
            _replace_rows(model, tree, [[str(row["id"]), str(row.get("title", "")), str(row.get("severity", "")),
                                       REVIEW.get(row.get("status"), str(row.get("status", "new")))] for row in rows])
            selected()
        refresh()
        return root, refresh

    def tab_workbench_modules(self):
        root = box()
        root.pack_start(label("Доступность локальных модулей. Отсутствующая зависимость не заменяется демо-результатом. "
                              "Установка пакетов и настройка прав описаны в README."), False, False, 0)
        model, tree, scroll = _table(["Модуль", "Доступность", "Зависимости"])
        root.pack_start(scroll, False, False, 0)
        details, details_scroll = textview(160)
        root.pack_start(details_scroll, False, False, 0)
        message = label("")
        state = {"items": {}}
        def selected(*_):
            row = state["items"].get(_selected(tree), {})
            tool = self.wb.tools.get(row.get("id"))
            detail = dict(row)
            if tool:
                detail["description"] = tool.description
                detail["requires"] = list(tool.requires)
                detail["timeout"] = tool.timeout
            _set_text(details, detail)
        def versions(*_):
            try:
                job = self.wb.probe_versions(project_id=getattr(self, "selected_project", None))
                message.set_text(f"Проверка версий запущена: {job}. Результат во вкладке «Задачи».")
            except Exception as exc:
                message.set_text(str(exc))
        root.pack_start(button("Проверить версии инструментов", versions), False, False, 0)
        root.pack_start(message, False, False, 0)
        tree.get_selection().connect("changed", selected)
        def refresh():
            rows = self.wb.tool_status()
            state["items"] = {str(row["id"]): row for row in rows}
            data = []
            for row in rows:
                missing = row.get("missing", [])
                missing = ", ".join(str(item) for item in missing) if isinstance(missing, (tuple, list)) else str(missing)
                data.append([str(row["id"]), str(row.get("title", row["id"])), "Готов" if row.get("available") else "Требует установки", missing])
            _replace_rows(model, tree, data)
            selected()
        refresh()
        return root, refresh
