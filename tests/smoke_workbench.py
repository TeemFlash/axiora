"""GTK workbench contract smoke; run with a display or xvfb-run -a.

Uses a fake manager: never starts scans, opens a serial port or requires root.
"""
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import gi
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk
from axiora_tool_api import Field, Tool
from axiora_workbench_pages import WorkbenchPages


def pump():
    for _ in range(10):
        while Gtk.events_pending():
            Gtk.main_iteration_do(False)
        time.sleep(.005)


class Store:
    def __init__(self):
        self.project_rows = [{"id": "p1", "name": "Лаборатория", "scope": ["127.0.0.1/32", "::1/128"], "notes": "Начальные заметки"}]
        self.finding_rows = [{"id": "f1", "project_id": "p1", "title": "Проверка TLS", "severity": "info", "status": "new", "evidence": "test"}]
        self.attachment_rows = []
        self.job_rows = []
        self.job_reads = []

    def projects(self):
        return self.project_rows

    def create_project(self, name, scope, notes=""):
        key = "p" + str(len(self.project_rows) + 1)
        self.project_rows.append(dict(id=key, name=name, scope=scope, notes=notes))
        return key

    def update_project(self, project_id, **fields):
        next(row for row in self.project_rows if row["id"] == project_id).update(fields)

    def attachments(self, project_id):
        return [row for row in self.attachment_rows if row["project_id"] == project_id]

    def attach(self, project_id, path, note=""):
        self.attachment_rows.append(dict(project_id=project_id, path=path, note=note))
        return path

    def findings(self, project_id):
        return [row for row in self.finding_rows if row["project_id"] == project_id]

    def review_finding(self, finding_id, status, note=""):
        next(row for row in self.finding_rows if row["id"] == finding_id).update(status=status, review_note=note)

    def get_job(self, job_id):
        self.job_reads.append(job_id)
        return dict(next(row for row in self.job_rows if row["id"] == job_id))


class Workbench:
    def __init__(self, path):
        self.store = Store()
        self.path = path
        self.submitted = []
        self.cancelled = []
        self.probed = False
        self.job_list_modes = []
        self.job_rows = [dict(id="j1", tool_id="test", project_id="p1", status="running", created=time.time(),
                             params={"target": "127.0.0.1"}, result={"evidence": "full-selected-job"},
                             log_tail="streamed output", artifact_dir=str(path))]
        self.store.job_rows = self.job_rows
        fields = (Field("target", "Цель", "127.0.0.1", required=True),
                  Field("secret", "Пароль", kind="password", secret=True),
                  Field("choice", "Режим", "two", kind="select", choices=("one", "two")),
                  Field("multi", "Несколько строк", "first\nsecond", kind="multiline"),
                  Field("count", "Количество", "3", kind="int"),
                  Field("file", "Файл", kind="file"),
                  Field("enabled", "Включено", "true", kind="bool"))
        tool = Tool("test", "Проверка элементов управления", "Диагностика", "Тестовая форма без внешних команд", fields, (), lambda *_: {}, timeout=30)
        self.tools = {tool.id: tool}

    def submit(self, tool_id, params, project_id, timeout=120, remote=None):
        self.submitted.append(dict(tool_id=tool_id, params=params, project_id=project_id, timeout=timeout, remote=remote))
        return "j2"

    def jobs(self, project_id=None, include_results=True):
        self.job_list_modes.append(include_results)
        return [dict(row, result=row["result"] if include_results else {}) for row in self.job_rows
                if not project_id or row["project_id"] == project_id]

    def cancel(self, job_id):
        self.cancelled.append(job_id)

    def tool_status(self):
        return [dict(id="test", title="Тест", available=True, missing=[], path="")]

    def compare_jobs(self, first, second):
        return {"first": first, "second": second, "changes": []}

    def export_report(self, project_id, format="html"):
        path = self.path / (project_id + "." + format)
        path.write_text("report", encoding="utf-8")
        return str(path)

    def probe_versions(self, project_id=None):
        self.probed = True
        return "versions"


class Window(WorkbenchPages, Gtk.Window):
    def __init__(self, workbench):
        Gtk.Window.__init__(self)
        self.set_default_size(800, 480)
        self.engine = SimpleNamespace(workbench=workbench)
        self.refreshers = []
        self.pages = []
        self.notebook = Gtk.Notebook(scrollable=True)
        for title, method in (("Инструменты", self.tab_workbench_tools), ("Задачи", self.tab_workbench_jobs),
                              ("Проекты", self.tab_workbench_projects), ("Находки", self.tab_workbench_findings),
                              ("Модули", self.tab_workbench_modules)):
            page, refresh = method()
            self.pages.append(page)
            self.refreshers.append(refresh)
            scroll = Gtk.ScrolledWindow()
            scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
            scroll.add(page)
            self.notebook.append_page(scroll, Gtk.Label(label=title))
        row = Gtk.Box()
        nav = Gtk.Label(label="Axiora")
        nav.set_size_request(140, -1)
        row.pack_start(nav, False, False, 0)
        row.pack_start(self.notebook, True, True, 0)
        self.add(row)

    def toast(self, text):
        self.last_toast = text


def descendants(root):
    yield root
    if isinstance(root, Gtk.Container):
        for child in root.get_children():
            yield from descendants(child)


def click(root, name):
    next(item for item in descendants(root) if isinstance(item, Gtk.Button) and item.get_label() == name).clicked()
    pump()


def main():
    failures = []
    original_hook = sys.excepthook
    def capture(kind, value, traceback):
        failures.append(f"{kind.__name__}: {value}")
        original_hook(kind, value, traceback)
    sys.excepthook = capture
    with tempfile.TemporaryDirectory(prefix="axiora-workbench-ui-") as directory:
        manager = Workbench(Path(directory))
        window = Window(manager)
        window.show_all()
        pump()
        for index, refresh in enumerate(window.refreshers):
            window.notebook.set_current_page(index)
            refresh()
            pump()
            assert window.get_size().width == 800, window.get_size()
            assert window.get_size().height == 480, window.get_size()
        controls = window._wb_tool_controls
        controls["secret"][1].set_text("temporary-password")
        window.wb_launch_button.clicked()
        pump()
        assert manager.submitted[-1]["params"]["secret"] == "temporary-password"
        assert manager.submitted[-1]["params"]["count"] == 3
        assert manager.submitted[-1]["params"]["enabled"] is True
        assert manager.submitted[-1]["params"]["choice"] == "two"
        assert not controls["secret"][1].get_text()
        controls["target"][1].set_text("")
        window.wb_launch_button.clicked()
        assert len(manager.submitted) == 1
        controls["target"][1].set_text("127.0.0.2")
        window.refreshers[0]()
        assert controls["target"][1].get_text() == "127.0.0.2"
        window.wb_remote_enabled.set_active(True)
        window.wb_remote_host.set_text("lab")
        window.wb_remote_directory.set_text("/opt/axiora")
        window.wb_launch_button.clicked()
        assert manager.submitted[-1]["remote"] == {"host": "lab", "directory": "/opt/axiora"}
        click(window.pages[1], "Остановить")
        assert manager.cancelled == ["j1"]
        # Repeated ticks must not read all historical results or reload the
        # selected result unless its metadata changes. Logs still update.
        reads = len(manager.store.job_reads)
        window.refreshers[1]()
        window.refreshers[1]()
        assert len(manager.store.job_reads) == reads
        assert manager.job_list_modes and not any(manager.job_list_modes)
        output = next(item for item in descendants(window.pages[1]) if isinstance(item, Gtk.TextView))
        def visible_output():
            buf = output.get_buffer()
            return buf.get_text(buf.get_start_iter(), buf.get_end_iter(), True)
        assert "full-selected-job" in visible_output()
        manager.job_rows[0]["log_tail"] = "new streamed log"
        window.refreshers[1]()
        assert "new streamed log" in visible_output()
        assert len(manager.store.job_reads) == reads
        manager.job_rows[0]["progress"] = "Second step"
        window.refreshers[1]()
        assert len(manager.store.job_reads) == reads + 1
        manager.job_rows[0].update(status="succeeded", finished=time.time(), result={"large": "x" * 2000000})
        window.refreshers[1]()
        assert len(manager.store.job_reads) == reads + 2
        assert len(visible_output()) < 161000 and "Вывод сокращён" in visible_output()
        click(window.pages[1], "Сравнить")
        click(window.pages[3], "Сохранить проверку")
        assert "review_note" in manager.store.finding_rows[0]
        click(window.pages[4], "Проверить версии инструментов")
        assert manager.probed
        # Project edits must survive the regular refresh tick.
        project_entries = [item for item in descendants(window.pages[2]) if isinstance(item, Gtk.Entry)]
        project_entries[0].set_text("Несохранённые правки")
        window.refreshers[2]()
        assert project_entries[0].get_text() == "Несохранённые правки"
        click(window.pages[2], "Сохранить проект")
        assert manager.store.project_rows[0]["name"] == "Несохранённые правки"
        click(window.pages[2], "JSON")
        for _ in range(20):
            pump()
            if (Path(directory) / "p1.json").exists():
                break
        assert (Path(directory) / "p1.json").exists()
        controls["secret"][1].set_text("logout-secret")
        window.clear_workbench_secrets()
        assert not controls["secret"][1].get_text()
        window.destroy()
        pump()
    sys.excepthook = original_hook
    assert not failures, failures
    print("Workbench GTK smoke passed: five tabs at 800x480, fields, submit, stop, projects, review, export, secret cleanup")


if __name__ == "__main__":
    main()
