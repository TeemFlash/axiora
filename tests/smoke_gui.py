"""Run in an existing desktop session: python3 tests/smoke_gui.py."""
import os
from pathlib import Path
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
# All data is disposable; never touch a user's Axiora database.
temp = tempfile.TemporaryDirectory(prefix='axiora-smoke-')
os.environ['AXIORA_HOME'] = temp.name
import axiora as app
from gi.repository import Gtk, Gdk, GLib

failures = []
sys.excepthook = lambda kind, value, tb: failures.append(f'{kind.__name__}: {value}')

def pump():
    for _ in range(20):
        while Gtk.events_pending():
            Gtk.main_iteration_do(False)
        time.sleep(.01)

provider = Gtk.CssProvider()
provider.load_from_data(app.CSS)
Gtk.StyleContext.add_provider_for_screen(Gdk.Screen.get_default(), provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
engine = app.Engine(app.DB(str(Path(temp.name) / 'live.db')))
window = app.AxioraWindow(engine, app.WebPanel(engine), (800, 480))
window.show_all()
window.banner.hide()
pump()
assert window.stack.get_visible_child_name() == 'login'
window.entry_login.set_text('admin')
window.entry_pass.set_text('wrong')
window.on_login()
assert window.stack.get_visible_child_name() == 'login'
window.entry_pass.set_text('admin')
window.on_login()
pump()
assert window.stack.get_visible_child_name() == 'main'
assert engine.total == 0 and not engine.devices
for key, notebook in window.notebooks.items():
    for page in range(notebook.get_n_pages()):
        window.goto(key, page)
        pump()
        print(f'OK {key}/{page} size={window.get_size().width}x{window.get_size().height}')
assert window.get_size().width == 800, window.get_size()
# Check the same credentials protect the local HTTP API.
import base64
import json
from urllib.request import Request, urlopen
from urllib.error import HTTPError
url = window.web.start()
assert url
try:
    urlopen(url + '/api', timeout=2)
    raise AssertionError('Unauthenticated API request was accepted')
except HTTPError as exc:
    assert exc.code == 401
request = Request(url + '/api', headers={'Authorization': 'Basic ' + base64.b64encode(b'admin:admin').decode()})
with urlopen(request, timeout=2) as response:
    assert json.load(response)['events'] == 0
# Feed real-shaped worker output through the GTK/SQLite bridge.
engine.hardware.emit('data', 'mfrc522', {'uid': '04:01:02:03'})
engine.hardware.emit('data', 'nrf24', {'payload': 'ABCD'})
window.poll_hardware()
assert engine.total == 2 and engine.rfid[0][1] == '04:01:02:03'
# Exercise the memory editor without touching a physical card.
window.goto('src', 1)
pump()
window.memory_key.set_text('FFFFFFFFFFFF')
preview = dict(uid='04:01:02:03', sak=8, action='read', block=4, sector=1,
               card_type='1K', before='00' * 16, data='00' * 16, verified=True)
window.on_memory_result(preview)
assert window.memory_write_btn.get_sensitive()
window.memory_block.set_value(5)
assert not window.memory_write_btn.get_sensitive()
window.memory_block.set_value(4)
window.on_memory_result({'error': 'test auth failure'})
assert window.memory_preview is None
# Verify real-shaped pulse frames reach capture history without false RFID events.
engine.hardware.emit('data', 'cc1101', {'pulse_frame': {'pulses': [[1, 350], [0, 10850]], 'decoded': None},
                                      'frequency': 433.92, 'profile': {'mode': 'ook_raw'}})
window.poll_hardware()
assert len(engine.capture_history) == 1
assert engine.total == 2
window.goto('hardware', 0)
pump()
shot_dir = Path('/tmp/axiora-ui')
shot_dir.mkdir(exist_ok=True)
def screenshot(name):
    width, height = window.get_size()
    import cairo
    surface = cairo.ImageSurface(cairo.FORMAT_ARGB32, width, height)
    window.draw(cairo.Context(surface))
    surface.write_to_png(str(shot_dir / name))
screenshot('hardware.png')
window.goto('src', 1)
pump()
screenshot('card-memory.png')
window.goto('src', 3)
pump()
screenshot('cc1101.png')
window.goto('dash')
pump()
screenshot('dashboard.png')
window.on_logout()
pump()
screenshot('login.png')
assert window.stack.get_visible_child_name() == 'login'
assert window.web.server is None
assert not window.memory_key.get_text()
assert window.memory_preview is None
window.destroy()
pump()
assert not engine.hardware.thread.is_alive()
assert not failures, failures
print('GUI smoke passed; screenshots /tmp/axiora-ui')
temp.cleanup()
