#!/bin/sh
# Install only the launcher for the current user. No sudo or boot modifications.
set -eu
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
applications_dir="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
mkdir -p "$applications_dir"
python3 - "$project_dir" "$applications_dir/axiora.desktop" <<'PY'
from pathlib import Path
import os
import sys
root, output = sys.argv[1:]
local_python = Path(root) / '.venv/bin/python'
interpreter = os.environ.get('AXIORA_PYTHON') or (str(local_python) if local_python.is_file() else '/usr/bin/python3')
if not Path(interpreter).is_absolute() or not os.access(interpreter, os.X_OK):
    raise SystemExit('AXIORA_PYTHON должен указывать на существующий исполняемый Python абсолютным путём')
# Desktop Entry quoting rules differ from shell quoting.
def quoted(path):
    if '\n' in path or '\r' in path:
        raise SystemExit('Путь ярлыка не должен содержать переводы строки')
    for old, new in [('\\', '\\\\'), ('"', '\\"'), ('`', '\\`'), ('$', '\\$')]:
        path = path.replace(old, new)
    return '"' + path.replace('%', '%%') + '"'
Path(output).write_text('[Desktop Entry]\nType=Application\nName=Axiora\n'
    'Comment=Network diagnostics, security, RFID and radio workbench\n'
    f'Exec={quoted(interpreter)} {quoted(str(Path(root) / "axiora.py"))}\n'
    'Icon=applications-engineering\nTerminal=false\nCategories=Utility;Network;Electronics;\n', encoding='utf-8')
print(f'Ярлык установлен: {output}')
PY
