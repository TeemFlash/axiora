#!/bin/sh
# Install only the launcher for the current user. No sudo or boot modifications.
set -eu
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
applications_dir="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
mkdir -p "$applications_dir"
python3 - "$project_dir" "$applications_dir/axiora.desktop" <<'PY'
from pathlib import Path
import sys
root, output = sys.argv[1:]
# Desktop Entry quoting rules differ from shell quoting.
path = str(Path(root) / 'axiora.py')
for old, new in [('\\', '\\\\'), ('"', '\\"'), ('`', '\\`'), ('$', '\\$')]:
    path = path.replace(old, new)
path = path.replace('%', '%%')
Path(output).write_text('[Desktop Entry]\nType=Application\nName=Axiora\n'
    'Comment=RFID, Radio, GPS and GPIO console\n'
    f'Exec=/usr/bin/python3 "{path}"\n'
    'Icon=applications-engineering\nTerminal=false\nCategories=Utility;Electronics;\n', encoding='utf-8')
print(f'Ярлык установлен: {output}')
PY
