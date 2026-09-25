#!/bin/sh
# One entry point; package installation needs sudo, the desktop application does not.
set -eu
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ "$(id -u)" = 0 ]; then
    echo 'Запустите ./install-and-run.sh без sudo. Скрипт сам запросит необходимые права.' >&2
    exit 1
fi
if [ ! -x /usr/bin/python3 ]; then
    if ! command -v apt-get >/dev/null 2>&1 || ! command -v sudo >/dev/null 2>&1; then
        echo 'Нужны Kali/Debian, sudo и /usr/bin/python3.' >&2
        exit 1
    fi
    for argument in "$@"; do
        case "$argument" in
            --) break ;;
            --help|-h|--dry-run|--run-only)
                echo 'Для этой команды сначала установите python3: sudo apt-get install python3' >&2
                exit 1 ;;
        esac
    done
    sudo -- apt-get update
    sudo -- env DEBIAN_FRONTEND=noninteractive apt-get install -y python3
fi
exec /usr/bin/python3 "$project_dir/axiora_setup.py" "$@"
