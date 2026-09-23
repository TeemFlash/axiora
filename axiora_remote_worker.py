#!/usr/bin/env python3
"""One-shot SSH worker; JSON stdin/stdout, fixed registered tools only."""
import base64
import contextlib
import hashlib
import json
from pathlib import Path
import select
import signal
import sys
import tempfile
import threading

from axiora_workbench import CancelledError, TaskContext, Workbench, redact


def main():
    # Read one newline-delimited request; keep stdin open for SSH disconnect detection.
    line = sys.stdin.buffer.readline(1024 * 1024 + 1)
    if len(line) > 1024 * 1024:
        print(json.dumps({'version': 1, 'ok': False, 'error': 'Запрос превышает 1 МиБ'}))
        return 1
    stopped = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stopped.set())
    signal.signal(signal.SIGHUP, lambda *_: stopped.set())
    wb = None
    secrets = []
    try:
        request = json.loads(line)
        if request.get('version') != 1:
            raise ValueError('Несовместимый протокол')
        if request.get('keepalive'):
            def watch_disconnect():
                try:
                    if not sys.stdin.buffer.read(1):
                        stopped.set()
                except (OSError, ValueError):
                    stopped.set()
            threading.Thread(target=watch_disconnect, name='ssh-disconnect', daemon=True).start()
        with tempfile.TemporaryDirectory(prefix='axiora-remote-') as directory:
            wb = Workbench(Path(directory) / 'state')
            project_id = wb.store.create_project('SSH', request['scope'])
            tool, params, _, secrets, scope = wb._prepare(request['tool'], request['params'], project_id, None)
            if tool.id.startswith('system.secret_'):
                raise ValueError('Хранилище секретов недоступно через SSH worker')
            timeout = float(request['timeout'])
            if not 1 <= timeout <= 3600:
                raise ValueError('Тайм-аут 1–3600 секунд')
            ctx = TaskContext(Path(directory) / 'artifacts', scope, stopped, timeout, secrets=secrets)
            # EOF cancels live SSH jobs; standalone one-shot CLI requests omit keepalive.
            with contextlib.redirect_stdout(sys.stderr):
                result = redact(tool.run(ctx, params), secrets)
            ctx.check_cancel()
            result_bytes = len(json.dumps(result, ensure_ascii=False).encode('utf-8'))
            if result_bytes > 20 * 1024 * 1024:
                raise ValueError('JSON результата превышает лимит SSH; уменьшите объём проверки')
            artifacts, omitted, total = [], [], 0
            protocol_bytes = result_bytes + 65536
            for path in sorted(ctx.directory.glob('*')):
                if not path.is_file() or path.is_symlink():
                    continue
                size = path.stat().st_size
                encoded_size = 4 * ((size + 2) // 3) + 1024
                if (size > 8 * 1024 * 1024 or total + size > 16 * 1024 * 1024 or
                        protocol_bytes + encoded_size > 23 * 1024 * 1024):
                    omitted.append({'name': path.name, 'bytes': size, 'reason': 'Лимит SSH передачи'})
                    continue
                raw = path.read_bytes()
                total += len(raw)
                protocol_bytes += encoded_size
                artifacts.append({'name': path.name, 'sha256': hashlib.sha256(raw).hexdigest(),
                                  'base64': base64.b64encode(raw).decode()})
            response = {'version': 1, 'ok': True, 'result': result, 'artifacts': artifacts, 'omitted_artifacts': omitted}
            print(json.dumps(response, ensure_ascii=False))
        return 0
    except Exception as exc:
        print(json.dumps({'version': 1, 'ok': False, 'error': redact(str(exc), secrets)}, ensure_ascii=False))
        return 1
    finally:
        if wb:
            wb.close()


if __name__ == '__main__':
    raise SystemExit(main())
