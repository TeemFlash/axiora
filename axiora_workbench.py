"""Bounded task execution and evidence-based network workbench (no GTK)."""
import base64
import hashlib
import html
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import queue
import re
import shlex
import shutil
import signal
import subprocess
import threading
import time
from urllib.parse import urlsplit

from axiora_projects import ProjectStore, uid
from axiora_tool_api import CommandResult, Field, Tool


class CancelledError(RuntimeError):
    pass


class TaskTimeout(TimeoutError):
    pass


def target_identity(value):
    value = str(value).strip()
    if not value or any(c.isspace() for c in value) or value.startswith('-'):
        raise ValueError('Цель должна быть одним IP, CIDR, именем узла или HTTP(S) URL')
    if '://' in value:
        url = urlsplit(value)
        if url.scheme not in ('http', 'https') or not url.hostname or url.username or url.password:
            raise ValueError('Ожидается HTTP(S) URL без учётных данных')
        _ = url.port
        value = url.hostname
    value = value.rstrip('.').lower()
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        if not re.fullmatch(r'(?=.{1,253}$)[a-z0-9](?:[a-z0-9_.-]*[a-z0-9])?', value):
            raise ValueError('Недопустимая цель: ' + value) from None
        return value


class Scope:
    """Explicit IP/CIDR and exact DNS names; no implicit DNS expansion."""
    def __init__(self, text):
        self.text = str(text)
        values = [part for part in re.split(r'[\s,;]+', self.text) if part]
        if len(values) > 1024:
            raise ValueError('Не более 1024 целей в области проверки')
        self.entries = [target_identity(value) for value in values]

    def check(self, target):
        candidate = target_identity(target)
        for entry in self.entries:
            if isinstance(entry, str) and isinstance(candidate, str) and entry == candidate:
                return
            if not isinstance(entry, str) and not isinstance(candidate, str):
                if entry.version == candidate.version and candidate.subnet_of(entry):
                    return
        raise ValueError(f'Цель {target} отсутствует в области проверки проекта')


def dependency_path(name):
    if '|' in name:
        return next((path for candidate in name.split('|') if (path := dependency_path(candidate))), None)
    if name.startswith('python:'):
        try:
            spec = importlib.util.find_spec(name[7:])
            return str(spec.origin or name) if spec else None
        except (ModuleNotFoundError, ValueError):
            return None
    return shutil.which(name)


def redact(value, secrets):
    if isinstance(value, dict):
        return {str(k): redact(v, secrets) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v, secrets) for v in value]
    if isinstance(value, tuple):
        return [redact(v, secrets) for v in value]
    if isinstance(value, str):
        for secret in sorted(set(secrets), key=len, reverse=True):
            if secret:
                value = value.replace(secret, '[REDACTED]')
    return value


def secret_parts(value):
    """Redact secret JSON leaf values too (HTTP headers/body can be echoed)."""
    parts = {str(value)} if value else set()
    def visit(item):
        if isinstance(item, dict):
            for child in item.values():
                visit(child)
        elif isinstance(item, list):
            for child in item:
                visit(child)
        elif isinstance(item, str) and item:
            parts.add(item)
            if item.lower().startswith(('bearer ', 'basic ')):
                parts.add(item.split(' ', 1)[1])
            # Cookie values may be echoed individually by HTTP endpoints.
            if '=' in item:
                for entry in item.split(';'):
                    if '=' in entry:
                        token = entry.split('=', 1)[1].strip()
                        if token:
                            parts.add(token)
    try:
        visit(json.loads(str(value)))
    except (ValueError, TypeError):
        visit(str(value))
    return parts


class TaskContext:
    def __init__(self, directory, scope, cancelled=None, timeout=120, progress=None, secrets=()):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.directory, 0o700)
        self.scope = Scope(scope)
        self.cancelled = cancelled or threading.Event()
        self.deadline = time.monotonic() + float(timeout)
        self.progress = progress or (lambda _: None)
        self.secrets = tuple(str(v) for v in secrets if v)
        self.log_path = self.directory / 'task.log'
        self.process = None
        self._last_disk_check = 0

    def path(self, name):
        candidate = self.directory / str(name)
        if Path(name).is_absolute() or candidate.resolve().parent != self.directory.resolve():
            raise ValueError('Имя артефакта должно быть простым именем файла')
        if candidate.is_symlink():
            raise ValueError('Символические ссылки в артефактах запрещены')
        return candidate

    def save_json(self, name, data):
        path = self.path(name)
        encoded = json.dumps(redact(data, self.secrets), ensure_ascii=False, indent=2)
        if len(encoded.encode()) > 64 * 1024 * 1024:
            raise ValueError('Артефакт превышает 64 МиБ')
        path.write_text(encoded, encoding='utf-8')
        os.chmod(path, 0o600)
        return str(path)

    def log(self, text):
        text = redact(str(text), self.secrets)
        size = self.log_path.stat().st_size if self.log_path.exists() else 0
        remaining = 16 * 1024 * 1024 - size
        if remaining > 0:
            with self.log_path.open('ab') as stream:
                os.chmod(self.log_path, 0o600)
                stream.write((text + '\n').encode('utf-8', errors='replace')[:remaining])

    def emit(self, text):
        text = redact(str(text), self.secrets)
        self.progress(text[-4000:])
        self.log(text)

    def check_target(self, target):
        self.scope.check(target)

    def check_cancel(self):
        if self.cancelled.is_set():
            raise CancelledError('Задача остановлена')
        if time.monotonic() >= self.deadline:
            raise TaskTimeout('Превышено время выполнения задачи')
        if time.monotonic() - self._last_disk_check > .5:
            self._last_disk_check = time.monotonic()
            total = 0
            for path in self.directory.rglob('*'):
                if path.is_symlink():
                    raise RuntimeError('Недопустимая ссылка в артефактах')
                if path.is_file():
                    size = path.stat().st_size
                    total += size
                    if size > 64 * 1024 * 1024:
                        raise RuntimeError('Артефакт превысил 64 МиБ; задача остановлена')
            if total > 256 * 1024 * 1024:
                raise RuntimeError('Артефакты задачи превысили 256 МиБ')

    @staticmethod
    def _terminate(proc):
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            proc.wait(timeout=2)
            return
        try:
            proc.wait(timeout=1)
        except subprocess.TimeoutExpired:
            pass
        # The leader may have exited while descendants still hold our pipes.
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait(timeout=2)

    def run(self, argv, timeout=None, stdin=None, output_name=None, allowed_exit=(0,), env=None,
            max_output=2 * 1024 * 1024, keep_stdin_open=False, log_output=True):
        self.check_cancel()
        if not isinstance(argv, (list, tuple)) or not argv or any(not isinstance(v, (str, Path)) for v in argv):
            raise ValueError('Команда задаётся списком аргументов')
        argv = [str(v) for v in argv]
        if any('\0' in value for value in argv):
            raise ValueError('Недопустимый аргумент команды')
        self.emit('$ ' + shlex.join(argv))
        command_env = os.environ.copy()
        command_env.update({'LC_ALL': 'C', 'LANG': 'C'})
        if env:
            command_env.update(env)
        local_deadline = min(self.deadline, time.monotonic() + float(timeout)) if timeout else self.deadline
        chunks = {'stdout': bytearray(), 'stderr': bytearray()}
        truncated = threading.Event()
        raw_error = []
        raw_path = self.path(output_name) if output_name else None
        raw_file = raw_path.open('wb') if raw_path else None
        if raw_path:
            os.chmod(raw_path, 0o600)
        try:
            proc = subprocess.Popen(argv, stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=command_env,
                                    cwd=self.directory, start_new_session=True, umask=0o077)
        except Exception:
            if raw_file:
                raw_file.close()
            raise
        self.process = proc

        def drain(name, stream):
            try:
                while True:
                    block = stream.read(65536)
                    if not block:
                        break
                    if raw_file and name == 'stdout':
                        if raw_file.tell() + len(block) > 64 * 1024 * 1024:
                            raise RuntimeError('Вывод превысил 64 МиБ')
                        raw_file.write(block)
                    keep = max(0, max_output - len(chunks[name]))
                    chunks[name].extend(block[:keep])
                    if len(block) > keep:
                        truncated.set()
            except Exception as exc:
                raw_error.append(exc)
            finally:
                stream.close()

        readers = [threading.Thread(target=drain, args=(name, getattr(proc, name)), daemon=True)
                   for name in chunks]
        for reader in readers:
            reader.start()
        writer = None
        if stdin is not None:
            def feed():
                try:
                    proc.stdin.write(stdin.encode() if isinstance(stdin, str) else stdin)
                    proc.stdin.flush()
                    if not keep_stdin_open:
                        proc.stdin.close()
                except (BrokenPipeError, OSError):
                    pass
            writer = threading.Thread(target=feed, daemon=True)
            writer.start()
        error = None
        try:
            while proc.poll() is None:
                self.check_cancel()
                if time.monotonic() >= local_deadline:
                    raise TaskTimeout('Команда превысила тайм-аут')
                if raw_error:
                    raise raw_error[0]
                self.cancelled.wait(.08)
            self.check_cancel()
        except Exception as exc:
            error = exc
        finally:
            self._terminate(proc)
            for reader in readers:
                reader.join(timeout=3)
            if writer:
                writer.join(timeout=1)
            if proc.stdin and not proc.stdin.closed:
                proc.stdin.close()
            if raw_file:
                raw_file.close()
            self.process = None
        if any(reader.is_alive() for reader in readers):
            raise RuntimeError('Не удалось закрыть поток дочернего процесса; результат неполный')
        stdout = bytes(chunks['stdout']).decode('utf-8', errors='replace')
        stderr = bytes(chunks['stderr']).decode('utf-8', errors='replace')
        if log_output:
            self.log(stdout)
            self.log(stderr)
        if raw_path and self.secrets:
            try:
                raw_path.write_text(redact(raw_path.read_text(encoding='utf-8'), self.secrets), encoding='utf-8')
            except UnicodeDecodeError:
                # Binary evidence is retained as-is, in the private job directory.
                pass
        if error:
            raise error
        if raw_error:
            raise raw_error[0]
        if truncated.is_set():
            raise RuntimeError('Текстовый вывод превысил лимит; сузьте проверку (результат неполный)')
        if allowed_exit is not None and proc.returncode not in allowed_exit:
            raise RuntimeError(f'{argv[0]}: код {proc.returncode}: ' + redact((stderr or stdout)[-1800:], self.secrets))
        return CommandResult(proc.returncode, stdout, stderr)


class Workbench:
    def __init__(self, directory, tools=None, workers=2, disabled=False):
        self.store = ProjectStore(directory)
        self.directory = self.store.directory
        (self.directory / 'jobs').mkdir(exist_ok=True, mode=0o700)
        (self.directory / 'attachments').mkdir(exist_ok=True, mode=0o700)
        self.disabled = disabled
        self.tools = {}
        if tools is None:
            from axiora_network_tools import TOOLS as network
            from axiora_device_tools import TOOLS as devices
            tools = list(network) + list(devices)
        for tool in tools:
            if tool.id in self.tools:
                raise ValueError('Повторяющийся идентификатор модуля: ' + tool.id)
            self.tools[tool.id] = tool
        for tool in self._system_tools():
            self.tools[tool.id] = tool
        self._queue = queue.Queue(maxsize=64)
        self._cancel = {}
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._threads = []
        self._worker_count = max(1, min(4, workers))
        self._versions = {}

    def _start(self):
        with self._lock:
            if not self._threads:
                for _ in range(self._worker_count):
                    worker = threading.Thread(target=self._worker, name='axiora-job', daemon=True)
                    self._threads.append(worker)
                    worker.start()

    def _system_tools(self):
        def inventory(ctx, params):
            versions = {}
            probes = {'nmap': ['--version'], 'tshark': ['--version'], 'dumpcap': ['--version'],
                      'iperf3': ['--version'], 'nuclei': ['-version'], 'iw': ['--version'],
                      'ssh': ['-V'], 'rtl_433': ['-V'], 'sigrok-cli': ['--version'],
                      'testssl.sh': ['--version'], 'bluetoothctl': ['--version']}
            for name, args in probes.items():
                ctx.check_cancel()
                if dependency_path(name):
                    try:
                        output = ctx.run([name] + args, timeout=5, allowed_exit=None)
                        versions[name] = (output.stdout or output.stderr)[:600]
                    except (TaskTimeout, CancelledError):
                        raise
                    except Exception as exc:
                        versions[name] = str(exc)
            self._versions = versions
            data = self.tool_status()
            ctx.save_json('modules.json', data)
            return {'summary': 'Проверены зависимости и версии', 'data': data}

        def secret_store(ctx, params):
            from axiora_vault import SecretVault
            SecretVault().set(params['name'], params['value'])
            return {'summary': 'Секрет сохранён в системном Secret Service. Ссылка: vault:' + params['name']}

        def secret_delete(ctx, params):
            from axiora_vault import SecretVault
            SecretVault().delete(params['name'])
            return {'summary': 'Секрет удалён'}

        return [Tool('system.inventory', 'Зависимости и версии', 'Система',
                     'Проверка установленных инструментов без установки и обновления.', (), (), inventory),
                Tool('system.secret_store', 'Сохранить секрет', 'Система',
                     'Системное зашифрованное хранилище Secret Service. В полях паролей используйте vault:имя.',
                     (Field('name', 'Имя секрета', required=True), Field('value', 'Значение', secret=True, required=True)),
                     ('python:keyring',), secret_store),
                Tool('system.secret_delete', 'Удалить секрет', 'Система',
                     'Удаляет запись из системного Secret Service.',
                     (Field('name', 'Имя секрета', required=True),), ('python:keyring',), secret_delete)]

    def tool_status(self):
        rows = []
        for tool in self.tools.values():
            paths = {name: dependency_path(name) for name in tool.requires}
            missing = [name for name, path in paths.items() if not path]
            rows.append({'id': tool.id, 'title': tool.title, 'category': tool.category,
                         'available': not missing, 'missing': missing,
                         'path': ', '.join(path for path in paths.values() if path),
                         'version': '\n'.join(self._versions.get(name, '') for name in paths).strip()})
        return rows

    def probe_versions(self, project_id=None):
        return self.submit('system.inventory', {}, project_id or self.store.projects()[0]['id'], timeout=120)

    def _prepare(self, tool_id, params, project_id, remote):
        if tool_id not in self.tools:
            raise ValueError('Неизвестный модуль')
        tool = self.tools[tool_id]
        fields = {field.name: field for field in tool.fields}
        if set(params) - fields.keys():
            raise ValueError('Неизвестные параметры: ' + ', '.join(set(params) - fields.keys()))
        values = {field.name: params.get(field.name, field.default) for field in tool.fields}
        secrets = []
        for field in tool.fields:
            value = values[field.name]
            if field.required and not str(value).strip():
                raise ValueError('Заполните поле: ' + field.label)
            if field.choices and str(value) not in [str(v) for v in field.choices]:
                raise ValueError('Недопустимое значение: ' + field.label)
            if field.secret and value:
                if str(value).startswith('vault:'):
                    from axiora_vault import SecretVault
                    value = values[field.name] = SecretVault().get(str(value)[6:])
                secrets.extend(secret_parts(value))
        project = self.store.get_project(project_id)
        scope = Scope(project['scope'])
        for name in tool.targets:
            value = values.get(name)
            if value:
                scope.check(str(value).strip())
        if remote:
            validate_remote(remote)
            if tool_id.startswith('system.secret_'):
                raise ValueError('Хранилище секретов доступно только локально')
        else:
            missing = [name for name in tool.requires if not dependency_path(name)]
            if missing:
                raise RuntimeError('Не установлены зависимости: ' + ', '.join(missing))
        persisted = {key: ('[SECRET]' if fields[key].secret and values[key] else values[key]) for key in values}
        return tool, values, persisted, secrets, project['scope']

    def submit(self, tool_id, params, project_id, timeout=None, remote=None):
        if self.disabled:
            raise RuntimeError('Рабочие проверки отключены в --demo; запустите Axiora без --demo')
        if self._stop.is_set():
            raise RuntimeError('Диспетчер задач закрыт')
        tool, values, persisted, secrets, scope = self._prepare(tool_id, params, project_id, remote)
        timeout = float(timeout if timeout is not None else tool.timeout)
        if not 1 <= timeout <= 3600:
            raise ValueError('Тайм-аут должен быть от 1 до 3600 секунд')
        with self._lock:
            if self._queue.full():
                raise RuntimeError('Очередь заполнена (64 задачи)')
            ident = uid()
            directory = self.directory / 'jobs' / ident
            directory.mkdir(parents=True, mode=0o700)
            self.store.add_job({'id': ident, 'project_id': project_id, 'tool_id': tool_id,
                                'params': persisted, 'remote': remote, 'status': 'queued',
                                'created': time.time(), 'timeout': timeout, 'scope': scope,
                                'artifact_dir': str(directory), 'log_path': str(directory / 'task.log')})
            cancelled = self._cancel[ident] = threading.Event()
            self._queue.put_nowait((ident, tool, values, secrets, scope, cancelled, timeout, remote))
            self._start()
        return ident

    def _worker(self):
        while not self._stop.is_set() or not self._queue.empty():
            try:
                item = self._queue.get(timeout=.2)
            except queue.Empty:
                continue
            ident, tool, values, secrets, scope, cancelled, timeout, remote = item
            ctx = TaskContext(self.directory / 'jobs' / ident, scope, cancelled, timeout,
                              lambda message: self.store.update_job(ident, progress=message), secrets)
            result = None
            try:
                ctx.check_cancel()
                self.store.update_job(ident, status='running', started=time.time())
                result = execute_remote(ctx, remote, tool.id, values, scope, timeout) if remote else tool.run(ctx, values)
                ctx.check_cancel()
                if not isinstance(result, dict):
                    raise TypeError('Модуль вернул результат неверного формата')
                result = redact(result, secrets)
                ctx.save_json('result.json', result)
                self.store.ingest_result(ident, result)
                self.store.update_job(ident, status='succeeded', finished=time.time(), result=result,
                                      summary=str(result.get('summary', 'Задача завершена')), progress='Завершено')
            except Exception as exc:
                status = 'cancelled' if isinstance(exc, CancelledError) else 'timed_out' if isinstance(exc, TimeoutError) else 'failed'
                message = redact(str(exc), secrets)
                ctx.log(message)
                self.store.update_job(ident, status=status, finished=time.time(), error=message,
                                      summary=message, progress=status)
            finally:
                for path in ctx.directory.rglob('*'):
                    if path.is_file() and not path.is_symlink():
                        try:
                            os.chmod(path, 0o600)
                        except OSError:
                            pass
                # Drop plaintext parameters after completion; nothing secret is stored in SQLite.
                values.clear()
                with self._lock:
                    self._cancel.pop(ident, None)
                self._queue.task_done()

    def jobs(self, project_id=None, include_results=True):
        return self.store.jobs(project_id, include_results=include_results)

    def cancel(self, job_id):
        with self._lock:
            event = self._cancel.get(job_id)
            if event:
                event.set()

    def cancel_all(self):
        with self._lock:
            for event in self._cancel.values():
                event.set()

    def job_log(self, job_id, max_bytes=32000):
        path = Path(self.store.get_job(job_id)['log_path'])
        if not path.is_file():
            return ''
        with path.open('rb') as stream:
            stream.seek(max(0, path.stat().st_size - max_bytes))
            return stream.read(max_bytes).decode('utf-8', errors='replace')

    def compare_jobs(self, first_id, second_id):
        first, second = self.store.get_job(first_id), self.store.get_job(second_id)
        if first['project_id'] != second['project_id']:
            raise ValueError('Выберите две задачи одного проекта')
        if first['status'] != 'succeeded' or second['status'] != 'succeeded':
            raise ValueError('Для сравнения нужны две успешно завершённые задачи')
        if first['tool_id'] != second['tool_id']:
            raise ValueError('Сравниваются результаты одного модуля')
        result = {'before': first_id, 'after': second_id, 'tool': first['tool_id']}
        for kind in ('assets', 'findings'):
            def canonical(item):
                return json.dumps(item, sort_keys=True, ensure_ascii=False)
            old = {canonical(item) for item in first['result'].get(kind, [])}
            new = {canonical(item) for item in second['result'].get(kind, [])}
            result[kind] = {'added': [json.loads(v) for v in sorted(new - old)],
                            'removed': [json.loads(v) for v in sorted(old - new)]}
        import difflib
        result['data_diff'] = '\n'.join(difflib.unified_diff(
            json.dumps(first['result'].get('data', {}), ensure_ascii=False, indent=2, sort_keys=True).splitlines(),
            json.dumps(second['result'].get('data', {}), ensure_ascii=False, indent=2, sort_keys=True).splitlines(),
            fromfile=first_id, tofile=second_id))
        result['note'] = 'Исчезновение находки само по себе не доказывает исправление; сравните параметры и полноту проверок.'
        return result

    def export_report(self, project_id, format='html'):
        from axiora_reports import export_project
        return export_project(self.store, project_id, format)

    def close(self):
        self._stop.set()
        self.cancel_all()
        for thread in self._threads:
            thread.join(timeout=5)
        if not any(thread.is_alive() for thread in self._threads):
            self.store.close()


def validate_remote(remote):
    if not isinstance(remote, dict) or set(remote) - {'host', 'directory', 'port'}:
        raise ValueError('Неизвестные параметры SSH исполнителя')
    host = str(remote.get('host', ''))
    if not re.fullmatch(r'(?:[a-zA-Z0-9_][a-zA-Z0-9_.-]*@)?[a-zA-Z0-9][a-zA-Z0-9_.-]*', host):
        raise ValueError('SSH: укажите hostname/alias или user@hostname')
    directory = str(remote.get('directory', ''))
    if not directory.startswith('/') or '\n' in directory or '\0' in directory:
        raise ValueError('SSH: нужен абсолютный путь к установленной Axiora')
    port = int(remote.get('port', 22))
    if not 1 <= port <= 65535:
        raise ValueError('SSH: порт 1–65535')


def execute_remote(ctx, remote, tool_id, params, scope, timeout):
    validate_remote(remote)
    payload = json.dumps({'version': 1, 'tool': tool_id, 'params': params, 'scope': scope,
                          'timeout': max(1, timeout - 3), 'keepalive': True}, ensure_ascii=False) + '\n'
    script = str(Path(remote['directory']) / 'axiora_remote_worker.py')
    command = 'exec python3 ' + shlex.quote(script)
    output = ctx.run(['ssh', '-T', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
                      '-o', 'ConnectTimeout=10', '-p', str(remote.get('port', 22)),
                      remote['host'], command], stdin=payload, max_output=24 * 1024 * 1024,
                     keep_stdin_open=True, log_output=False)
    try:
        response = json.loads(output.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError('SSH исполнитель вернул неверный JSON; проверьте путь и версии Axiora') from exc
    if response.get('version') != 1 or not response.get('ok'):
        raise RuntimeError('SSH: ' + str(response.get('error', 'Несовместимый протокол')))
    total, paths = 0, {}
    for artifact in response.get('artifacts', []):
        name = artifact['name']
        # Validate the original name too; never import a remote path.
        ctx.path(name)
        path = ctx.path('remote-task.log' if name == 'task.log' else name)
        raw = base64.b64decode(artifact['base64'], validate=True)
        total += len(raw)
        if len(raw) > 8 * 1024 * 1024 or total > 16 * 1024 * 1024:
            raise RuntimeError('Превышен лимит передачи удалённых артефактов')
        if hashlib.sha256(raw).hexdigest() != artifact['sha256']:
            raise RuntimeError('Контрольная сумма удалённого артефакта не совпала')
        path.write_bytes(raw)
        os.chmod(path, 0o600)
        paths[name] = str(path)
    omitted = response.get('omitted_artifacts', [])
    omitted_names = {item['name'] for item in omitted}
    def rewrite(value):
        if isinstance(value, dict):
            return {key: rewrite(item) for key, item in value.items()}
        if isinstance(value, list):
            return [rewrite(item) for item in value]
        if isinstance(value, str) and value.startswith('/tmp/axiora-remote-'):
            name = Path(value).name
            if name in paths:
                return paths[name]
            if name in omitted_names:
                return '[Не передан и удалён на исполнителе: ' + name + ']'
        return value
    result = rewrite(response['result'])
    result['remote'] = {'host': remote['host'], 'omitted_artifacts': omitted,
                        'evidence_complete': not omitted, 'local_artifacts': paths}
    if omitted:
        result['summary'] = str(result.get('summary', 'Вычисления завершены')) + ' — НЕПОЛНЫЕ АРТЕФАКТЫ: ' + ', '.join(sorted(omitted_names))
        ctx.emit('Часть удалённых артефактов превышает лимит передачи и удалена на исполнителе. Уменьшите лимит захвата и повторите задачу.')
    return result
