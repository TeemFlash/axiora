"""Persistent, thread-safe projects, evidence and review decisions."""
import hashlib
import fcntl
import json
import os
from pathlib import Path
import shutil
import sqlite3
import threading
import time
import uuid


def uid():
    return uuid.uuid4().hex


class ProjectStore:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.directory, 0o700)
        self.owner_lock = (self.directory / 'owner.lock').open('a+b')
        os.chmod(self.directory / 'owner.lock', 0o600)
        try:
            fcntl.flock(self.owner_lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            self.owner_lock.close()
            raise RuntimeError('Этот каталог проектов уже открыт другой Axiora. Закройте её или выберите другой --home.') from None
        self.lock = threading.RLock()
        self.db = sqlite3.connect(self.directory / 'projects.sqlite3', check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        with self.lock:
            self.db.executescript('''
                PRAGMA journal_mode=WAL;
                PRAGMA foreign_keys=ON;
                CREATE TABLE IF NOT EXISTS projects (
                    id TEXT PRIMARY KEY, name TEXT NOT NULL, scope TEXT NOT NULL,
                    notes TEXT NOT NULL, created REAL NOT NULL, updated REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS jobs (
                    id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id),
                    tool_id TEXT NOT NULL, params TEXT NOT NULL, remote TEXT,
                    status TEXT NOT NULL, created REAL NOT NULL, started REAL,
                    finished REAL, summary TEXT NOT NULL DEFAULT '', error TEXT NOT NULL DEFAULT '',
                    progress TEXT NOT NULL DEFAULT '', result TEXT NOT NULL DEFAULT '{}',
                    timeout REAL NOT NULL, artifact_dir TEXT NOT NULL, log_path TEXT NOT NULL,
                    scope TEXT NOT NULL DEFAULT '');
                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id),
                    job_id TEXT NOT NULL REFERENCES jobs(id), fingerprint TEXT NOT NULL,
                    title TEXT NOT NULL, target TEXT NOT NULL, severity TEXT NOT NULL,
                    confidence TEXT NOT NULL, evidence TEXT NOT NULL, remediation TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'new', note TEXT NOT NULL DEFAULT '',
                    data TEXT NOT NULL, updated REAL NOT NULL,
                    UNIQUE(project_id, fingerprint));
                CREATE TABLE IF NOT EXISTS assets (
                    id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id),
                    job_id TEXT NOT NULL REFERENCES jobs(id), identity TEXT NOT NULL,
                    data TEXT NOT NULL, updated REAL NOT NULL,
                    UNIQUE(project_id, identity));
                CREATE TABLE IF NOT EXISTS attachments (
                    id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id),
                    name TEXT NOT NULL, path TEXT NOT NULL, sha256 TEXT NOT NULL,
                    size INTEGER NOT NULL, note TEXT NOT NULL, created REAL NOT NULL);
            ''')
            if 'scope' not in {row['name'] for row in self.db.execute('PRAGMA table_info(jobs)')}:
                self.db.execute("ALTER TABLE jobs ADD COLUMN scope TEXT NOT NULL DEFAULT ''")
            self.db.execute("UPDATE jobs SET status='interrupted', finished=?, error=? WHERE status IN ('queued','running')",
                            (time.time(), 'Предыдущий процесс завершился до окончания задачи'))
            self.db.commit()
        os.chmod(self.directory / 'projects.sqlite3', 0o600)
        if not self.projects():
            self.create_project('Лаборатория', '127.0.0.1/32\n::1/128\nlocalhost')

    def _rows(self, sql, args=()):
        with self.lock:
            return [dict(row) for row in self.db.execute(sql, args).fetchall()]

    def projects(self):
        return self._rows('SELECT * FROM projects ORDER BY created')

    def get_project(self, project_id):
        rows = self._rows('SELECT * FROM projects WHERE id=?', (project_id,))
        if not rows:
            raise ValueError('Проект не найден')
        return rows[0]

    def create_project(self, name, scope, notes=''):
        from axiora_workbench import Scope
        Scope(scope)
        if not str(name).strip() or len(str(name)) > 160:
            raise ValueError('Название проекта: 1–160 символов')
        project_id, now = uid(), time.time()
        with self.lock, self.db:
            self.db.execute('INSERT INTO projects VALUES(?,?,?,?,?,?)',
                            (project_id, name.strip(), str(scope), str(notes), now, now))
        return project_id

    def update_project(self, project_id, **fields):
        project = self.get_project(project_id)
        if set(fields) - {'name', 'scope', 'notes'}:
            raise ValueError('Неизвестное поле проекта')
        project.update(fields)
        from axiora_workbench import Scope
        Scope(project['scope'])
        if not project['name'].strip() or len(project['name']) > 160:
            raise ValueError('Название проекта: 1–160 символов')
        with self.lock, self.db:
            self.db.execute('UPDATE projects SET name=?,scope=?,notes=?,updated=? WHERE id=?',
                            (project['name'].strip(), project['scope'], project['notes'], time.time(), project_id))

    def add_job(self, job):
        columns = tuple(job)
        values = [json.dumps(job[k], ensure_ascii=False) if k in ('params', 'remote', 'result') else job[k] for k in columns]
        with self.lock, self.db:
            self.db.execute(f"INSERT INTO jobs ({','.join(columns)}) VALUES ({','.join('?' for _ in columns)})", values)

    def update_job(self, job_id, **values):
        allowed = {'status', 'started', 'finished', 'summary', 'error', 'progress', 'result'}
        if set(values) - allowed:
            raise ValueError('Неизвестное поле задачи')
        data = [json.dumps(v, ensure_ascii=False) if k == 'result' else v for k, v in values.items()]
        with self.lock, self.db:
            self.db.execute('UPDATE jobs SET ' + ','.join(k + '=?' for k in values) + ' WHERE id=?', data + [job_id])

    @staticmethod
    def _job(row):
        for field in ('params', 'remote', 'result'):
            row[field] = json.loads(row[field]) if row.get(field) else None
        return row

    def jobs(self, project_id=None, include_results=True):
        columns = '*' if include_results else ("id,project_id,tool_id,params,remote,status,created,started,finished,"
                  "summary,error,progress,'{}' AS result,timeout,artifact_dir,log_path,scope")
        query = 'SELECT ' + columns + ' FROM jobs'
        args = ()
        if project_id is not None:
            query += ' WHERE project_id=?'
            args = (project_id,)
        return [self._job(row) for row in self._rows(query + ' ORDER BY created DESC', args)]

    def get_job(self, job_id):
        rows = self._rows('SELECT * FROM jobs WHERE id=?', (job_id,))
        if not rows:
            raise ValueError('Задача не найдена')
        return self._job(rows[0])

    def ingest_result(self, job_id, result):
        job = self.get_job(job_id)
        now = time.time()
        with self.lock, self.db:
            for item in result.get('assets', []):
                if not isinstance(item, dict):
                    continue
                identity = str(item.get('address') or item.get('ip') or item.get('mac') or item.get('hostname') or item.get('name') or item.get('id') or '')
                if not identity:
                    continue
                self.db.execute('''INSERT INTO assets VALUES(?,?,?,?,?,?)
                    ON CONFLICT(project_id,identity) DO UPDATE SET job_id=excluded.job_id,
                    data=excluded.data,updated=excluded.updated''',
                    (uid(), job['project_id'], job_id, identity, json.dumps(item, ensure_ascii=False), now))
            for finding in result.get('findings', []):
                if not isinstance(finding, dict):
                    continue
                title, target = str(finding.get('title', 'Находка')), str(finding.get('target', ''))
                key = [job['tool_id'], target, title, str(finding.get('port', '')), str(finding.get('template_id', '')),
                       str(finding.get('plugin_id', '')), str(finding.get('parameter', '')),
                       str(finding.get('matcher_id', '')), str(finding.get('method', ''))]
                fingerprint = hashlib.sha256(json.dumps(key, ensure_ascii=False).encode()).hexdigest()
                evidence = finding.get('evidence', '')
                if not isinstance(evidence, str):
                    evidence = json.dumps(evidence, ensure_ascii=False)
                self.db.execute('''INSERT INTO findings VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(project_id,fingerprint) DO UPDATE SET job_id=excluded.job_id,
                    evidence=excluded.evidence,data=excluded.data,severity=excluded.severity,
                    confidence=excluded.confidence,remediation=excluded.remediation,updated=excluded.updated,
                    status=CASE WHEN findings.status='fixed' THEN 'new' ELSE findings.status END,
                    note=CASE WHEN findings.status='fixed' THEN findings.note || char(10) ||
                         'Повторное обнаружение после отметки об исправлении; требуется проверка.' ELSE findings.note END''',
                    (uid(), job['project_id'], job_id, fingerprint, title, target,
                     str(finding.get('severity', 'info')), str(finding.get('confidence', 'requires_review')),
                     evidence, str(finding.get('remediation', 'Проверьте результат и документацию производителя')),
                     'new', '', json.dumps(finding, ensure_ascii=False), now))

    def findings(self, project_id):
        rows = self._rows('SELECT * FROM findings WHERE project_id=? ORDER BY updated DESC', (project_id,))
        for row in rows:
            row['data'] = json.loads(row['data'])
        return rows

    def assets(self, project_id):
        rows = self._rows('SELECT * FROM assets WHERE project_id=? ORDER BY identity', (project_id,))
        for row in rows:
            row['data'] = json.loads(row['data'])
        return rows

    def review_finding(self, finding_id, status, note=''):
        if status not in ('new', 'confirmed', 'false_positive', 'fixed', 'accepted'):
            raise ValueError('Неизвестный статус находки')
        with self.lock, self.db:
            cur = self.db.execute('UPDATE findings SET status=?,note=?,updated=? WHERE id=?',
                                 (status, str(note), time.time(), finding_id))
            if not cur.rowcount:
                raise ValueError('Находка не найдена')

    def attach(self, project_id, path, note=''):
        self.get_project(project_id)
        source = Path(path).expanduser().resolve()
        if not source.is_file() or source.stat().st_size > 64 * 1024 * 1024:
            raise ValueError('Вложение должно быть файлом не более 64 МиБ')
        ident = uid()
        directory = self.directory / 'attachments' / project_id
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        dest = directory / (ident + '-' + source.name)
        digest = hashlib.sha256()
        try:
            with source.open('rb') as src, dest.open('xb') as out:
                os.chmod(dest, 0o600)
                size = 0
                while True:
                    chunk = src.read(1024 * 1024)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > 64 * 1024 * 1024:
                        raise ValueError('Вложение выросло выше лимита 64 МиБ')
                    digest.update(chunk)
                    out.write(chunk)
            with self.lock, self.db:
                self.db.execute('INSERT INTO attachments VALUES(?,?,?,?,?,?,?,?)',
                                (ident, project_id, source.name, str(dest), digest.hexdigest(), size, str(note), time.time()))
        except Exception:
            dest.unlink(missing_ok=True)
            raise
        return str(dest)

    def attachments(self, project_id):
        return self._rows('SELECT * FROM attachments WHERE project_id=? ORDER BY created DESC', (project_id,))

    def close(self):
        with self.lock:
            self.db.close()
            if not self.owner_lock.closed:
                fcntl.flock(self.owner_lock.fileno(), fcntl.LOCK_UN)
                self.owner_lock.close()
