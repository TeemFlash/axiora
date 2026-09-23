"""Portable project reports with source jobs and evidence integrity hashes."""
import hashlib
import html
import json
import os
from pathlib import Path
import time
import uuid


def project_snapshot(store, project_id):
    project = store.get_project(project_id)
    jobs = store.jobs(project_id)
    evidence = []
    for job in jobs:
        for path in sorted(Path(job['artifact_dir']).glob('*')):
            if path.is_file() and not path.is_symlink():
                digest = hashlib.sha256()
                with path.open('rb') as stream:
                    for block in iter(lambda: stream.read(1024 * 1024), b''):
                        digest.update(block)
                evidence.append({'job_id': job['id'], 'name': path.name, 'bytes': path.stat().st_size,
                                 'sha256': digest.hexdigest()})
    return {'schema': 'axiora.project-report.v1', 'generated': time.time(), 'project': project,
            'assets': store.assets(project_id), 'jobs': jobs, 'findings': store.findings(project_id),
            'attachments': store.attachments(project_id), 'evidence': evidence,
            'interpretation': 'Автоматические результаты требуют проверки. Отсутствие находок не доказывает отсутствие уязвимостей. '
                              'Снимок работающих задач может быть неполным; для финального отчёта дождитесь завершения.'}


def export_project(store, project_id, format='html'):
    format = format.lower()
    if format not in ('html', 'json', 'pdf'):
        raise ValueError('Поддерживаются HTML, JSON и PDF')
    data = project_snapshot(store, project_id)
    directory = store.directory / 'reports'
    directory.mkdir(exist_ok=True, mode=0o700)
    output = directory / (time.strftime('%Y%m%d-%H%M%S-') + uuid.uuid4().hex[:8] + '.' + format)
    if format == 'json':
        output.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')
    elif format == 'html':
        esc = lambda value: html.escape(str(value))
        project = data['project']
        body = ['<!doctype html><html lang="ru"><meta charset="utf-8"><title>Axiora — отчёт</title>',
                '<style>body{font:16px system-ui;margin:3em auto;max-width:1100px;padding:0 1em;color:#17324a}'
                'pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f2f5f8;padding:1em}'
                'table{border-collapse:collapse;width:100%}td,th{padding:.5em;border:1px solid #ccd;text-align:left}'
                'article{break-inside:avoid;border-top:1px solid #ccd;margin-top:1.5em}small{color:#456}</style>',
                '<h1>Axiora: ' + esc(project['name']) + '</h1>',
                '<p>' + esc(data['interpretation']) + '</p>',
                '<h2>Область проверки</h2><pre>' + esc(project['scope']) + '</pre>',
                '<h2>Заметки</h2><pre>' + esc(project['notes']) + '</pre>',
                '<h2>Задачи</h2><table><tr><th>ID / модуль</th><th>Статус</th><th>Результат</th></tr>']
        for job in data['jobs']:
            body.append('<tr><td>' + esc(job['id'] + '\n' + job['tool_id']) + '</td><td>' + esc(job['status']) +
                        '</td><td>' + esc(job['summary'] or job['error']) + '</td></tr>')
        body.append('</table><h2>Находки и проверка результатов</h2>')
        for item in data['findings']:
            body.extend(['<article><h3>' + esc(item['title']) + '</h3>',
                         '<p>' + esc(f"{item['target']} | {item['severity']} | {item['confidence']} | {item['status']}") + '</p>',
                         '<small>Источник: ' + esc(item['job_id']) + '</small>',
                         '<pre>' + esc(item['evidence']) + '</pre>',
                         '<p>Исправление: ' + esc(item['remediation']) + '</p>',
                         '<p>Рецензия: ' + esc(item['note']) + '</p></article>'])
        for title, key in [('Устройства', 'assets'), ('Вложения', 'attachments'), ('Контрольные суммы артефактов', 'evidence')]:
            body.append('<h2>' + title + '</h2><pre>' + esc(json.dumps(data[key], ensure_ascii=False, indent=2)) + '</pre>')
        body.append('<h2>Полные результаты и параметры</h2>')
        for job in data['jobs']:
            body.append('<details><summary>' + esc(job['tool_id'] + ' — ' + job['id']) + '</summary><pre>' +
                        esc(json.dumps(job, ensure_ascii=False, indent=2)) + '</pre></details>')
        body.append('</html>')
        output.write_text('\n'.join(body), encoding='utf-8')
    else:
        try:
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.pdfbase import pdfmetrics
            from reportlab.pdfbase.ttfonts import TTFont
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
        except ImportError:
            raise RuntimeError('Для PDF установите python3-reportlab и fonts-dejavu-core') from None
        font = next((path for path in (Path('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf'),
                                     Path('/usr/share/fonts/TTF/DejaVuSans.ttf')) if path.is_file()), None)
        if font is None:
            raise RuntimeError('Для русского текста PDF установите fonts-dejavu-core')
        pdfmetrics.registerFont(TTFont('AxioraDejaVu', str(font)))
        styles = getSampleStyleSheet()
        normal = ParagraphStyle('Axiora', parent=styles['Normal'], fontName='AxioraDejaVu', fontSize=9,
                                leading=13, splitLongWords=True, wordWrap='CJK')
        heading = ParagraphStyle('AxioraHeading', parent=normal, fontSize=15, leading=20, spaceAfter=10,
                                 keepWithNext=True)
        story = []
        def paragraph(text, style=normal):
            # Split large text so a long scanner response can flow across pages.
            for offset in range(0, max(1, len(str(text))), 1800):
                part = str(text)[offset:offset + 1800]
                story.append(Paragraph(html.escape(part).replace('\n', '<br/>'), style))
            story.append(Spacer(1, 8))
        paragraph('Axiora: ' + data['project']['name'], heading)
        paragraph(time.strftime('Создан %d.%m.%Y %H:%M:%S', time.localtime(data['generated'])))
        paragraph(f"Устройств: {len(data['assets'])} • задач: {len(data['jobs'])} • находок: {len(data['findings'])}")
        paragraph(data['interpretation'])
        paragraph('Область проверки\n' + data['project']['scope'])
        if data['project']['notes']:
            paragraph('Заметки\n' + data['project']['notes'])
        paragraph('Находки и результаты проверки', heading)
        if not data['findings']:
            paragraph('Зарегистрированных находок нет. Учитывайте полноту и состояние выполненных задач.')
        for index, item in enumerate(data['findings'], 1):
            paragraph(f"{index}. {item['title']}", heading)
            paragraph(f"Цель: {item['target']}\nСерьёзность: {item['severity']} • достоверность: {item['confidence']}\n"
                      f"Статус проверки: {item['status']}")
            paragraph('Доказательства\n' + item['evidence'])
            paragraph('Исправление\n' + item['remediation'])
            if item['note']:
                paragraph('Комментарий проверяющего\n' + item['note'])
            paragraph('Задача-источник: ' + item['job_id'])
        paragraph('Выполненные задачи', heading)
        for job in data['jobs']:
            paragraph(job['tool_id'] + ' — ' + job['status'], heading)
            paragraph(job['summary'] or job['error'])
            paragraph('Создана: ' + time.strftime('%d.%m.%Y %H:%M:%S', time.localtime(job['created'])) +
                      '\nID: ' + job['id'] + '\nОбласть при запуске: ' + job.get('scope', 'не сохранена'))
            paragraph('Параметры: ' + json.dumps(job['params'], ensure_ascii=False, indent=2))
        paragraph('Устройства', heading)
        for item in data['assets']:
            paragraph(item['identity'], heading)
            paragraph(json.dumps(item['data'], ensure_ascii=False, indent=2))
        paragraph('Вложения', heading)
        for item in data['attachments']:
            paragraph(f"{item['name']} ({item['size']} байт)\n{item['note']}\nSHA-256: {item['sha256']}")
        paragraph('Контрольные суммы исходных артефактов', heading)
        for item in data['evidence']:
            paragraph(f"{item['name']} ({item['bytes']} байт)\nЗадача: {item['job_id']}\nSHA-256: {item['sha256']}")
        paragraph('Полные структурированные результаты доступны в JSON-экспорте проекта; исходные файлы — в каталогах задач.')
        SimpleDocTemplate(str(output), title='Axiora — ' + data['project']['name'],
                          author='Axiora', leftMargin=36, rightMargin=36, topMargin=36, bottomMargin=36).build(story)
    os.chmod(output, 0o600)
    return str(output)
