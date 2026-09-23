#!/usr/bin/env python3
"""Headless access to the same workbench registry, projects and job runner."""
import argparse
import getpass
import json
import os
from pathlib import Path
import sys
import time

from axiora_workbench import Workbench


def main(argv=None):
    parser = argparse.ArgumentParser(description='Axiora workbench без GTK; права текущего пользователя ОС')
    parser.add_argument('--home', default=str(Path(os.environ.get('AXIORA_HOME', '~/.axiora')).expanduser() / 'live' / 'workbench'))
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('tools')
    sub.add_parser('projects')
    create = sub.add_parser('create-project')
    create.add_argument('name')
    create.add_argument('--scope', required=True)
    create.add_argument('--notes', default='')
    run = sub.add_parser('run')
    run.add_argument('tool')
    run.add_argument('--project', required=True)
    run.add_argument('--params', help='JSON-файл параметров; - для stdin. Секреты можно вводить интерактивно.')
    run.add_argument('--timeout', type=int)
    run.add_argument('--ssh')
    run.add_argument('--remote-directory')
    run.add_argument('--ssh-port', type=int, default=22)
    report = sub.add_parser('report')
    report.add_argument('--project', required=True)
    report.add_argument('--format', choices=('json', 'html', 'pdf'), default='html')
    jobs = sub.add_parser('jobs')
    jobs.add_argument('--project')
    args = parser.parse_args(argv)
    workbench = Workbench(args.home)
    try:
        if args.command == 'tools':
            data = workbench.tool_status()
            for item in data:
                tool = workbench.tools[item['id']]
                item['description'] = tool.description
                item['fields'] = [field.__dict__ for field in tool.fields]
        elif args.command == 'projects':
            data = workbench.store.projects()
        elif args.command == 'create-project':
            data = {'id': workbench.store.create_project(args.name, args.scope, args.notes)}
        elif args.command == 'jobs':
            data = workbench.jobs(args.project)
        elif args.command == 'report':
            data = {'path': workbench.export_report(args.project, args.format)}
        else:
            if args.tool not in workbench.tools:
                raise ValueError('Неизвестный модуль')
            if args.params == '-':
                params = json.load(sys.stdin)
            elif args.params:
                params = json.loads(Path(args.params).read_text(encoding='utf-8'))
            else:
                params = {}
            if not isinstance(params, dict):
                raise ValueError('Параметры должны быть JSON объектом')
            if sys.stdin.isatty():
                for field in workbench.tools[args.tool].fields:
                    if field.secret and field.required and not params.get(field.name):
                        params[field.name] = getpass.getpass(field.label + ': ')
            remote = {'host': args.ssh, 'directory': args.remote_directory, 'port': args.ssh_port} if args.ssh else None
            ident = workbench.submit(args.tool, params, args.project, timeout=args.timeout, remote=remote)
            try:
                while True:
                    data = workbench.store.get_job(ident)
                    if data['status'] not in ('queued', 'running'):
                        break
                    time.sleep(.1)
            except KeyboardInterrupt:
                workbench.cancel(ident)
                print('Остановка задачи…', file=sys.stderr)
                return 130
        print(json.dumps(data, ensure_ascii=False, indent=2))
        return 0 if args.command != 'run' or data['status'] == 'succeeded' else 1
    except (ValueError, RuntimeError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    finally:
        workbench.close()


if __name__ == '__main__':
    raise SystemExit(main())
