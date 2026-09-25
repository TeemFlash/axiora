#!/usr/bin/env python3
"""Install dependencies for Kali/Debian, then launch Axiora as the desktop user.

This installer is separate from the application. Importing it has no side effects.
"""
import argparse
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import shlex
import shutil
import subprocess
import sys


BASE_PACKAGES = (
    'python3', 'python3-venv', 'python3-pip', 'python3-gi', 'gir1.2-gtk-3.0',
    'python3-cairo', 'python3-gi-cairo', 'python3-serial', 'fonts-dejavu-core',
    'gnome-keyring', 'ca-certificates', 'debconf', 'libcap2-bin',
    'nmap', 'tshark', 'wireshark-common', 'iperf3', 'iputils-ping',
    'iputils-tracepath', 'dnsutils', 'iproute2', 'network-manager',
    'network-manager-gnome', 'openssh-client',
)
FULL_PACKAGES = ('nuclei', 'testssl.sh', 'zaproxy', 'iw', 'bluez', 'lldpd', 'snmp',
                 'sigrok-cli', 'rtl-433', 'rtl-sdr', 'onboard')
PI_BUILD_PACKAGES = ('device-tree-compiler', 'build-essential', 'python3-dev', 'swig')
PI_PREFERRED_PACKAGES = ('python3-spidev', 'python3-gpiozero', 'python3-lgpio', 'python3-libgpiod')
BASE_COMMANDS = ('nmap', 'tshark', 'dumpcap', 'iperf3', 'ping', 'tracepath', 'dig',
                 'ip', 'nmcli', 'nm-connection-editor', 'ssh')
FULL_COMMANDS = ('nuclei', 'testssl.sh|testssl', 'zaproxy', 'iw', 'bluetoothctl',
                 'lldpcli', 'snmpbulkwalk', 'sigrok-cli', 'rtl_433', 'rtl_sdr', 'onboard')
SESSION_ENV = ('DISPLAY', 'WAYLAND_DISPLAY', 'XAUTHORITY', 'XDG_RUNTIME_DIR',
               'DBUS_SESSION_BUS_ADDRESS', 'XDG_SESSION_TYPE', 'XDG_CURRENT_DESKTOP',
               'XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'LANG', 'LC_ALL', 'AXIORA_HOME')


def run_command(argv, *, input=None, capture=False, env=None):
    """No shell expansion, eval, or remote installer scripts."""
    print('+ ' + shlex.join(str(value) for value in argv), flush=True)
    result = subprocess.run([str(value) for value in argv], input=input, text=True, check=True,
                            stdout=subprocess.PIPE if capture else None, env=env)
    return result.stdout if capture else ''


def read_os_release(path=Path('/etc/os-release')):
    values = {}
    for line in path.read_text(encoding='utf-8').splitlines():
        if '=' in line and not line.startswith('#'):
            key, value = line.split('=', 1)
            values[key] = value.strip().strip('"').strip("'")
    return values


def board_model():
    for path in (Path('/proc/device-tree/model'), Path('/sys/firmware/devicetree/base/model')):
        try:
            return path.read_bytes().rstrip(b'\0').decode('utf-8', errors='replace')
        except OSError:
            pass
    return ''


def supported_os(release):
    names = {release.get('ID', ''), *release.get('ID_LIKE', '').split()}
    return bool(names & {'kali', 'debian', 'ubuntu', 'raspbian'})


def parse_candidates(output):
    """Parse LC_ALL=C apt-cache policy output for explicitly requested packages."""
    candidates, package = {}, None
    for line in output.splitlines():
        if line and not line[0].isspace() and line.endswith(':'):
            package = line[:-1].split(':', 1)[0]
        elif package and line.strip().startswith('Candidate:'):
            value = line.split(':', 1)[1].strip()
            candidates[package] = value if value != '(none)' else None
    return candidates


def command_available(name):
    return any(shutil.which(option) for option in name.split('|'))


def session_needs_groups(names):
    current = set(os.getgroups()) | {os.getgid()}
    for name in names:
        try:
            if grp.getgrnam(name).gr_gid not in current:
                return True
        except KeyError:
            continue
    return False


def launch_command(python, application, args, username, *, fresh_groups, environment=None):
    argv = [str(python), str(application)] + list(args)
    if not fresh_groups:
        return argv
    environment = os.environ if environment is None else environment
    # sudo creates a new supplementary-group list; the GUI UID remains the user.
    session = [f'{key}={environment[key]}' for key in SESSION_ENV if key in environment]
    return ['sudo', '-H', '-u', username, '--', '/usr/bin/env'] + session + argv


class Installer:
    def __init__(self, project, options, run=run_command, release=None, model=None):
        self.project = Path(project).resolve()
        self.options, self.run = options, run
        self.release = read_os_release() if release is None else release
        self.model = board_model() if model is None else model
        self.pi = self.model.startswith('Raspberry Pi 5')
        self.venv = self.project / '.venv'
        self.python = self.venv / 'bin/python'
        self.marker = self.venv / '.axiora-install.json'
        self.templates = self.project / '.tools/nuclei-templates'
        self.username = pwd.getpwuid(os.getuid()).pw_name
        self.groups = ['wireshark', 'dialout'] + (['axiora'] if self.pi else [])

    def fingerprint(self):
        digest = hashlib.sha256()
        for name in ('axiora_setup.py', 'axiora_setup_pi.py', 'install-and-run.sh',
                     'requirements-tools.txt', 'requirements-hardware.txt', 'hardware/99-axiora.rules'):
            path = self.project / name
            if path.is_file():
                digest.update(name.encode() + path.read_bytes())
        values = (self.options.core, self.options.no_templates, self.pi,
                  self.release.get('ID'), sys.version_info[:2])
        digest.update(repr(values).encode())
        return digest.hexdigest()

    def cached(self):
        try:
            state = json.loads(self.marker.read_text())
            return state.get('fingerprint') == self.fingerprint() and self.python.is_file()
        except (OSError, ValueError):
            return False

    def check_dependencies(self):
        names = BASE_COMMANDS + (() if self.options.core else FULL_COMMANDS)
        missing = [name for name in names if not command_available(name)]
        if missing:
            raise RuntimeError('Не найдены программы: ' + ', '.join(missing))
        code = "import gi; gi.require_version('Gtk','3.0'); from gi.repository import Gtk; import cairo, gi._gi_cairo; import serial, netmiko, keyring, reportlab"
        if self.pi:
            code += "; import spidev,gpiozero,lgpio,gpiod; assert hasattr(gpiod,'request_lines'), 'Нужен gpiod 2.x'"
        self.run([self.python, '-c', code], capture=True)
        config = self.venv / 'pyvenv.cfg'
        if 'include-system-site-packages = true' not in config.read_text().lower():
            raise RuntimeError('Окружение .venv должно быть создано с --system-site-packages')
        if not self.options.core and not self.options.no_templates:
            if not any(self.templates.glob('http/**/*.yaml')):
                raise RuntimeError('HTTP-шаблоны Nuclei отсутствуют; повторите установку')

    def plan(self):
        return list(BASE_PACKAGES + (() if self.options.core else FULL_PACKAGES) + (PI_BUILD_PACKAGES if self.pi else ()))

    def dry_run(self):
        print('Проверка плана; команды установки и запуска не выполняются.')
        print('Система:', self.release.get('PRETTY_NAME', self.release.get('ID')), '• плата:', self.model or 'не Pi 5')
        print('APT:', ' '.join(self.plan()))
        if self.pi:
            print('Аппаратные APT-пакеты при наличии:', ' '.join(PI_PREFERRED_PACKAGES))
            print('GPIO Python fallback: requirements-hardware.txt, PYPI=1 для сборки lgpio.')
        print('Окружение:', self.venv, '(--system-site-packages)')
        print('Python-пакеты: requirements-tools.txt')
        print('Группы:', ', '.join(self.groups))
        if not self.options.core and not self.options.no_templates:
            print('Nuclei: загрузка шаблонов в', self.templates)
        if self.options.configure_pi:
            print('SPI/UART: отдельный управляемый блок config.txt, резервная копия; затем нужна перезагрузка.')
        if not supported_os(self.release):
            print('Установка на этой ОС не поддерживается; нужен Kali/Debian/Ubuntu. --run-only доступен при готовом окружении.')

    def install(self):
        # A failed repair must not leave an earlier success marker valid.
        self.marker.unlink(missing_ok=True)
        env = dict(os.environ, LC_ALL='C', LANG='C')
        self.run(['sudo', '-v'])
        self.run(['sudo', '--', 'apt-get', 'update'])
        required = self.plan()
        queried = required + (list(PI_PREFERRED_PACKAGES) if self.pi else [])
        policy = self.run(['apt-cache', 'policy', *queried], capture=True, env=env)
        candidates = parse_candidates(policy)
        missing = [name for name in required if not candidates.get(name)]
        if missing:
            raise RuntimeError('В подключённых APT-репозиториях нет пакетов: ' + ', '.join(missing) +
                               '. Проверьте репозитории Kali/архитектуру. --core устанавливает базовый набор без дополнительных сканеров и радиоутилит.')
        packages = required + [name for name in PI_PREFERRED_PACKAGES if self.pi and candidates.get(name)]
        if not shutil.which('debconf-set-selections'):
            self.run(['sudo', '--', 'env', 'DEBIAN_FRONTEND=noninteractive', 'apt-get', 'install', '-y', 'debconf'])
        selections = 'wireshark-common wireshark-common/install-setuid boolean true\n'
        try:
            installed = self.run(['dpkg-query', '-W', '-f=${db:Status-Status}', 'iperf3'], capture=True)
        except subprocess.CalledProcessError:
            installed = ''
        if installed.strip() != 'installed':
            selections += 'iperf3 iperf3/start_daemon boolean false\n'
        self.run(['sudo', '--', 'debconf-set-selections'], input=selections)
        self.run(['sudo', '--', 'env', 'DEBIAN_FRONTEND=noninteractive', 'apt-get', 'install', '-y', *packages])
        self.run(['sudo', '--', 'env', 'DEBIAN_FRONTEND=noninteractive', 'dpkg-reconfigure', '-f', 'noninteractive', 'wireshark-common'])
        # Preserve the environment directory; venv upgrades configuration without deleting it.
        self.run(['/usr/bin/python3', '-m', 'venv', '--system-site-packages', str(self.venv)])
        self.run([self.python, '-m', 'pip', 'install', '-r', self.project / 'requirements-tools.txt'])
        if self.pi:
            self.run([self.python, '-m', 'pip', 'install', '-r', self.project / 'requirements-hardware.txt'],
                     env=dict(os.environ, PYPI='1'))
            self.run(['sudo', '--', 'groupadd', '-f', 'axiora'])
            self.run(['sudo', '--', 'install', '-m', '0644', self.project / 'hardware/99-axiora.rules', '/etc/udev/rules.d/99-axiora.rules'])
            self.run(['sudo', '--', 'udevadm', 'control', '--reload-rules'])
            self.run(['sudo', '--', 'udevadm', 'trigger', '--subsystem-match=spidev'])
            self.run(['sudo', '--', 'udevadm', 'trigger', '--subsystem-match=gpio'])
        self.run(['sudo', '--', 'usermod', '-aG', ','.join(self.groups), self.username])
        if not self.options.core and not self.options.no_templates:
            self.templates.mkdir(parents=True, exist_ok=True)
            self.run(['nuclei', '-ut', '-ud', self.templates])
        self.check_dependencies()
        self.marker.write_text(json.dumps({'fingerprint': self.fingerprint(), 'profile': 'core' if self.options.core else 'full'}, indent=2) + '\n')
        self.marker.chmod(0o600)

    def execute(self):
        if self.options.dry_run:
            self.dry_run()
            return 0
        if os.geteuid() == 0:
            raise RuntimeError('Запустите скрипт без sudo; GUI и pip не должны работать от root')
        if self.options.enable_rdm6300 and not self.options.configure_pi:
            raise ValueError('--enable-rdm6300 используется только вместе с --configure-pi')
        if self.options.boot_dir and not self.options.configure_pi:
            raise ValueError('--boot-dir используется только вместе с --configure-pi')
        if self.options.configure_pi and not self.pi:
            raise RuntimeError('--configure-pi рассчитан только на Raspberry Pi 5')
        if self.options.run_only:
            if not self.python.is_file():
                raise RuntimeError('Нет .venv/bin/python; сначала выполните обычную установку')
        else:
            if not supported_os(self.release) or not shutil.which('apt-get'):
                raise RuntimeError('Автоустановка поддерживает Kali/Debian/Ubuntu; эта ОС: ' + self.release.get('ID', 'unknown'))
            if not shutil.which('sudo'):
                raise RuntimeError('Нужен sudo и пользователь с правом установки пакетов')
            if not os.access(self.project, os.W_OK):
                raise RuntimeError('Каталог проекта должен быть доступен на запись текущему пользователю')
            ready = self.cached() and not self.options.reinstall
            if ready:
                try:
                    self.check_dependencies()
                except (RuntimeError, OSError, subprocess.CalledProcessError) as exc:
                    print('Проверка прежней установки не прошла:', exc)
                    ready = False
            if not ready:
                self.install()
            else:
                print('Зависимости уже установлены; повторная установка не требуется.')
            self.run(['/bin/sh', self.project / 'install-desktop.sh'], env=dict(os.environ, AXIORA_PYTHON=str(self.python)))
        if self.options.configure_pi:
            from axiora_setup_pi import configure_pi
            changed = configure_pi(self.project, self.run, self.options.boot_dir, self.options.enable_rdm6300)
            if changed:
                print('SPI/UART настроены. Перезагрузите Pi для применения; скрипт не перезагружает её автоматически.')
        if self.options.install_only:
            print('Установка завершена. Войдите в сеанс заново для применения групп, затем запустите ./install-and-run.sh.')
            return 0
        if '--diagnose' not in self.options.app_args and not (os.environ.get('DISPLAY') or os.environ.get('WAYLAND_DISPLAY')):
            print('Установка готова, но графического сеанса нет. В Xfce запустите ./install-and-run.sh --run-only.')
            return 0
        refresh_groups = session_needs_groups(self.groups)
        command = launch_command(self.python, self.project / 'axiora.py', self.options.app_args,
                                 self.username, fresh_groups=refresh_groups)
        print('Запуск Axiora от пользователя ' + self.username, flush=True)
        self.run(command)
        return 0


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description='Установка и запуск Axiora для Kali Linux / Debian.')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--install-only', action='store_true', help='установить без запуска GUI')
    group.add_argument('--run-only', action='store_true', help='запуск готовой .venv без APT/pip')
    parser.add_argument('--core', action='store_true', help='базовая сеть/PCAP и GUI без дополнительных сканеров/SDR')
    parser.add_argument('--reinstall', action='store_true', help='повторить APT/pip и обновить шаблоны')
    parser.add_argument('--no-templates', action='store_true', help='не загружать набор шаблонов Nuclei')
    parser.add_argument('--dry-run', action='store_true', help='показать план без изменений')
    parser.add_argument('--configure-pi', action='store_true', help='настроить SPI/UART Pi 5 с резервной копией config.txt')
    parser.add_argument('--boot-dir', type=Path, help='активный загрузочный каталог, например /boot/firmware')
    parser.add_argument('--enable-rdm6300', action='store_true', help='включить UART4 ПОСЛЕ переноса TX RDM6300 на GPIO13')
    parser.add_argument('app_args', nargs=argparse.REMAINDER, help='аргументы Axiora после --')
    args = parser.parse_args(argv)
    if args.app_args[:1] == ['--']:
        args.app_args = args.app_args[1:]
    if args.run_only and (args.reinstall or args.configure_pi):
        parser.error('--run-only нельзя сочетать с --reinstall или --configure-pi')
    return args


def main(argv=None):
    try:
        return Installer(Path(__file__).resolve().parent, parse_args(argv)).execute()
    except KeyboardInterrupt:
        print('\nОперация остановлена; повторный запуск продолжит установку.', file=sys.stderr)
        return 130
    except (OSError, RuntimeError, ValueError, subprocess.CalledProcessError) as exc:
        print('Установка/запуск не завершены: ' + str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
