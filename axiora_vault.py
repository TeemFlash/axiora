"""Use only the desktop Secret Service backend; never fall back to plaintext."""
import re


class SecretVault:
    SERVICE = 'axiora.workbench'

    def __init__(self, backend=None):
        if backend is None:
            try:
                from keyring.backends.SecretService import Keyring
                backend = Keyring()
                if backend.priority <= 0:
                    raise RuntimeError('Secret Service недоступен')
            except Exception as exc:
                raise RuntimeError('Нужно разблокированное системное хранилище Secret Service '
                                   '(python3-keyring, gnome-keyring, сеанс D-Bus): ' + str(exc)) from exc
        self.backend = backend

    @staticmethod
    def name(name):
        if not re.fullmatch(r'[a-zA-Z0-9_.-]{1,80}', str(name)):
            raise ValueError('Имя секрета: 1–80 латинских букв, цифр, _, . или -')
        return str(name)

    def set(self, name, value):
        if not value or len(str(value)) > 8192:
            raise ValueError('Секрет должен содержать 1–8192 символов')
        self.backend.set_password(self.SERVICE, self.name(name), str(value))

    def get(self, name):
        value = self.backend.get_password(self.SERVICE, self.name(name))
        if value is None:
            raise ValueError('Секрет не найден: ' + str(name))
        return value

    def delete(self, name):
        self.backend.delete_password(self.SERVICE, self.name(name))
