"""Small, GUI-independent contract for Axiora workbench adapters.

Adapters use ctx.run(argv), ctx.path(name), ctx.save_json(name, data),
ctx.check_cancel() and ctx.emit(message). No shell commands are accepted.
"""
from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class Field:
    name: str
    label: str
    default: str = ""
    kind: str = "text"
    choices: tuple = ()
    required: bool = False
    secret: bool = False


@dataclass(frozen=True)
class Tool:
    id: str
    title: str
    category: str
    description: str
    fields: tuple
    requires: tuple
    run: Callable
    targets: tuple = ()
    timeout: int = 120


@dataclass
class CommandResult:
    returncode: int
    stdout: str
    stderr: str
