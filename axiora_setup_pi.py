"""Opt-in Raspberry Pi boot configuration; privileged work goes through run()."""
from datetime import datetime, timezone
from pathlib import Path
import re
import tempfile
import uuid


BEGIN = "# BEGIN AXIORA MANAGED BOOT"
END = "# END AXIORA MANAGED BOOT"
BOOT_CANDIDATES = (Path("/boot/firmware"), Path("/boot"))
_CONFLICTING_OVERLAYS = (
    "axiora-spi", "spi", "w5500", "w5100", "ads7846", "xpt2046",
    "uart0", "uart2", "uart4",
)


def select_boot_dir(boot_dir=None, *, candidates=None):
    """Find an unambiguous boot tree; candidates is injectable for local tests."""
    paths = (Path(boot_dir),) if boot_dir is not None else (
        BOOT_CANDIDATES if candidates is None else candidates)
    found = []
    for candidate in paths:
        path = Path(candidate).resolve()
        if not (path / "config.txt").is_file() or not (path / "overlays").is_dir():
            continue
        if any((path / "config.txt").samefile(other / "config.txt") and
               (path / "overlays").samefile(other / "overlays") for other in found):
            continue
        found.append(path)
    if not found:
        raise ValueError("Не найден каталог загрузчика с config.txt и overlays; "
                         "укажите активный каталог через --boot-dir.")
    if len(found) != 1:
        raise ValueError("Найдено несколько каталогов загрузчика: " +
                         ", ".join(map(str, found)) +
                         ". Укажите активный каталог через --boot-dir.")
    return found[0]


def merge_boot_config(text, *, enable_rdm=False):
    """Append/replace our terminal block, never silently discard user settings."""
    lines = text.splitlines(keepends=True)
    starts = [i for i, line in enumerate(lines) if line.strip() == BEGIN]
    ends = [i for i, line in enumerate(lines) if line.strip() == END]
    for line in lines:
        if "AXIORA MANAGED BOOT" in line and line.strip() not in (BEGIN, END):
            raise ValueError("Повреждены маркеры AXIORA MANAGED BOOT в config.txt.")
    if starts or ends:
        if len(starts) != 1 or len(ends) != 1 or starts[0] >= ends[0]:
            raise ValueError("Повреждены или повторяются маркеры AXIORA MANAGED BOOT.")
        start, end = starts[0], ends[0]
        allowed = {"[all]", "dtoverlay=axiora-spi", "dtoverlay=uart0-pi5",
                   "dtoverlay=uart4-pi5"}
        if any(line.strip() not in allowed for line in lines[start + 1:end]):
            raise ValueError("В блоке AXIORA MANAGED BOOT есть ручные изменения; "
                             "сохраните их отдельно перед автоматической настройкой.")
        # Moving a block containing [all] could change the meaning of later settings.
        if any(line.strip() and not line.lstrip().startswith("#") for line in lines[end + 1:]):
            raise ValueError("После блока AXIORA MANAGED BOOT есть настройки; "
                             "переместите блок в конец config.txt вручную.")
        prefix, suffix = "".join(lines[:start]), "".join(lines[end + 1:])
        outside = lines[:start] + lines[end + 1:]
    else:
        prefix, suffix, outside = text, "", lines

    for number, line in enumerate(outside, 1):
        directive = line.split("#", 1)[0].strip().lower()
        if re.match(r"include(?:\s|=|$)", directive):
            raise ValueError(f"config.txt: include в строке {number}; вложенные файлы "
                             "могут менять GPIO. Настройте загрузчик вручную.")
        overlay = re.match(r"dtoverlay\s*=\s*([^,\s]+)", directive)
        if overlay and overlay.group(1).startswith(_CONFLICTING_OVERLAYS):
            raise ValueError(f"config.txt: конфликтующий dtoverlay в строке {number}: "
                             f"{directive}. Проверьте его вручную.")
        # A custom prefix/alternate DTB bypasses our checked overlays directory.
        if re.match(r"(?:overlay_prefix|os_prefix|device_tree)\s*=", directive):
            raise ValueError(f"config.txt: нестандартный путь Device Tree в строке "
                             f"{number}; настройте загрузчик вручную.")

    newline = "\r\n" if "\r\n" in text else "\n"
    block = [BEGIN, "[all]", "dtoverlay=axiora-spi", "dtoverlay=uart0-pi5"]
    if enable_rdm:
        block.append("dtoverlay=uart4-pi5")
    block.append(END)
    if prefix and not prefix.endswith(("\n", "\r")):
        prefix += newline
    return prefix + newline.join(block) + newline + suffix


def configure_pi(project: Path, run, boot_dir: Path | None = None,
                 enable_rdm=False) -> bool:
    """Compile the overlay, back up config and install only changed files.

    The caller validates that the actual host is a Pi 5 and has obtained the
    explicit --configure-pi opt-in. run accepts argv and optional input,
    capture and env keywords; it must raise on command failure.
    """
    boot = select_boot_dir(boot_dir)
    config = (boot / "config.txt").resolve(strict=True)
    overlays = (boot / "overlays").resolve(strict=True)
    original = config.read_bytes()
    merged = merge_boot_config(original.decode("utf-8"), enable_rdm=enable_rdm).encode("utf-8")
    required = ["uart0-pi5.dtbo"] + (["uart4-pi5.dtbo"] if enable_rdm else [])
    for name in required:
        if not (overlays / name).is_file():
            raise ValueError(f"В {overlays} отсутствует {name}; нужен образ с "
                             "overlays Raspberry Pi 5. Загрузчик не изменён.")
    source = Path(project) / "hardware" / "axiora-spi-overlay.dts"
    if not source.is_file():
        raise ValueError(f"Не найден исходник Device Tree: {source}")
    destination = overlays / "axiora-spi.dtbo"
    if destination.is_symlink():
        raise ValueError(f"{destination} является ссылкой; проверьте её вручную.")
    with tempfile.TemporaryDirectory(prefix="axiora-pi-") as directory:
        compiled = Path(directory) / "axiora-spi.dtbo"
        run(["dtc", "-@", "-I", "dts", "-O", "dtb", "-o", str(compiled), str(source)])
        payload = compiled.read_bytes()
        overlay_changed = not destination.is_file() or destination.read_bytes() != payload
        config_changed = merged != original
        if not (overlay_changed or config_changed):
            return False
        # Detect an administrator edit made while dtc was running before writing.
        if config.read_bytes() != original:
            raise ValueError("config.txt изменился во время подготовки; повторите настройку.")
        if config_changed:
            prepared = Path(directory) / "config.txt"
            prepared.write_bytes(merged)
            token = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:12]
            backup = config.with_name(config.name + ".axiora-backup-" + token)
            run(["sudo", "--", "cp", "--preserve=mode", "--no-clobber", "--",
                 str(config), str(backup)])
            print(f"Резервная копия config.txt: {backup}")
        # Install the overlay first: never reference a not-yet-installed DTBO.
        if overlay_changed:
            run(["sudo", "--", "install", "-m", "644", "--", str(compiled), str(destination)])
        if config_changed:
            mode = format(config.stat().st_mode & 0o777, "o")
            run(["sudo", "--", "install", "-m", mode, "--", str(prepared), str(config)])
    print("Настройка загрузчика Axiora сохранена; применится после вашей перезагрузки.")
    return True
