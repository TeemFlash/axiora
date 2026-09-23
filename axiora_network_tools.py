"""Network workbench adapters. Commands are argv lists, never shell text.

External tools are optional and run only when explicitly selected. Parsers retain
raw artifacts, distinguish observations from findings, and fail on malformed data.
"""
from collections import Counter
import csv
import hashlib
import io
import ipaddress
import json
from pathlib import Path
import re
import shutil
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import xml.etree.ElementTree as ET

from axiora_tool_api import Field, Tool

MAX_TEXT = 2 * 1024 * 1024
SEVERITIES = {"info", "low", "medium", "high", "critical"}
NSE_PROFILES = {
    "inventory": ("http-title", "http-headers", "ssl-cert", "ssh-hostkey", "smb-protocols"),
    "configuration": ("http-security-headers", "ssl-enum-ciphers", "ssh2-enum-algos", "smb2-security-mode"),
    "known-vulnerabilities": ("ssl-heartbleed", "ssl-poodle", "smb-vuln-ms17-010"),
}


def text_param(value, label="значение", max_length=4096):
    value = str(value).strip()
    if len(value) > max_length or "\x00" in value or any(ord(c) < 32 for c in value if c not in "\n\t"):
        raise ValueError(f"Некорректное {label}")
    return value


def bounded_int(value, low, high, label):
    if isinstance(value, bool) or not re.fullmatch(r"\d+", str(value).strip()):
        raise ValueError(f"{label}: требуется целое число {low}–{high}")
    number = int(value)
    if not low <= number <= high:
        raise ValueError(f"{label}: допустимо {low}–{high}")
    return number


def host(value, networks=False):
    value = text_param(value, "адрес", 253)
    if not value or value.startswith("-") or any(c.isspace() for c in value):
        raise ValueError("Укажите один IP-адрес или DNS-имя")
    if "/" in value:
        if not networks:
            raise ValueError("Для этой операции требуется один узел, без CIDR")
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise ValueError("Некорректная подсеть CIDR") from exc
        if net.num_addresses > 1024:
            raise ValueError("Один запуск ограничен 1024 адресами")
        return str(net)
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    if re.fullmatch(r"[0-9.,*-]+", value):
        raise ValueError("Некорректный IPv4-адрес")
    # Only unambiguous DNS names; no option/range/file syntax accepted by scanners.
    if not all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
               for label in value.rstrip(".").split(".")):
        raise ValueError("Некорректное DNS-имя")
    return value


def url(value):
    value = text_param(value, "URL", 4096)
    if any(c.isspace() for c in value) or "\\" in value:
        raise ValueError("URL не должен содержать пробелы или обратную косую черту")
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Некорректный URL") from exc
    if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ValueError("Требуется HTTP/HTTPS URL без логина, пароля и фрагмента")
    host(parsed.hostname)
    if port is not None:
        bounded_int(port, 1, 65535, "Порт")
    return value


def iface(value):
    value = text_param(value, "интерфейс", 32)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,31}", value):
        raise ValueError("Некорректное имя интерфейса")
    # Prevent dumpcap remote capture / FIFO / extcap input; names must be local.
    if value not in {name for _, name in socket.if_nameindex()}:
        raise ValueError(f"Локальный интерфейс {value!r} не найден")
    return value


def ports(value):
    value = text_param(value, "порты", 4096)
    if not value or not re.fullmatch(r"\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*", value):
        raise ValueError("Порты: например 22,80,443 или 1-1024")
    for item in value.split(","):
        pair = item.split("-")
        nums = [bounded_int(v, 1, 65535, "Порт") for v in pair]
        if len(nums) == 2 and nums[0] > nums[1]:
            raise ValueError("Начало диапазона портов больше конца")
    return value


def choice(params, key, choices, default):
    value = str(params.get(key, default))
    if value not in choices:
        raise ValueError(f"{key}: допустимо {', '.join(choices)}")
    return value


def existing_file(value, max_size=64 * 1024 * 1024, suffixes=()):
    path = Path(str(value)).expanduser().resolve()
    if not path.is_file() or path.stat().st_size > max_size:
        raise ValueError(f"Требуется файл размером не более {max_size // 1024 // 1024} MiB")
    if suffixes and path.suffix.lower() not in suffixes:
        raise ValueError(f"Допустимые расширения: {', '.join(suffixes)}")
    return path


def read_text(path, limit=MAX_TEXT):
    if path.stat().st_size > limit:
        raise ValueError(f"Вывод {path.name} превышает лимит {limit} байт; откройте исходный артефакт")
    return path.read_text(encoding="utf-8")


def json_object(text, label):
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise ValueError(f"Некорректный JSON: {label}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"{label}: ожидается JSON-объект")
    return data


def check_target(ctx, target):
    ctx.check_cancel()
    ctx.check_target(target)


def result(summary, data=None, assets=None, findings=None):
    return {"summary": summary, "assets": assets or [], "findings": findings or [], "data": data or {}}


def parse_nmap(xml):
    if len(xml.encode("utf-8")) > MAX_TEXT or "<!ENTITY" in xml.upper():
        raise ValueError("XML Nmap слишком большой или содержит запрещённые сущности")
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as exc:
        raise ValueError("Nmap вернул неполный или некорректный XML") from exc
    if root.tag != "nmaprun":
        raise ValueError("Ожидался корневой элемент nmaprun")
    finished = root.find("runstats/finished")
    if finished is None or finished.get("exit") != "success":
        raise ValueError("Nmap не подтвердил успешное завершение: " + (finished.get("errormsg", "нет runstats") if finished is not None else "нет runstats"))
    assets, findings = [], []
    for node in root.findall("host"):
        addresses = [dict(item.attrib) for item in node.findall("address")]
        address = next((a["addr"] for a in addresses if a.get("addrtype") in ("ipv4", "ipv6")), "")
        if not address:
            continue
        services, script_rows = [], []
        for port_node in node.findall("ports/port"):
            state = port_node.find("state")
            service = port_node.find("service")
            row = {"port": int(port_node.get("portid", "0")), "protocol": port_node.get("protocol", ""),
                   "state": state.get("state", "unknown") if state is not None else "unknown",
                   "service": dict(service.attrib) if service is not None else {}, "scripts": []}
            for script in port_node.findall("script"):
                entry = {"id": script.get("id", ""), "output": script.get("output", ""), "port": row["port"]}
                row["scripts"].append(entry)
                script_rows.append(entry)
            services.append(row)
        for script in node.findall("hostscript/script"):
            script_rows.append({"id": script.get("id", ""), "output": script.get("output", "")})
        state = node.find("status")
        asset = {"address": address, "target": address, "addresses": addresses,
                 "names": [h.get("name", "") for h in node.findall("hostnames/hostname")],
                 "status": state.get("state", "unknown") if state is not None else "unknown", "services": services,
                 "scripts": script_rows}
        assets.append(asset)
        for entry in script_rows:
            # A version match is not proof; only explicit NSE vulnerability state is reported.
            if re.search(r"(?m)^\s*(?:State:\s*)?VULNERABLE\s*(?:$|:)", entry["output"], re.I):
                findings.append({"title": f"NSE: {entry['id']}", "target": address, "severity": "high",
                                 "confidence": "scanner-reported", "evidence": entry["output"], "port": entry.get("port"),
                                 "remediation": "Проверьте рекомендацию NSE и версию исправления; подтвердите результат повторной проверкой."})
    return result(f"Nmap: {sum(a['status'] == 'up' for a in assets)} доступных узлов, {len(findings)} результатов проверки", {"scanner": root.attrib}, assets, findings)


def nmap_run(ctx, params):
    target = host(params.get("target", ""), networks=True)
    check_target(ctx, target)
    mode = choice(params, "mode", ("discovery", "services", "nse"), "services")
    rate = bounded_int(params.get("rate", "100"), 1, 1000, "Максимальная скорость")
    output = ctx.path("nmap.xml")
    argv = ["nmap", "-n", "--noninteractive", "--max-retries", "1", "--max-rate", str(rate),
            "--host-timeout", "240s", "--reason", "-oX", str(output)]
    if ":" in target:
        argv.append("-6")
    if mode == "discovery":
        argv.append("-sn")
    else:
        argv += ["-sT", "-sV", "--version-light", "-p", ports(params.get("ports", "22,80,443,445,3389,8080"))]
        if choice(params, "skip_discovery", ("no", "yes"), "no") == "yes":
            argv.append("-Pn")
        if mode == "nse":
            profile = choice(params, "profile", tuple(NSE_PROFILES), "configuration")
            argv += ["--script", ",".join(NSE_PROFILES[profile]), "--script-timeout", "30s"]
    argv.append(target)
    ctx.run(argv, timeout=600, output_name="nmap-console.txt")
    parsed = parse_nmap(read_text(output))
    parsed["data"]["xml"] = str(output)
    return parsed


def diagnostics(ctx, params):
    target = host(params.get("target", ""))
    check_target(ctx, target)
    mode = choice(params, "mode", ("ping", "trace", "dns", "route", "mtu", "connection"), "ping")
    source = str(params.get("source", "")).strip()
    if source:
        try:
            source = str(ipaddress.ip_address(source))
        except ValueError as exc:
            raise ValueError("Исходный адрес должен быть локальным IP") from exc
    if mode == "ping":
        count = bounded_int(params.get("count", "4"), 1, 100, "Число пакетов")
        argv = ["ping", "-n", "-c", str(count), "-W", "2", "-i", "1"]
        if source:
            argv += ["-I", source]
        argv += [target]
        response = ctx.run(argv, timeout=count * 3 + 5, allowed_exit=(0, 1), output_name="ping.txt")
        loss = re.search(r"([\d.]+)% packet loss", response.stdout)
        data = {"output": response.stdout, "exit_code": response.returncode}
        if loss:
            data["packet_loss_percent"] = float(loss.group(1))
        return result("Ping: ответы получены" if response.returncode == 0 else "Ping: нет ответов; ICMP может фильтроваться", data)
    if mode == "trace":
        if source:
            raise ValueError("Исходный IP задаётся в режимах ping и mtu; для маршрута используйте route")
        if shutil.which("tracepath"):
            argv = ["tracepath", "-n", "-m", "20", target]
        else:
            argv = ["traceroute", "-n", "-m", "20", "-q", "1", "-w", "1", target]
        response = ctx.run(argv, timeout=90, output_name="trace.txt", allowed_exit=(0, 1))
    elif mode == "dns":
        record = choice(params, "record", ("A", "AAAA", "MX", "TXT", "NS", "SOA", "CAA", "PTR"), "A")
        argv = ["dig", "+time=3", "+tries=1"]
        server = str(params.get("dns_server", "")).strip()
        if server:
            server = host(server)
            check_target(ctx, server)
            argv.append("@" + server)
        if record == "PTR":
            try:
                ipaddress.ip_address(target)
            except ValueError as exc:
                raise ValueError("PTR требует IP-адрес") from exc
            argv += ["-x", target]
        else:
            argv += [target, record]
        response = ctx.run(argv, timeout=10, output_name="dns.txt", allowed_exit=(0, 9))
    elif mode == "route":
        try:
            address = ipaddress.ip_address(target)
        except ValueError as exc:
            raise ValueError("Для route укажите IP-адрес") from exc
        argv = ["ip", "-j", "-6" if address.version == 6 else "-4", "route", "get", str(address)]
        if source:
            argv += ["from", source]
        response = ctx.run(argv, timeout=5, output_name="route.json")
        try:
            route = json.loads(response.stdout)
        except json.JSONDecodeError as exc:
            raise ValueError("ip route вернул некорректный JSON") from exc
        return result("Маршрут, выбранный ядром", {"route": route})
    elif mode == "mtu":
        size = bounded_int(params.get("payload", "1472"), 0, 8972, "Размер ICMP payload")
        argv = ["ping", "-n", "-c", "3", "-W", "2", "-M", "do", "-s", str(size)]
        if source:
            argv += ["-I", source]
        argv += [target]
        response = ctx.run(argv, timeout=15, output_name="mtu.txt", allowed_exit=(0, 1, 2))
        return result("DF-проба завершена; отсутствие ответа само по себе не определяет MTU",
                      {"payload_bytes": size, "output": response.stdout, "stderr": response.stderr, "exit_code": response.returncode})
    else:
        interface = iface(params.get("interface", "eth0"))
        response = ctx.run(["nmcli", "--mode", "multiline", "--fields", "GENERAL,IP4,IP6,DHCP4,DHCP6", "device", "show", interface],
                           timeout=10, output_name="connection.txt")
    return result(f"Диагностика {mode} завершена", {"output": response.stdout, "stderr": response.stderr, "exit_code": response.returncode})


def iperf_run(ctx, params):
    target = host(params.get("target", ""))
    check_target(ctx, target)
    port = bounded_int(params.get("port", "5201"), 1, 65535, "Порт")
    seconds = bounded_int(params.get("duration", "10"), 1, 120, "Длительность")
    streams = bounded_int(params.get("streams", "1"), 1, 4, "Потоки")
    mbps = bounded_int(params.get("mbps", "10"), 1, 1000, "Скорость на поток, Мбит/с")
    proto = choice(params, "protocol", ("tcp", "udp"), "tcp")
    argv = ["iperf3", "-c", target, "-p", str(port), "-t", str(seconds), "-P", str(streams),
            "-b", f"{mbps}M", "--connect-timeout", "5000", "-J"]
    if proto == "udp":
        argv.append("-u")
    if choice(params, "reverse", ("no", "yes"), "no") == "yes":
        argv.append("-R")
    source = str(params.get("source", "")).strip()
    if source:
        try:
            source = str(ipaddress.ip_address(source))
        except ValueError as exc:
            raise ValueError("Исходный адрес должен быть локальным IP") from exc
        argv += ["-B", source]
    response = ctx.run(argv, timeout=seconds + 20, output_name="iperf3.json")
    data = json_object(response.stdout, "iperf3")
    if data.get("error"):
        raise ValueError(f"iperf3: {data['error']}")
    if "end" not in data:
        raise ValueError("iperf3 не вернул итоговые измерения")
    return result("Измерение iperf3 завершено", data)


PACKET_FIELDS = ("frame.number", "frame.time_epoch", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst",
                 "_ws.col.Protocol", "frame.len", "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
                 "tcp.analysis.retransmission", "dns.flags.rcode")


def parse_packets(text):
    protocols, flows = Counter(), Counter()
    packets, byte_count, retransmissions, dns_errors = 0, 0, 0, 0
    for row in csv.reader(io.StringIO(text), delimiter="\t", quotechar='"'):
        if not row:
            continue
        if len(row) != len(PACKET_FIELDS):
            raise ValueError("TShark вернул неполную строку; возможно превышен лимит вывода")
        try:
            length = int(row[7])
        except ValueError as exc:
            raise ValueError("Некорректная длина пакета TShark") from exc
        packets += 1
        byte_count += length
        protocols[row[6] or "unknown"] += 1
        src, dst = row[2] or row[3], row[4] or row[5]
        if src or dst:
            flows[(src, row[8] or row[10], dst, row[9] or row[11], "tcp" if row[8] else "udp" if row[10] else row[6])] += 1
        retransmissions += bool(row[12])
        dns_errors += bool(row[13] and row[13] != "0")
    return {"packets_analyzed": packets, "bytes_analyzed": byte_count, "protocols": dict(protocols),
            "tcp_retransmissions": retransmissions, "dns_error_responses": dns_errors,
            "flows": [{"source": key[0], "source_port": key[1], "destination": key[2], "destination_port": key[3],
                       "protocol": key[4], "packets": count} for key, count in flows.most_common(1000)],
            "flow_count": len(flows)}


def analyze_capture(ctx, path, display_filter="", packet_limit=10000, artifact="packets.tsv"):
    argv = ["tshark", "-n", "-r", str(path), "-c", str(packet_limit)]
    if display_filter:
        argv += ["-Y", text_param(display_filter, "display filter", 2048)]
    argv += ["-T", "fields", "-E", "separator=/t", "-E", "quote=d", "-E", "occurrence=f"]
    for field in PACKET_FIELDS:
        argv += ["-e", field]
    response = ctx.run(argv, timeout=90, output_name=artifact, max_output=8 * 1024 * 1024)
    artifact_path = ctx.path(artifact)
    data = parse_packets(read_text(artifact_path, 8 * 1024 * 1024) if artifact_path.is_file() else response.stdout)
    data.update({"source_file": str(path), "packet_read_limit": packet_limit,
                 "display_filter": display_filter, "note": "Лимит относится к прочитанным кадрам до display filter; статистика относится только к выбранным кадрам."})
    return data


def capture_run(ctx, params):
    interface = iface(params.get("interface", "eth0"))
    seconds = bounded_int(params.get("duration", "15"), 1, 300, "Длительность")
    count = bounded_int(params.get("packets", "10000"), 1, 100000, "Пакеты")
    megabytes = bounded_int(params.get("megabytes", "16"), 1, 60, "Размер файла MiB")
    path = ctx.path("capture.pcapng")
    argv = ["dumpcap", "-i", interface, "-a", f"duration:{seconds}", "-a", f"filesize:{megabytes * 1024}",
            "-c", str(count), "-s", "2048", "-w", str(path)]
    capture_filter = text_param(params.get("capture_filter", ""), "BPF filter", 2048)
    if capture_filter:
        argv += ["-f", capture_filter]
    if choice(params, "monitor", ("no", "yes"), "no") == "yes":
        argv.append("-I")
    ctx.run(argv, timeout=seconds + 15, output_name="dumpcap.txt")
    if not path.is_file():
        raise ValueError("dumpcap не создал PCAPNG")
    data = analyze_capture(ctx, path, str(params.get("display_filter", "")), min(count, 10000))
    data["capture_file"] = str(path)
    data["capture_snaplen"] = 2048
    return result(f"Захват сохранён; разобрано {data['packets_analyzed']} кадров", data)


def pcap_run(ctx, params):
    path = existing_file(params.get("file", ""))
    limit = bounded_int(params.get("packets", "10000"), 1, 20000, "Пакеты")
    data = analyze_capture(ctx, path, str(params.get("display_filter", "")), limit)
    other = str(params.get("compare", "")).strip()
    if other:
        second = analyze_capture(ctx, existing_file(other), str(params.get("display_filter", "")), limit, "comparison-packets.tsv")
        keys = set(data["protocols"]) | set(second["protocols"])
        data["comparison"] = {"other": second, "protocol_delta_other_minus_first":
                              {k: second["protocols"].get(k, 0) - data["protocols"].get(k, 0) for k in sorted(keys)}}
    ctx.save_json("pcap-summary.json", data)
    return result(f"PCAP: разобрано {data['packets_analyzed']} кадров", data)


def parse_nuclei(text):
    rows, findings = [], []
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        row = json_object(line, f"Nuclei, строка {number}")
        info = row.get("info")
        if not isinstance(info, dict) or not row.get("template-id"):
            raise ValueError(f"Nuclei, строка {number}: нет template-id/info")
        if row.get("matcher-status") is False:
            continue
        severity = str(info.get("severity", "info")).lower()
        classification = info.get("classification") or {}
        findings.append({"title": str(info.get("name") or row["template-id"]),
                         "target": str(row.get("matched-at") or row.get("host") or ""),
                         "template_id": str(row["template-id"]), "matcher_id": str(row.get("matcher-name", "")),
                         "severity": severity if severity in SEVERITIES else "info", "confidence": "template-match",
                         "evidence": {"template_id": row["template-id"], "matcher": row.get("matcher-name"),
                                      "matched_at": row.get("matched-at"), "extracted": row.get("extracted-results", []),
                                      "request": row.get("request", ""), "response": row.get("response", "")},
                         "remediation": info.get("remediation", "Проверьте описание шаблона и подтвердите результат после исправления."),
                         "references": info.get("reference", []), "classification": classification})
        rows.append(row)
    return result(f"Nuclei: {len(findings)} совпадений шаблонов", {"matches": rows}, findings=findings)


def nuclei_run(ctx, params):
    target = url(params.get("target", ""))
    check_target(ctx, target)
    template_value = str(params.get("template", "")).strip()
    if not template_value:
        raise ValueError("Выберите локальный YAML-шаблон Nuclei или каталог шаблонов")
    template = Path(template_value).expanduser().resolve()
    if not template.exists() or (not template.is_dir() and template.suffix.lower() not in (".yaml", ".yml")):
        raise ValueError("Укажите установленный локальный YAML-шаблон Nuclei или каталог шаблонов")
    rate = bounded_int(params.get("rate", "5"), 1, 100, "Запросы/с")
    output = ctx.path("nuclei.jsonl")
    # No template download, cloud reporting, OAST service or automatic redirect.
    argv = ["nuclei", "-u", target, "-t", str(template), "-jsonl", "-o", str(output), "-silent", "-nc",
            "-duc", "-ni", "-dr", "-pt", "http,ssl", "-rl", str(rate), "-c", "2", "-bs", "1",
            "-timeout", "5", "-retries", "0", "-rsr", "1048576", "-rss", "65536"]
    ctx.run(argv, timeout=600, output_name="nuclei-console.txt")
    if not output.is_file():
        raise ValueError("Nuclei не создал JSONL; проверьте шаблоны и версию программы")
    parsed = parse_nuclei(read_text(output))
    parsed["data"]["output_file"] = str(output)
    parsed["data"]["template_path"] = str(template)
    return parsed


def parse_testssl(text):
    try:
        rows = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError("Некорректный JSON testssl.sh") from exc
    if not isinstance(rows, list):
        raise ValueError("Ожидался плоский JSON-массив testssl.sh")
    findings = []
    for row in rows:
        if not isinstance(row, dict) or not {"id", "severity", "finding"} <= row.keys():
            raise ValueError("Некорректная запись testssl.sh")
        severity = str(row["severity"]).lower()
        if severity in ("low", "medium", "high", "critical", "warn"):
            findings.append({"title": f"TLS: {row['id']}", "target": str(row.get("ip", "")),
                             "severity": "low" if severity == "warn" else severity, "confidence": "scanner-reported",
                             "evidence": row["finding"], "cve": row.get("cve", ""), "cwe": row.get("cwe", ""),
                             "remediation": "Обновите TLS-конфигурацию или сертификат согласно результату testssl.sh и перепроверьте."})
    return result(f"TLS: {len(rows)} проверок, {len(findings)} замечаний", {"checks": rows}, findings=findings)


def tls_run(ctx, params):
    target = url(params.get("target", ""))
    if urllib.parse.urlsplit(target).scheme != "https":
        raise ValueError("Для TLS укажите https://имя:порт")
    check_target(ctx, target)
    mode = choice(params, "mode", ("configuration", "full"), "configuration")
    executable = shutil.which("testssl.sh") or shutil.which("testssl")
    if not executable:
        raise ValueError("Установите testssl.sh (в Kali пакет testssl.sh)")
    output = ctx.path("testssl.json")
    argv = [executable, "--warnings", "batch", "--color", "0", "--connect-timeout", "5", "--openssl-timeout", "5", "--jsonfile", str(output)]
    if mode == "configuration":
        argv += ["--protocols", "--server-defaults", "--server-preference"]
    argv.append(target)
    response = ctx.run(argv, timeout=900, output_name="testssl-console.txt", allowed_exit=tuple(range(50)))
    if not output.is_file():
        raise ValueError(f"testssl.sh не создал JSON (код {response.returncode})")
    parsed = parse_testssl(read_text(output))
    parsed["data"]["exit_code"] = response.returncode
    parsed["data"]["completed_without_errors"] = response.returncode == 0
    if response.returncode:
        parsed["summary"] += f"; неоднозначные результаты/ошибки testssl.sh (код {response.returncode}), см. журнал"
    for finding in parsed["findings"]:
        finding["target"] = target
    return parsed


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def http_request(target, method="GET", headers=None, body=None, verify=True, timeout=5, limit=1024 * 1024, check=None):
    handlers = [urllib.request.ProxyHandler({}), NoRedirect()]
    if not verify:
        handlers.append(urllib.request.HTTPSHandler(context=ssl._create_unverified_context()))
    opener = urllib.request.build_opener(*handlers)
    request = urllib.request.Request(target, data=body, method=method, headers=headers or {})
    started = time.monotonic()
    try:
        response = opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as exc:
        response = exc
    with response:
        chunks, remaining = [], limit + 1
        while remaining:
            if check:
                check()
            if time.monotonic() - started > timeout:
                raise TimeoutError("HTTP: превышен общий тайм-аут ответа")
            # read1 returns after at most one underlying read, allowing cancellation
            # and a total deadline even when the peer sends a slow trickle of bytes.
            chunk = response.read1(min(8192, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        return {"url": target, "status": response.status, "headers": list(response.headers.items()),
                "body": content[:limit].decode("utf-8", errors="replace"), "body_truncated": len(content) > limit,
                "body_bytes": min(len(content), limit), "body_sha256": hashlib.sha256(content[:limit]).hexdigest(),
                "elapsed_ms": round((time.monotonic() - started) * 1000, 2)}


def http_headers(value):
    headers_text = str(value).strip() or "{}"
    if len(headers_text.encode()) > 65536:
        raise ValueError("HTTP headers ограничены 64 KiB")
    headers = json_object(headers_text, "HTTP headers")
    for name, value in headers.items():
        if not isinstance(value, str) or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name) or any(c in value for c in "\r\n\x00"):
            raise ValueError("Некорректное имя или значение HTTP-заголовка")
        if name.lower() in ("host", "content-length", "transfer-encoding", "connection"):
            raise ValueError(f"Заголовок {name} управляется HTTP-клиентом")
    return headers


def http_run(ctx, params):
    target = url(params.get("target", ""))
    check_target(ctx, target)
    method = choice(params, "method", ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"), "GET")
    headers = http_headers(params.get("headers", "{}"))
    body = str(params.get("body", ""))
    if len(body.encode()) > 65536:
        raise ValueError("HTTP body ограничен 64 KiB")
    verify = choice(params, "verify_tls", ("yes", "no"), "yes") == "yes"
    data = http_request(target, method, headers, body.encode() if body else None, verify, check=ctx.check_cancel)
    ctx.check_cancel()
    ctx.save_json("http-response.json", data)
    return result(f"HTTP {data['status']}, {data['elapsed_ms']} мс; перенаправления не выполнялись", data)


def access_check(ctx, params):
    target = url(params.get("target", ""))
    check_target(ctx, target)
    method = choice(params, "method", ("GET", "HEAD"), "GET")
    expected = choice(params, "expected", ("compare_only", "second_denied"), "compare_only")
    verify = choice(params, "verify_tls", ("yes", "no"), "yes") == "yes"
    # Validate both roles before sending either request. Credentials are supplied
    # by the operator; no guessing, automatic login or session reuse is performed.
    first_headers = http_headers(params.get("first_headers", "{}"))
    second_headers = http_headers(params.get("second_headers", "{}"))
    first = http_request(target, method=method, headers=first_headers, verify=verify, check=ctx.check_cancel)
    check_target(ctx, target)
    second = http_request(target, method=method, headers=second_headers, verify=verify, check=ctx.check_cancel)
    ctx.check_cancel()
    evidence = {"url": target, "method": method, "expected": expected,
                "first": {key: first[key] for key in ("status", "body_bytes", "body_sha256", "body_truncated")},
                "second": {key: second[key] for key in ("status", "body_bytes", "body_sha256", "body_truncated")},
                "status_equal": first["status"] == second["status"],
                "body_hash_equal": first["body_sha256"] == second["body_sha256"],
                "length_equal": first["body_bytes"] == second["body_bytes"]}
    findings = []
    if expected == "second_denied" and 200 <= second["status"] < 300:
        verdict = "requires_review"
        findings.append({"title": "Web: второй контекст получил HTTP 2xx вопреки ожидаемому отказу",
                         "target": target, "method": method, "severity": "medium", "confidence": "requires_review",
                         "evidence": evidence, "remediation": "Проверьте, содержит ли второй ответ защищённые данные или действие. "
                         "Сверьте права обеих ролей и серверную проверку доступа; HTTP 2xx может быть страницей входа или ошибкой приложения."})
    elif expected == "second_denied" and second["status"] in (401, 403):
        verdict = "expected_http_denial"
    elif expected == "second_denied":
        verdict = "inconclusive"
    else:
        verdict = "comparison_only"
    data = {"comparison": evidence, "verdict": verdict, "first_response": first, "second_response": second,
            "note": "Различие или совпадение статусов и тел не доказывает корректность либо нарушение авторизации. "
                    "Сравните содержание и ожидаемые права вручную. При обрезке SHA-256 относится только к сохранённому префиксу; "
                    "HEAD сравнивает только статусы и заголовки. Перенаправления не выполняются."}
    ctx.save_json("access-check.json", data)
    summary = f"Сравнение доступа: HTTP {first['status']} → {second['status']}; {verdict}"
    return result(summary, data, findings=findings)


def openapi_run(ctx, params):
    path = existing_file(params.get("file", ""), max_size=2 * 1024 * 1024, suffixes=(".json",))
    data = json_object(read_text(path), "OpenAPI")
    version = str(data.get("openapi") or data.get("swagger") or "")
    if not version or not isinstance(data.get("paths"), dict):
        raise ValueError("Ожидается OpenAPI 3.x или Swagger 2.0 JSON с paths")
    endpoints = []
    for route, methods in data["paths"].items():
        if not isinstance(methods, dict):
            raise ValueError("Некорректный объект OpenAPI paths")
        for method, operation in methods.items():
            if method.lower() not in ("get", "post", "put", "patch", "delete", "head", "options", "trace"):
                continue
            if not isinstance(operation, dict):
                raise ValueError("Некорректная операция OpenAPI")
            endpoints.append({"method": method.upper(), "path": route, "summary": operation.get("summary", ""),
                              "operationId": operation.get("operationId", ""), "parameters": operation.get("parameters", []),
                              "security": operation.get("security", data.get("security", [])),
                              "responses": list(operation.get("responses", {}))})
    parsed = {"version": version, "info": data.get("info", {}), "servers": data.get("servers", []),
              "host": data.get("host"), "basePath": data.get("basePath"), "endpoints": endpoints,
              "note": "Импорт инвентаризирует операции; внешние $ref не загружаются. Запросы выполняются отдельно через HTTP inspector."}
    ctx.save_json("openapi-inventory.json", parsed)
    return result(f"OpenAPI: {len(endpoints)} операций", parsed)


def segmentation(ctx, params):
    try:
        matrix = json.loads(str(params.get("matrix", "[]")))
    except json.JSONDecodeError as exc:
        raise ValueError("Матрица должна быть JSON-массивом") from exc
    if not isinstance(matrix, list) or not 1 <= len(matrix) <= 128:
        raise ValueError("Матрица: 1–128 записей {target, port, expected: open|closed}")
    timeout = bounded_int(params.get("timeout", "2"), 1, 5, "Тайм-аут")
    source = str(params.get("source", "")).strip()
    if source:
        try:
            source = str(ipaddress.ip_address(source))
        except ValueError as exc:
            raise ValueError("Исходный адрес должен быть локальным IP") from exc
    validated = []
    # Validate the entire matrix and its scope before making any connection.
    for item in matrix:
        if not isinstance(item, dict):
            raise ValueError("Каждая строка матрицы должна быть объектом")
        target = host(item.get("target", ""))
        check_target(ctx, target)
        port = bounded_int(item.get("port", ""), 1, 65535, "Порт")
        expected = item.get("expected", "open")
        if expected not in ("open", "closed"):
            raise ValueError("expected: open или closed")
        validated.append((target, port, expected))
    rows, findings = [], []
    for target, port, expected in validated:
        ctx.check_cancel()
        check_target(ctx, target)
        started = time.monotonic()
        error = ""
        try:
            with socket.create_connection((target, port), timeout=timeout, source_address=(source, 0) if source else None):
                state = "open"
        except ConnectionRefusedError as exc:
            state, error = "refused", str(exc)
        except (TimeoutError, socket.timeout) as exc:
            state, error = "timeout", str(exc)
        except OSError as exc:
            state, error = "error", str(exc)
        # Timeout or routing failure cannot establish that a firewall blocked the port.
        verdict = "pass" if state == "open" and expected == "open" else "fail" if state == "open" and expected == "closed" else "inconclusive" if state in ("timeout", "error") else "pass" if expected == "closed" else "fail"
        row = {"target": target, "port": port, "expected": expected, "observed": state, "verdict": verdict,
               "source": source or "kernel-selected", "elapsed_ms": round((time.monotonic() - started) * 1000, 2), "error": error}
        rows.append(row)
        ctx.emit(f"{target}:{port} → {state} ({verdict})")
        if verdict == "fail":
            findings.append({"title": "Сегментация: фактическая доступность отличается от ожидаемой", "target": target,
                             "port": port, "parameter": source or "kernel-selected",
                             "severity": "medium" if expected == "closed" else "low", "confidence": "observed",
                             "evidence": row, "remediation": "Сверьте маршрут, состояние службы и правила межсетевого экрана."})
    ctx.save_json("segmentation.json", rows)
    return result(f"Матрица: {len(rows)} проверок, {len(findings)} расхождений", {"checks": rows}, findings=findings)


def zap_call(base, key, component, kind, action, arguments=None):
    endpoint = base.rstrip("/") + f"/JSON/{component}/{kind}/{action}/"
    if arguments:
        endpoint += "?" + urllib.parse.urlencode(arguments)
    response = http_request(endpoint, headers={"X-ZAP-API-Key": key}, limit=MAX_TEXT)
    if response["body_truncated"]:
        raise ValueError("Ответ ZAP превышает 2 MiB")
    data = json_object(response["body"], "ZAP API")
    if response["status"] != 200 or "code" in data:
        raise ValueError("Ошибка ZAP API: " + str(data.get("message") or data.get("code") or response["status"]))
    return data


def zap_alerts(rows):
    findings = []
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("Некорректная запись ZAP alerts")
        risk = str(row.get("risk", "Informational")).lower()
        findings.append({"title": str(row.get("alert", "ZAP finding")), "target": str(row.get("url", "")),
                         "plugin_id": str(row.get("pluginId", "")), "parameter": str(row.get("param", "")),
                         "method": str(row.get("method", "")),
                         "severity": risk if risk in SEVERITIES else "info", "confidence": str(row.get("confidence", "unknown")),
                         "evidence": {"evidence": row.get("evidence", ""), "parameter": row.get("param", ""),
                                      "description": row.get("description", ""), "pluginId": row.get("pluginId")},
                         "remediation": row.get("solution", ""), "references": row.get("reference", "")})
    return findings


def zap_run(ctx, params):
    base = url(params.get("endpoint", "http://127.0.0.1:8090"))
    parsed = urllib.parse.urlsplit(base)
    if parsed.hostname not in ("127.0.0.1", "::1") or parsed.path not in ("", "/") or parsed.query:
        raise ValueError("ZAP API должен слушать 127.0.0.1 или [::1], без пути и query")
    key = str(params.get("api_key", ""))
    if not key or any(c in key for c in "\r\n\x00"):
        raise ValueError("Укажите API key ZAP")
    mode = choice(params, "mode", ("policies", "alerts", "scan"), "policies")
    ctx.check_cancel()
    if mode == "policies":
        data = zap_call(base, key, "ascan", "view", "scanPolicyNames")
        return result("Политики локального ZAP", data)
    target = url(params.get("target", ""))
    check_target(ctx, target)
    if mode == "alerts":
        rows = zap_call(base, key, "core", "view", "alerts", {"baseurl": target, "start": "0", "count": "1000"}).get("alerts", [])
        # ZAP baseurl is a prefix; reject adjacent host/path prefix matches.
        target_parts = urllib.parse.urlsplit(target)
        rows = [row for row in rows if urllib.parse.urlsplit(str(row.get("url", ""))).netloc == target_parts.netloc]
        return result(f"ZAP: {len(rows)} сохранённых замечаний (лимит 1000)", {"alerts": rows}, findings=zap_alerts(rows))
    policy = text_param(params.get("policy", "Default Policy"), "политика", 128)
    policies = zap_call(base, key, "ascan", "view", "scanPolicyNames").get("scanPolicyNames", [])
    if policy not in policies:
        raise ValueError(f"Политика {policy!r} не найдена; сначала получите список политик")
    seconds = bounded_int(params.get("duration", "120"), 10, 600, "Длительность ZAP")
    name, context_id, scan_id, completed = "axiora-" + uuid.uuid4().hex[:12], None, None, False
    try:
        context_id = zap_call(base, key, "context", "action", "newContext", {"contextName": name}).get("contextId")
        if context_id is None:
            raise ValueError("ZAP не вернул contextId")
        scoped_url = urllib.parse.urlunsplit(urllib.parse.urlsplit(target)._replace(query=""))
        zap_call(base, key, "context", "action", "includeInContext", {"contextName": name, "regex": re.escape(scoped_url) + r"(?:\?.*)?"})
        zap_call(base, key, "context", "action", "setContextInScope", {"contextName": name, "booleanInScope": "true"})
        ctx.check_cancel()
        zap_call(base, key, "core", "action", "accessUrl", {"url": target, "followRedirects": "false"})
        scan_id = zap_call(base, key, "ascan", "action", "scan", {"url": target, "recurse": "false", "inScopeOnly": "true",
                            "scanPolicyName": policy, "contextId": context_id}).get("scan")
        if scan_id is None:
            raise ValueError("ZAP не вернул scan ID")
        deadline, last_status = time.monotonic() + seconds, None
        while time.monotonic() < deadline:
            ctx.check_cancel()
            status = zap_call(base, key, "ascan", "view", "status", {"scanId": scan_id}).get("status")
            progress = bounded_int(status, 0, 100, "ZAP progress")
            if progress != last_status:
                ctx.emit(f"ZAP scan {scan_id}: {progress}%")
                last_status = progress
            if progress == 100:
                completed = True
                break
            # Interruptible without depending on an Event type in the contract.
            for _ in range(10):
                ctx.check_cancel()
                time.sleep(0.1)
    finally:
        if scan_id is not None and not completed:
            try:
                zap_call(base, key, "ascan", "action", "stop", {"scanId": scan_id})
            except Exception as exc:
                ctx.emit(f"Не удалось остановить ZAP scan {scan_id}: {exc}")
        if context_id is not None:
            try:
                zap_call(base, key, "context", "action", "removeContext", {"contextName": name})
            except Exception as exc:
                ctx.emit(f"Не удалось удалить временный контекст ZAP: {exc}")
    ctx.check_cancel()
    rows = zap_call(base, key, "core", "view", "alerts", {"baseurl": target, "start": "0", "count": "1000"}).get("alerts", [])
    rows = [row for row in rows if str(row.get("url", "")).split("?", 1)[0] == target.split("?", 1)[0]]
    data = {"scan_id": scan_id, "completed": completed, "alerts": rows,
            "note": "Один URL, без spider; alerts могут включать прежние результаты текущей сессии ZAP. Лимит 1000."}
    ctx.save_json("zap.json", data)
    return result(f"ZAP: {'завершён' if completed else 'остановлен по лимиту времени'}, {len(rows)} замечаний", data, findings=zap_alerts(rows))


F = Field
TOOLS = [
    Tool("net.nmap", "Nmap: карта сети и службы", "Сеть", "Обнаружение IPv4/IPv6, TCP-службы и выбранные профили NSE. XML сохраняется в проекте.",
         (F("target", "Узел или CIDR (до 1024 адресов)", required=True),
          F("mode", "Режим", "services", "choice", ("discovery", "services", "nse")),
          F("ports", "TCP-порты", "22,80,443,445,3389,8080"), F("rate", "Макс. пакетов/с", "100"),
          F("profile", "Профиль NSE", "configuration", "choice", tuple(NSE_PROFILES)),
          F("skip_discovery", "Считать узлы доступными (-Pn)", "no", "choice", ("no", "yes"))), ("nmap",), nmap_run, ("target",), 620),
    Tool("net.diagnostics", "Ping / DNS / маршрут / MTU / DHCP", "Сеть", "Диагностика без изменения сетевой конфигурации. Режим connection показывает настройки NetworkManager/DHCP.",
         (F("target", "IP или DNS-имя", required=True),
          F("mode", "Проверка", "ping", "choice", ("ping", "trace", "dns", "route", "mtu", "connection")),
          F("count", "Ping: число пакетов", "4"), F("source", "Исходный IP (ping, route, mtu)"),
          F("record", "DNS запись", "A", "choice", ("A", "AAAA", "MX", "TXT", "NS", "SOA", "CAA", "PTR")),
          F("dns_server", "DNS-сервер (пусто = системный)"), F("payload", "MTU: ICMP payload, байт", "1472"),
          F("interface", "Connection: интерфейс", "eth0")), (), diagnostics, ("target",), 320),
    Tool("net.iperf", "Скорость TCP / UDP (iperf3)", "Сеть", "Требуется iperf3 -s на второй машине. Лимит скорости применяется к каждому потоку.",
         (F("target", "Адрес сервера", required=True), F("port", "Порт сервера", "5201"),
          F("protocol", "Протокол", "tcp", "choice", ("tcp", "udp")), F("duration", "Секунды", "10"),
          F("streams", "Параллельные потоки", "1"), F("mbps", "Мбит/с на поток", "10"),
          F("reverse", "Обратное направление", "no", "choice", ("no", "yes")), F("source", "Исходный IP")),
         ("iperf3",), iperf_run, ("target",), 150),
    Tool("net.capture", "Захват пакетов", "Трафик", "Ограниченный по времени, размеру и пакетам PCAPNG; snaplen 2048. Нужны права dumpcap.",
         (F("interface", "Интерфейс", "eth0", required=True), F("duration", "Секунды (1–300)", "15"),
          F("packets", "Лимит кадров", "10000"), F("megabytes", "Лимит MiB (1–60)", "16"),
          F("capture_filter", "Capture filter (BPF)"), F("display_filter", "Display filter (TShark)"),
          F("monitor", "Wi-Fi monitor mode", "no", "choice", ("no", "yes"))),
         ("dumpcap", "tshark"), capture_run, timeout=420),
    Tool("net.pcap", "Анализ / сравнение PCAP", "Трафик", "Протоколы, потоки, TCP retransmissions, ошибки DNS. Статистика ограниченной выборки, не всей сети.",
         (F("file", "PCAP / PCAPNG файл", kind="file", required=True), F("display_filter", "Display filter"),
          F("packets", "Лимит прочитанных кадров (до 20000)", "10000"), F("compare", "Второй PCAP для сравнения", kind="file")),
         ("tshark",), pcap_run, timeout=200),
    Tool("sec.nuclei", "Nuclei: выбранные шаблоны", "Безопасность", "Локальные HTTP/TLS-шаблоны, ограничение запросов. Без загрузки шаблонов, OAST и переходов по redirect.",
         (F("target", "HTTP/HTTPS URL", required=True), F("template", "Путь к YAML-шаблону / каталогу", kind="file", required=True),
          F("rate", "Запросы/с (1–100)", "5")), ("nuclei",), nuclei_run, ("target",), 620),
    Tool("sec.tls", "TLS и сертификаты", "Безопасность", "Проверки testssl.sh с исходным JSON. Full может занять несколько минут.",
         (F("target", "https://имя:порт", required=True), F("mode", "Набор проверок", "configuration", "choice", ("configuration", "full"))),
         ("testssl.sh|testssl",), tls_run, ("target",), 920),
    Tool("web.http", "HTTP / API inspector", "Web / API", "Метод, заголовки, тело, статус, cookies и ответ. Redirect отображается без перехода; тело ответа до 1 MiB.",
         (F("target", "URL", required=True), F("method", "Метод", "GET", "choice", ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")),
          F("headers", "Заголовки JSON", "{}", secret=True), F("body", "Тело запроса", "", secret=True),
          F("verify_tls", "Проверять TLS-сертификат", "yes", "choice", ("yes", "no"))), (), http_run, ("target",), 15),
    Tool("web.openapi", "Импорт OpenAPI / Swagger JSON", "Web / API", "Локальный каталог операций, параметров и требований авторизации; без загрузки внешних $ref.",
         (F("file", "OpenAPI JSON", kind="file", required=True),), (), openapi_run),
    Tool("web.access_check", "Сравнение ролей / сессий", "Web / API", "Два GET/HEAD запроса к одному URL с заданными заголовками ролей. Статус, размер и SHA-256 ответа; расхождение требует ручной проверки.",
         (F("target", "URL", required=True), F("method", "Метод", "GET", "choice", ("GET", "HEAD")),
          F("first_headers", "Контекст A: заголовки JSON", "{}", secret=True),
          F("second_headers", "Контекст B: заголовки JSON ({} = без сессии)", "{}", secret=True),
          F("expected", "Ожидаемая политика", "compare_only", "choice", ("compare_only", "second_denied")),
          F("verify_tls", "Проверять TLS-сертификат", "yes", "choice", ("yes", "no"))),
         (), access_check, ("target",), 30),
    Tool("web.zap", "Локальный ZAP API", "Web / API", "Политики, сохранённые alerts и активная проверка одного URL по выбранной политике. ZAP запускается отдельно.",
         (F("endpoint", "Локальный API endpoint", "http://127.0.0.1:8090"), F("api_key", "ZAP API key", required=True, secret=True),
          F("mode", "Операция", "policies", "choice", ("policies", "alerts", "scan")), F("target", "URL проверки"),
          F("policy", "Имя политики", "Default Policy"), F("duration", "Лимит секунд", "120")), (), zap_run, ("target",), 650),
    Tool("net.segmentation", "Матрица сегментации / VPN", "Сеть", "TCP-проверки доступности с ожидаемой политикой. Timeout означает неопределённый результат, не доказанное блокирование.",
         (F("matrix", "JSON: target, port, expected", '[{"target":"127.0.0.1","port":22,"expected":"open"}]', kind="multiline", required=True),
          F("source", "Локальный исходный IP (например VPN)"), F("timeout", "Тайм-аут на узел, секунды", "2")),
         (), segmentation, timeout=660),
]
