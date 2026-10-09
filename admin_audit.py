#!/usr/bin/env python3
"""
admin_audit_win.py — выдача/отзыв прав администратора и аудит системы (Windows).

Запуск из PowerShell или cmd, открытого "От имени администратора":
    python admin_audit_win.py grant  <user>
    python admin_audit_win.py revoke <user>
    python admin_audit_win.py audit [--json] [--output report.txt]

Зависимости: только стандартная библиотека Python 3.6+ и встроенный PowerShell.
Лог действий: admin_audit.log рядом со скриптом.
"""

import argparse
import ctypes
import datetime
import json
import logging
import os
import platform
import re
import subprocess
import sys

LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "admin_audit.log")


# --------------------------------------------------------------------------- #
# Утилиты
# --------------------------------------------------------------------------- #
def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[logging.StreamHandler(sys.stdout),
                  logging.FileHandler(LOG_FILE, encoding="utf-8")],
    )


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def require_admin():
    if platform.system() != "Windows":
        sys.exit("Этот скрипт только для Windows.")
    if not is_admin():
        sys.exit("Ошибка: запустите терминал от имени администратора.")


def run(cmd, timeout=90):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           encoding="cp866", errors="replace")
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except (OSError, subprocess.TimeoutExpired) as e:
        return 1, "", str(e)


def ps(script, as_json=False):
    """Выполнить PowerShell-команду. При as_json возвращает разобранный JSON."""
    if as_json:
        script = f"[Console]::OutputEncoding=[Text.Encoding]::UTF8; {script} | ConvertTo-Json -Depth 3 -Compress"
    code, out, err = run(["powershell", "-NoProfile", "-NonInteractive",
                          "-ExecutionPolicy", "Bypass", "-Command", script])
    if code != 0 or not out:
        return None if as_json else (err or out)
    if as_json:
        try:
            data = json.loads(out)
            return data if isinstance(data, list) else [data]
        except json.JSONDecodeError:
            return None
    return out


def valid_username(name):
    # Запрещённые символы в именах Windows-аккаунтов
    return bool(name) and len(name) <= 20 and not re.search(r'[\\/\[\]:;|=,+*?<>"@]', name)


def local_user_exists(name):
    code, _, _ = run(["net", "user", name])
    return code == 0


def admin_group_name():
    """Группа администраторов локализована (Administrators / Администраторы) — берём по SID."""
    out = ps("(Get-LocalGroup -SID 'S-1-5-32-544').Name")
    return (out or "Administrators").strip()


# --------------------------------------------------------------------------- #
# Выдача / отзыв
# --------------------------------------------------------------------------- #
def grant(user):
    if not valid_username(user) or not local_user_exists(user):
        sys.exit(f"Локальный пользователь '{user}' не найден или имя некорректно.")
    group = admin_group_name()
    code, out, err = run(["net", "localgroup", group, user, "/add"])
    if code != 0:
        if "1378" in (out + err):
            sys.exit(f"{user} уже в группе {group}.")
        sys.exit(f"Не удалось выдать права: {out} {err}")
    logging.info("Права администратора выданы: %s (группа %s)", user, group)


def revoke(user):
    if not valid_username(user) or not local_user_exists(user):
        sys.exit(f"Локальный пользователь '{user}' не найден или имя некорректно.")
    group = admin_group_name()
    code, out, err = run(["net", "localgroup", group, user, "/delete"])
    if code != 0:
        sys.exit(f"Не удалось отозвать права: {out} {err}")
    logging.info("Права администратора отозваны: %s (группа %s)", user, group)


# --------------------------------------------------------------------------- #
# Аудит
# --------------------------------------------------------------------------- #
def audit_admins():
    data = ps("Get-LocalGroupMember -SID 'S-1-5-32-544' | "
              "Select-Object Name,ObjectClass,PrincipalSource", as_json=True)
    return [f"{d['Name']} ({d['ObjectClass']}, {d['PrincipalSource']})" for d in data] if data else []


def audit_users():
    data = ps("Get-LocalUser | Select-Object Name,Enabled,PasswordRequired,"
              "@{n='LastLogon';e={if($_.LastLogon){$_.LastLogon.ToString('s')}else{''}}},"
              "@{n='PwdLastSet';e={if($_.PasswordLastSet){$_.PasswordLastSet.ToString('s')}else{''}}}",
              as_json=True)
    res = []
    for u in data or []:
        flags = []
        if u["Enabled"] and not u["PasswordRequired"]:
            flags.append("ПАРОЛЬ НЕ ТРЕБУЕТСЯ")
        res.append(f"{u['Name']}: {'вкл' if u['Enabled'] else 'выкл'}, "
                   f"последний вход={u['LastLogon'] or '—'}, пароль сменён={u['PwdLastSet'] or '—'}"
                   + (f"  [!] {', '.join(flags)}" if flags else ""))
    return res


def audit_password_policy():
    _, out, _ = run(["net", "accounts"])
    return out.splitlines()


def audit_firewall():
    data = ps("Get-NetFirewallProfile | Select-Object Name,Enabled", as_json=True)
    return [f"{d['Name']}: {'включён' if d['Enabled'] in (True, 1) else 'ВЫКЛЮЧЕН [!]'}"
            for d in data] if data else ["(не удалось получить)"]


def audit_defender():
    data = ps("Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,"
              "@{n='Sig';e={$_.AntivirusSignatureLastUpdated.ToString('s')}}", as_json=True)
    if not data:
        return ["Defender недоступен (возможно, стоит сторонний антивирус)"]
    d = data[0]
    return [f"Антивирус: {'вкл' if d['AntivirusEnabled'] else 'ВЫКЛ [!]'}",
            f"Защита в реальном времени: {'вкл' if d['RealTimeProtectionEnabled'] else 'ВЫКЛ [!]'}",
            f"Базы обновлены: {d['Sig']}"]


def audit_uac():
    out = ps("(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System')"
             ".EnableLUA")
    return ["UAC включён" if out.strip() == "1" else "UAC ВЫКЛЮЧЕН [!]"]


def audit_rdp():
    out = ps("(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server')"
             ".fDenyTSConnections")
    return ["RDP выключен" if out.strip() == "1" else "RDP ВКЛЮЧЁН [!] (проверьте, что он нужен)"]


def audit_smb1():
    out = ps("(Get-SmbServerConfiguration).EnableSMB1Protocol")
    return ["SMBv1 ВКЛЮЧЁН [!] (устаревший, уязвимый протокол)" if out.strip().lower() == "true"
            else "SMBv1 выключен"]


def audit_bitlocker():
    data = ps("Get-BitLockerVolume | Select-Object MountPoint,ProtectionStatus", as_json=True)
    return [f"{d['MountPoint']}: {'защищён' if d['ProtectionStatus'] in (1, 'On') else 'не защищён'}"
            for d in data] if data else ["(BitLocker недоступен)"]


def audit_listening_ports():
    data = ps("Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess "
              "| Sort-Object LocalPort", as_json=True)
    names = {}
    procs = ps("Get-Process | Select-Object Id,ProcessName", as_json=True) or []
    for p in procs:
        names[p["Id"]] = p["ProcessName"]
    return [f"{d['LocalAddress']}:{d['LocalPort']}  ({names.get(d['OwningProcess'], '?')}, PID {d['OwningProcess']})"
            for d in data] if data else []


def audit_failed_logins():
    data = ps("Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625} -MaxEvents 10 -ErrorAction SilentlyContinue "
              "| Select-Object @{n='T';e={$_.TimeCreated.ToString('s')}},"
              "@{n='User';e={$_.Properties[5].Value}},@{n='IP';e={$_.Properties[19].Value}}", as_json=True)
    return [f"{d['T']}  пользователь={d['User']}  ip={d['IP']}" for d in data] if data else ["(нет событий)"]


def audit_startup():
    data = ps("Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,User", as_json=True)
    return [f"{d['Name']} -> {d['Command']} ({d['User']})" for d in data] if data else []


def audit_updates():
    data = ps("Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5 "
              "HotFixID,@{n='D';e={if($_.InstalledOn){$_.InstalledOn.ToString('yyyy-MM-dd')}}}",
              as_json=True)
    return [f"{d['HotFixID']} ({d['D']})" for d in data] if data else ["(нет данных)"]


def run_audit():
    return {
        "timestamp": datetime.datetime.now().isoformat(timespec="seconds"),
        "hostname": platform.node(),
        "os": f"{platform.system()} {platform.release()} ({platform.version()})",
        "administrators": audit_admins(),
        "local_users": audit_users(),
        "password_policy": audit_password_policy(),
        "firewall": audit_firewall(),
        "defender": audit_defender(),
        "uac": audit_uac(),
        "rdp": audit_rdp(),
        "smb1": audit_smb1(),
        "bitlocker": audit_bitlocker(),
        "listening_ports": audit_listening_ports(),
        "failed_logins_last10": audit_failed_logins(),
        "startup_programs": audit_startup(),
        "latest_updates": audit_updates(),
    }


def format_report(data):
    lines = [f"=== АУДИТ СИСТЕМЫ: {data['hostname']} ({data['timestamp']}) ===",
             f"ОС: {data['os']}", ""]
    for key, val in data.items():
        if key in ("timestamp", "hostname", "os"):
            continue
        lines.append(f"--- {key} ---")
        lines += [f"  {i}" for i in val] if val else ["  (ничего не найдено)"]
        lines.append("")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
def main():
    parser = argparse.ArgumentParser(description="Выдача админ-прав и аудит системы (Windows)")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("grant", help="выдать права администратора").add_argument("user")
    sub.add_parser("revoke", help="отозвать права администратора").add_argument("user")
    a = sub.add_parser("audit", help="аудит системы")
    a.add_argument("--json", action="store_true")
    a.add_argument("--output", help="сохранить отчёт в файл")
    args = parser.parse_args()

    require_admin()
    setup_logging()

    if args.cmd == "grant":
        grant(args.user)
    elif args.cmd == "revoke":
        revoke(args.user)
    else:
        data = run_audit()
        text = json.dumps(data, ensure_ascii=False, indent=2) if args.json else format_report(data)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(text)
            logging.info("Отчёт сохранён: %s", args.output)
        else:
            print(text)


if __name__ == "__main__":
    main()
