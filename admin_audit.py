#!/usr/bin/env python3
"""
admin_audit.py — выдача/отзыв административных прав и аудит системы (Linux).

Использование (нужен root):
    sudo python3 admin_audit.py grant  <user> [--nopasswd]
    sudo python3 admin_audit.py revoke <user>
    sudo python3 admin_audit.py audit  [--json] [--output report.txt]

Все действия по выдаче/отзыву прав пишутся в /var/log/admin_audit.log.
"""

import argparse
import datetime
import grp
import json
import logging
import os
import pwd
import re
import shutil
import subprocess
import sys
import tempfile

LOG_FILE = "/var/log/admin_audit.log"
SUDOERS_D = "/etc/sudoers.d"


# --------------------------------------------------------------------------- #
# Общие утилиты
# --------------------------------------------------------------------------- #
def setup_logging():
    handlers = [logging.StreamHandler(sys.stdout)]
    try:
        handlers.append(logging.FileHandler(LOG_FILE))
    except OSError:
        pass
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=handlers,
    )


def require_root():
    if os.geteuid() != 0:
        sys.exit("Ошибка: скрипт нужно запускать от root (sudo).")


def run(cmd, timeout=60):
    """Запуск команды без shell; возвращает (код, stdout, stderr)."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except (OSError, subprocess.TimeoutExpired) as e:
        return 1, "", str(e)


def user_exists(name):
    try:
        pwd.getpwnam(name)
        return True
    except KeyError:
        return False


def admin_group():
    """Группа администраторов зависит от дистрибутива: sudo (Debian) или wheel (RHEL)."""
    for name in ("sudo", "wheel"):
        try:
            grp.getgrnam(name)
            return name
        except KeyError:
            continue
    return None


def valid_username(name):
    return bool(re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", name))


# --------------------------------------------------------------------------- #
# Выдача / отзыв прав
# --------------------------------------------------------------------------- #
def grant(user, nopasswd=False):
    if not valid_username(user) or not user_exists(user):
        sys.exit(f"Пользователь '{user}' не найден или имя некорректно.")
    if user == "root":
        sys.exit("root уже обладает полными правами.")

    group = admin_group()
    if not group:
        sys.exit("Не найдена группа sudo/wheel. Установите sudo.")

    code, _, err = run(["usermod", "-aG", group, user])
    if code != 0:
        sys.exit(f"Не удалось добавить в группу {group}: {err}")
    logging.info("Пользователь %s добавлен в группу %s", user, group)

    if nopasswd:
        logging.warning("Включён NOPASSWD для %s — это снижает безопасность!", user)
        path = os.path.join(SUDOERS_D, f"90-{user}")
        content = f"{user} ALL=(ALL) NOPASSWD:ALL\n"
        # Проверяем синтаксис через visudo ДО установки файла
        with tempfile.NamedTemporaryFile("w", delete=False) as tmp:
            tmp.write(content)
            tmp_path = tmp.name
        code, _, err = run(["visudo", "-cf", tmp_path])
        if code != 0:
            os.unlink(tmp_path)
            sys.exit(f"Ошибка синтаксиса sudoers: {err}")
        shutil.move(tmp_path, path)
        os.chmod(path, 0o440)
        os.chown(path, 0, 0)
        logging.info("Создан %s", path)

    logging.info("Админ-права выданы: %s (выполнил uid=%s)", user, os.getenv("SUDO_UID", "0"))


def revoke(user):
    if not valid_username(user) or not user_exists(user):
        sys.exit(f"Пользователь '{user}' не найден или имя некорректно.")

    for group in ("sudo", "wheel", "admin"):
        try:
            grp.getgrnam(group)
        except KeyError:
            continue
        if user in grp.getgrnam(group).gr_mem:
            run(["gpasswd", "-d", user, group])
            logging.info("Пользователь %s удалён из группы %s", user, group)

    path = os.path.join(SUDOERS_D, f"90-{user}")
    if os.path.exists(path):
        os.remove(path)
        logging.info("Удалён %s", path)

    logging.info("Админ-права отозваны: %s", user)


# --------------------------------------------------------------------------- #
# Аудит
# --------------------------------------------------------------------------- #
def audit_uid0():
    return [u.pw_name for u in pwd.getpwall() if u.pw_uid == 0 and u.pw_name != "root"]


def audit_admin_groups():
    result = {}
    for g in ("sudo", "wheel", "admin"):
        try:
            result[g] = list(grp.getgrnam(g).gr_mem)
        except KeyError:
            pass
    return result


def audit_sudoers():
    """Ищет NOPASSWD и широкие правила в sudoers и sudoers.d."""
    files = ["/etc/sudoers"]
    if os.path.isdir(SUDOERS_D):
        files += [os.path.join(SUDOERS_D, f) for f in sorted(os.listdir(SUDOERS_D))]
    findings = []
    for f in files:
        try:
            with open(f) as fh:
                for n, line in enumerate(fh, 1):
                    s = line.strip()
                    if s and not s.startswith("#") and "NOPASSWD" in s:
                        findings.append(f"{f}:{n}: {s}")
        except OSError:
            continue
    return findings


def audit_empty_passwords():
    empty = []
    try:
        with open("/etc/shadow") as fh:
            for line in fh:
                parts = line.split(":")
                if len(parts) > 1 and parts[1] == "":
                    empty.append(parts[0])
    except OSError:
        return ["(нет доступа к /etc/shadow)"]
    return empty


def audit_login_shell_users():
    nologin = ("nologin", "false")
    return [
        f"{u.pw_name} (uid={u.pw_uid}, {u.pw_shell})"
        for u in pwd.getpwall()
        if u.pw_uid >= 1000 and not u.pw_shell.endswith(nologin)
    ]


def audit_suid(limit=50):
    code, out, _ = run(
        ["find", "/usr", "/bin", "/sbin", "/opt", "-xdev", "-perm", "-4000", "-type", "f"],
        timeout=120,
    )
    files = out.splitlines() if code == 0 else []
    return files[:limit]


def audit_world_writable(limit=30):
    code, out, _ = run(
        ["find", "/etc", "/usr/bin", "/usr/sbin", "-xdev", "-type", "f", "-perm", "-0002"],
        timeout=120,
    )
    files = out.splitlines() if code == 0 else []
    return files[:limit]


def audit_listening_ports():
    code, out, _ = run(["ss", "-tulnH"])
    return out.splitlines() if code == 0 else []


def audit_ssh():
    path = "/etc/ssh/sshd_config"
    wanted = {"permitrootlogin": "no", "passwordauthentication": "no", "permitemptypasswords": "no"}
    current, issues = {}, []
    try:
        with open(path) as fh:
            for line in fh:
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                k, _, v = s.partition(" ")
                current[k.lower()] = v.strip().lower()
    except OSError:
        return ["sshd_config недоступен"]
    for k, good in wanted.items():
        val = current.get(k)
        if val != good:
            issues.append(f"{k} = {val or 'не задано (по умолчанию)'} (рекомендуется: {good})")
    return issues


def audit_last_logins():
    _, out, _ = run(["last", "-n", "10", "-w"])
    return out.splitlines()


def audit_failed_logins():
    code, out, _ = run(["lastb", "-n", "10", "-w"])
    return out.splitlines() if code == 0 else ["(lastb недоступен или нет записей)"]


def audit_updates():
    if shutil.which("apt"):
        _, out, _ = run(["apt", "list", "--upgradable"], timeout=120)
        return [l for l in out.splitlines() if "/" in l][:30]
    if shutil.which("dnf"):
        _, out, _ = run(["dnf", "-q", "check-update"], timeout=180)
        return out.splitlines()[:30]
    return []


def run_audit():
    return {
        "timestamp": datetime.datetime.now().isoformat(timespec="seconds"),
        "hostname": os.uname().nodename,
        "kernel": os.uname().release,
        "uid0_extra_accounts": audit_uid0(),
        "admin_groups": audit_admin_groups(),
        "sudoers_nopasswd": audit_sudoers(),
        "empty_passwords": audit_empty_passwords(),
        "login_shell_users": audit_login_shell_users(),
        "suid_files": audit_suid(),
        "world_writable_system_files": audit_world_writable(),
        "listening_ports": audit_listening_ports(),
        "ssh_config_issues": audit_ssh(),
        "last_logins": audit_last_logins(),
        "failed_logins": audit_failed_logins(),
        "pending_updates": audit_updates(),
    }


def format_report(data):
    lines = [f"=== АУДИТ СИСТЕМЫ: {data['hostname']} ({data['timestamp']}) ===",
             f"Ядро: {data['kernel']}", ""]
    warn_keys = {"uid0_extra_accounts", "sudoers_nopasswd", "empty_passwords",
                 "world_writable_system_files", "ssh_config_issues"}
    for key, val in data.items():
        if key in ("timestamp", "hostname", "kernel"):
            continue
        flag = " [!]" if key in warn_keys and val else ""
        lines.append(f"--- {key}{flag} ---")
        if isinstance(val, dict):
            for k, v in val.items():
                lines.append(f"  {k}: {', '.join(v) if v else '(пусто)'}")
        elif val:
            lines += [f"  {item}" for item in val]
        else:
            lines.append("  (ничего не найдено)")
        lines.append("")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
def main():
    parser = argparse.ArgumentParser(description="Выдача админ-прав и аудит системы (Linux)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("grant", help="выдать админ-права пользователю")
    g.add_argument("user")
    g.add_argument("--nopasswd", action="store_true", help="sudo без пароля (небезопасно)")

    r = sub.add_parser("revoke", help="отозвать админ-права")
    r.add_argument("user")

    a = sub.add_parser("audit", help="аудит системы")
    a.add_argument("--json", action="store_true", help="вывод в JSON")
    a.add_argument("--output", help="сохранить отчёт в файл")

    args = parser.parse_args()
    require_root()
    setup_logging()

    if args.cmd == "grant":
        grant(args.user, args.nopasswd)
    elif args.cmd == "revoke":
        revoke(args.user)
    elif args.cmd == "audit":
        data = run_audit()
        text = json.dumps(data, ensure_ascii=False, indent=2) if args.json else format_report(data)
        if args.output:
            with open(args.output, "w") as fh:
                fh.write(text)
            os.chmod(args.output, 0o600)
            logging.info("Отчёт сохранён: %s", args.output)
        else:
            print(text)


if __name__ == "__main__":
    main()
