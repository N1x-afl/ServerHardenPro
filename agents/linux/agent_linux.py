#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║           ServerHardenPro — Agente de Auditoría Linux           ║
║                          Fase 2                                  ║
║  Uso: python3 agent_linux.py                                     ║
║  Salida: resultado_<hostname>.json                               ║
╚══════════════════════════════════════════════════════════════════╝
"""

import os
import json
import subprocess
import platform
import socket
import datetime
import sys
import urllib.request
import urllib.error

# ── URL del panel — cambiá si usás otro puerto ────────────────────
# ── URL del panel ────────────────────────────────────────────────
# Podés configurarla de 3 formas:
#   1. Argumento:        python3 agent_linux.py --api http://192.168.1.10:8010
#   2. Variable de env:  export SHP_API=http://192.168.1.10:8010
#   3. Valor por defecto: localhost (cambialo si es necesario)
API_URL = os.environ.get("SHP_API", "http://localhost:8010/audit")

# ── Colores para la terminal ──────────────────────────────────────
class C:
    CYAN    = "\033[96m"
    GREEN   = "\033[92m"
    RED     = "\033[91m"
    YELLOW  = "\033[93m"
    WHITE   = "\033[97m"
    MUTED   = "\033[90m"
    BOLD    = "\033[1m"
    RESET   = "\033[0m"

# ── Helper: ejecutar comando shell ───────────────────────────────
def run(cmd):
    """Ejecuta un comando y devuelve stdout como string."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=10
        )
        return result.stdout.strip()
    except Exception:
        return ""

def file_contains(path, text):
    """Retorna True si el archivo contiene el texto buscado."""
    try:
        with open(path, "r", errors="ignore") as f:
            return text.lower() in f.read().lower()
    except Exception:
        return False

def file_exists(path):
    return os.path.isfile(path)

# ══════════════════════════════════════════════════════════════════
#  CHECKS — cada función retorna un dict con:
#    name, category, description, status (PASS/FAIL/WARN), severity
# ══════════════════════════════════════════════════════════════════

# ── SSH ───────────────────────────────────────────────────────────

def check_ssh_root_login():
    val = run("sshd -T 2>/dev/null | grep 'permitrootlogin'")
    passed = "no" in val.lower() or "prohibit-password" in val.lower()
    return {
        "name": "Root login deshabilitado",
        "category": "SSH",
        "description": "PermitRootLogin debe ser 'no' o 'prohibit-password'",
        "status": "PASS" if passed else "FAIL",
        "severity": "ALTA",
        "detail": val or "No se pudo leer sshd_config"
    }

def check_ssh_password_auth():
    val = run("sshd -T 2>/dev/null | grep 'passwordauthentication'")
    passed = "no" in val.lower()
    return {
        "name": "Autenticación por contraseña SSH desactivada",
        "category": "SSH",
        "description": "PasswordAuthentication debe ser 'no'",
        "status": "PASS" if passed else "FAIL",
        "severity": "ALTA",
        "detail": val or "No se pudo leer sshd_config"
    }

def check_ssh_port():
    val = run("sshd -T 2>/dev/null | grep '^port'")
    port = val.split()[-1] if val else "22"
    passed = port != "22"
    return {
        "name": "Puerto SSH no estándar",
        "category": "SSH",
        "description": "Se recomienda cambiar el puerto 22 por defecto",
        "status": "PASS" if passed else "WARN",
        "severity": "MEDIA",
        "detail": f"Puerto actual: {port}"
    }

def check_ssh_max_auth_tries():
    val = run("sshd -T 2>/dev/null | grep 'maxauthtries'")
    try:
        num = int(val.split()[-1])
        passed = num <= 4
    except Exception:
        passed = False
    return {
        "name": "Máximo de intentos SSH ≤ 4",
        "category": "SSH",
        "description": "MaxAuthTries debe ser 4 o menos",
        "status": "PASS" if passed else "WARN",
        "severity": "MEDIA",
        "detail": val or "No se pudo obtener MaxAuthTries"
    }

def check_ssh_protocol():
    val = run("sshd -T 2>/dev/null | grep 'protocol'")
    passed = "2" in val
    return {
        "name": "SSH Protocolo 2 en uso",
        "category": "SSH",
        "description": "Solo debe usarse SSHv2",
        "status": "PASS" if passed else "WARN",
        "severity": "ALTA",
        "detail": val or "No se pudo verificar protocolo"
    }

# ── FIREWALL ──────────────────────────────────────────────────────

def check_ufw_active():
    val = run("ufw status 2>/dev/null")
    passed = "active" in val.lower()
    return {
        "name": "Firewall UFW activo",
        "category": "Firewall",
        "description": "UFW debe estar activo y con reglas definidas",
        "status": "PASS" if passed else "FAIL",
        "severity": "ALTA",
        "detail": val.split("\n")[0] if val else "UFW no encontrado"
    }

def check_iptables_rules():
    val = run("iptables -L INPUT --line-numbers 2>/dev/null | wc -l")
    try:
        lines = int(val)
        passed = lines > 3
    except Exception:
        passed = False
    return {
        "name": "Reglas iptables definidas",
        "category": "Firewall",
        "description": "INPUT chain debe tener reglas configuradas",
        "status": "PASS" if passed else "WARN",
        "severity": "ALTA",
        "detail": f"Líneas en INPUT chain: {val}"
    }

# ── USUARIOS ──────────────────────────────────────────────────────

def check_empty_passwords():
    val = run("awk -F: '($2 == \"\" ) {print $1}' /etc/shadow 2>/dev/null")
    passed = val == ""
    return {
        "name": "Sin usuarios con contraseña vacía",
        "category": "Usuarios",
        "description": "Ningún usuario debe tener contraseña vacía",
        "status": "PASS" if passed else "FAIL",
        "severity": "ALTA",
        "detail": f"Usuarios sin contraseña: {val}" if val else "Ninguno detectado ✓"
    }

def check_root_uid():
    val = run("awk -F: '($3 == 0 && $1 != \"root\") {print $1}' /etc/passwd")
    passed = val == ""
    return {
        "name": "Solo root tiene UID 0",
        "category": "Usuarios",
        "description": "Ninguna otra cuenta debe tener UID 0",
        "status": "PASS" if passed else "FAIL",
        "severity": "ALTA",
        "detail": f"Usuarios con UID 0: {val}" if val else "Solo root ✓"
    }

def check_sudo_users():
    val = run("getent group sudo 2>/dev/null || getent group wheel 2>/dev/null")
    users = val.split(":")[-1] if val else ""
    count = len([u for u in users.split(",") if u.strip()])
    passed = count <= 3
    return {
        "name": "Cantidad razonable de usuarios sudo",
        "category": "Usuarios",
        "description": "Limitar usuarios con privilegios sudo",
        "status": "PASS" if passed else "WARN",
        "severity": "MEDIA",
        "detail": f"Usuarios en sudo/wheel: {users or 'ninguno'}"
    }

def check_password_max_days():
    val = run("grep '^PASS_MAX_DAYS' /etc/login.defs 2>/dev/null")
    try:
        days = int(val.split()[-1])
        passed = days <= 90
    except Exception:
        passed = False
    return {
        "name": "Expiración de contraseña ≤ 90 días",
        "category": "Usuarios",
        "description": "PASS_MAX_DAYS debe ser 90 o menos",
        "status": "PASS" if passed else "WARN",
        "severity": "MEDIA",
        "detail": val or "No se pudo leer login.defs"
    }

# ── SISTEMA ───────────────────────────────────────────────────────

def check_updates_available():
    val = run("apt-get -s upgrade 2>/dev/null | grep -c '^Inst' || yum check-update 2>/dev/null | grep -c '^[a-zA-Z]'")
    try:
        pending = int(val)
        passed = pending == 0
    except Exception:
        pending = "N/A"
        passed = False
    return {
        "name": "Sin actualizaciones de seguridad pendientes",
        "category": "Sistema",
        "description": "El sistema debe estar actualizado",
        "status": "PASS" if passed else "WARN",
        "severity": "ALTA",
        "detail": f"Paquetes pendientes: {pending}"
    }

def check_suid_files():
    val = run("find / -perm -4000 -type f 2>/dev/null | grep -v '/usr/bin\\|/usr/sbin\\|/bin\\|/sbin'")
    passed = val == ""
    count = len(val.strip().split("\n")) if val else 0
    return {
        "name": "Sin SUID fuera de directorios estándar",
        "category": "Sistema",
        "description": "Archivos SUID solo deben existir en /usr/bin, /usr/sbin",
        "status": "PASS" if passed else "WARN",
        "severity": "MEDIA",
        "detail": f"{count} archivo(s) SUID no estándar encontrados" if val else "Ninguno ✓"
    }

def check_world_writable():
    val = run("find / -xdev -type f -perm -0002 2>/dev/null | head -5")
    passed = val == ""
    return {
        "name": "Sin archivos world-writable",
        "category": "Sistema",
        "description": "No deben existir archivos escribibles por todos",
        "status": "PASS" if passed else "WARN",
        "severity": "MEDIA",
        "detail": val if val else "Ninguno detectado ✓"
    }

def check_core_dumps():
    val = run("ulimit -c 2>/dev/null")
    passed = val == "0"
    return {
        "name": "Core dumps deshabilitados",
        "category": "Sistema",
        "description": "Los core dumps pueden exponer datos sensibles",
        "status": "PASS" if passed else "WARN",
        "severity": "BAJA",
        "detail": f"ulimit -c: {val}"
    }

# ── AUDITORÍA / LOGS ──────────────────────────────────────────────

def check_auditd():
    val = run("systemctl is-active auditd 2>/dev/null")
    passed = "active" in val.lower()
    return {
        "name": "Auditd activo",
        "category": "Auditoría",
        "description": "El servicio auditd debe estar corriendo",
        "status": "PASS" if passed else "FAIL",
        "severity": "MEDIA",
        "detail": f"Estado: {val or 'no encontrado'}"
    }

def check_rsyslog():
    val = run("systemctl is-active rsyslog 2>/dev/null || systemctl is-active syslog 2>/dev/null")
    passed = "active" in val.lower()
    return {
        "name": "Syslog activo (rsyslog)",
        "category": "Auditoría",
        "description": "El sistema de logs debe estar operativo",
        "status": "PASS" if passed else "WARN",
        "severity": "MEDIA",
        "detail": f"Estado: {val or 'no encontrado'}"
    }

# ── KERNEL / RED ──────────────────────────────────────────────────

def check_ip_forward():
    val = run("sysctl net.ipv4.ip_forward 2>/dev/null")
    passed = "= 0" in val
    return {
        "name": "IP Forwarding deshabilitado",
        "category": "Red",
        "description": "net.ipv4.ip_forward debe ser 0 (a menos que sea router)",
        "status": "PASS" if passed else "WARN",
        "severity": "MEDIA",
        "detail": val or "No se pudo leer"
    }

def check_icmp_redirects():
    val = run("sysctl net.ipv4.conf.all.accept_redirects 2>/dev/null")
    passed = "= 0" in val
    return {
        "name": "ICMP Redirects deshabilitados",
        "category": "Red",
        "description": "accept_redirects debe ser 0",
        "status": "PASS" if passed else "WARN",
        "severity": "MEDIA",
        "detail": val or "No se pudo leer"
    }

def check_syn_cookies():
    val = run("sysctl net.ipv4.tcp_syncookies 2>/dev/null")
    passed = "= 1" in val
    return {
        "name": "SYN Cookies habilitados (anti DoS)",
        "category": "Red",
        "description": "tcp_syncookies debe ser 1",
        "status": "PASS" if passed else "WARN",
        "severity": "MEDIA",
        "detail": val or "No se pudo leer"
    }

# ── SERVICIOS ─────────────────────────────────────────────────────

def check_telnet():
    val = run("systemctl is-active telnet 2>/dev/null || systemctl is-active telnetd 2>/dev/null")
    passed = "active" not in val.lower()
    return {
        "name": "Telnet deshabilitado",
        "category": "Servicios",
        "description": "Telnet transmite en texto plano — debe estar inactivo",
        "status": "PASS" if passed else "FAIL",
        "severity": "ALTA",
        "detail": f"Estado: {val or 'inactivo ✓'}"
    }

def check_ftp():
    val = run("systemctl is-active vsftpd 2>/dev/null || systemctl is-active proftpd 2>/dev/null")
    passed = "active" not in val.lower()
    return {
        "name": "FTP deshabilitado",
        "category": "Servicios",
        "description": "FTP no cifrado debe estar inactivo",
        "status": "PASS" if passed else "WARN",
        "severity": "MEDIA",
        "detail": f"Estado: {val or 'inactivo ✓'}"
    }

# ══════════════════════════════════════════════════════════════════
#  RUNNER PRINCIPAL
# ══════════════════════════════════════════════════════════════════

ALL_CHECKS = [
    # SSH
    check_ssh_root_login,
    check_ssh_password_auth,
    check_ssh_port,
    check_ssh_max_auth_tries,
    check_ssh_protocol,
    # Firewall
    check_ufw_active,
    check_iptables_rules,
    # Usuarios
    check_empty_passwords,
    check_root_uid,
    check_sudo_users,
    check_password_max_days,
    # Sistema
    check_updates_available,
    check_suid_files,
    check_world_writable,
    check_core_dumps,
    # Auditoría
    check_auditd,
    check_rsyslog,
    # Red
    check_ip_forward,
    check_icmp_redirects,
    check_syn_cookies,
    # Servicios
    check_telnet,
    check_ftp,
]

def print_banner():
    print(f"""
{C.CYAN}{C.BOLD}
 ╔═══════════════════════════════════════════════════╗
 ║       ServerHardenPro — Agente Linux v0.1        ║
 ║           Auditoría de Hardening                  ║
 ╚═══════════════════════════════════════════════════╝
{C.RESET}""")

def print_result(check):
    s = check["status"]
    if s == "PASS":
        icon = f"{C.GREEN}✅ PASS{C.RESET}"
    elif s == "FAIL":
        icon = f"{C.RED}❌ FAIL{C.RESET}"
    else:
        icon = f"{C.YELLOW}⚠  WARN{C.RESET}"

    cat  = f"{C.MUTED}[{check['category']:10}]{C.RESET}"
    name = f"{C.WHITE}{check['name']}{C.RESET}"
    detail = f"{C.MUTED}  → {check['detail']}{C.RESET}"

    print(f"  {icon}  {cat}  {name}")
    print(f"         {detail}")


# ══════════════════════════════════════════════════════════════════
#  INVENTARIO DE HARDWARE
# ══════════════════════════════════════════════════════════════════
def collect_inventory() -> dict:
    """Recolecta información de CPU, RAM, disco, uptime y detecta si es VM."""
    inv = {}

    # ── CPU ──────────────────────────────────────────────────────
    try:
        cpu_model = ""
        with open("/proc/cpuinfo") as f:
            for line in f:
                if "model name" in line:
                    cpu_model = line.split(":")[1].strip()
                    break
        inv["cpu_model"] = cpu_model or platform.processor()

        import multiprocessing
        inv["cpu_cores"]   = multiprocessing.cpu_count()
        inv["cpu_threads"] = inv["cpu_cores"]

        try:
            freq_line = open("/sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq").read().strip()
            inv["cpu_freq_mhz"] = round(int(freq_line) / 1000, 1)
        except Exception:
            inv["cpu_freq_mhz"] = 0.0
    except Exception:
        inv["cpu_model"] = platform.processor()
        inv["cpu_cores"] = 1
        inv["cpu_threads"] = 1
        inv["cpu_freq_mhz"] = 0.0

    # ── RAM ──────────────────────────────────────────────────────
    try:
        meminfo = {}
        with open("/proc/meminfo") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2:
                    meminfo[parts[0].rstrip(":")] = int(parts[1])
        total_kb   = meminfo.get("MemTotal", 0)
        free_kb    = meminfo.get("MemAvailable", meminfo.get("MemFree", 0))
        used_kb    = total_kb - free_kb
        inv["ram_total_gb"] = round(total_kb / 1024 / 1024, 2)
        inv["ram_used_gb"]  = round(used_kb  / 1024 / 1024, 2)
        inv["ram_free_gb"]  = round(free_kb  / 1024 / 1024, 2)
    except Exception:
        inv["ram_total_gb"] = 0.0
        inv["ram_used_gb"]  = 0.0
        inv["ram_free_gb"]  = 0.0

    # ── DISCO (partición raíz) ────────────────────────────────────
    try:
        import shutil
        disk = shutil.disk_usage("/")
        inv["disk_total_gb"] = round(disk.total / 1024**3, 2)
        inv["disk_used_gb"]  = round(disk.used  / 1024**3, 2)
        inv["disk_free_gb"]  = round(disk.free  / 1024**3, 2)
    except Exception:
        inv["disk_total_gb"] = 0.0
        inv["disk_used_gb"]  = 0.0
        inv["disk_free_gb"]  = 0.0

    # ── UPTIME ───────────────────────────────────────────────────
    try:
        with open("/proc/uptime") as f:
            uptime_secs = float(f.read().split()[0])
        inv["uptime_hours"] = round(uptime_secs / 3600, 2)
    except Exception:
        inv["uptime_hours"] = 0.0

    # ── KERNEL ───────────────────────────────────────────────────
    inv["kernel"] = platform.release()

    # ── DETECTAR VM ──────────────────────────────────────────────
    inv["is_vm"]   = False
    inv["vm_type"] = ""
    try:
        dmi = subprocess.check_output(
            ["systemd-detect-virt", "--vm"], stderr=subprocess.DEVNULL
        ).decode().strip()
        if dmi and dmi != "none":
            inv["is_vm"]   = True
            inv["vm_type"] = dmi.upper()
    except Exception:
        pass

    # Fallback: revisar /proc/cpuinfo y DMI
    if not inv["is_vm"]:
        try:
            cpuinfo = open("/proc/cpuinfo").read().lower()
            for hint, name in [("vmware","VMware"),("kvm","KVM"),
                                ("virtualbox","VirtualBox"),("xen","Xen"),
                                ("hyperv","Hyper-V"),("qemu","QEMU")]:
                if hint in cpuinfo:
                    inv["is_vm"]   = True
                    inv["vm_type"] = name
                    break
        except Exception:
            pass

    return inv

def run_audit():
    print_banner()

    hostname = socket.gethostname()
    os_info  = platform.platform()
    now      = datetime.datetime.now().isoformat()

    # Detectar nombre de distro para el logo del panel
    try:
        distro_info = platform.freedesktop_os_release()
        distro_name = distro_info.get("NAME", "") or distro_info.get("ID", "linux")
    except Exception:
        distro_name = platform.system()

    # ── Inventario de hardware ───────────────────────────────────
    inventory = collect_inventory()

    print(f"{C.CYAN}  Host   :{C.RESET} {hostname}")
    print(f"{C.CYAN}  OS     :{C.RESET} {os_info}")
    print(f"{C.CYAN}  CPU    :{C.RESET} {inventory.get('cpu_model','?')} ({inventory.get('cpu_cores','?')} cores)")
    print(f"{C.CYAN}  RAM    :{C.RESET} {inventory.get('ram_total_gb',0):.1f} GB total / {inventory.get('ram_free_gb',0):.1f} GB libre")
    print(f"{C.CYAN}  Disco  :{C.RESET} {inventory.get('disk_total_gb',0):.0f} GB total / {inventory.get('disk_free_gb',0):.0f} GB libre")
    print(f"{C.CYAN}  VM     :{C.RESET} {'Sí — ' + inventory.get('vm_type','') if inventory.get('is_vm') else 'No (Físico)'}")
    print(f"{C.CYAN}  Inicio :{C.RESET} {now}")
    print(f"\n{C.MUTED}  {'─'*60}{C.RESET}\n")

    if os.geteuid() != 0:
        print(f"{C.YELLOW}  ⚠  Ejecutando sin root — algunos checks pueden fallar.{C.RESET}")
        print(f"{C.YELLOW}     Recomendado: sudo python3 agent_linux.py\n{C.RESET}")

    results = []
    totals  = {"PASS": 0, "FAIL": 0, "WARN": 0}

    for check_fn in ALL_CHECKS:
        try:
            result = check_fn()
            print_result(result)
            results.append(result)
            totals[result["status"]] += 1
        except Exception as e:
            print(f"  {C.RED}ERROR{C.RESET}  {check_fn.__name__}: {e}")

    total  = len(results)
    score  = round((totals["PASS"] / total) * 100) if total else 0

    # ── Resumen ──
    print(f"\n{C.MUTED}  {'─'*60}{C.RESET}")
    print(f"\n{C.BOLD}  RESUMEN{C.RESET}")
    print(f"  {C.GREEN}✅ PASS  : {totals['PASS']}{C.RESET}")
    print(f"  {C.RED}❌ FAIL  : {totals['FAIL']}{C.RESET}")
    print(f"  {C.YELLOW}⚠  WARN  : {totals['WARN']}{C.RESET}")
    print(f"  {C.CYAN}📊 SCORE : {score}%{C.RESET}\n")

    # ── JSON ──
    output = {
        "server": {
            "hostname": hostname,
            "os": distro_name,
            "os_full": os_info,
            "ip": socket.gethostbyname(hostname),
            "audit_date": now,
            "agent_version": "0.1"
        },
        "summary": {
            "total": total,
            "pass": totals["PASS"],
            "fail": totals["FAIL"],
            "warn": totals["WARN"],
            "score_percent": score
        },
        "checks": results,
        "inventory": inventory
    }

    filename = f"resultado_{hostname}.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)

    print(f"  {C.GREEN}💾 Resultado guardado en:{C.RESET} {filename}")

    # ── Envío automático al panel ─────────────────────────────────
    send_to_panel(output)

    # ── Análisis de logs ──────────────────────────────────────────
    log_data = analyze_logs(hostname)
    send_logs_to_panel(log_data)

    return output


# ══════════════════════════════════════════════════════════════════
#  ANÁLISIS DE LOGS
# ══════════════════════════════════════════════════════════════════
def analyze_logs(hostname: str, period_hours: int = 24) -> dict:
    """Analiza auth.log y syslog buscando patrones de ataque y errores."""
    import re
    from collections import defaultdict
    from datetime import datetime, timedelta

    print(f"\n{C.CYAN}  📋 Analizando logs (últimas {period_hours}hs)...{C.RESET}")

    cutoff = datetime.now() - timedelta(hours=period_hours)
    result = {
        "hostname":     hostname,
        "period_hours": period_hours,
        "summary": {
            "auth_fail_total":    0,
            "auth_ok_total":      0,
            "brute_force_count":  0,
            "syslog_error_count": 0,
            "syslog_crit_count":  0,
        },
        "top_ips":      [],
        "top_users":    [],
        "brute_events": [],
        "syslog_errors":[],
    }

    # ── auth.log ─────────────────────────────────────────────────
    auth_log = "/var/log/auth.log"
    if os.path.exists(auth_log):
        ip_fails    = defaultdict(int)
        user_fails  = defaultdict(int)
        ip_timeline = defaultdict(list)  # ip -> list of datetimes
        year        = datetime.now().year

        # Regex patterns
        re_fail = re.compile(
            r"(\w+ +\d+ \d+:\d+:\d+).+Failed password for (?:invalid user )?(\S+) from (\S+)"
        )
        re_ok = re.compile(
            r"(\w+ +\d+ \d+:\d+:\d+).+Accepted (?:password|publickey) for (\S+) from (\S+)"
        )
        re_invalid = re.compile(
            r"(\w+ +\d+ \d+:\d+:\d+).+Invalid user (\S+) from (\S+)"
        )

        try:
            with open(auth_log, "r", errors="replace") as f:
                for line in f:
                    # Parse timestamp
                    ts_match = re.match(r"(\w+ +\d+ \d+:\d+:\d+)", line)
                    if not ts_match:
                        continue
                    try:
                        ts = datetime.strptime(f"{year} {ts_match.group(1)}", "%Y %b %d %H:%M:%S")
                        # Ajustar año si estamos en enero y el log es de diciembre
                        if ts > datetime.now() + timedelta(days=1):
                            ts = ts.replace(year=year - 1)
                    except ValueError:
                        continue

                    if ts < cutoff:
                        continue

                    # Failed password
                    m = re_fail.search(line)
                    if m:
                        user, ip = m.group(2), m.group(3)
                        ip_fails[ip] += 1
                        user_fails[user] += 1
                        ip_timeline[ip].append(ts)
                        result["summary"]["auth_fail_total"] += 1
                        continue

                    # Invalid user
                    m = re_invalid.search(line)
                    if m:
                        user, ip = m.group(2), m.group(3)
                        ip_fails[ip] += 1
                        user_fails[user] += 1
                        ip_timeline[ip].append(ts)
                        result["summary"]["auth_fail_total"] += 1
                        continue

                    # Accepted login
                    m = re_ok.search(line)
                    if m:
                        result["summary"]["auth_ok_total"] += 1

        except PermissionError:
            print(f"  {C.YELLOW}⚠  Sin permiso para leer {auth_log} — ejecutá con sudo{C.RESET}")

        # Top IPs (ordenadas por intentos)
        result["top_ips"] = [
            {"ip": ip, "attempts": count}
            for ip, count in sorted(ip_fails.items(), key=lambda x: -x[1])[:10]
        ]

        # Top usuarios atacados
        result["top_users"] = [
            {"user": user, "attempts": count}
            for user, count in sorted(user_fails.items(), key=lambda x: -x[1])[:10]
        ]

        # Detección de fuerza bruta: >=10 intentos en 5 minutos
        brute_events = []
        window = timedelta(minutes=5)
        threshold = 10
        for ip, times in ip_timeline.items():
            times_sorted = sorted(times)
            for i in range(len(times_sorted)):
                window_end = times_sorted[i] + window
                count_in_window = sum(1 for t in times_sorted[i:] if t <= window_end)
                if count_in_window >= threshold:
                    brute_events.append({
                        "ip":        ip,
                        "attempts":  count_in_window,
                        "first_seen": times_sorted[i].isoformat(),
                        "window_min": 5,
                    })
                    break  # Una alerta por IP es suficiente
        result["brute_events"]              = brute_events
        result["summary"]["brute_force_count"] = len(brute_events)

    else:
        print(f"  {C.MUTED}  auth.log no encontrado — saltando{C.RESET}")

    # ── syslog ────────────────────────────────────────────────────
    syslog_path = "/var/log/syslog"
    if not os.path.exists(syslog_path):
        syslog_path = "/var/log/messages"  # CentOS/RHEL

    if os.path.exists(syslog_path):
        syslog_errors = []
        re_level = re.compile(r"\b(error|crit|alert|emerg|fail|critical)\b", re.IGNORECASE)
        year = datetime.now().year

        try:
            with open(syslog_path, "r", errors="replace") as f:
                for line in f:
                    ts_match = re.match(r"(\w+ +\d+ \d+:\d+:\d+)", line)
                    if not ts_match:
                        continue
                    try:
                        ts = datetime.strptime(f"{year} {ts_match.group(1)}", "%Y %b %d %H:%M:%S")
                        if ts > datetime.now() + timedelta(days=1):
                            ts = ts.replace(year=year - 1)
                    except ValueError:
                        continue
                    if ts < cutoff:
                        continue

                    m = re_level.search(line)
                    if m:
                        level = m.group(1).upper()
                        # Evitar spam de líneas similares (deduplicar)
                        msg = line.strip()
                        if len(syslog_errors) < 50:
                            syslog_errors.append({
                                "timestamp": ts.isoformat(),
                                "level":     level,
                                "message":   msg[:200],
                            })
                        if level in ("CRIT","ALERT","EMERG","CRITICAL"):
                            result["summary"]["syslog_crit_count"] += 1
                        else:
                            result["summary"]["syslog_error_count"] += 1

        except PermissionError:
            print(f"  {C.YELLOW}⚠  Sin permiso para leer {syslog_path}{C.RESET}")

        result["syslog_errors"] = syslog_errors
    else:
        print(f"  {C.MUTED}  syslog no encontrado — saltando{C.RESET}")

    # ── Resumen por pantalla ──────────────────────────────────────
    s = result["summary"]
    print(f"  {C.RED}❌ Auth fallidos  : {s['auth_fail_total']}{C.RESET}")
    print(f"  {C.GREEN}✅ Auth exitosos  : {s['auth_ok_total']}{C.RESET}")
    if s["brute_force_count"]:
        print(f"  {C.RED}🚨 Fuerza bruta   : {s['brute_force_count']} eventos detectados{C.RESET}")
    print(f"  {C.YELLOW}⚠  Errores syslog : {s['syslog_error_count']} errores / {s['syslog_crit_count']} críticos{C.RESET}")

    return result


def send_logs_to_panel(log_data: dict):
    """Envía el análisis de logs al backend."""
    log_url = API_URL.replace("/audit", "/logs")
    print(f"\n{C.CYAN}  📡 Enviando análisis de logs...{C.RESET}")
    try:
        body = json.dumps(log_data, ensure_ascii=False, default=str).encode("utf-8")
        req  = urllib.request.Request(
            log_url, data=body,
            headers={"Content-Type": "application/json"}, method="POST"
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read().decode())
            print(f"  {C.GREEN}✅ Logs enviados:{C.RESET} {result.get('message','OK')}\n")
    except Exception as e:
        print(f"  {C.YELLOW}⚠  No se pudieron enviar los logs:{C.RESET} {e}\n")

def send_to_panel(data: dict):
    """Envía el resultado automáticamente al panel ServerHardenPro."""
    print(f"\n{C.CYAN}  📡 Enviando resultado al panel...{C.RESET}")
    print(f"  {C.MUTED}→ {API_URL}{C.RESET}")
    try:
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        req  = urllib.request.Request(
            API_URL,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read().decode())
            print(f"  {C.GREEN}✅ Panel actualizado:{C.RESET} {result.get('message', 'OK')}\n")
    except urllib.error.URLError as e:
        print(f"  {C.YELLOW}⚠  No se pudo conectar al panel:{C.RESET} {e.reason}")
        print(f"  {C.MUTED}   Verificá que el backend esté corriendo en {API_URL}{C.RESET}\n")
    except Exception as e:
        print(f"  {C.YELLOW}⚠  Error al enviar:{C.RESET} {e}\n")

# ══════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    run_audit()
