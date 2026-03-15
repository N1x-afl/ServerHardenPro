#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║         ServerHardenPro — Agente de Auditoría Windows           ║
║                          v0.5                                    ║
║  Uso normal:  python agent_windows.py                            ║
║  Custom API:  set SHP_API=https://IP && python agent_windows.py  ║
║  Custom IP:   set SHP_IP=192.168.1.100 && python agent_windows.py║
║  Requiere: ejecutar como Administrador                           ║
╚══════════════════════════════════════════════════════════════════╝
"""

import os
import json
import subprocess
import platform
import socket
import datetime
import sys
import ssl
import argparse
import urllib.request
import urllib.error
import ctypes

# ── URL del backend ───────────────────────────────────────────────
_DEFAULT_API = os.environ.get("SHP_API", "https://localhost/audit")
API_URL = _DEFAULT_API

# ── SSL — acepta certificados self-signed ─────────────────────────
SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

# ── Colores para la terminal ──────────────────────────────────────
class C:
    CYAN   = "\033[96m"
    GREEN  = "\033[92m"
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    WHITE  = "\033[97m"
    MUTED  = "\033[90m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

# ── Helper: ejecutar PowerShell ───────────────────────────────────
def ps(command):
    """Ejecuta un comando PowerShell y devuelve stdout como string."""
    try:
        result = subprocess.run(
            ["powershell", "-NonInteractive", "-NoProfile",
             "-ExecutionPolicy", "Bypass", "-Command", command],
            capture_output=True, text=True, timeout=15
        )
        return result.stdout.strip()
    except Exception:
        return ""

def reg_query(key, value=""):
    """Lee un valor del registro de Windows."""
    try:
        cmd = f'reg query "{key}"'
        if value:
            cmd += f' /v "{value}"'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return result.stdout.strip()
    except Exception:
        return ""

def service_status(name):
    """Devuelve el estado de un servicio de Windows."""
    val = ps(f"(Get-Service -Name '{name}' -ErrorAction SilentlyContinue).Status")
    return val.lower() if val else "not found"

def is_admin():
    """Verifica si el script corre como Administrador."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

# ══════════════════════════════════════════════════════════════════
#  CHECKS
# ══════════════════════════════════════════════════════════════════

# ── CONTRASEÑAS Y CUENTAS ─────────────────────────────────────────

def check_password_complexity():
    val = ps("(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters' -ErrorAction SilentlyContinue).RequireStrongKey")
    # Alternativa via secedit
    val2 = ps("secedit /export /cfg C:\\Windows\\Temp\\sec.cfg /quiet; Select-String 'PasswordComplexity' C:\\Windows\\Temp\\sec.cfg")
    passed = "1" in val or "1" in val2
    return {
        "name": "Complejidad de contraseñas habilitada",
        "category": "Contraseñas",
        "description": "Las contraseñas deben cumplir requisitos de complejidad",
        "status": "PASS" if passed else "FAIL",
        "severity": "ALTA",
        "detail": val2 or "No se pudo verificar"
    }

def check_password_min_length():
    val = ps("net accounts | Select-String 'Minimum password length'")
    try:
        length = int(val.split()[-1])
        passed = length >= 8
    except Exception:
        passed = False
        length = "N/A"
    return {
        "name": "Longitud mínima de contraseña ≥ 8",
        "category": "Contraseñas",
        "description": "Las contraseñas deben tener al menos 8 caracteres",
        "status": "PASS" if passed else "FAIL",
        "severity": "ALTA",
        "detail": f"Longitud mínima actual: {length}"
    }

def check_password_max_age():
    val = ps("net accounts | Select-String 'Maximum password age'")
    try:
        days = val.split()[-1]
        passed = days != "Unlimited" and int(days) <= 90
    except Exception:
        passed = False
        days = "N/A"
    return {
        "name": "Expiración de contraseña ≤ 90 días",
        "category": "Contraseñas",
        "description": "Las contraseñas deben expirar en 90 días o menos",
        "status": "PASS" if passed else "WARN",
        "severity": "MEDIA",
        "detail": f"Expiración actual: {days} días"
    }

def check_lockout_policy():
    val = ps("net accounts | Select-String 'Lockout threshold'")
    try:
        threshold = val.split()[-1]
        passed = threshold != "Never" and int(threshold) <= 5
    except Exception:
        passed = False
        threshold = "N/A"
    return {
        "name": "Política de bloqueo de cuenta configurada",
        "category": "Contraseñas",
        "description": "Bloquear cuenta después de 5 intentos fallidos",
        "status": "PASS" if passed else "FAIL",
        "severity": "ALTA",
        "detail": f"Umbral de bloqueo: {threshold} intentos"
    }

def check_guest_account():
    val = ps("(Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue).Enabled")
    passed = "false" in val.lower() if val else True
    return {
        "name": "Cuenta Guest deshabilitada",
        "category": "Contraseñas",
        "description": "La cuenta de invitado debe estar desactivada",
        "status": "PASS" if passed else "FAIL",
        "severity": "ALTA",
        "detail": f"Guest habilitado: {val or 'no encontrada ✓'}"
    }

def check_administrator_renamed():
    val = ps("(Get-LocalUser | Where-Object {$_.SID -like '*-500'}).Name")
    passed = val.lower() != "administrator" if val else False
    return {
        "name": "Cuenta Administrator renombrada",
        "category": "Contraseñas",
        "description": "La cuenta built-in Administrator debe renombrarse",
        "status": "PASS" if passed else "WARN",
        "severity": "MEDIA",
        "detail": f"Nombre actual de la cuenta RID-500: {val or 'N/A'}"
    }

# ── FIREWALL ──────────────────────────────────────────────────────

def check_firewall_domain():
    val = ps("(Get-NetFirewallProfile -Profile Domain).Enabled")
    passed = "true" in val.lower()
    return {
        "name": "Firewall — Perfil Dominio activo",
        "category": "Firewall",
        "description": "Windows Firewall debe estar activo en perfil Dominio",
        "status": "PASS" if passed else "FAIL",
        "severity": "ALTA",
        "detail": f"Habilitado: {val or 'No se pudo leer'}"
    }

def check_firewall_private():
    val = ps("(Get-NetFirewallProfile -Profile Private).Enabled")
    passed = "true" in val.lower()
    return {
        "name": "Firewall — Perfil Privado activo",
        "category": "Firewall",
        "description": "Windows Firewall debe estar activo en perfil Privado",
        "status": "PASS" if passed else "FAIL",
        "severity": "ALTA",
        "detail": f"Habilitado: {val or 'No se pudo leer'}"
    }

def check_firewall_public():
    val = ps("(Get-NetFirewallProfile -Profile Public).Enabled")
    passed = "true" in val.lower()
    return {
        "name": "Firewall — Perfil Público activo",
        "category": "Firewall",
        "description": "Windows Firewall debe estar activo en perfil Público",
        "status": "PASS" if passed else "FAIL",
        "severity": "ALTA",
        "detail": f"Habilitado: {val or 'No se pudo leer'}"
    }

# ── WINDOWS UPDATE ────────────────────────────────────────────────

def check_windows_update_service():
    status = service_status("wuauserv")
    passed = "running" in status or "stopped" in status  # stopped es ok si usa WSUS
    return {
        "name": "Servicio Windows Update activo",
        "category": "Actualizaciones",
        "description": "El servicio Windows Update debe estar habilitado",
        "status": "PASS" if passed else "FAIL",
        "severity": "ALTA",
        "detail": f"Estado: {status}"
    }

def check_pending_updates():
    val = ps("(New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search('IsInstalled=0 and Type=Software').Updates.Count")
    try:
        count = int(val)
        passed = count == 0
    except Exception:
        count = "N/A"
        passed = False
    return {
        "name": "Sin actualizaciones críticas pendientes",
        "category": "Actualizaciones",
        "description": "El sistema debe estar al día con las actualizaciones",
        "status": "PASS" if passed else "WARN",
        "severity": "ALTA",
        "detail": f"Actualizaciones pendientes: {count}"
    }

# ── RDP ───────────────────────────────────────────────────────────

def check_rdp_nla():
    val = reg_query(
        "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp",
        "UserAuthentication"
    )
    passed = "0x1" in val or "1" in val
    return {
        "name": "RDP con NLA (Network Level Auth) habilitado",
        "category": "RDP",
        "description": "NLA agrega una capa de autenticación antes de la sesión RDP",
        "status": "PASS" if passed else "FAIL",
        "severity": "ALTA",
        "detail": val or "No se pudo verificar"
    }

def check_rdp_enabled():
    val = reg_query(
        "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server",
        "fDenyTSConnections"
    )
    # 0 = RDP habilitado, 1 = deshabilitado
    # Si no se usa RDP es mejor tenerlo deshabilitado
    rdp_on = "0x0" in val or "0" in val.split()[-1] if val else False
    return {
        "name": "RDP deshabilitado (si no se usa)",
        "category": "RDP",
        "description": "Si no se usa RDP, debe estar deshabilitado",
        "status": "WARN" if rdp_on else "PASS",
        "severity": "MEDIA",
        "detail": f"RDP {'HABILITADO — verificar si es necesario' if rdp_on else 'deshabilitado ✓'}"
    }

# ── SMB ───────────────────────────────────────────────────────────

def check_smb1_disabled():
    val = ps("(Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue).State")
    passed = "disabled" in val.lower() if val else False
    # Alternativa
    if not passed:
        val2 = ps("(Get-SmbServerConfiguration).EnableSMB1Protocol")
        passed = "false" in val2.lower() if val2 else False
        val = val2 or val
    return {
        "name": "SMBv1 deshabilitado",
        "category": "Servicios",
        "description": "SMBv1 es vulnerable a EternalBlue/WannaCry",
        "status": "PASS" if passed else "FAIL",
        "severity": "ALTA",
        "detail": f"Estado SMBv1: {val or 'No se pudo verificar'}"
    }

def check_smb_signing():
    val = ps("(Get-SmbServerConfiguration).RequireSecuritySignature")
    passed = "true" in val.lower() if val else False
    return {
        "name": "SMB Signing habilitado",
        "category": "Servicios",
        "description": "La firma SMB previene ataques man-in-the-middle",
        "status": "PASS" if passed else "WARN",
        "severity": "MEDIA",
        "detail": f"RequireSecuritySignature: {val or 'No se pudo leer'}"
    }

# ── AUDITORÍA Y LOGS ──────────────────────────────────────────────

def check_audit_logon():
    val = ps("auditpol /get /subcategory:'Logon' 2>$null")
    passed = "success and failure" in val.lower() or "success" in val.lower()
    return {
        "name": "Auditoría de inicio de sesión habilitada",
        "category": "Auditoría",
        "description": "Registrar intentos de inicio de sesión exitosos y fallidos",
        "status": "PASS" if passed else "FAIL",
        "severity": "ALTA",
        "detail": val or "No se pudo verificar"
    }

def check_audit_account_management():
    val = ps("auditpol /get /subcategory:'User Account Management' 2>$null")
    passed = "success" in val.lower()
    return {
        "name": "Auditoría de gestión de cuentas",
        "category": "Auditoría",
        "description": "Registrar cambios en cuentas de usuario",
        "status": "PASS" if passed else "WARN",
        "severity": "MEDIA",
        "detail": val or "No se pudo verificar"
    }

def check_event_log_size():
    val = ps("(Get-EventLog -List | Where-Object {$_.Log -eq 'Security'}).MaximumKilobytes")
    try:
        size_kb = int(val)
        passed = size_kb >= 20480  # 20 MB mínimo
    except Exception:
        passed = False
        size_kb = "N/A"
    return {
        "name": "Log de seguridad ≥ 20 MB",
        "category": "Auditoría",
        "description": "El log de seguridad debe tener suficiente capacidad",
        "status": "PASS" if passed else "WARN",
        "severity": "BAJA",
        "detail": f"Tamaño actual: {size_kb} KB"
    }

# ── SERVICIOS INNECESARIOS ────────────────────────────────────────

def check_telnet_disabled():
    val = ps("(Get-WindowsOptionalFeature -Online -FeatureName TelnetClient -ErrorAction SilentlyContinue).State")
    passed = "disabled" in val.lower() if val else True
    return {
        "name": "Cliente Telnet deshabilitado",
        "category": "Servicios",
        "description": "Telnet transmite en texto plano",
        "status": "PASS" if passed else "WARN",
        "severity": "MEDIA",
        "detail": f"Estado Telnet: {val or 'no encontrado ✓'}"
    }

def check_print_spooler():
    status = service_status("Spooler")
    # En servidores que no son de impresión, debería estar deshabilitado
    passed = "running" not in status
    return {
        "name": "Print Spooler deshabilitado (si no se imprime)",
        "category": "Servicios",
        "description": "PrintNightmare — Spooler debe deshabilitarse si no se usa",
        "status": "PASS" if passed else "WARN",
        "severity": "ALTA",
        "detail": f"Estado: {status}"
    }

def check_winrm():
    status = service_status("WinRM")
    return {
        "name": "WinRM — verificar si es necesario",
        "category": "Servicios",
        "description": "WinRM debe estar activo solo si se gestiona remotamente",
        "status": "WARN" if "running" in status else "PASS",
        "severity": "MEDIA",
        "detail": f"Estado WinRM: {status}"
    }

# ── ANTIVIRUS / DEFENDER ──────────────────────────────────────────

def check_defender_realtime():
    val = ps("(Get-MpComputerStatus -ErrorAction SilentlyContinue).RealTimeProtectionEnabled")
    passed = "true" in val.lower() if val else False
    return {
        "name": "Windows Defender — Protección en tiempo real",
        "category": "Antivirus",
        "description": "La protección en tiempo real de Defender debe estar activa",
        "status": "PASS" if passed else "FAIL",
        "severity": "ALTA",
        "detail": f"RealTimeProtection: {val or 'No se pudo verificar'}"
    }

def check_defender_updated():
    val = ps("(Get-MpComputerStatus -ErrorAction SilentlyContinue).AntivirusSignatureAge")
    try:
        days = int(val)
        passed = days <= 3
    except Exception:
        passed = False
        days = "N/A"
    return {
        "name": "Firmas de Defender actualizadas (≤ 3 días)",
        "category": "Antivirus",
        "description": "Las definiciones de virus deben estar al día",
        "status": "PASS" if passed else "WARN",
        "severity": "ALTA",
        "detail": f"Antigüedad de firmas: {days} días"
    }

# ── UAC ───────────────────────────────────────────────────────────

def check_uac_enabled():
    val = reg_query(
        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        "EnableLUA"
    )
    passed = "0x1" in val or ("1" in val and "0x0" not in val)
    return {
        "name": "UAC (Control de Cuentas) habilitado",
        "category": "Sistema",
        "description": "UAC previene cambios no autorizados al sistema",
        "status": "PASS" if passed else "FAIL",
        "severity": "ALTA",
        "detail": val or "No se pudo verificar"
    }

def check_uac_admin_prompt():
    val = reg_query(
        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        "ConsentPromptBehaviorAdmin"
    )
    # 2 = pedir credenciales (más seguro), 5 = solo notificar (default)
    passed = "0x2" in val or "2" in val.split()[-1] if val else False
    return {
        "name": "UAC solicita credenciales para admins",
        "category": "Sistema",
        "description": "ConsentPromptBehaviorAdmin = 2 es más seguro",
        "status": "PASS" if passed else "WARN",
        "severity": "MEDIA",
        "detail": val or "No se pudo verificar"
    }

# ══════════════════════════════════════════════════════════════════
#  RUNNER PRINCIPAL
# ══════════════════════════════════════════════════════════════════

ALL_CHECKS = [
    # Contraseñas
    check_password_complexity,
    check_password_min_length,
    check_password_max_age,
    check_lockout_policy,
    check_guest_account,
    check_administrator_renamed,
    # Firewall
    check_firewall_domain,
    check_firewall_private,
    check_firewall_public,
    # Actualizaciones
    check_windows_update_service,
    check_pending_updates,
    # RDP
    check_rdp_nla,
    check_rdp_enabled,
    # SMB
    check_smb1_disabled,
    check_smb_signing,
    # Auditoría
    check_audit_logon,
    check_audit_account_management,
    check_event_log_size,
    # Servicios
    check_telnet_disabled,
    check_print_spooler,
    check_winrm,
    # Antivirus
    check_defender_realtime,
    check_defender_updated,
    # Sistema
    check_uac_enabled,
    check_uac_admin_prompt,
]

def print_banner():
    print(f"""
{C.CYAN}{C.BOLD}
 ╔════════════════════════════════════════════════════╗
 ║      ServerHardenPro — Agente Windows v0.1        ║
 ║           Auditoría de Hardening                   ║
 ╚════════════════════════════════════════════════════╝
{C.RESET}""")

def print_result(check):
    s = check["status"]
    if s == "PASS":
        icon = f"{C.GREEN}✅ PASS{C.RESET}"
    elif s == "FAIL":
        icon = f"{C.RED}❌ FAIL{C.RESET}"
    else:
        icon = f"{C.YELLOW}⚠  WARN{C.RESET}"

    cat    = f"{C.MUTED}[{check['category']:14}]{C.RESET}"
    name   = f"{C.WHITE}{check['name']}{C.RESET}"
    detail = f"{C.MUTED}  → {check['detail']}{C.RESET}"

    print(f"  {icon}  {cat}  {name}")
    print(f"         {detail}")


# ══════════════════════════════════════════════════════════════════
#  INVENTARIO DE HARDWARE
# ══════════════════════════════════════════════════════════════════

def get_inventory():
    """Recopila información de hardware del sistema Windows."""
    inv = {}

    # CPU
    try:
        cpu_name = ps("(Get-WmiObject Win32_Processor).Name").strip()
        cpu_cores = ps("(Get-WmiObject Win32_Processor).NumberOfLogicalProcessors").strip()
        cpu_freq  = ps("(Get-WmiObject Win32_Processor).MaxClockSpeed").strip()
        inv["cpu"] = f"{cpu_name} ({cpu_cores} cores @ {int(cpu_freq or 0)//1000:.1f} GHz)"
    except:
        inv["cpu"] = "N/A"

    # RAM
    try:
        total_kb = ps("(Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory").strip()
        free_kb  = ps("(Get-WmiObject Win32_OperatingSystem).FreePhysicalMemory").strip()
        total_gb = int(total_kb or 0) / (1024**3)
        free_gb  = int(free_kb or 0) / (1024**2) / 1024
        used_pct = round((1 - free_gb/total_gb) * 100) if total_gb > 0 else 0
        inv["ram_total_gb"]  = round(total_gb, 2)
        inv["ram_free_gb"]   = round(free_gb, 2)
        inv["ram_used_pct"]  = used_pct
    except:
        inv["ram_total_gb"] = inv["ram_free_gb"] = inv["ram_used_pct"] = 0

    # Disco
    try:
        disk_info = ps("Get-WmiObject Win32_LogicalDisk -Filter \"DriveType=3\" | Select-Object DeviceID,Size,FreeSpace | ConvertTo-Json")
        disks = json.loads(disk_info) if disk_info.strip().startswith('[') else [json.loads(disk_info)] if disk_info.strip().startswith('{') else []
        disk_list = []
        for d in disks:
            size = int(d.get("Size") or 0)
            free = int(d.get("FreeSpace") or 0)
            if size > 0:
                used_pct = round((1 - free/size)*100)
                disk_list.append({
                    "mount": d.get("DeviceID","?"),
                    "total_gb": round(size/(1024**3),1),
                    "free_gb":  round(free/(1024**3),1),
                    "used_pct": used_pct
                })
        inv["disks"] = disk_list
    except:
        inv["disks"] = []

    # Uptime
    try:
        boot_time = ps("(Get-CimInstance Win32_OperatingSystem).LastBootUpTime").strip()
        inv["boot_time"] = boot_time[:19] if boot_time else "N/A"
    except:
        inv["boot_time"] = "N/A"

    # Tipo de equipo (VM/Físico)
    try:
        model = ps("(Get-WmiObject Win32_ComputerSystem).Model").strip()
        manufacturer = ps("(Get-WmiObject Win32_ComputerSystem).Manufacturer").strip()
        vm_keywords = ["virtual", "vmware", "virtualbox", "hyper-v", "kvm", "xen", "qemu"]
        is_vm = any(kw in (model + manufacturer).lower() for kw in vm_keywords)
        inv["is_vm"]       = is_vm
        inv["vm_type"]     = model if is_vm else "Físico"
        inv["manufacturer"] = manufacturer
        inv["model"]        = model
    except:
        inv["is_vm"] = False
        inv["vm_type"] = "Físico"

    # Windows version
    try:
        win_ver = ps("(Get-WmiObject Win32_OperatingSystem).Caption").strip()
        win_build = ps("(Get-WmiObject Win32_OperatingSystem).BuildNumber").strip()
        inv["os_full"] = f"{win_ver} (Build {win_build})"
    except:
        inv["os_full"] = platform.platform()

    return inv


# ══════════════════════════════════════════════════════════════════
#  ANÁLISIS DE EVENT LOGS
# ══════════════════════════════════════════════════════════════════

def analyze_logs(hours=24):
    """Analiza Event Logs de Windows en busca de eventos de seguridad."""
    print(f"\n{C.CYAN}  📋 Analizando Event Logs (últimas {hours}hs)...{C.RESET}")

    log_data = {
        "hostname":          socket.gethostname(),
        "period_hours":      hours,
        "auth_fail_total":   0,
        "auth_ok_total":     0,
        "brute_force_count": 0,
        "syslog_error_count": 0,
        "syslog_crit_count": 0,
        "top_ips":    [],
        "top_users":  [],
        "brute_events": [],
        "syslog_errors": []
    }

    try:
        # Auth failures (Event ID 4625 — Login fallido)
        fail_cmd = f"""
$start = (Get-Date).AddHours(-{hours})
$events = Get-WinEvent -FilterHashtable @{{
    LogName='Security'; Id=4625; StartTime=$start
}} -ErrorAction SilentlyContinue
$count = if ($events) {{ ($events | Measure-Object).Count }} else {{ 0 }}
Write-Output $count
"""
        fail_count = ps(fail_cmd).strip()
        log_data["auth_fail_total"] = int(fail_count or 0)

        # Auth success (Event ID 4624 — Login exitoso)
        ok_cmd = f"""
$start = (Get-Date).AddHours(-{hours})
$events = Get-WinEvent -FilterHashtable @{{
    LogName='Security'; Id=4624; StartTime=$start
}} -ErrorAction SilentlyContinue
$count = if ($events) {{ ($events | Measure-Object).Count }} else {{ 0 }}
Write-Output $count
"""
        ok_count = ps(ok_cmd).strip()
        log_data["auth_ok_total"] = int(ok_count or 0)

        # Brute force detection (5+ failures from same account in 10 min)
        brute_cmd = f"""
$start = (Get-Date).AddHours(-{hours})
$events = Get-WinEvent -FilterHashtable @{{
    LogName='Security'; Id=4625; StartTime=$start
}} -ErrorAction SilentlyContinue
if ($events) {{
    $grouped = $events | ForEach-Object {{
        $xml = [xml]$_.ToXml()
        $xml.Event.EventData.Data | Where-Object {{ $_.Name -eq 'TargetUserName' }} | Select-Object -ExpandProperty '#text'
    }} | Group-Object | Where-Object {{ $_.Count -ge 5 }} | Sort-Object Count -Descending | Select-Object -First 5
    if ($grouped) {{
        $grouped | ForEach-Object {{ "$($_.Name):$($_.Count)" }}
    }}
}}
"""
        brute_raw = ps(brute_cmd).strip()
        if brute_raw:
            brute_events = []
            for line in brute_raw.splitlines():
                if ':' in line:
                    user, count = line.rsplit(':', 1)
                    brute_events.append({"user": user.strip(), "count": int(count.strip())})
            log_data["brute_events"]    = brute_events
            log_data["brute_force_count"] = len(brute_events)

        # Top users with failures
        top_users_cmd = f"""
$start = (Get-Date).AddHours(-{hours})
$events = Get-WinEvent -FilterHashtable @{{
    LogName='Security'; Id=4625; StartTime=$start
}} -ErrorAction SilentlyContinue
if ($events) {{
    $events | ForEach-Object {{
        $xml = [xml]$_.ToXml()
        $xml.Event.EventData.Data | Where-Object {{ $_.Name -eq 'TargetUserName' }} | Select-Object -ExpandProperty '#text'
    }} | Group-Object | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object {{ "$($_.Name):$($_.Count)" }}
}}
"""
        top_users_raw = ps(top_users_cmd).strip()
        if top_users_raw:
            top_users = []
            for line in top_users_raw.splitlines():
                if ':' in line:
                    user, count = line.rsplit(':', 1)
                    top_users.append({"user": user.strip(), "count": int(count.strip())})
            log_data["top_users"] = top_users

        # System errors (Event Log System — Error/Critical)
        sys_err_cmd = f"""
$start = (Get-Date).AddHours(-{hours})
$errors = Get-WinEvent -FilterHashtable @{{
    LogName='System'; Level=2; StartTime=$start
}} -ErrorAction SilentlyContinue
$crits = Get-WinEvent -FilterHashtable @{{
    LogName='System'; Level=1; StartTime=$start
}} -ErrorAction SilentlyContinue
$errCount  = if ($errors) {{ ($errors | Measure-Object).Count }} else {{ 0 }}
$critCount = if ($crits)  {{ ($crits  | Measure-Object).Count }} else {{ 0 }}
Write-Output "$errCount $critCount"
"""
        sys_raw = ps(sys_err_cmd).strip().split()
        if len(sys_raw) >= 2:
            log_data["syslog_error_count"] = int(sys_raw[0] or 0)
            log_data["syslog_crit_count"]  = int(sys_raw[1] or 0)

        # Recent critical system events
        crit_events_cmd = f"""
$start = (Get-Date).AddHours(-{hours})
$events = Get-WinEvent -FilterHashtable @{{
    LogName='System'; Level=1; StartTime=$start
}} -ErrorAction SilentlyContinue | Select-Object -First 5
if ($events) {{
    $events | ForEach-Object {{ "$($_.TimeCreated.ToString('yyyy-MM-dd HH:mm'))|$($_.ProviderName)|$($_.Message.Substring(0,[Math]::Min(80,$_.Message.Length)))" }}
}}
"""
        crit_raw = ps(crit_events_cmd).strip()
        if crit_raw:
            crit_list = []
            for line in crit_raw.splitlines():
                parts = line.split('|', 2)
                if len(parts) == 3:
                    crit_list.append({
                        "time": parts[0], "source": parts[1], "message": parts[2]
                    })
            log_data["syslog_errors"] = crit_list

    except Exception as e:
        print(f"  {C.YELLOW}⚠  Error analizando logs: {e}{C.RESET}")

    print(f"  {C.RED}❌ Auth fallidos  :{C.RESET} {log_data['auth_fail_total']}")
    print(f"  {C.GREEN}✅ Auth exitosos  :{C.RESET} {log_data['auth_ok_total']}")
    print(f"  {C.YELLOW}⚠  Errores sistema:{C.RESET} {log_data['syslog_error_count']} errores / {log_data['syslog_crit_count']} críticos")
    if log_data["brute_force_count"] > 0:
        print(f"  {C.RED}🚨 Fuerza bruta   :{C.RESET} {log_data['brute_force_count']} cuenta(s) sospechosa(s)")

    return log_data


def send_logs(log_data: dict):
    """Envía análisis de logs al backend."""
    log_url = API_URL.replace("/audit", "/logs")
    print(f"\n{C.CYAN}  📡 Enviando análisis de logs...{C.RESET}")
    try:
        body = json.dumps(log_data, ensure_ascii=False, default=str).encode("utf-8")
        req  = urllib.request.Request(
            log_url, data=body,
            headers={"Content-Type": "application/json"}, method="POST"
        )
        with urllib.request.urlopen(req, timeout=15, context=SSL_CTX) as resp:
            result = json.loads(resp.read().decode())
            print(f"  {C.GREEN}✅ Logs enviados:{C.RESET} {result.get('message','OK')}\n")
    except Exception as e:
        print(f"  {C.YELLOW}⚠  No se pudieron enviar los logs:{C.RESET} {e}\n")


def run_audit():
    print_banner()

    hostname = socket.gethostname()
    os_info  = platform.platform()
    now      = datetime.datetime.now().isoformat()

    print(f"{C.CYAN}  Host    :{C.RESET} {hostname}")
    print(f"{C.CYAN}  OS      :{C.RESET} {os_info}")
    print(f"{C.CYAN}  Inicio  :{C.RESET} {now}")
    print(f"\n{C.MUTED}  {'─'*62}{C.RESET}\n")

    if not is_admin():
        print(f"{C.YELLOW}  ⚠  No se está ejecutando como Administrador.{C.RESET}")
        print(f"{C.YELLOW}     Algunos checks pueden dar resultados incorrectos.{C.RESET}")
        print(f"{C.YELLOW}     Recomendado: clic derecho → Ejecutar como administrador\n{C.RESET}")

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

    total = len(results)
    score = round((totals["PASS"] / total) * 100) if total else 0

    # ── Resumen ──
    print(f"\n{C.MUTED}  {'─'*62}{C.RESET}")
    print(f"\n{C.BOLD}  RESUMEN{C.RESET}")
    print(f"  {C.GREEN}✅ PASS  : {totals['PASS']}{C.RESET}")
    print(f"  {C.RED}❌ FAIL  : {totals['FAIL']}{C.RESET}")
    print(f"  {C.YELLOW}⚠  WARN  : {totals['WARN']}{C.RESET}")
    print(f"  {C.CYAN}📊 SCORE : {score}%{C.RESET}\n")

    # ── Inventario ──
    print(f"\n{C.CYAN}  🖥️  Recopilando inventario de hardware...{C.RESET}")
    inventory = get_inventory()
    print(f"  {C.GREEN}✅ CPU   :{C.RESET} {inventory.get('cpu','N/A')}")
    print(f"  {C.GREEN}✅ RAM   :{C.RESET} {inventory.get('ram_total_gb',0)} GB total / {inventory.get('ram_free_gb',0)} GB libre")
    print(f"  {C.GREEN}✅ Tipo  :{C.RESET} {'VM — ' + inventory.get('vm_type','') if inventory.get('is_vm') else 'Físico'}")

    # ── JSON ──
    output = {
        "server": {
            "hostname": hostname,
            "os": os_info,
            "os_full": inventory.get("os_full", os_info),
            "ip": os.environ.get("SHP_IP") or socket.gethostbyname(hostname),
            "audit_date": now,
            "agent_version": "0.5",
            "platform": "windows"
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

    # Guardar JSON localmente como backup
    filename = f"resultado_{hostname}.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)
    print(f"  {C.GREEN}💾 Backup guardado en:{C.RESET} {filename}")

    # Enviar al backend
    send_to_panel(output)

    # Analizar y enviar logs
    log_data = analyze_logs(hours=24)
    log_data["hostname"] = hostname
    send_logs(log_data)

    return output

def send_to_panel(data: dict):
    """Envía el resultado al panel ServerHardenPro."""
    print(f"\n{C.CYAN}  📡 Enviando resultado al panel...{C.RESET}")
    print(f"  {C.MUTED}→ {API_URL}{C.RESET}")
    try:
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        req  = urllib.request.Request(
            API_URL, data=body,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=15, context=SSL_CTX) as resp:
            result = json.loads(resp.read().decode())
            print(f"  {C.GREEN}✅ Panel actualizado:{C.RESET} {result.get('message', 'OK')}\n")
    except urllib.error.URLError as e:
        print(f"  {C.YELLOW}⚠  No se pudo conectar al panel:{C.RESET} {e.reason}")
        print(f"  {C.MUTED}   Verificá que el backend esté corriendo en {API_URL}{C.RESET}\n")
    except Exception as e:
        print(f"  {C.YELLOW}⚠  Error al enviar:{C.RESET} {e}\n")

# ══════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ServerHardenPro — Agente Windows")
    parser.add_argument("--api", help="URL del backend (ej: https://192.168.10.90)")
    args = parser.parse_args()

    if args.api:
        base = args.api.rstrip("/")
        API_URL = f"{base}/audit"

    if platform.system() != "Windows":
        print(f"\n  ❌ Este agente solo corre en Windows.\n"
              f"  Para Linux usá: python3 agent_linux.py\n")
        sys.exit(1)

    run_audit()