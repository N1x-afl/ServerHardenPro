#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║         ServerHardenPro — Agente de Auditoría Windows           ║
║                          Fase 3                                  ║
║  Uso: python agent_windows.py                                    ║
║  Requiere: ejecutar como Administrador                           ║
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
import ctypes

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

    # ── JSON ──
    output = {
        "server": {
            "hostname": hostname,
            "os": os_info,
            "ip": socket.gethostbyname(hostname),
            "audit_date": now,
            "agent_version": "0.1",
            "platform": "windows"
        },
        "summary": {
            "total": total,
            "pass": totals["PASS"],
            "fail": totals["FAIL"],
            "warn": totals["WARN"],
            "score_percent": score
        },
        "checks": results
    }

    filename = f"resultado_{hostname}.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)

    print(f"  {C.GREEN}💾 Resultado guardado en:{C.RESET} {filename}")
    print(f"{C.MUTED}  (Este archivo será enviado al panel en la Fase 4){C.RESET}\n")

    return output

# ══════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    if platform.system() != "Windows":
        print(f"\n  ❌ Este agente solo corre en Windows.\n"
              f"  Para Linux usá: python3 agent_linux.py\n")
        sys.exit(1)
    run_audit()