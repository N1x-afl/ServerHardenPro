# ╔══════════════════════════════════════════════════════════════════╗
# ║   ServerHardenPro — Instalador Task Scheduler (Windows)        ║
# ║   Uso: Ejecutar como Administrador en PowerShell               ║
# ║   Instala tarea automática de auditoría cada 6 horas           ║
# ╚══════════════════════════════════════════════════════════════════╝

param(
    [string]$ApiUrl = "",
    [int]$IntervalHours = 6
)

Write-Host "`n  ╔══════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║  ServerHardenPro — Task Scheduler   ║" -ForegroundColor Cyan
Write-Host "  ╚══════════════════════════════════════╝`n" -ForegroundColor Cyan

# ── Verificar Administrador ───────────────────────────────────────
$currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "  ❌ Ejecutar como Administrador" -ForegroundColor Red
    exit 1
}

# ── Detectar Python ───────────────────────────────────────────────
$pythonPath = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $pythonPath) {
    Write-Host "  ❌ Python no encontrado. Instalalo desde python.org" -ForegroundColor Red
    exit 1
}
Write-Host "  ✅ Python encontrado: $pythonPath" -ForegroundColor Green

# ── Detectar ruta del agente ──────────────────────────────────────
$agentPath = Join-Path $PSScriptRoot "agent_windows.py"
if (-not (Test-Path $agentPath)) {
    Write-Host "  ❌ No se encontró agent_windows.py en $PSScriptRoot" -ForegroundColor Red
    Write-Host "  Ejecutá este script desde la carpeta agents/windows/" -ForegroundColor Yellow
    exit 1
}

# ── Pedir URL si no se pasó ───────────────────────────────────────
if (-not $ApiUrl) {
    $ApiUrl = Read-Host "  URL del backend (Enter para https://localhost)"
    if (-not $ApiUrl) { $ApiUrl = "https://localhost" }
}

# Pedir IP si no se pasó
$SHPIp = Read-Host "`n  IP de este equipo (Enter para detectar automáticamente)"


# ── Pedir intervalo ───────────────────────────────────────────────
Write-Host "`n  Intervalo de auditoría:" -ForegroundColor Cyan
Write-Host "  1) Cada 1 hora"
Write-Host "  2) Cada 6 horas (recomendado)"
Write-Host "  3) Cada 12 horas"
Write-Host "  4) Una vez al día"
$opt = Read-Host "  Opción [2]"
if (-not $opt) { $opt = "2" }

switch ($opt) {
    "1" { $IntervalHours = 1 }
    "3" { $IntervalHours = 12 }
    "4" { $IntervalHours = 24 }
    default { $IntervalHours = 6 }
}

# ── Crear carpeta de logs ─────────────────────────────────────────
$logDir = "C:\ProgramData\ServerHardenPro\logs"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
Write-Host "  ✅ Directorio de logs: $logDir" -ForegroundColor Green

# ── Crear tarea en Task Scheduler ────────────────────────────────
$taskName = "ServerHardenPro-Agent"
$logFile  = "$logDir\agent.log"

# Eliminar tarea anterior si existe
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

# Acción
# Build argument string
$agentArgs = "`"$agentPath`" --api `"$ApiUrl`""

# Add SHP_IP to environment if provided
$envVars = @("SHP_API=$ApiUrl")
if ($SHPIp) { $envVars += "SHP_IP=$SHPIp" }

$action = New-ScheduledTaskAction `
    -Execute $pythonPath `
    -Argument $agentArgs `
    -WorkingDirectory $PSScriptRoot

# Trigger — repetir cada X horas
$trigger = New-ScheduledTaskTrigger `
    -RepetitionInterval (New-TimeSpan -Hours $IntervalHours) `
    -Once `
    -At (Get-Date)

# Configuración — correr como SYSTEM con privilegios máximos
$settings = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 10) `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 5)

$principal = New-ScheduledTaskPrincipal `
    -UserId "SYSTEM" `
    -LogonType ServiceAccount `
    -RunLevel Highest

Register-ScheduledTask `
    -TaskName $taskName `
    -Action $action `
    -Trigger $trigger `
    -Settings $settings `
    -Principal $principal `
    -Description "ServerHardenPro — Auditoría automática de hardening cada $IntervalHours horas" `
    -Force | Out-Null

Write-Host "  ✅ Tarea creada: $taskName (cada $IntervalHours horas)" -ForegroundColor Green

# ── Ejecutar ahora ────────────────────────────────────────────────
$runNow = Read-Host "`n  ¿Ejecutar auditoría ahora para verificar? (s/N)"
if ($runNow -eq "s" -or $runNow -eq "S") {
    Write-Host "  Ejecutando auditoría...`n" -ForegroundColor Cyan
    $env:SHP_API = $ApiUrl
    if ($SHPIp) { $env:SHP_IP = $SHPIp }
    & $pythonPath $agentPath
}

Write-Host "`n  ✅ Instalación completa!" -ForegroundColor Green
Write-Host "  📋 Logs en: $logDir" -ForegroundColor Cyan
Write-Host "  🔧 Para desinstalar: Unregister-ScheduledTask -TaskName '$taskName' -Confirm:`$false`n" -ForegroundColor Cyan
