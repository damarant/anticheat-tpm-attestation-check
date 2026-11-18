<#
.SYNOPSIS
    Verifies TPM attestation / Secure Boot / PCR 7 state on Windows 11.
.DESCRIPTION
    Checks TPM status, the latest TPM-WMI event 1041, PCR 7 / TCG log
    match, Secure Boot state and presence of GRUB / Linux dual boot.
    Produces a clear verdict and saves a log next to the script.
.NOTES
    Must be run as Administrator. Read-only: does not modify anything.
    Author : damarant
    GitHub : https://github.com/damarant/
    License: MIT
#>

# ---------- Banner ----------
Write-Host ""
Write-Host "  ============================================================" -ForegroundColor DarkCyan
Write-Host "   Anti-Cheat TPM Attestation Check" -ForegroundColor Cyan
Write-Host "   damarant - https://github.com/damarant/" -ForegroundColor Cyan
Write-Host "   MIT License" -ForegroundColor DarkGray
Write-Host "  ============================================================" -ForegroundColor DarkCyan

# ---------- Self-elevation ----------
if (-not ([Security.Principal.WindowsPrincipal] `
        [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Administrator privileges required. Relaunching with elevation..." -ForegroundColor Yellow
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}

$ErrorActionPreference = "Continue"

# Log saved next to the script
$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$logFile = Join-Path $scriptDir ("TPM-Verify_{0:yyyyMMdd_HHmmss}.txt" -f (Get-Date))

$results  = [ordered]@{}
$problems = New-Object System.Collections.Generic.List[string]
$advice   = New-Object System.Collections.Generic.List[string]

function Write-Section($title) {
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host $title -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
}
function Write-OK($msg)   { Write-Host "[ OK ]  $msg" -ForegroundColor Green;  $results[$msg] = "OK" }
function Write-Warn($msg) { Write-Host "[WARN]  $msg" -ForegroundColor Yellow; $results[$msg] = "WARN"; $problems.Add($msg) | Out-Null }
function Write-Fail($msg) { Write-Host "[FAIL]  $msg" -ForegroundColor Red;    $results[$msg] = "FAIL"; $problems.Add($msg) | Out-Null }
function Write-Info($msg) { Write-Host "[INFO]  $msg" -ForegroundColor Gray;   $results[$msg] = "INFO" }

Write-Host ""
Write-Host "  TPM ATTESTATION / SECURE BOOT / PCR 7 CHECK" -ForegroundColor White
Write-Host "  Windows 11" -ForegroundColor White
Write-Host "  Log: $logFile" -ForegroundColor DarkGray

# ---------- 1. TPM ----------
Write-Section "1. TPM status"
try {
    $tpm = Get-Tpm
    if ($tpm.TpmPresent)   { Write-OK  "TPM present" }                else { Write-Fail "TPM not present" }
    if ($tpm.TpmReady)     { Write-OK  "TPM ready (TpmReady)" }       else { Write-Fail "TPM not ready (TpmReady=False)" }
    if ($tpm.TpmEnabled)   { Write-OK  "TPM enabled" }                else { Write-Fail "TPM not enabled" }
    if ($tpm.TpmActivated) { Write-OK  "TPM activated" }              else { Write-Fail "TPM not activated" }
    if ($tpm.TpmOwned)     { Write-OK  "TPM owned (TpmOwned)" }       else { Write-Warn "TPM not owned (TpmOwned=False)" }
    Write-Info "Manufacturer: $($tpm.ManufacturerIdTxt) - version $($tpm.ManufacturerVersion)"
    if ($tpm.RestartPending) {
        Write-Warn "RestartPending=True: on Intel PTT this is often an ASUS firmware quirk; irrelevant if everything else is OK."
        $advice.Add("RestartPending=True is not the cause of the block: ignore it if everything else is OK.") | Out-Null
    } else {
        Write-OK "No pending TPM restart"
    }
} catch {
    Write-Fail "Unable to read TPM status: $($_.Exception.Message)"
}

# ---------- 2. Attestation readiness (tpmtool) ----------
Write-Section "2. Ready for attestation (tpmtool)"
try {
    $tt = & tpmtool getdeviceinformation 2>$null | Out-String
    if ($tt -match "Ready For Attestation\s*:\s*True") {
        Write-OK "TPM is ready for attestation"
    } elseif ($tt -match "Ready For Attestation\s*:\s*False") {
        Write-Fail "TPM is NOT ready for attestation"
        $advice.Add("TPM is not ready for attestation: review the following steps.") | Out-Null
    } else {
        Write-Warn "Unable to determine 'Ready For Attestation' (unexpected tpmtool output)"
    }
} catch {
    Write-Warn "tpmtool unavailable or error: $($_.Exception.Message)"
}

# ---------- 3. TPM-WMI event 1041 ----------
Write-Section "3. Latest pre-attestation health check (event 1041)"
$evt = $null
try {
    $evt = Get-WinEvent -LogName System -MaxEvents 500 |
           Where-Object { $_.ProviderName -eq "Microsoft-Windows-TPM-WMI" -and $_.Id -eq 1041 } |
           Select-Object -First 1
} catch {}

if (-not $evt) {
    Write-Fail "No event 1041 found in the System log"
    $advice.Add("No event 1041: the health check has never run. Restart Windows and retry.") | Out-Null
} else {
    Write-Info "Most recent event: $($evt.TimeCreated)"
    $obj = $null
    try {
        $json = ($evt.Message -split '\{',2)[1]
        $obj  = "{$json" | ConvertFrom-Json
    } catch { $obj = $null }

    if ($obj) {
        Write-Info "HealthStatus: $($obj.HealthStatus)"
        if ($obj.HealthStatus -eq "Attestable") {
            Write-OK "Health status: Attestable"
        } else {
            Write-Fail "Health status: $($obj.HealthStatus) (expected: Attestable)"
        }

        # Required
        foreach ($r in $obj.Required) {
            if ($r.Value -eq $r.DesiredValue) { Write-OK "Required.$($r.Field) = $($r.Value)" }
            else { Write-Fail "Required.$($r.Field) = $($r.Value) (expected $($r.DesiredValue))" }
        }

        # Expected -> PcrsMatchTcgLog
        $pcrs = ($obj.Expected | Where-Object Field -eq "PcrsMatchTcgLog").Value
        if ($pcrs -eq $true) {
            Write-OK "PcrsMatchTcgLog = True (PCR and TCG log match)"
        } else {
            Write-Fail "PcrsMatchTcgLog = $pcrs (PCR and TCG log do NOT match)"
            $advice.Add("PCR 7 does not match the TCG log. Typical cause: dual boot with GRUB/Linux. Move 'Windows Boot Manager' to first place in the BIOS boot order.") | Out-Null
        }

        # BitMask (if present in the message)
        if ($evt.Message -match 'BitMaskOfPcrMismatches"\s*:\s*(\d+)') {
            $mask = [int]$Matches[1]
            if ($mask -eq 0) {
                Write-OK "BitMaskOfPcrMismatches = 0"
            } else {
                Write-Fail "BitMaskOfPcrMismatches = ${mask}"
                if ($mask -band 128) { Write-Fail "Bit 128 indicates PCR 7 mismatch" }
                $advice.Add("BitMaskOfPcrMismatches=${mask}: PCR mismatch. Bit 128 = PCR 7.") | Out-Null
            }
        }

        # Secure Boot consistency
        $sb = $obj.Informational | Where-Object Field -eq "SecureBootEnabled"
        if ($sb) {
            if ($sb.ValueFromComputer -eq $true -and $sb.ValueFromTcgLog -eq $true) {
                Write-OK "Secure Boot enabled and consistent between computer and TCG log"
            } else {
                Write-Fail "Secure Boot inconsistent (computer=$($sb.ValueFromComputer), TCG=$($sb.ValueFromTcgLog))"
            }
        }

        # Attestation certificates
        foreach ($name in "EkCertRsa2048IsAvailable","EkCertEccP256IsAvailable","WindowsAikCertRsa2048IsAvailable","WindowsAikCertEccP256IsAvailable") {
            $c = $obj.Informational | Where-Object Field -eq $name
            if ($c) {
                if ($c.Value -eq $true) { Write-OK "${name} = True" }
                else { Write-Warn "${name} = False (Informational: does not block attestation)" }
            }
        }
    } else {
        Write-Warn "Unable to parse event 1041 JSON"
        $advice.Add("Event 1041 present but not parsable: attach the log to whoever is assisting you.") | Out-Null
    }
}

# ---------- 4. Secure Boot (UEFI confirm) ----------
Write-Section "4. Secure Boot"
try {
    $sbState = Confirm-SecureBootUEFI -ErrorAction Stop
    if ($sbState) { Write-OK "Secure Boot enabled" } else { Write-Fail "Secure Boot disabled" }
} catch {
    Write-Warn "Unable to read Secure Boot state: $($_.Exception.Message)"
}

# ---------- 5. GRUB / Linux dual boot detection ----------
Write-Section "5. GRUB / Linux dual boot detection"
$grubFound = $false
try {
    $fw = & bcdedit /enum firmware 2>$null | Out-String
    if ($fw -match "(?i)(ubuntu|grub|shim|linux|mint|fedora|debian|manjaro|arch)") {
        $grubFound = $true
        Write-Warn "EFI entries related to Linux/GRUB found in the firmware boot order."
        $advice.Add("Linux/GRUB dual boot detected: if PCR 7 is mismatched, move 'Windows Boot Manager' to first place in the BIOS boot order.") | Out-Null
    } else {
        Write-OK "No Linux/GRUB EFI entries found in the boot order."
    }

    # EFI boot order (first entries)
    $bootOrder = & bcdedit /enum "{fwbootmgr}" 2>$null | Out-String
    if ($bootOrder -match "(?s)displayorder\s*\{(.+?)\}") {
        Write-Info "Firmware boot order (displayorder): $($Matches[1])"
    }
} catch {
    Write-Warn "Unable to read firmware boot order: $($_.Exception.Message)"
}

# ---------- 6. Verdict ----------
Write-Section "VERDICT"
$failCount = ($results.Values | Where-Object { $_ -eq "FAIL" }).Count
if ($failCount -eq 0) {
    Write-Host "  ALL GOOD: TPM / PCR 7 attestation is correct." -ForegroundColor Green
    Write-Host "  If an anti-cheat still blocks, the cause is not PCR 7." -ForegroundColor Green
} else {
    Write-Host "  ISSUES DETECTED: $failCount" -ForegroundColor Red
    Write-Host ""
    Write-Host "  Recommended actions:" -ForegroundColor Yellow
    $advice | Select-Object -Unique | ForEach-Object { Write-Host "   - $_" -ForegroundColor Yellow }
    if ($grubFound) {
        Write-Host ""
        Write-Host "  Note: a Linux/GRUB dual boot was detected. This is the most" -ForegroundColor Yellow
        Write-Host "  common cause of PCR 7 mismatch on Windows 11 24H2." -ForegroundColor Yellow
    }
}

# ---------- Log save ----------
try {
    $out = @()
    $out += "TPM / SECURE BOOT / PCR 7 CHECK - $(Get-Date)"
    $out += "Computer: $env:COMPUTERNAME"
    $out += "Script by damarant - https://github.com/damarant/ - MIT License"
    $out += ""
    foreach ($k in $results.Keys) { $out += ("[{0}] {1}" -f $results[$k], $k) }
    $out += ""
    $out += "=== Event 1041 (full message) ==="
    if ($evt) { $out += $evt.Message }
    $out | Out-File -FilePath $logFile -Encoding UTF8
    Write-Host ""
    Write-Host "Log saved to: $logFile" -ForegroundColor DarkGray
} catch {
    Write-Host "Unable to save log: $($_.Exception.Message)" -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "Press ENTER to close..." -ForegroundColor DarkGray
[void][System.Console]::ReadLine()