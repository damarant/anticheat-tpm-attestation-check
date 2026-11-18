# Anti-Cheat TPM Attestation Check

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform: Windows 11](https://img.shields.io/badge/Platform-Windows%2011-blue.svg)](https://www.microsoft.com/windows/windows-11)
[![PowerShell 5.1+](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://learn.microsoft.com/powershell/)

Read-only PowerShell script to verify **TPM attestation**, **Secure Boot** and **PCR 7 / TCG log** state on Windows 11.

It helps diagnose access blocks caused by anti-cheat systems that require hardware attestation — in particular **RICOCHET** (Call of Duty / Warzone) and **Vanguard** (Valorant / League of Legends).

## The problem

Some anti-cheat systems verify the integrity of the system boot chain via TPM and Secure Boot. If PCR 7 does not match the TCG log, attestation fails and the game blocks access with messages such as:

> *"A failed authentication state has been applied to you"*

The most common cause on Windows 11 24H2 is **dual boot with Linux**: GRUB/Shim in the EFI partition alters the measured boot chain, even if Linux is never booted.

## What the script does

Read-only checks:

- TPM status (present, ready, enabled, activated, owned)
- `Ready For Attestation` via `tpmtool`
- TPM-WMI event 1041: `HealthStatus`, `Required` fields, `PcrsMatchTcgLog`, `BitMaskOfPcrMismatches`, Secure Boot consistency, EK/AIK certificates
- Secure Boot state via `Confirm-SecureBootUEFI`
- Presence of Linux/GRUB EFI entries in the boot order

It produces a clear verdict (`ALL GOOD` / `ISSUES DETECTED`) with recommended actions, and saves a full log next to the script.

## What it does NOT do

- Does not clear the TPM
- Does not reset Secure Boot keys
- Does not modify PK, KEK, DB, DBX
- Does not reinstall Windows
- Does not create services
- Does not write to the registry

It is safe to run on production machines.

## Requirements

- Windows 11
- PowerShell 5.1 or later
- Administrator privileges (the script requests elevation automatically)

## Installation

1. Download `scripts/Verify-TPM-Attestation.ps1`
2. Download `scripts/Run-Verify.bat` into the same folder
3. Double-click `Run-Verify.bat`

Alternatively, from an elevated PowerShell window:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
& ".\Verify-TPM-Attestation.ps1"
```

`-Scope Process` applies the bypass only to the current session: it does not change the system policy.

## Output

Messages are color-coded:

|Color|Meaning|
|---|---|
|Green|Check passed|
|Yellow|Non-blocking anomaly|
|Red|Problem that may prevent attestation|
|Gray|Context information|

At the end a verdict is shown together with the path of the log saved next to the script (`TPM-Verify_yyyyMMdd_HHmmss.txt`).

For detailed interpretation of the results, see [`docs/INTERPRETATION.md`](docs/INTERPRETATION.md)


## Use cases

- Warzone / Call of Duty blocked by RICOCHET with "authentication failed"
    
- Valorant / League of Legends blocked by Vanguard with TPM/Secure Boot errors
    
- General diagnostics of boot issues related to TPM and Secure Boot
    

It has no effect on anti-cheat systems that do not require hardware attestation (e.g. BattlEye, Easy Anti-Cheat).

## License

MIT — see [`LICENSE`](LICENSE)


## References

- [Microsoft — Measured Boot](https://learn.microsoft.com/windows/security/hardware-security/measured-boot)
    
- [Microsoft — Secure Boot](https://learn.microsoft.com/windows/security/operating-system-security/system-security/secure-the-windows-10-boot-process)
    
- [Trusted Computing Group — TPM 2.0 Specifications](https://trustedcomputinggroup.org/resource/tpm-library-specification/)

