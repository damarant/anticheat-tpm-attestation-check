
# Interpreting the results

This page explains how to read the script output and what to do based on the results.

## `PcrsMatchTcgLog = False`

PCR 7 does not match the TCG log. The most common cause on Windows 11 24H2 is **dual boot with Linux**: GRUB/Shim in the EFI partition alters the measured boot chain, even if Linux is never booted.

**Solution**: enter the BIOS, move `Windows Boot Manager` to first place in the boot priority order (above the `ubuntu`/Linux Mint entry), save and reboot. CSM disabled, Secure Boot in Standard/Windows UEFI mode.

## `BitMaskOfPcrMismatches = 128`

Bit 128 corresponds exclusively to PCR 7. Same cause and same solution as the previous point. A value such as `912` indicates multiple mismatched PCRs: in that case the problem is broader and must be analyzed with the log at hand.

## `HealthStatus` other than `Attestable`

The system is not attestable. The `Required` fields in red indicate which prerequisite is missing (TPM absent, minimum version not met, TPM not responsive, attestation certificate unavailable, TCG log not found).

## `RestartPending = True`

On Intel PTT platforms this value is often persistent due to an ASUS firmware quirk and **is not the cause of the block**. It should be ignored if everything else is OK. There is no need to clear the TPM.

## Missing ECC P384 certificates

`EkCertEccP384IsAvailable = False` and `WindowsAikCertEccP384IsAvailable = False` are in `Informational`, not in `Required`: they do not block attestation. They depend on the fact that Intel PTT 2.0 on some platforms does not expose ECC P384.

## `Secure Boot inconsistent (computer=..., TCG=...)`

Secure Boot appears enabled at system level but not in the TCG log (or vice versa). This usually indicates that the firmware is not correctly measuring the Secure Boot state, or that the Secure Boot mode in the BIOS is not the expected one (Standard / Windows UEFI).

## "No event 1041 found"

The pre-attestation health check has never run. Restart Windows and run the script again.

## "Unable to parse event 1041 JSON"

The message format has changed in a Windows build that is not yet supported. Attach the `TPM-Verify_*.txt` log to a report.

## Supported anti-cheat systems

| Anti-cheat | Requires hardware attestation | The script is useful |
|---|---|---|
| RICOCHET (Call of Duty / Warzone) | Yes | Yes |
| Vanguard (Valorant / LoL) | Yes (on-demand mode) | Yes |
| BattlEye | No | No |
| Easy Anti-Cheat | No | No |