# install-hyper-reV.ps1
#
# Durable install: places hyper-reV OUTSIDE \EFI\Microsoft\Boot\ at
# \EFI\hyper-reV\, and adds a custom UEFI NVRAM boot entry that firmware
# honors before Microsoft's. Microsoft's bootmgfw.efi stays intact on disk
# (no restore trick), so there is no sweep for Windows to trigger and no
# need to re-run this installer every boot.
#
# Requires: this uefi-boot build has bootmgfw::start_hooked() and
# hva.cpp's HVA_PATH = \efi\hyper-reV\hyperv-attachment.dll (both land in
# the uefi-boot.efi binary next to this script).
#
# Run from an Administrator PowerShell.

#requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'

$here    = Split-Path -Parent $MyInvocation.MyCommand.Path
# Build outputs are under build\Release\ next to this script.
$bin_dir = Join-Path $here 'build\Release'
$efi_src = Join-Path $bin_dir 'uefi-boot.efi'
$dll_src = Join-Path $bin_dir 'hyperv-attachment.dll'

if (-not (Test-Path $efi_src)) { throw "Missing: $efi_src (build uefi-boot first)" }
if (-not (Test-Path $dll_src)) { throw "Missing: $dll_src (build hyperv-attachment first)" }

# Mount EFI partition at Z:
$efi = 'Z:'
if (-not (Test-Path "${efi}\")) {
    & mountvol $efi /S
    if ($LASTEXITCODE -ne 0) { throw "mountvol failed" }
}

$dst_dir = "${efi}\EFI\hyper-reV"
if (-not (Test-Path $dst_dir)) {
    New-Item -ItemType Directory -Path $dst_dir | Out-Null
}

Copy-Item -Force $efi_src (Join-Path $dst_dir 'hyper-reV.efi')
Copy-Item -Force $dll_src (Join-Path $dst_dir 'hyperv-attachment.dll')

Write-Host "Files deployed:"
Get-ChildItem $dst_dir | Select-Object Name, Length, LastWriteTime | Format-Table | Out-String | Write-Host

# Reuse an existing hyper-reV BCD entry if one is already in the store; create
# a new one only when there's nothing to reuse.
$existing = bcdedit /enum firmware 2>&1 | Out-String
$guid     = $null

$matched = [regex]::Match($existing,
    'identifier\s+(\{[0-9a-fA-F-]+\})[\s\S]{0,400}?description\s+hyper-reV')
if ($matched.Success) {
    $guid = $matched.Groups[1].Value
    Write-Host "Reusing existing BCD entry: $guid"
} else {
    $copy_output = bcdedit /copy "{bootmgr}" /d "hyper-reV" 2>&1 | Out-String
    $guid_match  = [regex]::Match($copy_output, '\{[0-9a-fA-F-]+\}')
    if (-not $guid_match.Success) {
        throw "Could not parse GUID from bcdedit output:`n$copy_output"
    }
    $guid = $guid_match.Value
    Write-Host "Created BCD entry: $guid"
}

& bcdedit /set $guid path \EFI\hyper-reV\hyper-reV.efi | Out-Null
& bcdedit /set "{fwbootmgr}" displayorder $guid /addfirst | Out-Null
& bcdedit /set hypervisorlaunchtype auto | Out-Null

Write-Host ""
Write-Host "NVRAM boot entry installed first in firmware boot order."
Write-Host "Reboot. Startup screen should show 'successfully placed winload hooks'."
Write-Host "Verify with: usermode.exe hfpc  (nonzero = HV live)"
