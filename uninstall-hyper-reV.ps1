# uninstall-hyper-reV.ps1
#
# Removes the hyper-reV NVRAM boot entry + wipes \EFI\hyper-reV\ files.
# Microsoft's bootmgfw.efi is never touched (we didn't replace it).
# After this + reboot, system boots normally with no HV.

#requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'

# Find every hyper-reV firmware entry
$fw = bcdedit /enum firmware 2>&1 | Out-String

$pattern = '(?ms)identifier\s+(\{[0-9a-fA-F-]+\})[\s\S]{0,600}?description\s+hyper-reV'
$matches = [regex]::Matches($fw, $pattern)

if ($matches.Count -eq 0) {
    Write-Host "No hyper-reV BCD entry found. Skipping NVRAM cleanup."
} else {
    foreach ($m in $matches) {
        $guid = $m.Groups[1].Value
        Write-Host "Deleting BCD entry: $guid"
        & bcdedit /delete $guid /cleanup | Out-Null
    }
}

# Mount EFI and wipe our directory
$efi = 'Z:'
if (-not (Test-Path "${efi}\")) {
    & mountvol $efi /S
    if ($LASTEXITCODE -ne 0) { throw "mountvol failed" }
}

$dst_dir = "${efi}\EFI\hyper-reV"
if (Test-Path $dst_dir) {
    Remove-Item -Recurse -Force $dst_dir
    Write-Host "Removed $dst_dir"
} else {
    Write-Host "$dst_dir not present."
}

Write-Host ""
Write-Host "hyper-reV uninstalled. Reboot to confirm Windows boots normally."
