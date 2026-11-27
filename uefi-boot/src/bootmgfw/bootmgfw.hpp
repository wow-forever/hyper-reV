#pragma once
#include "../efi/status.hpp"

namespace bootmgfw
{
	// Legacy: restores Microsoft bootmgfw from \efi\microsoft\boot\bootmgfw.original.efi
	// over bootmgfw.efi, deletes the .original, then chainloads with winload hooks.
	// Used when uefi-boot.efi is installed AT \efi\microsoft\boot\bootmgfw.efi.
	efi::status restore_and_start_hooked();

	// New: just chainloads \efi\microsoft\boot\bootmgfw.efi (Microsoft's intact binary)
	// with winload hooks. Used when uefi-boot.efi is installed OUTSIDE
	// \efi\microsoft\boot\ (e.g. \efi\hyper-reV\hyper-reV.efi) and firmware
	// boots us via a custom NVRAM boot entry — Microsoft bootmgfw stays intact
	// on disk, no restore trick needed, nothing deleted.
	efi::status start_hooked();
}
