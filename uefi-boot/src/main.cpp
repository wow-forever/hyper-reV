#include "mem/mem.hpp"
#include "bootmgfw/bootmgfw.hpp"
#include "efi/boot.hpp"
#include "efi/status.hpp"
#include "hyperv_attachment/hva.hpp"

extern "C" {
#include <visual-uefi/EDK-II/BaseLib/vshacks.h>
#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
}

extern "C" CONST UINT8 _gDriverUnloadImageCount = 1;
extern "C" CONST UINT32 _gUefiDriverRevision = 0x200;
extern "C" CHAR8* gEfiCallerBaseName = "hyper-reV";

extern "C"
EFI_STATUS
EFIAPI
UefiUnload (
    IN EFI_HANDLE ImageHandle
    )
{
    (void)ImageHandle;
    return EFI_SUCCESS;
}

extern "C"
EFI_STATUS
EFIAPI
UefiMain (
    IN EFI_HANDLE ImageHandle,
    IN EFI_SYSTEM_TABLE* SystemTable
    )
{
    efi::status stat = efi::find_boot_info();

    if (!stat)
        return stat;

    stat = mem::init();

    if (!stat)
        return stat;

    stat = hva::load_from_disk();

    if (!stat)
        return stat;

    // New install path: uefi-boot.efi lives at \efi\hyper-reV\hyper-reV.efi
    // and is launched by a custom NVRAM boot entry. Microsoft's bootmgfw.efi
    // stays intact on disk, so we just chainload it (no restore trick).
    // Fall back to the legacy restore path if the new-path chainload fails —
    // keeps old installs (uefi-boot.efi AT \efi\microsoft\boot\bootmgfw.efi)
    // working without a re-install.
    const efi::status stat2 = bootmgfw::start_hooked();

    if (stat2)
        return stat2;

    return bootmgfw::restore_and_start_hooked();
}
