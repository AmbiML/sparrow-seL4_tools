/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <autoconf.h>
#include <elfloader/gen_config.h>

#include <drivers.h>
#include <drivers/uart.h>
#include <printf.h>
#include <types.h>
#include <abort.h>
#include <strops.h>
#include <cpuid.h>

#include <binaries/efi/efi.h>
#include <elfloader.h>

/* 0xd00dfeed in big endian */
#define DTB_MAGIC (0xedfe0dd0)

/* Maximum alignment we need to preserve when relocating (64K) */
#define MAX_ALIGN_BITS (14)

ALIGN(BIT(PAGE_BITS)) VISIBLE
char core_stack_alloc[CONFIG_MAX_NUM_NODES][BIT(PAGE_BITS)];

struct image_info kernel_info;
struct image_info user_info;
void *dtb;
uint32_t dtb_size;

extern void finish_relocation(int offset, void *_dynamic, unsigned int total_offset);
void continue_boot(int was_relocated);

/*
 * Make sure the ELF loader is below the kernel's first virtual address
 * so that when we enable the MMU we can keep executing.
 */
extern char _DYNAMIC[];
void relocate_below_kernel(void)
{
    /*
     * These are the ELF loader's physical addresses,
     * since we are either running with MMU off or
     * identity-mapped.
     */
    uintptr_t UNUSED start = (uintptr_t)_text;
    uintptr_t end = (uintptr_t)_end;

    if (end <= kernel_info.virt_region_start) {
        /*
         * If the ELF loader is already below the kernel,
         * skip relocation.
         */
        continue_boot(0);
        return;
    }

#ifdef CONFIG_IMAGE_EFI
    /*
     * Note: we make the (potentially incorrect) assumption
     * that there is enough physical RAM below the kernel's first vaddr
     * to fit the ELF loader.
     * FIXME: do we need to make sure we don't accidentally wipe out the DTB too?
     */
    uintptr_t size = end - start;

    /*
     * we ROUND_UP size in this calculation so that all aligned things
     * (interrupt vectors, stack, etc.) end up in similarly aligned locations.
     * The strictes alignment requirement we have is the 64K-aligned AArch32
     * page tables, so we use that to calculate the new base of the elfloader.
     */
    uintptr_t new_base = kernel_info.virt_region_start - (ROUND_UP(size, MAX_ALIGN_BITS));
    uint32_t offset = start - new_base;
    printf("relocating from %p-%p to %p-%p... size=0x%x (padded size = 0x%x)\n", start, end, new_base, new_base + size,
           size, ROUND_UP(size, MAX_ALIGN_BITS));

    memmove((void *)new_base, (void *)start, size);

    /* call into assembly to do the finishing touches */
    finish_relocation(offset, _DYNAMIC, new_base);
#else
    printf("The ELF loader does not support relocating itself. You probably need to move the kernel window higher, or the load address lower.\n");
    abort();
#endif
}

/*
 * Entry point.
 *
 * Unpack images, setup the MMU, jump to the kernel.
 */
void main(UNUSED void *arg)
{
    unsigned int num_apps;

    void *bootloader_dtb = NULL;

    initialise_devices();

#ifdef CONFIG_IMAGE_UIMAGE
    if (arg) {
        uint32_t magic = *(uint32_t *)arg;
        /*
         * This might happen on ancient bootloaders which
         * still think Linux wants atags instead of a
         * device tree.
         */
        if (magic != DTB_MAGIC) {
            printf("Bootloader did not supply a valid device tree!\n");
            arg = NULL;
        }
    }
    bootloader_dtb = arg;
#else
    bootloader_dtb = NULL;
#endif

#ifdef CONFIG_IMAGE_EFI
    if (efi_exit_boot_services() != EFI_SUCCESS) {
        printf("Unable to exit UEFI boot services!\n");
        abort();
    }

    bootloader_dtb = efi_get_fdt();
#endif

    /* Print welcome message. */
    platform_init();
    printf("\nELF-loader started on ");
    print_cpuid();

    printf("  paddr=[%p..%p]\n", _text, _end - 1);

    /*
     * U-Boot will either pass us a DTB, or (if we're being booted via bootelf)
     * pass '0' in argc.
     */
    if (bootloader_dtb) {
        printf("  dtb=%p\n", dtb);
    } else {
        printf("No DTB passed in from boot loader.\n");
    }

    /* Unpack ELF images into memory. */
    load_images(&kernel_info, &user_info, 1, &num_apps, bootloader_dtb, &dtb, &dtb_size);
    if (num_apps != 1) {
        printf("No user images loaded!\n");
        abort();
    }

    /*
     * We don't really know where we've been loaded.
     * It's possible that EFI loaded us in a place
     * that will become part of the 'kernel window'
     * once we switch to the boot page tables.
     * Make sure this is not the case.
     */
    relocate_below_kernel();
    printf("Relocation failed, aborting.\n");
    abort();
}

void continue_boot(int was_relocated)
{
    if (was_relocated) {
        printf("ELF loader relocated, continuing boot...\n");
    }

    /*
     * If we were relocated, we need to re-initialise the
     * driver model so all its pointers are set up properly.
     */
    if (was_relocated) {
        initialise_devices();
    }

#if (defined(CONFIG_ARCH_ARM_V7A) || defined(CONFIG_ARCH_ARM_V8A)) && !defined(CONFIG_ARM_HYPERVISOR_SUPPORT)
    if (is_hyp_mode()) {
        extern void leave_hyp(void);
        leave_hyp();
    }
#endif
    /* Setup MMU. */
    if (is_hyp_mode()) {
#ifdef CONFIG_ARCH_AARCH64
        extern void disable_caches_hyp();
        disable_caches_hyp();
#endif
        init_hyp_boot_vspace(&kernel_info);
    } else {
        /* If we are not in HYP mode, we enable the SV MMU and paging
         * just in case the kernel does not support hyp mode. */
        init_boot_vspace(&kernel_info);
    }

#if CONFIG_MAX_NUM_NODES > 1
    smp_boot();
#endif /* CONFIG_MAX_NUM_NODES */

    if (is_hyp_mode()) {
        printf("Enabling hypervisor MMU and paging\n");
        arm_enable_hyp_mmu();
    } else {
        printf("Enabling MMU and paging\n");
        arm_enable_mmu();
    }

    /* Enter kernel. */
    if ((uintptr_t)uart_get_mmio() < kernel_info.virt_region_start) {
        printf("Jumping to kernel-image entry point...\n\n");
    } else {
        /* Our serial port is no longer accessible */
    }

    ((init_arm_kernel_t)kernel_info.virt_entry)(user_info.phys_region_start,
                                                user_info.phys_region_end, user_info.phys_virt_offset,
                                                user_info.virt_entry, (paddr_t)dtb, dtb_size);

    /* We should never get here. */
    printf("Kernel returned back to the elf-loader.\n");
    abort();
}
