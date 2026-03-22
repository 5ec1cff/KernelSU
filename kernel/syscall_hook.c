#include "syscall_hook.h"

#include "linux/kallsyms.h"
#include <asm/cacheflush.h>
#include <linux/mm.h>
#include <linux/types.h>

#if defined(__aarch64__)
#include "patch_text.h"
#endif

ksu_syscall_fn_t *ksu_syscall_table = NULL;

#if defined(__aarch64__)
void ksu_replace_syscall_table(int nr, ksu_syscall_fn_t fn, ksu_syscall_fn_t *old)
{
    if (nr < 0 || nr >= __NR_syscalls) {
        pr_info("invalid nr: %d\n", nr);
        return;
    }
    pr_info("syscall 0x%lx ", (uintptr_t)&ksu_syscall_table[nr]);
    ksu_syscall_fn_t *orig_p = &ksu_syscall_table[nr], orig = READ_ONCE(*orig_p);
    if (old) {
        *old = orig;
    }

    pr_info("Before hook syscall %d, ptr=0x%lx, *ptr=0x%lx -> 0x%lx", nr,
            (unsigned long)orig_p, (unsigned long)orig, (uintptr_t)fn);

    if (ksu_patch_text(&ksu_syscall_table[nr], &fn, sizeof(fn),
                       KSU_PATCH_TEXT_FLUSH_DCACHE)) {
        pr_err("patch syscall %d failed", nr);
    }

    pr_info("After hook syscall %d, ptr=0x%lx, *ptr=0x%lx", nr,
            (unsigned long)orig_p,
            (unsigned long)READ_ONCE(ksu_syscall_table[nr]));
}
#else
static void disable_write_protection(void)
{
    unsigned long cr0 = read_cr0();
    clear_bit(16, &cr0);
	asm volatile("mov %0,%%cr0": "+r" (cr0) : : "memory");
}

static void enable_write_protection(void)
{
    unsigned long cr0 = read_cr0();
    set_bit(16, &cr0);
	asm volatile("mov %0,%%cr0": "+r" (cr0) : : "memory");
}


void ksu_replace_syscall_table(int nr, ksu_syscall_fn_t fn, ksu_syscall_fn_t *old)
{
    disable_write_protection();
    ksu_syscall_fn_t orig = ksu_syscall_table[nr];
    if (old) *old = orig;
    WRITE_ONCE(ksu_syscall_table[nr], fn);
    pr_info("hook nr %d new 0x%lx orig 0x%lx current 0x%lx\n", nr, (unsigned long) fn, (unsigned long) orig, (unsigned long) ksu_syscall_table[nr]);
    enable_write_protection();
}

#endif

void ksu_syscall_hook_init()
{
    ksu_syscall_table = kallsyms_lookup_name("sys_call_table");
    pr_info("sys_call_table=0x%lx\n", (unsigned long) ksu_syscall_table);
}
