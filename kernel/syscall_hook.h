#ifndef __KSU_H_KSU_SYSCALL_HOOK
#define __KSU_H_KSU_SYSCALL_HOOK
#include <asm/syscall.h>

#if defined(__aarch64__)
#define ksu_syscall_fn_t syscall_fn_t
#elif defined(__x86_64__)
#define ksu_syscall_fn_t sys_call_ptr_t
#endif

extern ksu_syscall_fn_t *ksu_syscall_table;

void ksu_replace_syscall_table(int nr, ksu_syscall_fn_t fn, ksu_syscall_fn_t *old);

void ksu_syscall_hook_init();

#endif
