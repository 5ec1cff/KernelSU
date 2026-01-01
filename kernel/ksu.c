#include <linux/kallsyms.h>
#include <linux/export.h>
#include <linux/fs.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/workqueue.h>
#include <linux/moduleparam.h>

#include "allowlist.h"
#include "feature.h"
#include "klog.h" // IWYU pragma: keep
#include "throne_tracker.h"
#include "syscall_hook_manager.h"
#include "ksud.h"
#include "supercalls.h"
#include "ksu.h"
#include "file_wrapper.h"
#include "pte.h"

struct cred *ksu_cred;

bool allow_shell = false;
module_param(allow_shell, bool, 0);

int __init kernelsu_init(void)
{
#ifdef CONFIG_KSU_DEBUG
    pr_alert("*************************************************************");
    pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
    pr_alert("**                                                         **");
    pr_alert("**         You are running KernelSU in DEBUG mode          **");
    pr_alert("**                                                         **");
    pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
    pr_alert("*************************************************************");
#endif
    if (allow_shell) {
        pr_alert("shell is allowed at init!");
    }

    ksu_cred = prepare_creds();
    if (!ksu_cred) {
        pr_err("prepare cred failed!\n");
    }

    ksu_feature_init();

    ksu_supercalls_init();

    ksu_syscall_hook_manager_init();

    ksu_allowlist_init();

    ksu_throne_tracker_init();

    ksu_ksud_init();

    ksu_file_wrapper_init();

#ifdef MODULE
#ifndef CONFIG_KSU_DEBUG
    kobject_del(&THIS_MODULE->mkobj.kobj);
#endif
#endif
    void *syscall_table = kallsyms_lookup_name("sys_call_table");
    if (!syscall_table) {
        pr_err("no sys_call_table found");
    } else {
        pte_t *ptep = page_from_virt((uintptr_t)syscall_table);
        pr_info("sys_call_table 0x%lx ptep=0x%lx pte=0x%lx",
                (uintptr_t)syscall_table, (uintptr_t)ptep,
                (uintptr_t)ptep->pte);

        pte_t *ptep_ptep = page_from_virt((uintptr_t)ptep);
        pr_info("sys_call_table_ptep 0x%lx ptep=0x%lx pte=0x%lx",
                (uintptr_t)ptep, (uintptr_t)ptep_ptep,
                (uintptr_t)ptep_ptep->pte);
    }
    return 0;
}

extern void ksu_observer_exit(void);
void kernelsu_exit(void)
{
    ksu_allowlist_exit();

    ksu_throne_tracker_exit();

    ksu_observer_exit();

    ksu_ksud_exit();

    ksu_syscall_hook_manager_exit();

    ksu_supercalls_exit();

    ksu_feature_exit();

    if (ksu_cred) {
        put_cred(ksu_cred);
    }
}

module_init(kernelsu_init);
module_exit(kernelsu_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("weishu");
MODULE_DESCRIPTION("Android KernelSU");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
MODULE_IMPORT_NS("VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver");
#else
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif
