#include "klog.h" // IWYU pragma: keep
#include "pte.h"

// https://github.com/fuqiuluo/ovo/blob/f7da411458e87d32438dc14fce5a3313ed0c967e/ovo/mmuhack.c#L21
pte_t *page_from_virt(unsigned long addr)
{
    struct mm_struct *mm = &init_mm;
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;

    pgd = pgd_offset(mm, addr);
    if (pgd_none(*pgd) || pgd_bad(*pgd))
        return NULL;
    pr_info("pgd of 0x%lx p=0x%lx v=0x%lx", addr, (uintptr_t)pgd,
            (uintptr_t)pgd_val(*pgd));

    p4d = p4d_offset(pgd, addr);
    if (p4d_none(*p4d) || p4d_bad(*p4d))
        return NULL;
    pr_info("p4d of 0x%lx p=0x%lx v=0x%lx", addr, (uintptr_t)p4d,
            (uintptr_t)p4d_val(*p4d));

    pud = pud_offset(p4d, addr);
#if defined(pud_leaf)
    if (pud_leaf(*pud)) {
        pr_info(
            "Address 0x%lx maps to a PUD-level huge page, returning PUD entry as PTE\n",
            addr);
        return (pte_t *)pud;
    }
#endif
    if (pud_none(*pud) || pud_bad(*pud))
        return NULL;
    pr_info("pud of 0x%lx p=0x%lx v=0x%lx", addr, (uintptr_t)pud,
            (uintptr_t)pud_val(*pud));

    pmd = pmd_offset(pud, addr);
#if defined(pmd_leaf)
    if (pmd_leaf(*pmd)) {
        pr_info(
            "Address 0x%lx maps to a PMD-level huge page, returning PMD entry as PTE\n",
            addr);
        return (pte_t *)pmd;
    }
#endif
    pr_info("pmd of 0x%lx p=0x%lx v=0x%lx", addr, (uintptr_t)pmd,
            (uintptr_t)pmd_val(*pmd));

    if (pmd_none(*pmd) || pmd_bad(*pmd))
        return NULL;

    pte = pte_offset_kernel(pmd, addr);
    if (!pte)
        return NULL;
    if (!pte_present(*pte))
        return NULL;

    return pte;
}

KSU_DEF_MTE_SYNC_TAGS;

#if (KSU_MTE_SYNC_TAGS_NR_PAGES + KSU_MTE_SYNC_TAGS_PTEP +                     \
     KSU_MTE_SYNC_TAGS_OLD_PTE + KSU_MTE_SYNC_TAGS_NORMAL) != 1
#error "Unsupported mte_sync_tags"
#else
#if KSU_MTE_SYNC_TAGS_NR_PAGES
#define mte_sync_tags_compat(_ptep, _old_pte, new_pte, nr_pages)               \
    mte_sync_tags(new_pte, nr_pages)
#elif KSU_MTE_SYNC_TAGS_PTEP
#define mte_sync_tags_compat(ptep, _old_pte, new_pte, _nr_pages)               \
    mte_sync_tags(ptep, new_pte)
#elif KSU_MTE_SYNC_TAGS_OLD_PTE
#define mte_sync_tags_compat(_ptep, old_pte, new_pte, _nr_pages)               \
    mte_sync_tags(old_pte, new_pte)
#elif KSU_MTE_SYNC_TAGS_NORMAL
#define mte_sync_tags_compat(_ptep, _old_pte, new_pte, _nr_pages)              \
    mte_sync_tags(new_pte);
#endif
#endif

// https://cs.android.com/android/kernel/superproject/+/common-android16-6.12:common/arch/arm64/include/asm/pgtable.h;l=643-645;drc=4bca12f98057dba0efac9881b21fad39274715ef
void ksu_set_pte(pte_t *ptep, pte_t pte)
{
    pte_t old_pte __maybe_unused = READ_ONCE(*ptep);

    if (pte_present(pte) && pte_user_exec(pte) && !pte_special(pte))
        __sync_icache_dcache(pte);

    if (system_supports_mte() && pte_access_permitted(pte, false) &&
        !pte_special(pte) && pte_tagged(pte)) {
        mte_sync_tags_compat(ptep, old_pte, pte, 1);
    }

    WRITE_ONCE(*ptep, pte);
    dsb(ishst);
    isb();
}
