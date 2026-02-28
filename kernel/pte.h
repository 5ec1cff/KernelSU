#ifndef __PTE_H
#define __PTE_H

#include <linux/mm.h>
#include <linux/types.h>

pte_t *page_from_virt(unsigned long addr);

void ksu_set_pte(pte_t *ptep, pte_t pte);

unsigned long phys_from_virt(unsigned long addr);

#endif
