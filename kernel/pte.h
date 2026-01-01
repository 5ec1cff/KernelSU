#ifndef __PTE_H
#define __PTE_H

#include <linux/mm.h>
#include <linux/types.h>

pte_t *page_from_virt(unsigned long addr);

#endif
