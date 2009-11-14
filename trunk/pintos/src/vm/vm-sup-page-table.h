#ifndef VM_SUP_PAGE_TABLE_H
#define VM_SUP_PAGE_TABLE_H

#include "vm/swap-disk.h"
#include <kernel/hash.h>

/* LOGOS-ADDED ENUMERATION */
enum vm_page_storage_type
{
  PAGE_STORAGE_NONE, 
  PAGE_STORAGE_SWAP_DISK
};

/* LOGOS-ADDED TYPE */
struct vm_sup_page_table_entry
{
   struct hash_elem elem;
   enum vm_page_storage_type storage_type;
   swap_disk_block_t block_num;
};

#endif /* vm/vm-sup-page-table.h */
