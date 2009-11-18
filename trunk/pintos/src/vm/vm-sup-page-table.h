#ifndef VM_SUP_PAGE_TABLE_H
#define VM_SUP_PAGE_TABLE_H

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
   void * upage;
   enum vm_page_storage_type storage_type;
};

bool vm_init_sup_page_table (struct hash *spd);
void vm_destroy_sup_page_table (struct hash *spd);
struct vm_sup_page_table_entry* vm_get_new_sup_page_table_entry (struct hash *spd, void * upage);
struct vm_sup_page_table_entry* vm_get_sup_page_table_entry (struct hash *spd, void * upage);

#endif /* vm/vm-sup-page-table.h */
