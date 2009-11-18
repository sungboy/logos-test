#ifndef VM_FRAME_TABLE_H
#define VM_FRAME_TABLE_H

#include "vm/vm.h"
#include <kernel/list.h>
#include "threads/synch.h"

/* LOGOS-ADDED TYPE */
struct vm_frame_table_entry
{
  struct list_elem elem;                /* Before using this variable, acquire vm_frame_table_lock first. */
  struct page_identifier pg_id;         /* Before using this variable, acquire vm_frame_table_lock first. */
  struct lock change_lock;              /* The lock for jobs on this frame such as swapping. */
};

/* LOGOS-ADDED VARIABLE */
extern struct lock vm_frame_table_lock; /* Lock for the frame table. */
extern struct list vm_frame_table;      /* Before using this variable, acquire vm_frame_table_lock first. */

#endif /* vm/vm-frame-table.h */
