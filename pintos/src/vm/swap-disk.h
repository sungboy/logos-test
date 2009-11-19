#ifndef VM_SWAP_DISK_H
#define VM_SWAP_DISK_H

#include "vm/vm.h"
#include "vm/vm-frame-table.h"
#include <devices/disk.h>
#include "threads/thread.h"

/* LOGOS-ADDED TYPE */
typedef disk_sector_t swap_slot_num_t;

bool swap_disk_init (void);
bool swap_disk_allocate (const struct page_identifier *pg_id, swap_slot_num_t* ssn, struct page_identifier *prev_pg_id);
void swap_disk_store (swap_slot_num_t ssn, void* kpage);
void swap_disk_load_and_release (const struct page_identifier *pg_id, void* kpage);
void swap_disk_release_thread (struct thread *t);

#endif /* vm/vm.h */
