#ifndef VM_VM_H
#define VM_VM_H

#include "threads/thread.h"

/* LOGOS-ADDED TYPE */
struct page_identifier
{
  struct thread* t;                     /* The owner thread of the page. */
  void * upage;                         /* The user virtual page start address. */
};

void vm_init (void);
void vm_free_all_thread_user_memory (struct thread* t);
bool vm_set_page_pageable (struct thread* t, void *upage);

void *vm_request_user_page (const struct page_identifier* pg_id);
void *vm_request_new_user_page (void);

bool vm_is_address_in_growable_stack_area (struct thread* t, const void* addr, void *esp);
bool vm_try_stack_growth (struct thread* t, const void* fault_addr, void *esp);

#endif /* vm/vm.h */
