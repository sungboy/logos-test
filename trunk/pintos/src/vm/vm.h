#ifndef VM_VM_H
#define VM_VM_H

#include "threads/thread.h"

void vm_init (void);
void vm_free_all_thread_user_memory (struct thread* t);
bool vm_set_page_pageable (struct thread* t, void *upage);

#endif /* vm/vm.h */
