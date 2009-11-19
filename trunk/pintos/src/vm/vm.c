#include "vm/vm.h"
#include "vm/vm-sup-page-table.h"
#include "vm/vm-frame-table.h"
#include "vm/swap-disk.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "threads/synch.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include <kernel/list.h>
#include <kernel/hash.h>

static struct vm_frame_table_entry *vm_add_new_fte (struct thread* t, void *upage, bool frame_table_lock_required);
static void vm_set_all_thread_pages_nonpageable_internal (struct thread* t, bool frame_table_lock_required);
static struct vm_frame_table_entry *vm_replacement_policy (const struct page_identifier *pg_id);

struct lock vm_frame_table_lock; /* LOGOS-ADDED VARIABLE. Lock for the frame table. */
struct list vm_frame_table;      /* LOGOS-ADDED VARIABLE. Before using this variable, acquire vm_frame_table_lock first. */

/* LOGOS-ADDED FUNCTION
   Initialize virtual memory. */
void
vm_init (void)
{
  lock_init (&vm_frame_table_lock);
  list_init (&vm_frame_table);
}

/* LOGOS-ADDED FUNCTION
   Free all user memory. */
void
vm_free_all_thread_user_memory (struct thread* t)
{
  lock_acquire (&vm_frame_table_lock);
  lock_acquire (&t->pagedir_lock);
  vm_set_all_thread_pages_nonpageable_internal (t, false);
  swap_disk_release_thread (t);
  lock_release (&t->pagedir_lock);
  lock_release (&vm_frame_table_lock);
}

/* LOGOS-ADDED FUNCTION */
static struct vm_frame_table_entry *
vm_add_new_fte (struct thread* t, void *upage, bool frame_table_lock_required)
{
  /* Add a struct vm_frame_table_entry to vm_frame_table. */
  struct vm_frame_table_entry* fte = (struct vm_frame_table_entry*)malloc (sizeof (struct vm_frame_table_entry));
  if (fte == NULL)
	  return NULL;

  fte->pg_id.t = t;
  fte->pg_id.upage = upage;
  lock_init (&fte->change_lock);

  if (frame_table_lock_required)
    lock_acquire (&vm_frame_table_lock);
  list_push_back (&vm_frame_table, &fte->elem); 
  if (frame_table_lock_required)
    lock_release (&vm_frame_table_lock);

  return fte;
}

/* LOGOS-ADDED FUNCTION
   Set a user virtual page pagable. */
bool
vm_set_page_pageable (struct thread* t, void *upage)
{
  return vm_add_new_fte(t, upage, true) != NULL;
}

/* LOGOS-ADDED FUNCTION
   Set all pages of a thread nonpageable. */
static void
vm_set_all_thread_pages_nonpageable_internal (struct thread* t, bool frame_table_lock_required)
{
  struct list_elem *e, *next;

  if (frame_table_lock_required)
    lock_acquire (&vm_frame_table_lock);

  for (e = list_begin (&vm_frame_table); e != list_end (&vm_frame_table);
       e = next)
    {
      struct vm_frame_table_entry *fte = list_entry (e, struct vm_frame_table_entry, elem);
      next = list_next (e);

	  if(fte->pg_id.t == t)
        {
          lock_acquire (&fte->change_lock);
          list_remove (e);
	      lock_release (&fte->change_lock);

	      free (fte);
        }
    }

  if (frame_table_lock_required)
    lock_release (&vm_frame_table_lock);
}

/* LOGOS-ADDED FUNCTION */
static unsigned
hash_hash_vm_sup_page_table_entry (const struct hash_elem *element, void *aux UNUSED)
{
  struct vm_sup_page_table_entry* spte = hash_entry (element, struct vm_sup_page_table_entry, elem);
  return hash_int ((int)spte->upage);
}

/* LOGOS-ADDED FUNCTION */
static bool
hash_less_vm_sup_page_table_entry (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
  struct vm_sup_page_table_entry* sptea = hash_entry (a, struct vm_sup_page_table_entry, elem);
  struct vm_sup_page_table_entry* spteb = hash_entry (b, struct vm_sup_page_table_entry, elem);

  return sptea->upage < spteb->upage;
}

/* LOGOS-ADDED FUNCTION
   */
static void
hash_release_action_vm_sup_page_table_entry (struct hash_elem *element, void *aux UNUSED)
{
  struct vm_sup_page_table_entry* spte = hash_entry (element, struct vm_sup_page_table_entry, elem);
  free(spte);
}

/* LOGOS-ADDED FUNCTION
   */
struct vm_sup_page_table_entry*
vm_get_new_sup_page_table_entry (struct hash *spd, void * upage)
{
  struct vm_sup_page_table_entry* ret;

  ret = (struct vm_sup_page_table_entry*)malloc (sizeof (struct vm_sup_page_table_entry));
  if(ret == NULL)
	  return NULL;

  ASSERT (is_user_vaddr (upage) && pg_ofs (upage) == 0);
  
  ret->upage = upage;
  ret->storage_type = PAGE_STORAGE_NONE;

  hash_insert (spd, &ret->elem);

  return ret;
}

/* LOGOS-ADDED FUNCTION
   */
struct vm_sup_page_table_entry*
vm_get_sup_page_table_entry (struct hash *spd, void * upage)
{
  struct hash_elem* elem;
  struct vm_sup_page_table_entry* ret;
  struct vm_sup_page_table_entry temp_spte;

  temp_spte.upage = upage;

  elem = hash_find (spd, &temp_spte.elem);
  if(elem == NULL)
	  return NULL;

  ret = hash_entry (elem, struct vm_sup_page_table_entry, elem);

  return ret;
}

/* LOGOS-ADDED FUNCTION */
bool
vm_init_sup_page_table (struct hash *spd)
{
  return hash_init (spd, hash_hash_vm_sup_page_table_entry, hash_less_vm_sup_page_table_entry, NULL);
}

/* LOGOS-ADDED FUNCTION */
void
vm_destroy_sup_page_table (struct hash *spd)
{
  hash_destroy (spd, hash_release_action_vm_sup_page_table_entry);
}

/* LOGOS-ADDED FUNCTION
   Reaplace a existing user page to the user page represented by pg_id and return it. 
   Sometimes, some physical free memory pages for user can be available. 
   We allow this function called by only the process that is the owner of the page represented by pg_id. 
*/
void *vm_request_user_page (const struct page_identifier* pg_id)
{
  void * kpage;
  struct vm_frame_table_entry *fte;
  swap_slot_num_t tssn;
  struct page_identifier prev_pg_id;
  struct vm_sup_page_table_entry *spte;
  bool b;
  struct lock temp_lock;

  bool write_required = false;
  swap_slot_num_t ssn_to_write;
  struct lock* replaced_page_pagedir_lock;

  ASSERT (pg_id != NULL);
  ASSERT (pg_id->t != NULL);

  /* We allow this function called by only the process that is the owner of the page represented by pg_id. */
  ASSERT (thread_current () == pg_id->t);

  /* Check whether pg_id is correct or not. */
  if (pg_id->upage == NULL)
    return NULL;

  if (!process_is_valid_user_virtual_address(pg_id->upage, 1, false) || pg_ofs(pg_id->upage)!=0)
    return NULL;

  /* Try to get a free page using the palloc_*_without_vm function. */
  kpage = palloc_get_page_without_vm (PAL_USER);

  /* Lock-related works. */
  lock_init (&temp_lock);
  replaced_page_pagedir_lock = &temp_lock;

  lock_acquire (&vm_frame_table_lock);
  lock_acquire (&pg_id->t->pagedir_lock);

  ASSERT (pagedir_get_page (pg_id->t->pagedir, pg_id->upage) == NULL);
  ASSERT (pagedir_get_sup_page_table_entry (pg_id->t->pagedir, pg_id->upage) != NULL);
  ASSERT (pagedir_get_sup_page_table_entry (pg_id->t->pagedir, pg_id->upage)->storage_type == PAGE_STORAGE_SWAP_DISK);

  if (kpage != NULL)
  {
      /* The palloc_*_without_vm function has suceeded. */
      /* Add a new frame table entry. */
	  fte = vm_add_new_fte (pg_id->t, pg_id->upage, false);
      if (fte == NULL)
        {
          ASSERT (0);
		  lock_release (&pg_id->t->pagedir_lock);
		  lock_release (&vm_frame_table_lock);
		  return NULL;
        }

	  lock_acquire (replaced_page_pagedir_lock);
  }

  if (kpage == NULL)
    {
      /* No free page in the main memory. Replace a page. */
      fte = vm_replacement_policy (pg_id);
      if (fte == NULL)
        {
          ASSERT (0);
		  lock_release (&pg_id->t->pagedir_lock);
		  lock_release (&vm_frame_table_lock);
          return NULL;
        }

	  replaced_page_pagedir_lock = &fte->pg_id.t->pagedir_lock;
      lock_acquire (replaced_page_pagedir_lock);

	  kpage = pagedir_get_page (fte->pg_id.t->pagedir, fte->pg_id.upage);
	  ASSERT (kpage != NULL);

      /* First, check whether swap-out is required or not. */
      if (pagedir_is_dirty (fte->pg_id.t->pagedir, fte->pg_id.upage))
        {
          /* If Swap-out is required, prepare to swap the old page out. */
          b = swap_disk_allocate(&fte->pg_id, &tssn, &prev_pg_id);
          if (!b)
            {
              ASSERT (0);
			  lock_release (replaced_page_pagedir_lock);
			  lock_release (&pg_id->t->pagedir_lock);
			  lock_release (&vm_frame_table_lock);
              return NULL;
            }

		  if (prev_pg_id.t != fte->pg_id.t || 
			  prev_pg_id.upage != fte->pg_id.upage)
            {
              if (prev_pg_id.t != NULL)
                {
                  lock_acquire (&prev_pg_id.t->pagedir_lock);

                  spte = pagedir_get_sup_page_table_entry (prev_pg_id.t->pagedir, prev_pg_id.upage);
                  ASSERT (spte != NULL);

                  spte->storage_type = PAGE_STORAGE_NONE;
                  pagedir_set_dirty (prev_pg_id.t->pagedir, prev_pg_id.upage, true);

				  lock_release (&prev_pg_id.t->pagedir_lock);
                }

              spte = pagedir_get_sup_page_table_entry (fte->pg_id.t->pagedir, fte->pg_id.upage);
			  ASSERT (spte != NULL);
			  ASSERT (spte->storage_type != PAGE_STORAGE_SWAP_DISK);

              spte->storage_type = PAGE_STORAGE_SWAP_DISK;
            }
		  else
            ASSERT (pagedir_get_sup_page_table_entry (fte->pg_id.t->pagedir, fte->pg_id.upage)->storage_type == PAGE_STORAGE_SWAP_DISK);

          ssn_to_write = tssn;
          write_required = true;
        }
	  else
        {
          /* Swap-out is not required because it is not modified from the source. */
          /* For now, the page stored in the swap disk is up-to-date. */
          /* Just reallocate it. */
          ASSERT (pagedir_get_sup_page_table_entry (fte->pg_id.t->pagedir, fte->pg_id.upage)->storage_type == PAGE_STORAGE_SWAP_DISK);

          b = swap_disk_allocate(&fte->pg_id, &tssn, &prev_pg_id);

          ASSERT (b && prev_pg_id.t == fte->pg_id.t && prev_pg_id.upage == fte->pg_id.upage);
        }

      /* Clear the present bit of the page table entry of the page that is being replaced. */
      pagedir_clear_page (fte->pg_id.t->pagedir, fte->pg_id.upage);

      /* Set fte as the frame table entry of the requested page. */
      lock_acquire (&fte->change_lock);
      fte->pg_id.t = pg_id->t;
      fte->pg_id.upage = pg_id->upage;
      lock_release (&fte->change_lock);
    }

  /* Swap out/in. */
  lock_acquire (&fte->change_lock);
  lock_release (&vm_frame_table_lock);
  if (write_required)
      swap_disk_store (tssn, kpage);
  lock_release (replaced_page_pagedir_lock);
  swap_disk_load_and_release (pg_id, kpage);
  lock_release (&fte->change_lock);

  /* Set the page table. */
  pagedir_set_dirty (pg_id->t->pagedir, pg_id->upage, false);
  pagedir_set_accessed (pg_id->t->pagedir, pg_id->upage, true);
  pagedir_set_page (pg_id->t->pagedir, pg_id->upage, kpage, pagedir_is_writable (pg_id->t->pagedir, pg_id->upage));

  lock_release (&pg_id->t->pagedir_lock);

  /* Return the kernel address that the requested page is located. */
  return kpage;
}

/* LOGOS-ADDED FUNCTION
   Reaplace a existing user page and return it as a new user page when called by allocators with no more physical memory for user available. 
*/
void *vm_request_new_user_page (void)
{
  /* TODO : Implement here correctly. */
  /* Important : At the end, remove the page that will be returned from the memory frame table. */
  return NULL;
}

/* LOGOS-ADDED FUNCTION
   Try to make the stack grow to cover the page represented by pg_id. 
*/
bool vm_try_stack_growth (const struct page_identifier* pg_id)
{
  /* TODO : Implement here correctly. */
  return false;
}

/* LOGOS-ADDED VARIABLE */
struct vm_frame_table_entry *clock_hand;

/* LOGOS-ADDED FUNCTION
   Select a page in memory to be replaced. 
*/
static struct vm_frame_table_entry *
vm_replacement_policy (const struct page_identifier *pg_id UNUSED)
{
  /* From Dongmin To Team Member : My part has not completed yet, but I think it is possible to implement this function using the data structures I made. 
     The paramter pg_id is the page identifier that represent the page we want to load. pg_id.t is NULL if the page is a new page. 
     Use vm_frame_table for the page frame table. 
	 It is a list of struct vm_frame_table_entry. Each struct vm_frame_table_entry represents a page in memory. 
	 Use pg_id in struct vm_frame_table_entry, (struct vm_frame_table_entry).pg_id.t->pagedir and pagedir_* functions for the accessed bit and the dirty(modified) bit. 
     I think you don't have to consider the mutual exclusion and locking much when you implement this function because I will ensure that this function is called by only one thread at a time. 
	 ( There may be some exceptions such as t->pagedir_lock, but if you want me to add it, i'll do that. Just consider the mutual exclusion and locking related to your own data structure 
	   although I think the additional mutual exclusion and locking is not necessary. )
     I think you have to add some external variables such as a clock hand.
     Implement the clock algorithm and return the pointer of struct vm_frame_table_entry representing the page you want to replace. 
     */

  /* TODO : Modify this function to run the clock algorithm correctly. */
  if (list_empty (&vm_frame_table))
    return NULL;

  if (!clock_hand)
    clock_hand = list_entry (list_head (&vm_frame_table), struct vm_frame_table_entry, elem);

  while (pagedir_is_accessed (clock_hand->pg_id.t->pagedir, clock_hand->pg_id.upage))
    {
      // set use bit 0
      pagedir_set_accessed (clock_hand->pg_id.t->pagedir, clock_hand->pg_id.upage, false);

      // move clock hand to next

      if (list_entry (list_end (&vm_frame_table), struct vm_frame_table_entry, elem) == clock_hand)
        clock_hand = list_entry (list_head (&vm_frame_table), struct vm_frame_table_entry, elem);
      else
        clock_hand = list_entry (list_next (&clock_hand->elem), struct vm_frame_table_entry, elem);
    }

  // found unused page

  // set clock hand next to the page will be replaced
  clock_hand = list_entry (list_next (&clock_hand->elem), struct vm_frame_table_entry, elem);  
  
  return list_entry (list_prev (&clock_hand->elem), struct vm_frame_table_entry, elem);
}
