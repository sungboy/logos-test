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
#include "userprog/pagedir.h"
#include "threads/synch.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include <kernel/list.h>
#include <kernel/hash.h>

static void vm_set_all_thread_pages_nonpageable (struct thread* t);
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
  vm_set_all_thread_pages_nonpageable (t);
  swap_disk_release_thread (t);
}

/* LOGOS-ADDED FUNCTION
   Set a user virtual page pagable. */
bool
vm_set_page_pageable (struct thread* t, void *upage)
{
  // Add a struct vm_frame_table_entry to vm_frame_table;
  struct vm_frame_table_entry* fte = (struct vm_frame_table_entry*)malloc (sizeof (struct vm_frame_table_entry));
  if (fte == NULL)
	  return false;

  fte->pg_id.t = t;
  fte->pg_id.upage = upage;
  lock_init (&fte->change_lock);

  lock_acquire (&vm_frame_table_lock);
  list_push_back (&vm_frame_table, &fte->elem); 
  lock_release (&vm_frame_table_lock);

  return true;
}

/* LOGOS-ADDED FUNCTION
   Set all pages of a thread nonpageable. */
static void
vm_set_all_thread_pages_nonpageable (struct thread* t)
{
  struct list_elem *e, *next;

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
*/
void *vm_request_user_page (const struct page_identifier* pg_id)
{
  /* TODO : Implement here correctly. */
  /* Important : Check pg_id is correct. */
  return NULL;
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

/* LOGOS-ADDED FUNCTION
   Select a page in memory to be replaced. 
*/
static struct vm_frame_table_entry *
vm_replacement_policy (const struct page_identifier *pg_id)
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

  return list_entry (list_begin (&vm_frame_table), struct vm_frame_table_entry, elem);
}
