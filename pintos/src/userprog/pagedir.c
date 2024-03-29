#include "userprog/pagedir.h"
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "threads/init.h"
#include "threads/pte.h"
#include "threads/palloc.h"
#include "threads/malloc.h"

static uint32_t *active_pd (void);
static void invalidate_pagedir (pagedir_t);

/* Creates a new page directory that has mappings for kernel
   virtual addresses, but none for user virtual addresses.
   Returns the new page directory, or a null pointer if memory
   allocation fails. */
pagedir_t
pagedir_create (void) 
{
#ifdef VM
  pagedir_t epd;
#endif
  uint32_t *pd = palloc_get_page (0);
  if (pd == NULL)
    return NULL;
  memcpy (pd, base_page_dir, PGSIZE);

#ifdef VM
  epd = (pagedir_t)malloc (sizeof (struct pagedir));
  if (epd == NULL)
    {
      palloc_free_page (pd);
	  return NULL;
    }
  epd->pd = pd;
  if (!vm_init_sup_page_table (&epd->spd))
    {
      palloc_free_page (pd);
	  free (epd);
	  return NULL;
    }

  return epd;
#else
  return pd;
#endif
}

/* Destroys page directory EPD, freeing all the pages it
   references. */
void
pagedir_destroy (pagedir_t epd) 
{
  uint32_t *pde;
  uint32_t *pd;
#ifdef VM
  if (epd == NULL)
    return;

  ASSERT (epd->pd != NULL);

  pd = epd->pd;
#else
  pd = epd;
#endif

  if (pd != NULL)
  {
    ASSERT (pd != base_page_dir);
    for (pde = pd; pde < pd + pd_no (PHYS_BASE); pde++)
      if (*pde & PTE_P) 
        {
          uint32_t *pt = pde_get_pt (*pde);
          uint32_t *pte;
        
          for (pte = pt; pte < pt + PGSIZE / sizeof *pte; pte++)
            if (*pte & PTE_P) 
              palloc_free_page (pte_get_page (*pte));
          palloc_free_page (pt);
        }
    palloc_free_page (pd);
  }
#ifdef VM
  vm_destroy_sup_page_table (&epd->spd);
  free (epd);
#endif
}

/* Returns the address of the page table entry for virtual
   address VADDR in page directory PD.
   If PD does not have a page table for VADDR, behavior depends
   on CREATE.  If CREATE is true, then a new page table is
   created and a pointer into it is returned.  Otherwise, a null
   pointer is returned. */
static uint32_t *
lookup_page (uint32_t *pd, const void *vaddr, bool create)
{
  uint32_t *pt, *pde;

  ASSERT (pd != NULL);

  /* Shouldn't create new kernel virtual mappings. */
  ASSERT (!create || is_user_vaddr (vaddr));

  /* Check for a page table for VADDR.
     If one is missing, create one if requested. */
  pde = pd + pd_no (vaddr);
  if (*pde == 0) 
    {
      if (create)
        {
          pt = palloc_get_page (PAL_ZERO);
          if (pt == NULL) 
            return NULL; 
      
          *pde = pde_create (pt);
        }
      else
        return NULL;
    }

  /* Return the page table entry. */
  pt = pde_get_pt (*pde);
  return &pt[pt_no (vaddr)];
}

/* Adds a mapping in page directory EPD from user virtual page
   UPAGE to the physical frame identified by kernel virtual
   address KPAGE.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   If WRITABLE is true, the new page is read/write;
   otherwise it is read-only.
   Returns true if successful, false if memory allocation
   failed. */
bool
pagedir_set_page (pagedir_t epd, void *upage, void *kpage, bool writable)
{
  uint32_t *pte;
  uint32_t *pd;
#ifdef VM
  ASSERT (epd != NULL);

  pd = epd->pd;
#else
  pd = epd;
#endif

  ASSERT (pg_ofs (upage) == 0);
  ASSERT (pg_ofs (kpage) == 0);
  ASSERT (is_user_vaddr (upage));
  ASSERT (vtop (kpage) >> PTSHIFT < ram_pages);
  ASSERT (pd != base_page_dir);

  pte = lookup_page (pd, upage, true);

  if (pte != NULL) 
    {
      ASSERT ((*pte & PTE_P) == 0);
      *pte = pte_create_user (kpage, writable);
#ifdef VM
      if (vm_get_new_sup_page_table_entry (&epd->spd, upage) == NULL)
        {
          *pte &= ~PTE_P;
          return false;
        }
#endif
      return true;
    }
  else
    return false;
}

/* Looks up the physical address that corresponds to user virtual
   address UADDR in EPD.  Returns the kernel virtual address
   corresponding to that physical address, or a null pointer if
   UADDR is unmapped. */
void *
pagedir_get_page (pagedir_t epd, const void *uaddr) 
{
  uint32_t *pte;
  uint32_t *pd;
#ifdef VM
  ASSERT (epd != NULL);

  pd = epd->pd;
#else
  pd = epd;
#endif

  ASSERT (is_user_vaddr (uaddr));
  
  pte = lookup_page (pd, uaddr, false);
  if (pte != NULL && (*pte & PTE_P) != 0)
    return pte_get_page (*pte) + pg_ofs (uaddr);
  else
    return NULL;
}

#ifdef VM
/* LOGOS-ADDED FUNCTION
   Looks up the supplemental page table entry that corresponds to user virtual
   address UADDR in EPD.  Returns the pointer of struct vm_sup_page_table_entry
   corresponding to that physical address, or a null pointer if
   UADDR is unmapped. */
struct vm_sup_page_table_entry *
pagedir_get_sup_page_table_entry (pagedir_t epd, const void *uaddr)
{
  uint32_t *pte;
  uint32_t *pd;
  struct vm_sup_page_table_entry* ret;
  ASSERT (epd != NULL);
  ASSERT (is_user_vaddr (uaddr));

  pd = epd->pd;
  
  pte = lookup_page (pd, uaddr, false);
  if (pte != NULL)
  {
     ret = vm_get_sup_page_table_entry (&epd->spd, (void*)uaddr);
     if (ret)
	   return ret;
  }

  return NULL;
}
#endif

/* Marks user virtual page UPAGE "not present" in page
   directory EPD.  Later accesses to the page will fault.  Other
   bits in the page table entry are preserved.
   UPAGE need not be mapped. */
void
pagedir_clear_page (pagedir_t epd, void *upage) 
{
  uint32_t *pte;
  uint32_t *pd;
#ifdef VM
  ASSERT (epd != NULL);

  pd = epd->pd;
#else
  pd = epd;
#endif

  ASSERT (pg_ofs (upage) == 0);
  ASSERT (is_user_vaddr (upage));

  pte = lookup_page (pd, upage, false);
  if (pte != NULL && (*pte & PTE_P) != 0)
    {
      *pte &= ~PTE_P;
      invalidate_pagedir (epd);
    }
}

/* Returns true if the PTE for virtual page VPAGE in EPD is dirty,
   that is, if the page has been modified since the PTE was
   installed.
   Returns false if EPD contains no PTE for VPAGE. */
bool
pagedir_is_dirty (pagedir_t epd, const void *vpage) 
{
  uint32_t *pte;
  uint32_t *pd;
#ifdef VM
  ASSERT (epd != NULL);

  pd = epd->pd;
#else
  pd = epd;
#endif

  pte = lookup_page (pd, vpage, false);
  return pte != NULL && (*pte & PTE_D) != 0;
}

/* Set the dirty bit to DIRTY in the PTE for virtual page VPAGE
   in EPD. */
void
pagedir_set_dirty (pagedir_t epd, const void *vpage, bool dirty) 
{
  uint32_t *pte;
  uint32_t *pd;
#ifdef VM
  ASSERT (epd != NULL);

  pd = epd->pd;
#else
  pd = epd;
#endif

  pte = lookup_page (pd, vpage, false);
  if (pte != NULL) 
    {
      if (dirty)
        *pte |= PTE_D;
      else 
        {
          *pte &= ~(uint32_t) PTE_D;
          invalidate_pagedir (epd);
        }
    }
}

/* Returns true if the PTE for virtual page VPAGE in PD has been
   accessed recently, that is, between the time the PTE was
   installed and the last time it was cleared.  Returns false if
   PD contains no PTE for VPAGE. */
bool
pagedir_is_accessed (pagedir_t epd, const void *vpage) 
{
  uint32_t *pte;
  uint32_t *pd;
#ifdef VM
  ASSERT (epd != NULL);

  pd = epd->pd;
#else
  pd = epd;
#endif

  pte = lookup_page (pd, vpage, false);
  return pte != NULL && (*pte & PTE_A) != 0;
}

/* Sets the accessed bit to ACCESSED in the PTE for virtual page
   VPAGE in PD. */
void
pagedir_set_accessed (pagedir_t epd, const void *vpage, bool accessed) 
{
  uint32_t *pte;
  uint32_t *pd;
#ifdef VM
  ASSERT (epd != NULL);

  pd = epd->pd;
#else
  pd = epd;
#endif

  pte = lookup_page (pd, vpage, false);
  if (pte != NULL) 
    {
      if (accessed)
        *pte |= PTE_A;
      else 
        {
          *pte &= ~(uint32_t) PTE_A; 
          invalidate_pagedir (epd);
        }
    }
}

/* Loads page directory PD into the CPU's page directory base
   register. */
void
pagedir_activate (pagedir_t epd) 
{
  uint32_t *pd;
#ifdef VM
  if(epd == NULL)
    pd = NULL;
  else
    pd = epd->pd;
#else
  pd = epd;
#endif

  if (pd == NULL)
    pd = base_page_dir;

  /* Store the physical address of the page directory into CR3
     aka PDBR (page directory base register).  This activates our
     new page tables immediately.  See [IA32-v2a] "MOV--Move
     to/from Control Registers" and [IA32-v3a] 3.7.5 "Base
     Address of the Page Directory". */
  asm volatile ("movl %0, %%cr3" : : "r" (vtop (pd)) : "memory");
}

/* Returns the currently active page directory. */
static uint32_t *
active_pd (void) 
{
  /* Copy CR3, the page directory base register (PDBR), into
     `pd'.
     See [IA32-v2a] "MOV--Move to/from Control Registers" and
     [IA32-v3a] 3.7.5 "Base Address of the Page Directory". */
  uintptr_t pd;
  asm volatile ("movl %%cr3, %0" : "=r" (pd));
  return ptov (pd);
}

/* Seom page table changes can cause the CPU's translation
   lookaside buffer (TLB) to become out-of-sync with the page
   table.  When this happens, we have to "invalidate" the TLB by
   re-activating it.

   This function invalidates the TLB if PD is the active page
   directory.  (If PD is not active then its entries are not in
   the TLB, so there is no need to invalidate anything.) */
static void
invalidate_pagedir (pagedir_t epd) 
{
  uint32_t *pd;
#ifdef VM
  ASSERT (epd != NULL);

  pd = epd->pd;
#else
  pd = epd;
#endif

  if (active_pd () == pd) 
    {
      /* Re-activating PD clears the TLB.  See [IA32-v3a] 3.12
         "Translation Lookaside Buffers (TLBs)". */
      pagedir_activate (epd);
    } 
}

/* LOGOS-ADDED FUNCTION
   Looks up the page and check whether the page is readable. */
bool
pagedir_is_readable (pagedir_t epd, const void *uaddr)
{
  return pagedir_exist (epd, uaddr);
}

/* LOGOS-ADDED FUNCTION
   Looks up the page and check whether the page exists. */
bool
pagedir_exist (pagedir_t epd, const void *uaddr)
{
  uint32_t *pte;
  uint32_t *pd;
#ifdef VM
  struct vm_sup_page_table_entry *spte;

  ASSERT (epd != NULL);

  pd = epd->pd;
#else
  pd = epd;
#endif

  ASSERT (is_user_vaddr (uaddr));
  
  pte = lookup_page (pd, uaddr, false);
  if (pte != NULL)
    {
      if ((*pte & PTE_P) != 0)
        return true;

#ifdef VM
      spte = pagedir_get_sup_page_table_entry (epd, uaddr);

      if (spte)
        if (spte->storage_type != PAGE_STORAGE_NONE)
	      return true;
#endif
    }

  return false;
}

/* LOGOS-ADDED FUNCTION
   Looks up the page and check whether the page is writable. */
bool
pagedir_is_writable (pagedir_t epd, const void *uaddr)
{
  uint32_t *pte;
  uint32_t *pd;
#ifdef VM
  struct vm_sup_page_table_entry *spte;

  ASSERT (epd != NULL);

  pd = epd->pd;
#else
  pd = epd;
#endif

  ASSERT (is_user_vaddr (uaddr));
  
  pte = lookup_page (pd, uaddr, false);
  if (pte != NULL)
    if ((*pte & PTE_W) != 0)
      {
        if ((*pte & PTE_P) != 0)
          return true;

#ifdef VM
        spte = pagedir_get_sup_page_table_entry (epd, uaddr);

        ASSERT (spte != NULL);

        if (spte->storage_type != PAGE_STORAGE_NONE)
          return true;
#endif
      }

  return false;
}
