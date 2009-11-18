#include "vm/vm.h"
#include "vm/vm-sup-page-table.h"
#include "vm/vm-frame-table.h"
#include "vm/swap-disk.h"
#include <string.h>
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "devices/disk.h"

static swap_slot_num_t swap_get_swap_slot (const struct page_identifier *pg_id);

/* LOGOS-ADDED ENUMERATION */
enum swap_slot_state
{
  SWAP_SLOT_NO_DATA, 
  SWAP_SLOT_ALLOCATED, 
  SWAP_SLOT_RELEASED_DATA, 
};
/* LOGOS-ADDED TYPE */
struct swap_slot
{
  enum swap_slot_state state;
  struct page_identifier pg_id;
};

static struct lock swap_disk_lock;             /* LOGOS-ADDED VARIABLES. The swap disk lock used all swap functions. */
static struct disk * swap_disk = NULL;         /* LOGOS-ADDED VARIABLES. the struct disk of the swap disk. */
static swap_slot_num_t swap_pg_cnt = 0;        /* LOGOS-ADDED VARIABLES. The number of pages the swap disk can store. */
static struct swap_slot *swap_table = NULL;    /* LOGOS-ADDED VARIABLES. The swap table. An array of (struct swap_slot)s. */
static swap_slot_num_t swap_next_slot = 0;     /* LOGOS-ADDED VARIABLES. The next slot to start finding free slot. */

/* LOGOS-ADDED FUNCTION */
bool swap_disk_init (void)
{
  swap_slot_num_t tssn;
  lock_init (&swap_disk_lock);

  swap_disk = disk_get (1, 1);
  if (swap_disk == NULL)
    return false;

  ASSERT (PGSIZE >= DISK_SECTOR_SIZE && PGSIZE % DISK_SECTOR_SIZE == 0);
  swap_pg_cnt = disk_size (swap_disk) * DISK_SECTOR_SIZE / PGSIZE;

  swap_table = (struct swap_slot *)malloc (sizeof (struct swap_slot)*swap_pg_cnt);
  if (swap_table == NULL)
    return false;

  for (tssn=0; tssn < swap_pg_cnt; tssn++)
    swap_table[tssn].state = SWAP_SLOT_NO_DATA;

  swap_next_slot = 0;

  return true;
}

/* LOGOS-ADDED FUNCTION 
   Before using this function, acuqire swap_disk_lock first.
*/
static swap_slot_num_t
swap_get_swap_slot (const struct page_identifier *pg_id)
{
  swap_slot_num_t tssn;

  ASSERT (pg_id != NULL);
  ASSERT (swap_table != NULL);

  for (tssn=0; tssn < swap_pg_cnt; tssn++)
    if (swap_table[tssn].state != SWAP_SLOT_NO_DATA)
      if (swap_table[tssn].pg_id.t == pg_id->t && swap_table[tssn].pg_id.upage == pg_id->upage)
        return tssn;

  return swap_pg_cnt;
}

/* LOGOS-ADDED FUNCTION */
bool
swap_disk_allocate (const struct page_identifier *pg_id, swap_slot_num_t* ssn, struct page_identifier *prev_pg_id)
{
  swap_slot_num_t tssn;
  bool first;

  ASSERT (pg_id != NULL && ssn != NULL && prev_pg_id !=NULL);
  ASSERT (pg_id->t != NULL);

  lock_acquire (&swap_disk_lock);

  ASSERT (swap_table!= NULL && swap_next_slot < swap_pg_cnt);

  /* Check the swap disk is something like an empty disk. */
  if (swap_pg_cnt == 0)
    {
      lock_release (&swap_disk_lock);
      return false;
    }

  /* Find and return the slot used for this page before if it exists. */
  tssn = swap_get_swap_slot (pg_id);
  if(tssn != swap_pg_cnt)
    {
      ASSERT (swap_table[tssn].state != SWAP_SLOT_ALLOCATED && swap_table[tssn].pg_id.t == pg_id->t && swap_table[tssn].pg_id.upage == pg_id->upage);
      swap_table[tssn].state = SWAP_SLOT_ALLOCATED;
	  *ssn = tssn;
      memcpy (prev_pg_id, &swap_table[tssn].pg_id, sizeof (*prev_pg_id));

      lock_release (&swap_disk_lock);
      return true;
    }

  /* Find a free slot and return it. */
  tssn = swap_next_slot;
  first = true;
  while (1)
    {
      if (!first && tssn == swap_next_slot)
        {
          lock_release (&swap_disk_lock);
		  return false;
        }

	  if (swap_table[tssn].state != SWAP_SLOT_ALLOCATED)
        {
          swap_next_slot = (tssn + 1) % swap_pg_cnt;
          break;
        }

      first = false;
	  tssn = (tssn + 1) % swap_pg_cnt;
    }

  if (swap_table[tssn].state == SWAP_SLOT_NO_DATA)
    {
      prev_pg_id->t = NULL;
      prev_pg_id->upage = NULL;
    }
  else
    memcpy (prev_pg_id, &swap_table[tssn].pg_id, sizeof (*prev_pg_id));
  swap_table[tssn].state = SWAP_SLOT_ALLOCATED;
  memcpy (&swap_table[tssn].pg_id, pg_id, sizeof (swap_table[tssn].pg_id));
  *ssn = tssn;

  lock_release (&swap_disk_lock);

  return true;
}

/* LOGOS-ADDED FUNCTION */
void
swap_disk_store (swap_slot_num_t ssn, void* kpage)
{
  disk_sector_t dsn;

  ASSERT (kpage != NULL && is_kernel_vaddr(kpage) && pg_ofs(kpage)==0);

  lock_acquire (&swap_disk_lock);

  ASSERT (ssn < swap_pg_cnt);
  ASSERT (swap_disk != NULL && swap_table != NULL);
  ASSERT (swap_table[ssn].state == SWAP_SLOT_ALLOCATED);

  for (dsn = 0; dsn < PGSIZE / DISK_SECTOR_SIZE; dsn++)
    disk_write (swap_disk, ssn * PGSIZE / DISK_SECTOR_SIZE + dsn, kpage + dsn * DISK_SECTOR_SIZE);

  lock_release (&swap_disk_lock);
}

/* LOGOS-ADDED FUNCTION */
void
swap_disk_load (const struct page_identifier *pg_id, void* kpage)
{
  swap_slot_num_t ssn;
  disk_sector_t dsn;

  ASSERT (pg_id != NULL && is_kernel_vaddr(kpage) && pg_ofs(kpage)==0);

  lock_acquire (&swap_disk_lock);

  ASSERT (swap_disk != NULL && swap_table != NULL);

  ssn = swap_get_swap_slot (pg_id);

  ASSERT (ssn < swap_pg_cnt);
  ASSERT (swap_table[ssn].state == SWAP_SLOT_ALLOCATED);

  for (dsn = 0; dsn < PGSIZE / DISK_SECTOR_SIZE; dsn++)
    disk_read (swap_disk, ssn * PGSIZE / DISK_SECTOR_SIZE + dsn, kpage + dsn * DISK_SECTOR_SIZE);

  swap_table[ssn].state = SWAP_SLOT_RELEASED_DATA;

  lock_release (&swap_disk_lock);
}

/* LOGOS-ADDED FUNCTION */
void
swap_disk_release_thread (struct thread *t)
{
  swap_slot_num_t tssn;

  ASSERT (t != NULL);

  lock_acquire (&swap_disk_lock);

  ASSERT (swap_table != NULL);

  for (tssn=0; tssn < swap_pg_cnt; tssn++)
    if (swap_table[tssn].state != SWAP_SLOT_NO_DATA)
      if (swap_table[tssn].pg_id.t == t)
        swap_table[tssn].state = SWAP_SLOT_NO_DATA;

  lock_release (&swap_disk_lock);
}
