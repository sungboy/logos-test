#ifndef USERPROG_PAGEDIR_H
#define USERPROG_PAGEDIR_H

#include <stdbool.h>
#include <stdint.h>
#ifdef VM
#include "vm/vm-sup-page-table.h"
#endif

#ifdef VM
struct pagedir
{
  uint32_t * pd;
  struct hash spd;
};
typedef struct pagedir *pagedir_t;
#else
typedef uint32_t *pagedir_t;
#endif

pagedir_t pagedir_create (void);
void pagedir_destroy (pagedir_t epd);
bool pagedir_set_page (pagedir_t epd, void *upage, void *kpage, bool rw);
void *pagedir_get_page (pagedir_t epd, const void *uaddr);

#ifdef VM
struct vm_sup_page_table_entry *pagedir_get_sup_page_table_entry (pagedir_t epd, const void *uaddr);
#endif

void pagedir_clear_page (pagedir_t epd, void *upage);
bool pagedir_is_dirty (pagedir_t epd, const void *upage);
void pagedir_set_dirty (pagedir_t epd, const void *upage, bool dirty);
bool pagedir_is_accessed (pagedir_t epd, const void *upage);
void pagedir_set_accessed (pagedir_t epd, const void *upage, bool accessed);
void pagedir_activate (pagedir_t epd);

bool pagedir_exist (pagedir_t epd, const void *uaddr);
bool pagedir_is_readable (pagedir_t epd, const void *uaddr);
bool pagedir_is_writable (pagedir_t epd, const void *uaddr);

#endif /* userprog/pagedir.h */
