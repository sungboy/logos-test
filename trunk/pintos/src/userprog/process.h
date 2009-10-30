#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

/* LOGOS-ADDED TYPE */
struct file_table_struct
{
	struct hash_elem elem;
	int fd;
	struct file * file;
};

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

bool process_is_valid_user_virtual_address (const void *uvaddr, size_t size, bool writable);
bool process_is_valid_user_virtual_address_for_string_read (const void *ustr);

bool process_init_file_table(struct thread* t);
struct file_table_struct* process_get_new_file_table_struct(struct thread* t, struct file* f);

#endif /* userprog/process.h */
