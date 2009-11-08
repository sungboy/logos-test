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
void process_exit (int status);
void process_activate (void);

bool process_is_valid_user_virtual_address (const void *uvaddr, size_t size, bool writable);
bool process_is_valid_user_virtual_address_for_string_read (const void *ustr);

bool process_init_file_table(struct thread* t);
void process_destroy_file_table(struct thread* t);

int process_open_file(struct thread* t, const char* file_name);
int process_read_file(struct thread* t, int fd, void *buffer, unsigned size);
int process_write_file(struct thread* t, int fd, const void *buffer, unsigned size);
bool process_close_file(struct thread* t, int fd);

int process_get_filesize(struct thread* t, int fd);
void process_seek_file(struct thread* t, int fd, unsigned position);
unsigned process_tell_file(struct thread* t, int fd);

#endif /* userprog/process.h */
