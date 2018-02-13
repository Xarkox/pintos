#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "filesys/filesys.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) {
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void halt() {
  power_off();
}

static bool create(const char *file, unsigned initial_size) {

  int i = 0;
  while(i < 126) {
    if (file_descriptor[i] == 0) {
      if (filesys_create(file, initial_size)) {
        files[i - 2] = file;
        return i;
      }
    }
    ++i;
  }
  return -1;
}

static int open(const char *name) {
  struct file* file = filesys_open(name); 
  int fd = get_fd(file);
  set_open(fd, 1);
  return fd;
}

static void close(int fd) {
  set_open(fd, 0);
}

static int read(int fd, void *buffer, unsigned size) {
  if (fd = 0) {
    return input_getc();
  }
  else {
    int bytes = file_read(get_file(fd), buffer, size);
    if (bytes > 0)
      return bytes;
    return -1;
  }
}

static int write(int fd, void *buffer, unsigned size) {
  char* fakebuf = "Hello World!\n";
  printf("----------\n");
  printf("File Descriptor: %d\n", fd);
  printf("Buffer: %s\n", buffer);
  printf("Size: %d\n", size);
  printf("----------\n");
  int bytes = 0;
  if (fd >= 2) {
    bytes = file_write(get_file(fd), buffer, size); // ERROR HERE
  } 
  else if (fd == 1) {
    while (size != 0) {
      putbuf(buffer, (size < 200) ? size : 200);
      buffer += (size < 200) ? size : 200;
      size -= (size < 200) ? size : 200;
    }
  }
  if (bytes > 0)
    return bytes;
  return -1;

}

void exit(int status) {
  process_exit();
  return status;
}

static void syscall_handler (struct intr_frame *f) {

  uint32_t *ptr = (uint32_t*) f->esp;
  switch(*ptr) {
    case SYS_HALT:
      halt();
      break;
    case SYS_CREATE: 
      create(ptr + 1, *(ptr + 2));
      break;
    case SYS_OPEN:
      open(ptr + 1);
      break;
    case SYS_CLOSE:
      close(*(ptr + 1));
      break;
    case SYS_READ:
      read(ptr + sizeof(uint32_t), *(ptr + sizeof(int)), ptr + sizeof(void*)); // Arbetar här
      break;
    case SYS_WRITE:
      write(*(ptr + 1), *(ptr + 2), *(ptr + 3));
      break;
    case SYS_EXIT:
      exit(*ptr + 1);
      break;
    default: 
      return 0;
  }
  thread_exit ();
}









