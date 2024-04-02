#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "threads/init.h"
#include "threads/palloc.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "userprog/exception.h"
#include "userprog/process.h"
#include "threads/synch.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
struct file_descriptor *find_file_descriptor(int fd);

void halt ();
void exit (int status);
int read (int fd, void *buffer, unsigned size);
int write (int fd, void *buffer, unsigned length);
bool create (const char *file, unsigned initial_size);
int open (const char *file);
void close (int fd);
int filesize (int fd);
pid_t fork (const char *thread_name, struct intr_frame *if_);
int wait (pid_t pid);
int exec (const char *cmd_line);
void seek (int fd, unsigned position);
unsigned tell (int fd);
bool remove(const char *file);
void *mmap(void *addr, size_t length, int writable, int fd, off_t offseet);
void munmap(void *addr);

/* Reads a byte at user virtual address UADDR.
 * UADDR must be below KERN_BASE.
 * Returns the byte value if successful, -1 if a segfault
 * occurred. */
static int64_t
get_user (const uint8_t *uaddr) {
    int64_t result;
    __asm __volatile (
    "movabsq $done_get, %0\n"
    "movzbq %1, %0\n"
    "done_get:\n"
    : "=&a" (result) : "m" (*uaddr));
    return result;
}

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

struct lock file_lock;

void
syscall_init (void) {
	lock_init(&file_lock);

	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	int syscall_num = f->R.rax;
	#ifdef VM
    	thread_current()->rsp = f->rsp; // 추가
	#endif
	switch (syscall_num) {
		case SYS_HALT:
			halt();
			break;
		case SYS_EXIT: 
			exit(f->R.rdi);
			break;
		case SYS_FORK:
			f->R.rax = fork(f->R.rdi, f);
			break;
		case SYS_EXEC:
			f->R.rax = exec(f->R.rdi);
			break;
		case SYS_WAIT:
			f->R.rax = wait(f->R.rdi);
			break;
		case SYS_CREATE:
			f->R.rax = create(f->R.rdi, f->R.rsi);
			break;
		case SYS_REMOVE:
			f->R.rax = remove(f->R.rdi);
			break;
		case SYS_OPEN:
			if (get_user(f->R.rdi) == -1)
				exit(-1);
			f->R.rax = open(f->R.rdi);
			break;
		case SYS_FILESIZE:
			f->R.rax = filesize(f->R.rdi);
			break;
		case SYS_READ:
			f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_WRITE:
			f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_SEEK:
			seek(f->R.rdi, f->R.rsi);
			break;
		case SYS_TELL:
			f->R.rax = tell(f->R.rdi);
			break;
		case SYS_CLOSE:
			close(f->R.rdi);
			break;
		case SYS_MMAP:
			f->R.rax = mmap(f->R.rdi, f->R.rsi, f->R.rdx, f->R.r10, f->R.r8);
			break;
		case SYS_MUNMAP:
        	munmap(f->R.rdi);
        	break;
		default:
			break;
	}
}
void munmap(void *addr)
{
    do_munmap(addr);
}

void *mmap(void *addr, size_t length, int writable, int fd, off_t offset){
	if (!addr || addr != pg_round_down(addr))
        return NULL;

    if (offset != pg_round_down(offset))
        return NULL;

    if (!is_user_vaddr(addr) || !is_user_vaddr(addr + length))
        return NULL;

    if (spt_find_page(&thread_current()->spt, addr))
        return NULL;

    struct file *f = find_file_descriptor(fd)->file_p;
    if (f == NULL)
        return NULL;

    if (file_length(f) == 0 || (int)length <= 0)
        return NULL;

    return do_mmap(addr, length, writable, f, offset); // 파일이 매핑된 가상 주소 반환
}

struct file_descriptor *find_file_descriptor(int fd) {
	struct file_descriptor **fd_list = thread_current()->fd_list;
	ASSERT(fd_list != NULL);
	ASSERT(fd > 1);
	return fd_list[fd];
}

void remove_file_descriptor(int fd) {
	struct file_descriptor **fd_list = thread_current()->fd_list;
	if (fd_list[fd] == NULL)
		return;
	file_close(fd_list[fd]->file_p);
	free(fd_list[fd]);
	fd_list[fd] = NULL;
}

void halt() {
	power_off();
}

void exit(int status) {
	// 쓰레드 이름이 명령줄 인자값을 그대로 받아와서 만들어짐. (init.c에 247번 줄 참조)
	char *thread_name = thread_current() -> name;
	char *temp = '\0';
	strtok_r (thread_name, " ", &temp);
	thread_current()->exit_status = status;
	printf("%s: exit(%d)\n", thread_name, status);
	thread_exit();
}
 
int read (int fd, void *buffer, unsigned size) {

	if(fd <0){
		return -1;
	}
	int byte = 0;
	if (fd == 0) {
		char *_buffer = buffer;
		while (byte < size) {
			_buffer[byte++] = input_getc();
		}
	}
	else if (fd == 1){
		return -1;
	}
	else { // 표준 입출력이 아닐 때
		lock_acquire(&file_lock);
		struct file_descriptor *file_desc = find_file_descriptor(fd);
		if (file_desc == NULL) return -1;
		byte = file_read(file_desc->file_p, buffer, size);
		lock_release(&file_lock);
	}
	return byte;
}

int write(int fd, void *buffer, unsigned length) {
	if(fd <0)
		exit(-1);

	int byte = 0;
	if (fd == 0) {
		return -1;
	} else if (fd == 1) {
		putbuf(buffer, length);
		byte = length;
	} else { //표준 입출력이 아닐 때
		lock_acquire(&file_lock);
		struct file_descriptor *file_desc = find_file_descriptor(fd);
		if (file_desc == NULL) return -1;
		byte = file_write(file_desc->file_p, buffer, length);
		lock_release(&file_lock);
	}
	return byte;
}

bool create (const char *file, unsigned initial_size) {
	if(*file == '\0')
		exit(-1);
	bool result = filesys_create(file, initial_size);
	return result;
}

int open (const char *file) {
	lock_acquire(&file_lock);
	struct file *opened_file;// = (struct file *)malloc(sizeof(struct file));
	opened_file = filesys_open(file);
	int fd = -1;
	if (opened_file != NULL) {
	 	fd = allocate_fd(opened_file, thread_current()->fd_list);
	}
	lock_release(&file_lock);
	return fd;
}

void close (int fd) {
	if (fd <= 1) return;
	remove_file_descriptor(fd);
}

int filesize (int fd) {
	struct file_descriptor *file_desc = find_file_descriptor(fd);
	if (file_desc == NULL) return -1;
	return file_length(file_desc->file_p);
}

pid_t fork (const char *thread_name, struct intr_frame *if_) {
	return process_fork(thread_name, if_);
}

int wait (pid_t pid) {
	return process_wait(pid);
}

int exec (const char *cmd_line) {
	int size = strlen(cmd_line) + 1;
	char *fn_copy = palloc_get_page(0);
	if ((fn_copy) == NULL) {
		exit(-1);
	}
	strlcpy(fn_copy, cmd_line, size);
	if (process_exec(fn_copy) == -1) {
		exit(-1);
	}
}
void seek (int fd, unsigned position) {
	if (fd < 2 || position < 0)
		exit(-1);
	struct file *opened_file = find_file_descriptor(fd)->file_p;
	file_seek(opened_file, position);
}

unsigned tell (int fd) {
	if (fd < 2)
		exit(-1);
	struct file *opened_file = find_file_descriptor(fd)->file_p;
	return file_tell(opened_file);
}

bool remove(const char *file) {
	lock_acquire(&file_lock);
	bool result = filesys_remove(file);
	lock_release(&file_lock);
    return result;
}