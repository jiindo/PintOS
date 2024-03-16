#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "threads/init.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "include/filesys/filesys.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
void halt();
void exit(int status);
int read (int fd, void *buffer, unsigned size);
int write(int fd, void *buffer, unsigned length);
bool create (const char *file, unsigned initial_size);

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

void
syscall_init (void) {
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
	/**
	 * TODO
	 * 1. 시스템 콜 번호를 받아온다.
	 * 2. 각 번호에 맞게 분기한다.
	 * 3. 각 시스템 콜에 맞는 코드를 작성한다.
	 */
	int syscall_num = f->R.rax;
	switch (syscall_num) {
		case SYS_HALT:
			halt();
			break;
		case SYS_EXIT: 
			exit(f->R.rdi);
			break;
		case SYS_FORK:
			/* code */
			break;
		case SYS_EXEC:
			/* code */
			break;
		case SYS_WAIT:
			/* code */
			break;
		case SYS_CREATE:
			f->R.rax = create(f->R.rdi, f->R.rsi);
			filesys_done();
			//exit(0);
			break;
		case SYS_REMOVE:
			/* code */
			break;
		case SYS_OPEN:
			/* code */
			break;
		case SYS_FILESIZE:
			/* code */
			break;
		case SYS_READ:
			f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_WRITE:
			f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_SEEK:
			/* code */
			break;
		case SYS_TELL:
			/* code */
			break;
		case SYS_CLOSE:
			/* code */
			break;
		default:
			break;
	}
}

void halt() {
	power_off();
}

void exit(int status) {
	// 쓰레드 이름이 명령줄 인자값을 그대로 받아와서 만들어짐. (init.c에 247번 줄 참조)
	char *thread_name = thread_current() -> name;
	char *temp = '\0';
	strtok_r (thread_name, " ", &temp);
	printf("%s: exit(%d)\n", thread_name, status);
	thread_exit();
}
 
int read (int fd, void *buffer, unsigned size) {
	int byte = 0;
	if (fd == 0) {
		char *_buffer = buffer;
		while (byte < size) {
			_buffer[byte++] = input_getc();
		}
	}
	else if (fd == 1)
		return -1;
	else {
		// 표준 입출력이 아닐 때
	}
	return byte;
}

int write(int fd, void *buffer, unsigned length) {
	int byte = 0;
	if (fd == 0) {
		return -1;
	} else if (fd == 1) {
		putbuf(buffer, length);
		byte = length;
	} else {
		// TODO: 표준 입출력이 아닐 때
	}
	return byte; // 실제 파일을 읽기 전까지, 임시로 입력받은 길이 값 반환
}

bool create (const char *file, unsigned initial_size) {
	if(file==NULL || !is_user_vaddr(file)) 
		exit(-1);

	return filesys_create(file, initial_size);
}