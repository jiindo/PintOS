#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

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
	// TODO: Your implementation goes here.
	/**
	 * TODO
	 * 1. 시스템 콜 번호를 받아온다.
	 * 2. 각 번호에 맞게 분기한다.
	 * 3. 각 시스템 콜에 맞는 코드를 작성한다.
	 */
	// SYS_HALT,                   /* Halt the operating system. */
	// SYS_EXIT,                   /* Terminate this process. */
	// SYS_FORK,                   /* Clone current process. */
	// SYS_EXEC,                   /* Switch current process. */
	// SYS_WAIT,                   /* Wait for a child process to die. */
	// SYS_CREATE,                 /* Create a file. */
	// SYS_REMOVE,                 /* Delete a file. */
	// SYS_OPEN,                   /* Open a file. */
	// SYS_FILESIZE,               /* Obtain a file's size. */
	// SYS_READ,                   /* Read from a file. */
	// SYS_WRITE,                  /* Write to a file. */
	// SYS_SEEK,                   /* Change position in a file. */
	// SYS_TELL,                   /* Report current position in a file. */
	// SYS_CLOSE,                  /* Close a file. */
	int syscall_num = f->R.rax;
	switch (syscall_num) {
		case SYS_HALT:
			/* code */
			break;
		case SYS_EXIT:
			/* code */
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
			/* code */
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
			/* code */
			break;
		case SYS_WRITE:
			/* code */
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