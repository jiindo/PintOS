#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "intrinsic.h"
#include "userprog/syscall.h"
#include "threads/malloc.h"
#include "vm/vm.h"

#ifdef VM
#include "vm/vm.h"
#endif

#define ARGV_LIMIT 32

static void process_cleanup (void);
static bool load (const char *file_name, struct intr_frame *if_);
static void initd (void *f_name);
static void __do_fork (void *);

struct thread *find_child_by(tid_t tid);

/* General process initializer for initd and other process. */
static void
process_init (void) {
	struct thread *current = thread_current ();
}

/* Starts the first userland program, called "initd", loaded from FILE_NAME.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. */
tid_t
process_create_initd (const char *file_name) {
	char *fn_copy;
	tid_t tid;

	/* Make a copy of FILE_NAME.
	 * Otherwise there's a race between the caller and load(). */
	fn_copy = palloc_get_page (0);
	if (fn_copy == NULL)
		return TID_ERROR;
	strlcpy (fn_copy, file_name, PGSIZE);

	/* Create a new thread to execute FILE_NAME. */
	tid = thread_create (file_name, PRI_DEFAULT, initd, fn_copy);
	if (tid == TID_ERROR)
		palloc_free_page (fn_copy);
	return tid;
}

/* A thread function that launches first user process. */
static void
initd (void *f_name) {
#ifdef VM
	supplemental_page_table_init (&thread_current ()->spt);
#endif

	process_init ();

	if (process_exec (f_name) < 0)
		PANIC("Fail to launch initd\n");
	NOT_REACHED ();
}

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */
tid_t
process_fork (const char *name, struct intr_frame *if_ UNUSED) {
	/* Clone current thread to new thread.*/
	void *aux[2] = {thread_current(), if_};
	pid_t pid = thread_create (name, PRI_DEFAULT, __do_fork, aux);
	if (TID_ERROR == pid)
		return TID_ERROR;

	struct thread *child = find_child_by(pid);
	if (TID_ERROR == child)
		return TID_ERROR;
	sema_down(&child->fork_sema);
	return pid;
}

#ifndef VM
/* Duplicate the parent's address space by passing this function to the
 * pml4_for_each. This is only for the project 2. */
static bool
duplicate_pte (uint64_t *pte, void *va, void *aux) {
	// 부모 프로세스의 pte, 부모 프로세스의 가상주소, 부모 프로세스 포인터
	struct thread *current = thread_current ();
	struct thread *parent = (struct thread *) aux;
	void *parent_page;
	void *newpage;
	bool writable;

	/* 1. If the parent_page is kernel page, then return immediately. */
	if (is_kernel_vaddr(va)) {
		return true;
	}
	/* 2. Resolve VA from the parent's page map level 4. */
	parent_page = pml4_get_page (parent->pml4, va);
	if (parent_page == NULL)
	 	return false;
	/* 3. Allocate new PAL_USER page for the child and set result to NEWPAGE. */
	newpage = palloc_get_page(PAL_USER);
	if (newpage == NULL)
		return false;
	/* 4. Duplicate parent's page to the new page and
	 *    check whether parent's page is writable or not 
	 *    (set WRITABLE according to the result). */
	writable = is_writable(pte);
	memcpy(newpage, parent_page, PGSIZE);
	/* 5. Add new page to child's page table at address VA with WRITABLE
	 *    permission. */
	if (!pml4_set_page (current->pml4, va, newpage, writable)) {
		/* 6. if fail to insert page, do error handling. */
		palloc_free_page(newpage);
		return false;
	}
	return true;
}
#endif

static void
duplicate_fd_list(struct thread *dest, struct thread *org) {
	struct file_descriptor **org_fd_list = org->fd_list;
	struct file_descriptor **dest_fd_list = dest->fd_list;
	for (int i = 2; i < FD_CNT_LIMIT; i++) {
		struct file_descriptor *org_file_desc = org_fd_list[i];
		if (org_file_desc == NULL)
			continue;
		struct file_descriptor *cpy_file_desc = calloc(sizeof(struct file_descriptor), 1);
		cpy_file_desc->fd = org_file_desc->fd;
		cpy_file_desc->file_p = file_duplicate(org_file_desc->file_p);
		if (cpy_file_desc->file_p == NULL) {
			free(cpy_file_desc);
			continue;
		}
		dest_fd_list[i] = cpy_file_desc;
	}
	dest->last_created_fd = org->last_created_fd;
}

static void 
fdlist_cleanup(struct thread *curr) {
	struct file_descriptor **fd_list = curr->fd_list;
	if (fd_list == NULL)
		return;
	for (int fd = 2; fd < FD_CNT_LIMIT; fd++)
		close(fd);
	palloc_free_multiple(fd_list, 2);
}

/* A thread function that copies parent's execution context.
 * Hint) parent->tf does not hold the userland context of the process.
 *       That is, you are required to pass second argument of process_fork to
 *       this function. */
static void
__do_fork (void *aux) {
	struct intr_frame if_;
	struct thread *parent = (struct thread *) ((void **) aux)[0];
	struct thread *current = thread_current ();
	struct intr_frame *parent_if = (struct intr_frame *) ((void **) aux)[1];
	bool succ = true;

	/* 1. Read the cpu context to local stack. */
	memcpy (&if_, parent_if, sizeof (struct intr_frame));
	/* 2. Duplicate PT */
	current->pml4 = pml4_create();
	if (current->pml4 == NULL)
		goto error;
	process_activate (current);
#ifdef VM
	supplemental_page_table_init (&current->spt);
	if (!supplemental_page_table_copy (&current->spt, &parent->spt))
		goto error;
#else
	if (!pml4_for_each (parent->pml4, duplicate_pte, parent))
		goto error;
#endif
	if (parent->last_created_fd == FD_CNT_LIMIT)
		goto error;
	duplicate_fd_list(current, parent);
	sema_up(&current->fork_sema);
	process_init ();
	/* Finally, switch to the newly created process. */
	if (succ) {
		if_.R.rax = 0;
		do_iret (&if_);
	}
error:
	sema_up(&current->fork_sema);
	exit(TID_ERROR);
}

/* Switch the current execution context to the f_name.
 * Returns -1 on fail. */
int
process_exec (void *f_name) {
	char *file_name = f_name;
	bool success;

	/* We cannot use the intr_frame in the thread structure.
	 * This is because when current thread rescheduled,
	 * it stores the execution information to the member. */
	struct intr_frame _if;
	_if.ds = _if.es = _if.ss = SEL_UDSEG;
	_if.cs = SEL_UCSEG;
	_if.eflags = FLAG_IF | FLAG_MBS;

	/* We first kill the current context */
	process_cleanup ();

	/* And then load the binary */
	success = load (file_name, &_if);

	/* If load failed, quit. */
	palloc_free_page (file_name);
	if (!success) {
		file_close(thread_current()->executable);
		thread_current()->executable = NULL;
		return -1;
	}

	/* Start switched process. */
	do_iret (&_if);
	NOT_REACHED ();
}


/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
 * immediately, without waiting.
 *
 * This function will be implemented in problem 2-2.  For now, it
 * does nothing. */
int
process_wait (tid_t child_tid UNUSED) {	
	struct thread *child = find_child_by(child_tid);
	if (TID_ERROR == child || !sema_try_down(&child->wait_sema)){
		return -1;
	}
	sema_down(&child->wait_sema);
	list_remove(&child->child_elem);
	sema_up(&child->exit_sema); // 동기화를 위한 종료 세마포어
	return child->exit_status;
}

/* Exit the process. This function is called by thread_exit (). */
void
process_exit (void) {
	struct thread *curr = thread_current ();
	sema_up(&curr->wait_sema);
	file_close(curr->executable);
	sema_down(&curr->exit_sema); // 동기화를 위한 종료 세마포어
	fdlist_cleanup(curr);
	process_cleanup ();
}

/* Free the current process's resources. */
static void
process_cleanup (void) {
	struct thread *curr = thread_current ();

#ifdef VM
	supplemental_page_table_kill (&curr->spt);
#endif
	uint64_t *pml4;
	/* Destroy the current process's page directory and switch back
	 * to the kernel-only page directory. */
	pml4 = curr->pml4;
	if (pml4 != NULL) {
		/* Correct ordering here is crucial.  We must set
		 * cur->pagedir to NULL before switching page directories,
		 * so that a timer interrupt can't switch back to the
		 * process page directory.  We must activate the base page
		 * directory before destroying the process's page
		 * directory, or our active page directory will be one
		 * that's been freed (and cleared). */
		curr->pml4 = NULL;
		pml4_activate (NULL);
		pml4_destroy (pml4);
	}
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
void
process_activate (struct thread *next) {
	/* Activate thread's page tables. */
	pml4_activate (next->pml4);

	/* Set thread's kernel stack for use in processing interrupts. */
	tss_update (next);
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr {
	unsigned char e_ident[EI_NIDENT];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

struct ELF64_PHDR {
	uint32_t p_type;
	uint32_t p_flags;
	uint64_t p_offset;
	uint64_t p_vaddr;
	uint64_t p_paddr;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

static bool setup_stack (struct intr_frame *if_);
static bool validate_segment (const struct Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes,
		bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */
static bool
load (const char *file_name, struct intr_frame *if_) {
	struct thread *t = thread_current ();
	struct ELF ehdr;
	struct file *file = NULL;
	off_t file_ofs;
	bool success = false;
	int i;

	/* Allocate and activate page directory. */
	t->pml4 = pml4_create ();
	if (t->pml4 == NULL)
		goto done;
	process_activate (thread_current ());

	// NOTE: 여러 인자가 들어올 경우 Tokenizing이 필요하다!
	int argc = 0;
	char *argv[ARGV_LIMIT], *token, *tokenized_arg; // 문자열(인자 값)의 포인터 배열 (32개로 제한), 쪼개진 문자열(앞), 쪼개진 문자열(뒤)
   	for (token = strtok_r (file_name, " ", &tokenized_arg); token != NULL; token = strtok_r (NULL, " ", &tokenized_arg))
		argv[argc++] = token;
		
	/* Open executable file. */
	file = filesys_open (file_name);
	if (file == NULL) {
		printf ("load: %s: open failed\n", file_name);
		goto done;
	}

	/* Read and verify executable header. */
	if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
			|| memcmp (ehdr.e_ident, "\177ELF\2\1\1", 7)
			|| ehdr.e_type != 2
			|| ehdr.e_machine != 0x3E // amd64
			|| ehdr.e_version != 1
			|| ehdr.e_phentsize != sizeof (struct Phdr)
			|| ehdr.e_phnum > 1024) {
		printf ("load: %s: error loading executable\n", file_name);
		goto done;
	}

	/* Read program headers. */
	file_ofs = ehdr.e_phoff;
	for (i = 0; i < ehdr.e_phnum; i++) {
		struct Phdr phdr;

		if (file_ofs < 0 || file_ofs > file_length (file))
			goto done;
		file_seek (file, file_ofs);

		if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
			goto done;
		file_ofs += sizeof phdr;
		switch (phdr.p_type) {
			case PT_NULL:
			case PT_NOTE:
			case PT_PHDR:
			case PT_STACK:
			default:
				/* Ignore this segment. */
				break;
			case PT_DYNAMIC:
			case PT_INTERP:
			case PT_SHLIB:
				goto done;
			case PT_LOAD:
				if (validate_segment (&phdr, file)) {
					bool writable = (phdr.p_flags & PF_W) != 0;
					uint64_t file_page = phdr.p_offset & ~PGMASK;
					uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
					uint64_t page_offset = phdr.p_vaddr & PGMASK;
					uint32_t read_bytes, zero_bytes;
					if (phdr.p_filesz > 0) {
						/* Normal segment.
						 * Read initial part from disk and zero the rest. */
						read_bytes = page_offset + phdr.p_filesz;
						zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
								- read_bytes);
					} else {
						/* Entirely zero.
						 * Don't read anything from disk. */
						read_bytes = 0;
						zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
					}
					if (!load_segment (file, file_page, (void *) mem_page,
								read_bytes, zero_bytes, writable))
						goto done;
				}
				else
					goto done;
				break;
		}
	}

	/* Set up stack. */
	if (!setup_stack (if_))
		goto done;

	/* Start address. */
	if_->rip = ehdr.e_entry;
	// ** No args **
	//  address   |      name      |     data       |  type		 |
	// 0x4747fff6 |	 argv[0][...]  | 'args-none\0'  | char[10]	 |
	// 0x4747ffee |    argv[0]     |   0x4747fff6   | char *	 | <----- rsi
	// 0x4747ffe6 | return address |       0        | void (*)() | <----- rsp 
	// printf("1 - check rsp (kernel VA) %p\n", &if_->rsp); ---> 0x800423ff97
	// printf("2 - check rsp (user VA) %p\n", if_->rsp);    ---> 0x47480000
	// printf("%x -- %x --- %x\n\n", USER_STACK - 10, USER_STACK - 18, USER_STACK - 26);

	// ** One or Many args ** (Not padding)
	//  address   |      name      |     data       |  type		 |
	// 0x4747fff9 |	 argv[1][...]  |   'onearg\0'   | char[7]	 |
	// 0x4747ffed |	 argv[0][...]  | 'args-single\0'| char[12]	 |
	// 0x4747ffe5 |    argv[1]     |   0x4747fff9   | char *	 |
	// 0x4747ffdd |    argv[0]     |   0x4747ffed   | char *	 | <----- rsi
	// 0x4747ffd5 | return address |       0        | void (*)() | <----- rsp 
	// printf("%x - %x - %x - %x - %x\n\n", USER_STACK - 7, USER_STACK - (7 + 12), USER_STACK - (7 + 12 + 8), USER_STACK - (7 + 12 + 8 + 8), USER_STACK - (7 + 12 + 8 + 8 + 8));

	// ** One or Many args ** (Padding)
	//  address   |      name      |     data       |  type		 |
	// 0x4747fff9 |	 argv[1][...]  |   'onearg\0'   | char[7]	 |
	// 0x4747ffed |	 argv[0][...]  | 'args-single\0'| char[12]	 |
	// 0x4747ffe8 |	 word-aligned  |       0        | uint8[5]	 |
	// 0x4747ffe0 |    argv[1]     |   0x4747fff9   | char *	 |
	// 0x4747ffd8 |    argv[0]     |   0x4747ffed   | char *	 | <----- rsi
	// 0x4747ffd0 | return address |       0        | void (*)() | <----- rsp 

	// 1. 매개변수의 값들을 (쪼개서) 저장한다.
	// 2. 매개변수가 담긴 값을 가리키는 주소를 저장한다.
	// 3. (optional) 지금까지 넣은 데이터를 8의 배수로 맞춰주기 위해 패딩을 넣는다.
	// 4. 마지막으로 반환 주소를 넣어준다.
	// 필요한 변수 : 스택 포인터, 매개변수 값들을 담은 변수, (패딩을 위한) 현재까지 사용한 byte 수 
	void **rsp = &if_->rsp; // stack 시작 지점, 0x47480000 (시작 지점에는 데이터 못 넣음)
	int total_argv_length = 0;
	uintptr_t argv_addr[ARGV_LIMIT];

	argv_addr[argc] = 0;
	for (int i = argc - 1; i > -1; i--) {
		int argv_length = strlen(argv[i]) + 1; // \0 포함
		total_argv_length += argv_length;
		*rsp -= argv_length; // 인자 길이만큼 스택 포인터 감소
		strlcpy(*rsp, argv[i], argv_length); // 주소에 문자열 값을저장
		argv_addr[i] = (uintptr_t) *rsp;
	}
	
	// Padding, 8의 배수로 정렬한다. ex) 현재 앞에서 char 27를 담은 경우, 8의 배수인 32로 맞춰줘야함. 따라서 5(32 - 27)만큼 스택 포인터를 낮춰준다.
	// ** Before padding **
	// 000000004747ffc0                                         00 00 00 |             ...|
	// 000000004747ffd0  00 00 00 00 00 ed ff 47-47 00 00 00 00 f9 ff 47 |.......GG......G|
	// 000000004747ffe0  47 00 00 00 00 00 00 00-00 00 00 00 00 61 72 67 |G............arg|
	// 000000004747fff0  73 2d 73 69 6e 67 6c 65-00 6f 6e 65 61 72 67 00 |s-single.onearg.|
	// ** After padding **
	// 000000004747ffc0                          00 00 00 00 00 00 00 00 |        ........|
	// 000000004747ffd0  ed ff 47 47 00 00 00 00-f9 ff 47 47 00 00 00 00 |..GG......GG....|
	// 000000004747ffe0  00 00 00 00 00 00 00 00-00 00 00 00 00 61 72 67 |.............arg|
	// 000000004747fff0  73 2d 73 69 6e 67 6c 65-00 6f 6e 65 61 72 67 00 |s-single.onearg.|
	int padding_size = ROUND_UP(total_argv_length, 8) - total_argv_length;
	*rsp -= padding_size;
	memset(*(uint8_t **) rsp, 0, padding_size); // 쓰레기 값이 있는 경우를 고려하여, 패딩은 모두 0으로 초기화

	// 매개변수가 담긴 값을 가리키는 주소를 저장한다.
	for (int i = argc; i > -1; i--) {
		*rsp -= 8; // 포인터 크기만큼 스택 포인터 감소
		**(uintptr_t **) rsp = argv_addr[i]; // rsp에 주소값을 저장
	}

	// 마지막으로 반환 주소를 넣어준다.
	*rsp -= 8;
	**(uintptr_t **) rsp = 0; // return address
	if_->R.rdi = argc;
	if_->R.rsi = (uint64_t) *rsp + sizeof(void *);

	file_deny_write(file);
	thread_current()->executable = file;

	// hex_dump(if_->rsp, if_->rsp, USER_STACK - if_->rsp, true); // 시작 지점, 출력할 데이터가 담겨있는 포인터, 출력할 크기, (추가 내용) 아스키 코드로 변환 여부)
	success = true;

done:
	/* We arrive here whether the load is successful or not. */
	return success;
}


/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Phdr *phdr, struct file *file) {
	/* p_offset and p_vaddr must have the same page offset. */
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
		return false;

	/* p_offset must point within FILE. */
	if (phdr->p_offset > (uint64_t) file_length (file))
		return false;

	/* p_memsz must be at least as big as p_filesz. */
	if (phdr->p_memsz < phdr->p_filesz)
		return false;

	/* The segment must not be empty. */
	if (phdr->p_memsz == 0)
		return false;

	/* The virtual memory region must both start and end within the
	   user address space range. */
	if (!is_user_vaddr ((void *) phdr->p_vaddr))
		return false;
	if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
		return false;

	/* The region cannot "wrap around" across the kernel virtual
	   address space. */
	if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
		return false;

	/* Disallow mapping page 0.
	   Not only is it a bad idea to map page 0, but if we allowed
	   it then user code that passed a null pointer to system calls
	   could quite likely panic the kernel by way of null pointer
	   assertions in memcpy(), etc. */
	if (phdr->p_vaddr < PGSIZE)
		return false;

	/* It's okay. */
	return true;
}

#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */

/* load() helpers. */
static bool install_page (void *upage, void *kpage, bool writable);

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	file_seek (file, ofs);
	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Get a page of memory. */
		uint8_t *kpage = palloc_get_page (PAL_USER);
		if (kpage == NULL)
			return false;

		/* Load this page. */
		if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes) {
			palloc_free_page (kpage);
			return false;
		}
		memset (kpage + page_read_bytes, 0, page_zero_bytes);

		/* Add the page to the process's address space. */
		if (!install_page (upage, kpage, writable)) {
			printf("fail\n");
			palloc_free_page (kpage);
			return false;
		}

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a minimal stack by mapping a zeroed page at the USER_STACK */
static bool
setup_stack (struct intr_frame *if_) {
	int8_t *kpage;
	bool success = false;

	kpage = palloc_get_page (PAL_USER | PAL_ZERO);
	if (kpage != NULL) {
		success = install_page (((uint8_t *) USER_STACK) - PGSIZE, kpage, true);
		if (success)
			if_->rsp = USER_STACK;
		else
			palloc_free_page (kpage);
	}
	return success;
}
// static bool
// setup_stack(struct intr_frame *if_)
// {
// 	bool success = false;

// 	// 스택은 아래로 성장하므로, USER_STACK에서 PGSIZE만큼 아래로 내린 지점에서 페이지를 생성한다.
// 	void *stack_bottom = (void *)(((uint8_t *)USER_STACK) - PGSIZE);

// 	/* TODO: Map the stack on stack_bottom and claim the page immediately.
// 	 * TODO: If success, set the rsp accordingly.
// 	 * TODO: You should mark the page is stack. */
// 	/* TODO: stack_bottom에 스택을 매핑하고 페이지를 즉시 요청하세요.
// 	 * TODO: 성공하면, rsp를 그에 맞게 설정하세요.
// 	 * TODO: 페이지가 스택임을 표시해야 합니다. */
// 	/* TODO: Your code goes here */

// 	// 1) stack_bottom에 페이지를 하나 할당받는다.
// 	if (vm_alloc_page(VM_ANON | VM_MARKER_0, stack_bottom, 1))
// 	// VM_MARKER_0: 스택이 저장된 메모리 페이지임을 식별하기 위해 추가
// 	// writable: argument_stack()에서 값을 넣어야 하니 True
// 	{
// 		// 2) 할당 받은 페이지에 바로 물리 프레임을 매핑한다.
// 		success = vm_claim_page(stack_bottom);
// 		if (success)
// 			// 3) rsp를 변경한다. (argument_stack에서 이 위치부터 인자를 push한다.)
// 			if_->rsp = USER_STACK;
// 	}
// 	return success;
// }

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable) {
	struct thread *t = thread_current ();

	/* Verify that there's not already a page at that virtual
	 * address, then map our page there. */
	return (pml4_get_page (t->pml4, upage) == NULL
			&& pml4_set_page (t->pml4, upage, kpage, writable));
}
#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */

// 실행 파일 내용을 페이지로 로딩하는 함수
// 처음 page fault가 발생할 때 호출
// 물리 페이지 로딩만 해준다. -> lazy load이기 때문!
// 인자로 들어오는 aux는 load_segment에서 넘어온 lazy_load_arg로, 읽어올 파일을 찾아 메모리에 적재한다.
bool lazy_load_segment (struct page *page, void *aux) {
	/* TODO: Load the segment from the file */
	/* TODO: This called when the first page fault occurs on address VA. */
	/* TODO: VA is available when calling this function. */

	struct lazy_load_arg *lazy_load_arg = (struct lazy_load_arg *)aux;

	// 파일의 위치를 ofs로 설정한다.
	file_seek(lazy_load_arg->file, lazy_load_arg->ofs);

	// 파일을 read_bytes만큼 읽어서 프레임에 적재한다.
	if (file_read(lazy_load_arg->file, page->frame->kva, lazy_load_arg->read_bytes) != (int) lazy_load_arg->read_bytes) {
		palloc_free_page(page->frame->kva);
		return false;
	}
	memset(page->frame->kva + lazy_load_arg->read_bytes, 0, lazy_load_arg->zero_bytes);

	return true;
}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. 
		 * 이 페이지를 채우는 방법을 계산한다. 
		 * 파일에서 PAGE_READ_BYTES 만큼 읽고, 나머지 PAGE_ZERO_BYTES 만큼 0으로 채웁니다.
		 */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* TODO: Set up aux to pass information to the lazy_load_segment. */
		// vm_alloc_page_with_initializer에 제공할 aux 인수로 필요한 보조 값들을 설정해야 한다.
		// loading을 위해 필요한 정보를 포함하는 구조체를 만들어야 한다.
		struct lazy_load_arg *lazy_load_arg = (struct lazy_load_arg *)malloc(sizeof(struct lazy_load_arg));
		lazy_load_arg->file = file;
		lazy_load_arg->ofs = ofs;
		lazy_load_arg->read_bytes = page_read_bytes;
		lazy_load_arg->zero_bytes = page_zero_bytes;


		if (!vm_alloc_page_with_initializer (VM_ANON, upage,
					writable, lazy_load_segment, lazy_load_arg))//맨 마지막 인자 aux -> lazy_load_arg
			return false;

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
		ofs += page_read_bytes;
	}
	return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool setup_stack (struct intr_frame *if_) {
	bool success = false;
	void *stack_bottom = (void *) (((uint8_t *) USER_STACK) - PGSIZE);

	/* TODO: Map the stack on stack_bottom and claim the page immediately.
	 * TODO: If success, set the rsp accordingly.
	 * TODO: You should mark the page is stack. */
	/* TODO: Your code goes here */

	// stack_bottom에 스택 페이지를 할당받는다.
	// VM_MARKER_0은 스택이 저장된 메모리 페이지임을 식별하기 위해 추가
	if(vm_alloc_page_with_initializer(VM_ANON, stack_bottom, true, NULL, NULL)){
		//성공 시 곧바로 물리 프레임을 할당
		// spt_find_page(&thread_current()->spt, stack_bottom)
		//이 위치에서부터 argument_stack으로부터 인자가 쌓인다
		if (vm_claim_page(stack_bottom)){
			success = true; 
			if_->rsp = USER_STACK;
		}
	}
	return success;
}
#endif /* VM */

/**
 * @brief pid(=tid) 기준으로 현재 프로세스의 자식 프로세스 검색
 * 
 * @param pid (=tid)
 * @return struct thread* or -1 (find fail)
 */
struct thread
*find_child_by(pid_t pid)
{
	struct thread *current = thread_current();
	struct list *children = &current->children;
	if (list_empty(children) || pid == -1) return -1;

	struct thread *child;
	struct list_elem *curr_child_elem = list_begin(children);
	ASSERT(curr_child_elem != NULL);
	while (curr_child_elem != list_tail(children)) {
		child = list_entry(curr_child_elem, struct thread, child_elem);
		if (child->tid == pid)
			return child;
		curr_child_elem = list_next(curr_child_elem);
	}
	return -1;
};
