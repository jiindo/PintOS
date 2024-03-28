/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "swap.h"

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */

		/* TODO: Insert the page into the spt. */
	}
err:
	return false;
}

/* 
* 인자로 들어온 SPT부터 가상 주소(va)와 대응되는 페이지 구조체를 찾아서 반환한다.
* 실패하면 NULL을 반환한다.
*/
struct page *spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function. */
	page = malloc(sizeof(struct page));
	struct hash_elem *e;

	// va가 가리키는 가상 페이지의 시작 지점을 va에 저장한다.
	// 해시 테이블에서 va에 해당하는 페이지를 찾는다.
	page->va = pg_round_down(va);
	e = hash_find(&spt->pages, &page->hash_elem);
	
	// 가상 메모리를 찾기 위해 선언한 페이지를 해제한다.
	free(page);

	// 찾은 페이지를 반환한다.
	if (e != NULL) {
		return hash_entry(e, struct page, hash_elem);
	}
	else {
		return NULL;
	}
}

// SPT에 페이지를 삽입한다.
bool spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
	int succ = false;
	/* TODO: Fill this function. */
	// 페이지를 해시 테이블에 삽입한다.
	if (hash_insert(&spt->pages, &page->hash_elem) == NULL) {
		return true;
	}
	else
		return false;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	vm_dealloc_page (page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */

	return NULL;
}

/* palloc() 함수를 호출해 프레임을 가져온다.
 * 사용 가능한 페이지가 없으면 페이지를 evict한 후 리턴한다(항상 유효한 주소를 반환).
 * 즉, 유저 풀 메모리가 가득 차면 프레임을 evict하여 사용 가능한 메모리 공간을 가져온다.
*/
static struct frame *vm_get_frame (void) {
	struct frame *frame = NULL;
	/* TODO: Fill this function. */

	// 프레임을 할당한다.
	void *kva = palloc_get_page(PAL_USER);
	if (kva == NULL) 
		PANIC("User pool is full!");
	
	frame = malloc(sizeof(struct frame));
	frame->kva = kva;

	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	struct page *page = NULL;
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */

	return vm_do_claim_page (page);
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

// 인자로 주어진 va에 페이지를 할당하고, 해당 페이지에 프레임을 할당한다.
bool vm_claim_page (void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function */
	// 페이지를 할당한다.
	page = spt_find_page(&thread_current()->spt, va);
	if (page == NULL) 
		return false;
	
	return vm_do_claim_page (page);
}

// 인자로 주어진 page에 물리 메모리 프레임을 할당한다.
static bool vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	struct thread *cur = thread_current();
	pml4_set_page(cur->pml4, page->va, frame->kva, page->writable);

	return swap_in (page, frame->kva);
}

/* SPT를 초기화한다. */
void supplemental_page_table_init(struct supplemental_page_table *spt UNUSED) {
	hash_init (&spt->pages, page_hash, page_less, NULL);
}

/* Copy supplemental page table from src to dst */
bool supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
}

// 주어진 aux 데이터에서 해시 요소에 대한 해시 값을 계산하고 반환
// 해시 테이블 초기화할 때 해시 값을 구해주는 함수의 포인터
unsigned page_hash (const struct hash_elem *p_, void *aux UNUSED) {
	const struct page *p = hash_entry (p_, struct page, hash_elem);
	return hash_bytes(&p->va, sizeof p->va);
}

// 해시 테이블을 초기화 할 때, 해시 요소를 비교하는 함수의 포인터
// a가 b보다 작으면 true, 그렇지 않으면 false를 반환한다.
bool page_less (const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED) {
	const struct page *a = hash_entry (a_, struct page, hash_elem);
	const struct page *b = hash_entry (b_, struct page, hash_elem);
	return a->va < b->va;
}