/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "list.h"
#include "include/threads/vaddr.h"
#include "lib/kernel/hash.h"
#include "include/threads/mmu.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include "lib/string.h"

unsigned page_hash(const struct hash_elem *p_, void *aux UNUSED);
bool page_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED);
void spt_kill(struct hash_elem *e, void *aux UNUSED);

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void vm_init(void)
{
	vm_anon_init();
	vm_file_init();
#ifdef EFILESYS /* For project 4 */
	pagecache_init();
#endif
	register_inspect_intr();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type(struct page *page)
{
	int ty = VM_TYPE(page->operations->type);
	switch (ty)
	{
	case VM_UNINIT:
		return VM_TYPE(page->uninit.type);
	default:
		return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim(void);
static bool vm_do_claim_page(struct page *page);
static struct frame *vm_evict_frame(void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool vm_alloc_page_with_initializer(enum vm_type type, void *upage, bool writable,
									vm_initializer *init, void *aux)
{

	ASSERT(VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current()->spt;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page(spt, upage) == NULL)
	{
		// TODO: Create the page, fetch the initialier according to the VM type,
		// 페이지를 생성하고, VM 타입에 맞게 초기화 함수를 가져온다.
		struct page *p = (struct page *)malloc(sizeof(struct page));

		typedef bool (*page_initializer)(struct page *, enum vm_type, void *);
		page_initializer type_page_initializer = NULL;

		switch (VM_TYPE(type))
		{
		// case VM_UNINIT:
		// 	page_initializer = uninit.page_initializer;
		// 	break;
		case VM_ANON:
			type_page_initializer = anon_initializer;
			break;
		case VM_FILE:
			type_page_initializer = file_backed_initializer;
			break;
		}

		// uninit 타입의 페이지로 초기화 한다.
		uninit_new(p, upage, init, type, aux, type_page_initializer);

		// TODO:  You should modify the field after calling the uninit_new. */
		p->writable = writable;

		/* TODO: Insert the page into the spt. */
		if (spt_insert_page(spt, p))
		{
			return true;
		}
	}
err:
	return false;
}

/*
 * 인자로 들어온 SPT부터 가상 주소(va)와 대응되는 페이지 구조체를 찾아서 반환한다.
 * 실패하면 NULL을 반환한다.
 */
struct page *spt_find_page(struct supplemental_page_table *spt UNUSED, void *va UNUSED)
{
	struct page *page = NULL;
	/* TODO: Fill this function. */
	page = malloc(sizeof(struct page));
	struct hash_elem *e;

	// va가 가리키는 가상 페이지의 시작 지점을 va에 저장한다.
	// 해시 테이블에서 va에 해당하는 페이지를 찾는다.
	page->va = pg_round_down(va);

	e = hash_find(&spt->spt_hash, &page->hash_elem);

	free(page);

	if (e == NULL)
	{
		return NULL;
	}

	page = hash_entry(e, struct page, hash_elem);

	return page;
	// e = hash_find(&spt->spt_hash, &page->hash_elem);

	// // 찾은 페이지를 반환한다.
	// return e != NULL ? hash_entry(e, struct page, hash_elem) : NULL;
}

// SPT에 페이지를 삽입한다.
bool spt_insert_page(struct supplemental_page_table *spt UNUSED,
					 struct page *page UNUSED)
{
	/* TODO: Fill this function. */
	// 페이지를 해시 테이블에 삽입한다.
	return hash_insert(&spt->spt_hash, &page->hash_elem) == NULL ? true : false;
}

void spt_remove_page(struct supplemental_page_table *spt, struct page *page)
{
	vm_dealloc_page(page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim(void)
{
	struct frame *victim = NULL;
	/* TODO: The policy for eviction is up to you. */

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame(void)
{
	struct frame *victim UNUSED = vm_get_victim();
	/* TODO: swap out the victim and return the evicted frame. */

	return NULL;
}

/* palloc() 함수를 호출해 프레임을 가져온다.
 * 사용 가능한 페이지가 없으면 페이지를 evict한 후 리턴한다(항상 유효한 주소를 반환).
 * 즉, 유저 풀 메모리가 가득 차면 프레임을 evict하여 사용 가능한 메모리 공간을 가져온다.
 */
static struct frame *vm_get_frame(void)
{
	struct frame *frame = NULL;
	/* TODO: Fill this function. */
	frame = malloc(sizeof(struct frame));
	frame->kva = palloc_get_page(PAL_USER); // user pool에서 새로운 physical page를 가져온다.

	if (frame->kva == NULL) // page 할당 실패 -> 나중에 swap_out 처리
		PANIC("todo");		// OS를 중지시키고, 소스 파일명, 라인 번호, 함수명 등의 정보와 함께 사용자 지정 메시지를 출력

	frame->page = NULL; // 프레임 멤버 초기화

	ASSERT(frame != NULL);
	ASSERT(frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void vm_stack_growth(void *addr UNUSED)
{
	 vm_alloc_page(VM_ANON | VM_MARKER_0, pg_round_down(addr), 1);
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp(struct page *page UNUSED)
{
}

/*
 * spt_find_page를 통해 spt를 참고하여 폴트된 주소에 대응하는 페이지 구조체를 해결
 *
 *
 */
// bool vm_try_handle_fault(struct intr_frame *f UNUSED, void *addr UNUSED,
// 						 bool user UNUSED, bool write UNUSED, bool not_present UNUSED)
// {

// 	struct supplemental_page_table *spt UNUSED = &thread_current()->spt;
// 	struct page *page = NULL;
// 	/* TODO: Validate the fault */
// 	/* TODO: Your code goes here */

// 	if (addr == NULL)
// 		return false;
// 	if (is_kernel_vaddr(addr))
// 		return false;

// 	// 접근한 메모리의 물리적 페이지가 존재하지 않는 경우 (lazy load)
// 	if (not_present)
// 	{

// 		// 주소에 대응하는 페이지 구조체를 찾는다.
// 		page = spt_find_page(spt, addr);

// 		if (page == NULL)
// 			return false;

// 		// write가 안되는 페이지에 write를 요청한 경우
// 		if (write == 1 && page->writable == 0)
// 			return false;

// 		return vm_do_claim_page(page);
// 	}
// 	return false;
// }
bool vm_try_handle_fault(struct intr_frame *f UNUSED, void *addr UNUSED,
                         bool user UNUSED, bool write UNUSED, bool not_present UNUSED)
{
    struct supplemental_page_table *spt UNUSED = &thread_current()->spt;
    struct page *page = NULL;
    if (addr == NULL)
        return false;

    if (is_kernel_vaddr(addr))
        return false;

    if (not_present) // 접근한 메모리의 physical page가 존재하지 않은 경우
    {
        /* TODO: Validate the fault */
        // 페이지 폴트가 스택 확장에 대한 유효한 경우인지를 확인한다.
        void *rsp = f->rsp; // user access인 경우 rsp는 유저 stack을 가리킨다.
        if (!user)            // kernel access인 경우 thread에서 rsp를 가져와야 한다.
            rsp = thread_current()->rsp;

        // 스택 확장으로 처리할 수 있는 폴트인 경우, vm_stack_growth를 호출한다.
        if (USER_STACK - (1 << 20) <= rsp - 8 && rsp - 8 == addr && addr <= USER_STACK)
            vm_stack_growth(addr);
        else if (USER_STACK - (1 << 20) <= rsp && rsp <= addr && addr <= USER_STACK)
            vm_stack_growth(addr);

        page = spt_find_page(spt, addr);
        if (page == NULL)
            return false;
        if (write == 1 && page->writable == 0) // write 불가능한 페이지에 write 요청한 경우
            return false;
        return vm_do_claim_page(page);
    }
    return false;
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void vm_dealloc_page(struct page *page)
{
	destroy(page);
	free(page);
}

// 인자로 주어진 va에 페이지를 할당하고, 해당 페이지에 프레임을 할당한다.
bool vm_claim_page(void *va UNUSED)
{
	struct page *page = NULL;
	/* TODO: Fill this function */
	// 페이지를 할당한다.

	// va에 해당하는 페이지를 찾는다.
	page = spt_find_page(&thread_current()->spt, va);
	if (page == NULL)
		return false;

	return vm_do_claim_page(page);
}

// 인자로 주어진 page에 물리 메모리 프레임을 할당한다.
static bool vm_do_claim_page(struct page *page)
{
	struct frame *frame = vm_get_frame();

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	// 가상 주소와 물리 주소의 매핑 정보를 페이지 테이블에 추가
	struct thread *cur = thread_current();
	pml4_set_page(cur->pml4, page->va, frame->kva, page->writable);

	// 페이지와 프레임의 가상 주소를 인자로 받아 페이지를 스왑 영역에서 물리 메모리로 가져오는 역할
	return swap_in(page, frame->kva);
}

/* SPT를 초기화한다. */
void supplemental_page_table_init(struct supplemental_page_table *spt UNUSED)
{
	hash_init(&spt->spt_hash, page_hash, page_less, NULL);
}

/*
 * src부터 dst까지 SPT를 복사한다.
 * 자식이 부모의 실행 context를 상속할 때(fork) 사용된다.
 * 초기화되지 않은(uninit) 페이지를 할당하고 이를 바로 claim해야 한다.
 */
bool supplemental_page_table_copy(struct supplemental_page_table *dst UNUSED,
                                  struct supplemental_page_table *src UNUSED)
{
    struct hash_iterator i;
    hash_first(&i, &src->spt_hash);
    while (hash_next(&i))
    {
        // src_page 정보
        struct page *src_page = hash_entry(hash_cur(&i), struct page, hash_elem);
        enum vm_type type = src_page->operations->type;
        void *upage = src_page->va;
        bool writable = src_page->writable;

        /* 1) type이 uninit이면 */
        if (type == VM_UNINIT)
        { // uninit page 생성 & 초기화
            vm_initializer *init = src_page->uninit.init;
            void *aux = src_page->uninit.aux;
            vm_alloc_page_with_initializer(VM_ANON, upage, writable, init, aux);
            continue;
        }
		
		/* 2) type이 file이면 */
        if (type == VM_FILE)
        {
            struct lazy_load_arg *file_aux = malloc(sizeof(struct lazy_load_arg));
            file_aux->file = src_page->file.file;
            file_aux->ofs = src_page->file.ofs;
            file_aux->read_bytes = src_page->file.read_bytes;
            file_aux->zero_bytes = src_page->file.zero_bytes;
            if (!vm_alloc_page_with_initializer(type, upage, writable, NULL, file_aux))
                return false;
            struct page *file_page = spt_find_page(dst, upage);
            file_backed_initializer(file_page, type, NULL);
            file_page->frame = src_page->frame;
            pml4_set_page(thread_current()->pml4, file_page->va, src_page->frame->kva, src_page->writable);
            continue;
        }

        /* 2) type이 uninit이 아니면 */
        if (!vm_alloc_page(type, upage, writable)) // uninit page 생성 & 초기화
            // init이랑 aux는 Lazy Loading에 필요함
            // 지금 만드는 페이지는 기다리지 않고 바로 내용을 넣어줄 것이므로 필요 없음
            return false;

        // vm_claim_page으로 요청해서 매핑 & 페이지 타입에 맞게 초기화
        if (!vm_claim_page(upage))
            return false;

        // 매핑된 프레임에 내용 로딩
        struct page *dst_page = spt_find_page(dst, upage);
        memcpy(dst_page->frame->kva, src_page->frame->kva, PGSIZE);
    }
    return true;
}
// bool supplemental_page_table_copy(struct supplemental_page_table *dst UNUSED,
// 								  struct supplemental_page_table *src UNUSED)
// {

// 	struct hash_iterator i;
// 	hash_first(&i, &src->spt_hash);

// 	while (hash_next(&i))
// 	{
// 		struct page *src_page = hash_entry(hash_cur(&i), struct page, hash_elem);
// 		struct page *dst_page = malloc(sizeof(struct page));

// 		enum vm_type type = src_page->operations->type; // 부모의 페이지 타입을 받아온다.
// 		void *va = src_page->va;						// 부모의 가상 주소를 받아온다.
// 		bool writable = src_page->writable;

// 		// 페이지 타입이 uninit인 경우
// 		if (type == VM_UNINIT || src_page->frame == NULL)
// 		{
// 			// 초기화되지 않은 페이지를 할당하고 claim한다.
// 			vm_initializer *init = src_page->uninit.init;
// 			void *aux = src_page->uninit.aux;
// 			if (!vm_alloc_page_with_initializer(type, va, writable, init, aux))
// 			{
// 				return false;
// 			}
// 		}
// 		else
// 		{ // 페이지 타입에 맞게 페이지를 할당하기 위해 do_claim_page를 호출한다.
// 			switch (type)
// 			{
// 			case VM_ANON:
// 				if (!vm_alloc_page_with_initializer(type, va, writable, NULL, NULL))
// 				{
// 					return false;
// 				}
// 				if (!vm_claim_page(va))
// 				{
// 					return false;
// 				}
// 				break;
// 			case VM_FILE:
// 				if (!vm_alloc_page_with_initializer(type, va, writable, NULL, NULL))
// 				{
// 					return false;
// 				}
// 				if (!vm_claim_page(va))
// 				{
// 					return false;
// 				}
// 				break;
// 			default:
// 				return false;
// 			}
// 		}
// 		dst_page = spt_find_page(dst, va);
// 		memcpy(dst_page->frame->kva, src_page->frame->kva, PGSIZE);
// 	}
// 	return true;
// }

/*
 * Spt에 의해 유지되던 모든 자원을 해제한다.
 * process가 exit할 때(userprog/process.c의 process_exit()) 호출된다.
 * 페이지 엔트리를 반복하면서 테이블의 페이지에 대해 destroy(page)를 호출한다.
 * 이 함수에서 실제 페이지 테이블(pml4)와 물리 주소(palloc된 메모리)에 대해 걱정할 필요는 없다
 * 		-> (spt가 cleanup 된 후 호출자가 clean 하기 때문).
 */
void supplemental_page_table_kill(struct supplemental_page_table *spt UNUSED)
{
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	hash_clear(&spt->spt_hash, spt_kill);
}

// 주어진 aux 데이터에서 해시 요소에 대한 해시 값을 계산하고 반환
// 해시 테이블 초기화할 때 해시 값을 구해주는 함수의 포인터
unsigned page_hash(const struct hash_elem *p_, void *aux UNUSED)
{
	const struct page *p = hash_entry(p_, struct page, hash_elem);
	return hash_bytes(&p->va, sizeof(p->va));
}

// 해시 테이블을 초기화 할 때, 해시 요소를 비교하는 함수의 포인터
// a가 b보다 작으면 true, 그렇지 않으면 false를 반환한다.
bool page_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED)
{
	const struct page *a = hash_entry(a_, struct page, hash_elem);
	const struct page *b = hash_entry(b_, struct page, hash_elem);
	return a->va < b->va;
}

void spt_kill(struct hash_elem *e, void *aux UNUSED)
{
	struct page *page = hash_entry(e, struct page, hash_elem);
	destroy(page);
	free(page);
}