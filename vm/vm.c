/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include <hash.h>
#include "threads/vaddr.h"
#include "threads/mmu.h"
#include "userprog/process.h"
#include <string.h>

struct list victim_list;
struct lock victim_list_lock;

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
	list_init(&victim_list);
	lock_init(&victim_list_lock);
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
	struct page *page;
	bool (*initializer) (struct page *, enum vm_type, void *);
	struct supplemental_page_table *spt = &thread_current()->spt;

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	/* Check whether the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initializer according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */
		page = (struct page *) malloc(sizeof(struct page));
		if (page == NULL){
			return false;
		}

		if (VM_TYPE(type) == VM_ANON) {
			initializer = anon_initializer;
		} else if (VM_TYPE(type) == VM_FILE) {
			initializer = file_backed_initializer;
		} else {
			PANIC("Invaild vm_type");
			return false;
		}

		uninit_new(page, upage, init, type, aux, initializer);
		
		page->writable = writable;
		page->page_vm_type = type;
		lock_init(&page->lock);

		/* TODO: Insert the page into the spt. */
		if(spt_insert_page(spt, page)){
			page->owner = thread_current();
			return true;
		}

	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt, void *va) {
	/* TODO: Fill this function. */
	struct page p;

	p.va = pg_round_down(va);
	struct hash_elem *e = hash_find(&thread_current()->spt.page_map, &p.spt_elem);

	if (e == NULL) {
		return NULL;
	} else {
		return hash_entry(e, struct page, spt_elem);
	}
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt, struct page *page) {
	/* TODO: Fill this function. */
	return hash_insert(&spt->page_map, &page->spt_elem) == NULL;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	hash_delete(&spt->page_map, &page->spt_elem);
	return;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	/* TODO: The policy for eviction is up to you. */

	struct list_elem *victim_iter = list_front(&victim_list);

	while (1){
		struct page *victim_page = list_entry (victim_iter, struct page, victim_list_elem);
		if (!lock_held_by_current_thread (&victim_page->lock) 
			&& lock_try_acquire (&victim_page->lock)) {
			void *victim_addr = victim_page->va;
			struct thread* victim_owner = victim_page->owner;

			if ((victim_owner == NULL) || (!pml4_is_accessed(&victim_owner->pml4, victim_addr))) 
			{
				list_remove(victim_iter);
				return victim_page->frame;
			} else {
				pml4_set_accessed(&victim_owner->pml4, victim_addr, 0);
			}
			lock_release(&victim_page->lock);
		}
		victim_iter = list_next(victim_iter);
	
		if (victim_iter == list_end(&victim_list)) {
			victim_iter = list_front(&victim_list);
		}
	}

	PANIC("unreachable: vm_get_victim");
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	lock_acquire(&victim_list_lock);
	struct frame *victim = vm_get_victim ();
	lock_release(&victim_list_lock);
	/* TODO: swap out the victim and return the evicted frame. */
	if (!swap_out(victim->page)) {
		return NULL;
	}
	struct lock* page_lock = &victim->page->lock;
	victim->page = NULL;

	lock_release(page_lock);

	return victim;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	/* TODO: Fill this function. */
	void *new = palloc_get_page(PAL_USER);

	if (new == NULL) {
		return vm_evict_frame();
	}

	struct frame *frame = (struct frame *)malloc(sizeof(struct frame));
	ASSERT (frame != NULL);

	frame->page = NULL;
	frame->kva = new;

	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr) {
	struct thread *curr = thread_current();
	void *sp = pg_round_down(addr);

	struct page *page;
	while((page = spt_find_page(&curr->spt, sp)) == NULL){
		if ((vm_alloc_page(VM_ANON | VM_MARKER_0, sp, true)) && vm_claim_page(sp)) {
			memset(sp, 0, PGSIZE);
			sp += PGSIZE;
		} else {
			PANIC("alloc & claim failed in vm_stack_growth");
		}
	}
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f, void *addr,
		bool user, bool write, bool not_present) {
	
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */
	struct supplemental_page_table *spt = &thread_current ()->spt;
	void *sp;

	if (user && is_kernel_vaddr(addr)){
		return false;
	}

	struct page *page = spt_find_page(spt, addr);
	if (page == NULL) {
		if (not_present &&
				addr >= (void *) (f->rsp - 8) &&
				addr >= (void *) (USER_STACK - 0x100 * PGSIZE) &&
				addr < (void *) USER_STACK) {
				vm_stack_growth (addr);
				return true;
		}

		return false;
	} else {
		if (page->writable == 0 && write) {
			return false;
		}
	
		return vm_do_claim_page (page);
	}
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	lock_acquire(&page->lock);
	struct frame* frame = page->frame;

	if (frame != NULL) {
		destroy (page);
		
		lock_acquire(&victim_list_lock);
		list_remove(&page->victim_list_elem);
		lock_release(&victim_list_lock);
		free(frame);
	} else {
		destroy (page);
	}

	lock_release(&page->lock);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va) {
	struct page *page = NULL;
	/* TODO: Fill this function */
	page = spt_find_page(&thread_current()->spt, va);

	if (page == NULL) {
		return false;
	}

	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	bool ret, writable = page->writable;
	struct frame *frame;

	frame = vm_get_frame ();
	ASSERT(frame != NULL);

	/* Set links */
	frame->page = page;
	page->frame = frame;

	ret = swap_in (page, frame->kva);

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	if (!pml4_set_page(page->owner->pml4, page->va, frame->kva, writable)) {
		return false;
	}
	lock_acquire(&victim_list_lock);
	list_push_back(&victim_list, &page->victim_list_elem);
	lock_release(&victim_list_lock);

	return ret;
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt) {
	hash_init(&spt->page_map, page_hash_func, cmp_page_hash, NULL);
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst,
		struct supplemental_page_table *src) {

	ASSERT(src != NULL);
	ASSERT(dst != NULL);

	struct hash_iterator iter;
	hash_first(&iter, &src->page_map);

	bool succ = true;
	struct page_load_info *aux_parent, *aux = NULL;

	while (hash_next(&iter) != NULL) {
		struct page *p = hash_entry(hash_cur(&iter), struct page, spt_elem);
		enum vm_type p_type = p->operations->type;
		lock_acquire(&p->lock);

		switch (p_type){
			case VM_UNINIT:
				aux = (struct page_load_info *) malloc(sizeof(struct page_load_info));
				aux_parent = (struct page_load_info *) p->uninit.aux;

				aux->file = file_reopen(aux_parent->file);
				aux->is_first_page = aux_parent->is_first_page;
				aux->num_left_page = aux_parent->num_left_page;
				aux->ofs = aux_parent->ofs;
				aux->read_bytes = aux_parent->read_bytes;
				aux->zero_bytes = aux_parent->zero_bytes;

				if (!vm_alloc_page_with_initializer(p->page_vm_type, p->va, p->writable, p->uninit.init, aux)) {
					return false;
				}

				break;
			case VM_ANON:
				if(!vm_alloc_page(VM_ANON | VM_MARKER_0, p->va, p->writable)) {
					return false;
				}

				if(!vm_claim_page(p->va)) {
					return false;
				}

				struct page *child_p = spt_find_page(&thread_current()->spt, p->va);
				lock_acquire(&child_p->lock);

				if (p->frame == NULL) {
					vm_do_claim_page(p);
				}

				ASSERT (p->frame != NULL);
				ASSERT (child_p->frame != NULL);

				memcpy(child_p->va, p->frame->kva, PGSIZE);
				lock_release(&child_p->lock);
				break;
			case VM_FILE:
				ASSERT (p->owner->pml4 != NULL);

				if (pml4_is_dirty(p->owner->pml4, p->va)) {
					if(!vm_alloc_page(VM_FILE, p->va, p->writable)){
						return false;
					}
					
					if(!vm_claim_page(p->va)) {
						return false;
					}

					struct page *child_p = spt_find_page(&thread_current()->spt, p->va);

					child_p->file.load_info.file = file_reopen(p->file.load_info.file);
					child_p->file.load_info.is_first_page = p->file.load_info.is_first_page;
					child_p->file.load_info.num_left_page = p->file.load_info.num_left_page;
					child_p->file.load_info.ofs = p->file.load_info.ofs;
					child_p->file.load_info.read_bytes = p->file.load_info.read_bytes;
					child_p->file.load_info.zero_bytes = p->file.load_info.zero_bytes;

					memcpy(child_p->va, p->frame->kva, PGSIZE);
				
					pml4_set_dirty(&thread_current()->pml4, p->va, true);
				} else {
					aux = (struct page_load_info *) malloc(sizeof(struct page_load_info));
					aux->file = file_reopen(p->file.load_info.file);
					aux->is_first_page = p->file.load_info.is_first_page;
					aux->num_left_page = p->file.load_info.num_left_page;
					aux->ofs = p->file.load_info.ofs;
					aux->read_bytes = p->file.load_info.read_bytes;
					aux->zero_bytes = p->file.load_info.zero_bytes;

					if(!vm_alloc_page_with_initializer(VM_FILE, p->va, p->writable, file_lazy_load, aux)){
						return false;
					}
				}

				break;
			default:
				break;
		}
		lock_release(&p->lock);
	}
	return succ;
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	hash_destroy(&spt->page_map, spt_page_destroy);
}

void spt_page_destroy(struct hash_elem *e, void *aux){
	struct page *page = hash_entry(e, struct page, spt_elem);
	vm_dealloc_page(page);
}

uint64_t
page_hash_func (const struct hash_elem *e, void *aux){
	const struct page *p = hash_entry(e, struct page, spt_elem);
	return hash_bytes(&p->va, sizeof(p->va));
}

bool
cmp_page_hash (const struct hash_elem *x, const struct hash_elem *y, void *aux){
	struct page *p_x = hash_entry(x, struct page, spt_elem);
	struct page *p_y = hash_entry(y, struct page, spt_elem);

	return p_x->va < p_y->va;
}

void free_page_load_info(struct page_load_info *load_info) {
	file_close(load_info->file);
	free(load_info);
}
