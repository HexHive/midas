#include <asm/tlbflush.h>
#include <linux/mm.h>
#include <linux/rmap.h>
#include <linux/swap.h>
#include <linux/uaccess.h>
#include "../../mm/internal.h"

#define MARKER() printk("    %d:%ld:%s:%d\n", current->pid, current->op_code, __func__, __LINE__);

#ifdef CONFIG_TOCTTOU_PROTECTION

#define CONFIG_MAX_PREALLOC 128
static void *duplicate_page_cache;
static void *snaps_cache;
static void *marked_frames_cache;
#ifdef CONFIG_TOCTTOU_ACCOUNTING
static unsigned syscall_counter, snapshot_counter, copy_counter;
#endif

void __init tiktok_init(void) {
#ifdef CONFIG_TOCTTOU_ACCOUNTING
    syscall_counter = 0;
    snapshot_counter = 0;
    copy_counter = 0;
#endif

    duplicate_page_cache = kmem_cache_create("dup_page_cache", sizeof(struct page_copy), PAGE_SIZE, SLAB_POISON, NULL);
    BUG_ON(!duplicate_page_cache);

    snaps_cache = kmem_cache_create("snaps_cache", sizeof(struct page_snap), __alignof__(struct page_snap), SLAB_POISON, NULL);
    BUG_ON(!snaps_cache);

    marked_frames_cache = kmem_cache_create("marked frames cache", sizeof(struct marked_frame), __alignof__(struct marked_frame), SLAB_POISON, NULL);
    BUG_ON(!marked_frames_cache);
}
arch_initcall(tiktok_init);

struct page_copy *tocttou_duplicate_page_alloc()
{
    struct page_copy *copy = kmem_cache_alloc(duplicate_page_cache, GFP_NOWAIT); 
    BUG_ON(!copy);
    copy->refcount = 0;
    return copy;
}

void tocttou_duplicate_page_free(struct page_copy *copy)
{
    BUG_ON(!copy);
    BUG_ON(copy->refcount != 0);
	kmem_cache_free(duplicate_page_cache, copy);
}

/* Every instance of syscall requires an identifier */
uintptr_t 
get_syscall_identifier(void) {
    return (uintptr_t)current;
}

/* Decide which syscalls should use Tocttou protection. 
 * Certain syscalls require asynchronous modification for correct behavior.
 * Other syscalls might be deemed benign, and have Tocttou protection turned off for performance
 */
int should_mark(void) {

	if (current->pid <= 1)
		return 0;

    /* TODO: Copied from Uros. What does this mean? */
	if (current->flags & PF_EXITING) {
		return 0;
	}

    if (current->op_code < 0)
        return 0;

    /* Here we ignore certain calls. Before benchmarking, make sure that the
	 * appropriate calls are uncommented. Alternately, you can add a preprocessor constant
	 * for different call groups
	*/
	switch (current->op_code) {

		// These calls needed to be ignored for the normal operation of the
		// submitted snap of TikTok
		// Finit_module and exit were left after the debugging run, but the system
		// runs perfectly fine with the protected
		case __NR_futex:
		case __NR_execve:
		//case __NR_finit_module:
		//case __NR_exit:
		case __NR_rt_sigtimedwait:

		// These calls were added as an optimization
		// The OS usually is not interested in the content of write calls, so
		// they do not need to be protected
		case __NR_writev:
		case __NR_pwrite64:
		case __NR_pwritev2:
		case __NR_write:
			return 0;
		
		/*
		// The additional calls represent the most frequent calls in the benchmarks
		//
		case __NR_epoll_ctl:
		case __NR_close:
		//case __NR_write:
		case __NR_read:
		case __NR_fcntl:
		case __NR_connect:
		case __NR_recvfrom:
		case __NR_epoll_wait:
		//case __NR_futex:
		case __NR_accept4:
		case __NR_openat:
		case __NR_socket:
		//case __NR_writev:
		case __NR_shutdown:
		case __NR_fstat:
		case __NR_sendfile:
		case __NR_stat:
		case __NR_mmap:
		case __NR_munmap:
		case __NR_getsockname:
		case __NR_times:*/
		// case -1:
		// 	return 0;
	}

    return 1;
    
    /* Allowlist for testing */
    switch (current->op_code) {
        case __NR_write:
        case __NR_pipe:
            return 1;
    }

    return 0;
}


static bool page_mark_one(struct page *page, struct vm_area_struct *vma,
		     unsigned long address, void *arg)
{
    pte_t *ppte, entry;
    struct mm_struct *mm = vma->vm_mm;
    /* Set up the structure to walk the PT in the current mapping */
	struct page_vma_mapped_walk pvmw = {
		.page = page,
		.vma = vma,
		.address = address,
	};

    while (page_vma_mapped_walk(&pvmw)) {
		ppte = pvmw.pte;
        entry = *ppte;
        BUG_ON(!pte_present(entry));
        BUG_ON(pte_rmarked(entry));

        /* Marking at the actual page tables */
        set_pte_at(mm, pvmw.address, ppte, pte_rmark(entry));
        flush_tlb_page(vma, pvmw.address);
    }

    return true;
}

bool page_unmark_one(struct page *page, struct vm_area_struct *vma,
		     unsigned long address, void *arg) 
{
    pte_t *ppte, entry;
    struct mm_struct *mm = vma->vm_mm;
    struct page_vma_mapped_walk pvmw = {
		.page = page,
		.vma = vma,
		.address = address,
	};

    while (page_vma_mapped_walk(&pvmw)) {
        ppte = pvmw.pte;
        entry = *ppte;
        BUG_ON(!pte_present(entry));
        BUG_ON(!pte_rmarked(entry));

        set_pte_at(mm, pvmw.address, ppte, pte_runmark(entry));
        flush_tlb_page(vma, pvmw.address);
    }
    return true;
}
EXPORT_SYMBOL(page_unmark_one);

static
unsigned long mark_and_read_subpage(uintptr_t id, unsigned long dst, unsigned long src, unsigned long size) {
    unsigned tries;
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *ptep, pte;
    struct page *pframe;
    void *copy_vaddr;
    struct page_snap *sysc_snap = NULL, *iter_snap = NULL;
    struct marked_frame *new_marked_pframe;
    /* Pre-setup for structure which walks reverse mappings for a frame */
	struct rmap_walk_control rwc = {
        .arg = NULL,
		.rmap_one = page_mark_one,
		.anon_lock = page_lock_anon_vma_read,
	};
    unsigned long ret;
    int unduped = 0;

    /* Reading within a single page */
    BUG_ON(((src + size - 1) & PAGE_SIZE) != (src & PAGE_SIZE));
    // BUG_ON(((dst + size - 1) & PAGE_SIZE) != (dst & PAGE_SIZE));

    /* We try this only thrice */
    for(tries = 0; tries < 4; tries++) {

        pgd = pgd_offset(current->mm, src);
        if(!pgd_present(*pgd)) {
            mm_populate(src & PAGE_MASK, PAGE_SIZE);
            /* Try again from scratch */
            continue;
        }

        p4d = p4d_offset(pgd, src);
        if(!p4d_present(*p4d)) {
            mm_populate(src & PAGE_MASK, PAGE_SIZE);
            /* Try again from scratch */
            continue;
        }

        pud = pud_offset(p4d, src);
        if(!pud_present(*pud)) {
            mm_populate(src & PAGE_MASK, PAGE_SIZE);
            /* Try again from scratch */
            continue;
        }

        pmd = pmd_offset(pud, src);
        if(!pmd_present(*pmd)) {
            mm_populate(src & PAGE_MASK, PAGE_SIZE);
            /* Try again from scratch */
            continue;
        }

        ptep = pte_offset_map(pmd, src);
        if(!pte_present(*ptep)) {
            mm_populate(src & PAGE_MASK, PAGE_SIZE);
            /* Try again from scratch */
            continue;
        }
        
        pte = *ptep;
        /* Here is our page frame */
        pframe = pte_page(pte);

        /* Prevent frame from being evicted. 
         * Double mark_page_accessed triggers activate_page, putting it on the active list.
         * Active pages should not get swapped out */
        mark_page_accessed(pframe);
        mark_page_accessed(pframe);

        mutex_lock(&pframe->snaps_lock);
        if(!pte_same(pte, *ptep)) {
            mutex_unlock(&pframe->snaps_lock);
            continue;
        }
        mutex_lock(&current->markings_lock);
        /* Check the list of duplicates for the frame to see if there is one corresponding to 
         * this syscall */
        list_for_each_entry(iter_snap, &pframe->snaps, other_nodes) {
            if(iter_snap->task == current) 
                sysc_snap = iter_snap;
            if(!iter_snap->copy)
                unduped = 1;            
        }
        if(sysc_snap == NULL) {  /* No snapshot for this syscall */
            sysc_snap = (struct page_snap *)kmem_cache_alloc(snaps_cache, GFP_KERNEL);
            BUG_ON(sysc_snap == NULL);
            BUG_ON(current == NULL);
            sysc_snap->task = current;
            sysc_snap->copy = NULL;
            /* New snap for the page frame */
            list_add(&sysc_snap->other_nodes, &pframe->snaps);

            /* New marked frame for this syscall */
            new_marked_pframe = (struct marked_frame *)kmem_cache_alloc(marked_frames_cache, GFP_KERNEL);
            BUG_ON(new_marked_pframe == NULL);
            new_marked_pframe->pframe = pframe;
            list_add(&new_marked_pframe->other_nodes, &current->marked_frames);
            copy_vaddr = page_address(pframe);

            /* If unduped, some snapshot had a NULL copy i.e. was pointing to the latest copy.
             * => In states 1 or 3, where page is already protected.
             * If !unduped, no snapshot points to the latest copy.
             * => Either state 0 or 2, and we need to protect page (calling page_mark_one)
             */
            if(!unduped)
                rmap_walk(pframe, &rwc);

        } else{
            if (sysc_snap->copy == NULL) /* Existing snapshot points to latest copy */
                copy_vaddr = page_address(pframe);
            else                              /* Existing snapshot to duplicate copy */
                copy_vaddr = &sysc_snap->copy->data;

        }
        mutex_unlock(&pframe->snaps_lock);
        mutex_unlock(&current->markings_lock);

        BUG_ON(copy_vaddr == NULL);
        src = (uintptr_t)copy_vaddr + (src & ~PAGE_MASK);

        ret = __raw_copy_from_user((void *)dst, (const void *)src, size);
        return ret;
    }

    return size;
}

unsigned long __must_check
raw_copy_to_user(void __user *dst, const void *src, unsigned long size) {
    return __raw_copy_to_user(dst, src, size);
}
EXPORT_SYMBOL(raw_copy_to_user);

unsigned long __must_check
raw_copy_from_user(void *dst, const void __user *src, unsigned long size) {
    uintptr_t id, address, cur_dst, cur_src;
    unsigned long cur_sz, remaining_sz, unread_sz;
    struct vm_area_struct *vma;

    id = get_syscall_identifier();

	might_fault();
    if(should_mark() && likely(access_ok(src, size))) {
        remaining_sz = size;
        cur_src = (uintptr_t)src;
        cur_dst = (uintptr_t)dst;
        vma = find_vma(current->mm, (uintptr_t) src);

        /* Individually handle each page */
        for(address = (uintptr_t) src & PAGE_MASK;
            address < (uintptr_t) (src + size);
            address += PAGE_SIZE) {

            cur_sz = (((cur_src + remaining_sz) & PAGE_MASK) == address)? 
                        remaining_sz :
                        PAGE_SIZE - (cur_src - address);


			if (address >= vma->vm_end) vma = vma->vm_next;
            //TODO: Shouldn't the next line be a BUG?
			if (unlikely(!vma)) break;

            unread_sz = mark_and_read_subpage(id, cur_dst, cur_src, cur_sz);
            remaining_sz -= (cur_sz - unread_sz);

            /* If unable to copy entire part, end of copy */
            if(unread_sz != 0) 
                return remaining_sz;

            cur_dst += cur_sz;
            cur_src += cur_sz;
        }

        /* remaining_sz should always be zero */
        return remaining_sz;
    } else /* Use standard method */
        return __raw_copy_from_user(dst, src, size);
}
EXPORT_SYMBOL(raw_copy_from_user);

void syscall_marking_cleanup() {
	struct marked_frame *marked_frame, *next;
    struct task_struct *curtsk = current;
	struct page_snap *iter_snap = NULL, *sysc_snap = NULL;
    int irq_dis, count_undup;
    struct rmap_walk_control rwc = {
        .arg = NULL,
        .rmap_one = page_unmark_one,
        .anon_lock = page_lock_anon_vma_read,
    };
#ifdef CONFIG_TOCTTOU_ACCOUNTING
    unsigned long local_snap_counter = 0, local_copy_counter = 0;
    unsigned long tmp;
#endif

    /* Enabling interrupts to prevent warning when flushing
        * TLBs with smp_call_function_many_cond as part of this rwalk 
        * which calls page_unmark_one. */
    irq_dis = irqs_disabled();
    local_irq_enable();

retry_syscall_cleanup:
	/* Reset the system call information */	
    mutex_lock(&curtsk->markings_lock);
	list_for_each_entry_safe(marked_frame, next, &curtsk->marked_frames, other_nodes) {
        /* Preventing mutex deadlock with COW tocttou page duplication code by backing
         * off */
        if(mutex_trylock(&marked_frame->pframe->snaps_lock) == 0) {
            mutex_unlock(&curtsk->markings_lock);
            goto retry_syscall_cleanup;
        }

#ifdef CONFIG_TOCTTOU_ACCOUNTING
        local_snap_counter++;
#endif
		/* Find and delete snap */
        count_undup = 0;
		list_for_each_entry(iter_snap, &marked_frame->pframe->snaps, other_nodes) {
			if(iter_snap->task == curtsk)
				sysc_snap = iter_snap;
            if(iter_snap->copy == NULL)
                count_undup++;
		}
		BUG_ON(sysc_snap == NULL);

		if(sysc_snap->copy) {
            /* When a copy exists, it gets freed along with the last snap which points
             * to it */
            if(sysc_snap->copy->refcount-- == 1) {
    			tocttou_duplicate_page_free(sysc_snap->copy);
#ifdef CONFIG_TOCTTOU_ACCOUNTING
                local_copy_counter++;
#endif
            }
        } else {
            /* When the last snapshot pointing to latest copy is released, unprotect */
            if(count_undup == 1)
                rmap_walk(marked_frame->pframe, &rwc);
        }
		list_del(&sysc_snap->other_nodes);
		kmem_cache_free(snaps_cache, sysc_snap);

		list_del(&marked_frame->other_nodes);
        mutex_unlock(&marked_frame->pframe->snaps_lock);
		kmem_cache_free(marked_frames_cache, marked_frame);
	}
    mutex_unlock(&curtsk->markings_lock);

    if(irq_dis)
        local_irq_disable();

#ifdef CONFIG_TOCTTOU_ACCOUNTING
    __atomic_add_fetch (&snapshot_counter, local_snap_counter, __ATOMIC_RELAXED);
    __atomic_add_fetch (&copy_counter, local_copy_counter, __ATOMIC_RELAXED);
    tmp = __atomic_add_fetch (&syscall_counter, 1, __ATOMIC_SEQ_CST);

    if((tmp & 0xffffful) == 0)
        printk("Syscall %lu snapshot %lu copy %lu\n", 
                    tmp, 
                    __atomic_load_n (&snapshot_counter, __ATOMIC_RELAXED), 
                    __atomic_load_n (&copy_counter, __ATOMIC_RELAXED));
#endif
}
EXPORT_SYMBOL(syscall_marking_cleanup);

#endif /* CONFIG_TOCTTOU_PROTECTION */