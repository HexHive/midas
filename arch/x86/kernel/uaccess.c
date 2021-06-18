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
static void *markings_cache;
static void *snaps_cache;
static void *marked_frames_cache;
DEFINE_PER_CPU(struct page_marking *, prealloc_markings[CONFIG_MAX_PREALLOC]);
DEFINE_PER_CPU(struct page_marking *, prealloc_markings[CONFIG_MAX_PREALLOC]);
DEFINE_PER_CPU(int, prealloc_markings_count);
DEFINE_PER_CPU(int, prealloc_markings_count);
#ifdef CONFIG_TOCTTOU_ACCOUNTING
static unsigned syscall_counter, snapshot_counter, copy_counter;
#endif

void __init tiktok_init(void) {
    int cpu, i;

#ifdef CONFIG_TOCTTOU_ACCOUNTING
    syscall_counter = 0;
    snapshot_counter = 0;
    copy_counter = 0;
#endif

    duplicate_page_cache = kmem_cache_create("dup_page_cache", sizeof(struct page_copy), PAGE_SIZE, SLAB_POISON, NULL);
    BUG_ON(!duplicate_page_cache);

    markings_cache = kmem_cache_create("markings_cache", sizeof(struct page_marking), __alignof__(struct page_marking), SLAB_POISON, NULL);
    BUG_ON(!markings_cache);

    snaps_cache = kmem_cache_create("snaps_cache", sizeof(struct page_snap), __alignof__(struct page_snap), SLAB_POISON, NULL);
    BUG_ON(!snaps_cache);

    marked_frames_cache = kmem_cache_create("marked frames cache", sizeof(struct marked_frame), __alignof__(struct marked_frame), SLAB_POISON, NULL);
    BUG_ON(!marked_frames_cache);

    for_each_possible_cpu(cpu) {
        for(i = 0; i < CONFIG_MAX_PREALLOC; i++) {
            per_cpu(prealloc_markings, cpu)[i] = tocttou_page_marking_alloc();
        }
        per_cpu(prealloc_markings_count, cpu) = CONFIG_MAX_PREALLOC;
    }
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

struct page_marking *tocttou_page_marking_alloc(void) {
    struct page_marking *marking = kmem_cache_alloc(markings_cache, GFP_KERNEL); 
    BUG_ON(!marking);
    marking->vaddr = 0;
    marking->owner_count = 0;
    return marking;
}

void tocttou_page_marking_free(struct page_marking *marking) {
    BUG_ON(!marking);
    BUG_ON(marking->owner_count != 0);
	kmem_cache_free(markings_cache, marking);
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
		case __NR_poll:
		case __NR_select:
		case __NR_execve:
		//case __NR_finit_module:
		//case __NR_exit:
		case __NR_pselect6:
		case __NR_ppoll:
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
    struct page_marking *marking;
    unsigned i = 0;
    /* Set up the structure to walk the PT in the current mapping */
	struct page_vma_mapped_walk pvmw = {
		.page = page,
		.vma = vma,
		.address = address,
	};
    int count = 0;
    struct mm_struct *mm = vma->vm_mm;
    BUG_ON(mm == NULL);
    mutex_lock(&mm->marked_pages_lock);

    while (page_vma_mapped_walk(&pvmw)) {
        BUG_ON(count != 0);
        count++;
		ppte = pvmw.pte;

        entry = *ppte;
        BUG_ON(!pte_present(entry));

        if (pte_rmarked(entry)) {
            list_for_each_entry(marking, &mm->marked_pages, other_nodes) {
                if(marking->vaddr == address) {
                    break;
                }
            }
            /* Bug if metadata not found */
            BUG_ON(&marking->other_nodes == &mm->marked_pages);
            marking->owner_count++;
        } else { /* Not marked yet, will mark */

            /* Find an available buffer, and take it. 
             * Mark acquisition by NULLing that space */
            do {
                i = get_cpu_var(prealloc_markings_count);
                BUG_ON(i == 0);
                marking = get_cpu_var(prealloc_markings)[i - 1];
                get_cpu_var(prealloc_markings_count) = i - 1;
            } while (marking == NULL);
            get_cpu_var(prealloc_markings)[i - 1] = NULL;
            marking->vaddr = address;
            marking->owner_count = 1;
            list_add(&marking->other_nodes, &mm->marked_pages);

            /* Marking at the actual page tables */
            set_pte_at(mm, pvmw.address, ppte, pte_rmark(entry));
			flush_tlb_page(vma, pvmw.address);
        }
    }
    mutex_unlock(&mm->marked_pages_lock);

    return true;
}

bool page_unmark_one(struct page *page, struct vm_area_struct *vma,
		     unsigned long address, void *arg) 
{
    pte_t *ppte, entry;
    struct page_marking *marking;
    struct page_vma_mapped_walk pvmw = {
		.page = page,
		.vma = vma,
		.address = address,
	};
    int tmp_owner_count, n_owners_released = *(int *)arg;
    struct mm_struct *mm = vma->vm_mm;
    BUG_ON(mm == NULL);
    mutex_lock(&mm->marked_pages_lock);

    while (page_vma_mapped_walk(&pvmw)) {
        ppte = pvmw.pte;
        entry = *ppte;
        BUG_ON(!pte_present(entry));
        BUG_ON(!pte_rmarked(entry));

        list_for_each_entry(marking, &mm->marked_pages, other_nodes) {
            if(marking->vaddr == address) {
                break;
            }
        }
        /* Bug if metadata not found */
        BUG_ON(&marking->other_nodes == &mm->marked_pages);
        
        /* Release node from markings list when last owner */
        tmp_owner_count = marking->owner_count;
        BUG_ON(tmp_owner_count < n_owners_released);
        tmp_owner_count -= n_owners_released;
        marking->owner_count = tmp_owner_count;
        if(tmp_owner_count == 0) {
            list_del(&marking->other_nodes);
            tocttou_page_marking_free(marking);
            set_pte_at(mm, pvmw.address, ppte, pte_runmark(entry));
			flush_tlb_page(vma, pvmw.address);
        }
    }
    mutex_unlock(&mm->marked_pages_lock);
    return true;
}
EXPORT_SYMBOL(page_unmark_one);

void tocttou_file_mark_start(struct file *file) {
    /* TODO */
}

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
    struct page_snap *iter_snap, *new_marked_snap;
    struct marked_frame *new_marked_pframe;
    /* Pre-setup for structure which walks reverse mappings for a frame */
	struct rmap_walk_control rwc = {
        .arg = NULL,
		.rmap_one = page_mark_one,
		.anon_lock = page_lock_anon_vma_read,
	};
    unsigned long ret;
    int i;

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
            if(iter_snap->task == current) {
                break;
            }
        }
        if(&iter_snap->other_nodes == &pframe->snaps) {  /* Unmarked, unduplicated: Add to pframe */
            
            new_marked_snap = (struct page_snap *)kmem_cache_alloc(snaps_cache, GFP_KERNEL);
            BUG_ON(new_marked_snap == NULL);
            new_marked_snap->task = current;
            new_marked_snap->copy = NULL;
            /* New snap for the page frame */
            list_add(&new_marked_snap->other_nodes, &pframe->snaps);

            /* New marked frame for this syscall */
            new_marked_pframe = (struct marked_frame *)kmem_cache_alloc(marked_frames_cache, GFP_KERNEL);
            BUG_ON(new_marked_pframe == NULL);
            new_marked_pframe->pframe = pframe;
            list_add(&new_marked_pframe->other_nodes, &current->marked_frames);
            copy_vaddr = page_address(pframe);

            /* Visit all VM spaces that map this page and mark the mapings
             * rwc.arg holds the preallocated struct page_marking because we cannot
             * call kmalloc under spinlocks. Calls page_mark_one.
             * Space allocated here. If not used, freed after the rmap_walk.
             * If needed during page_mark_one, added to VMA marked_pages list. 
             * Then freed during page_unmark_one. */
            for(i = 0; i < CONFIG_MAX_PREALLOC; i++) {
                if(!get_cpu_var(prealloc_markings)[i])
                    get_cpu_var(prealloc_markings)[i] = tocttou_page_marking_alloc();
            }
            get_cpu_var(prealloc_markings_count) = CONFIG_MAX_PREALLOC;
            rmap_walk(pframe, &rwc);

        } else{
            if (iter_snap->copy == NULL) /* Marked, unduplicated: Reading from original pframe */
                copy_vaddr = page_address(pframe);
            else                              /* Marked, duplicated: Read from iter_snap's pframe */
                copy_vaddr = &iter_snap->copy->data;

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
			if (unlikely(!vma)) break;
            /* TODO: Understand what parts of files are marked, and how */
			if (vma->vm_file && (vma->vm_flags & VM_SHARED)) 
                tocttou_file_mark_start(vma->vm_file);

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
	struct page_snap *snap;
    int owners_released = 1, irq_dis;
    struct rmap_walk_control rwc = {
        .arg = &owners_released,
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
    mutex_lock(&current->markings_lock);
	list_for_each_entry_safe(marked_frame, next, &current->marked_frames, other_nodes) {
        /* Preventing mutex deadlock with COW tocttou page duplication code by backing
         * off */
        if(mutex_trylock(&marked_frame->pframe->snaps_lock) == 0) {
            mutex_unlock(&current->markings_lock);
            goto retry_syscall_cleanup;
        }

#ifdef CONFIG_TOCTTOU_ACCOUNTING
        local_snap_counter++;
#endif
		/* Find and delete snap */
		list_for_each_entry(snap, &marked_frame->pframe->snaps, other_nodes) {
			if(snap->task == current)
				break;
		}
		BUG_ON(snap == NULL);


		/* Release frame for marked, duplicated frames. Duplication happened in 
         * the page-fault handler, which also unmarked them. 
         * For unduplicated ones, unmark */
		if(snap->copy) {
            if(snap->copy->refcount-- == 1) {
    			tocttou_duplicate_page_free(snap->copy);
#ifdef CONFIG_TOCTTOU_ACCOUNTING
                local_copy_counter++;
#endif
            }
        } else {
            /* Reverse walk to unmark all virtual pages */
            rmap_walk(marked_frame->pframe, &rwc);
        }
		list_del(&snap->other_nodes);
		kmem_cache_free(snaps_cache, snap);

		list_del(&marked_frame->other_nodes);
        mutex_unlock(&marked_frame->pframe->snaps_lock);
		kmem_cache_free(marked_frames_cache, marked_frame);
	}
    mutex_unlock(&current->markings_lock);

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