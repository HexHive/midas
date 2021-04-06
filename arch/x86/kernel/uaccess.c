#include <asm/tlbflush.h>
#include <linux/mm.h>
#include <linux/rmap.h>
#include <linux/swap.h>
#include <linux/uaccess.h>
#include "../../mm/internal.h"

#define MARKER() printk("Function %s:%d\n", __func__, __LINE__);

#ifdef CONFIG_TOCTTOU_PROTECTION
#define CONFIG_MAX_CORES 4

void *tocttou_duplicate_page_alloc()
{
    // TODO: Set up duplicate page cache
	// return kmem_cache_alloc(tocttou_duplicate_page_cache, GFP_KERNEL);
    struct page *pframe = alloc_page(GFP_USER);
    pframe->version_refcount = 0;
    return pframe;
}

void tocttou_duplicate_page_free(struct page *pframe)
{
    BUG_ON(pframe->version_refcount != 0);
    // TODO: Set up duplicate page cache
	// kmem_cache_free(tocttou_duplicate_page_cache, page);
    __free_page(pframe);
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

	if (!current->pid)
		return 0;

    /* TODO: Copied from Uros. What does this mean? */
	if (current->flags & PF_EXITING) {
		return 0;
	}

    /* Here we ignore certain calls. Before benchmarking, make sure that the
	 * appropriate calls are uncommented. Alternately, you can add a preprocessor constant
	 * for different call groups
	*/
	switch (current->op_code) {

		// These calls needed to be ignored for the normal operation of the
		// submitted version of TikTok
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
		case __NR_nanosleep:

		// These calls were added as an optimization
		// The OS usually is not interested in the content of write calls, so
		// they do not need to be protected
		// case __NR_writev:
		// case __NR_pwrite64:
		// case __NR_pwritev2:
		// case __NR_write:
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
		case -1:
			return 0;
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
    pte_t * ppte;
    struct page_marking *marking, **spaces;
    unsigned i;
    /* Set up the structure to walk the PT in the current mapping */
	struct page_vma_mapped_walk pvmw = {
		.page = page,
		.vma = vma,
		.address = address,
	};

    int count = 0;
    while (page_vma_mapped_walk(&pvmw)) {
        BUG_ON(count != 0);
        count++;
		ppte = pvmw.pte;

        if (pte_rmarked(*ppte)) {
            list_for_each_entry(marking, &vma->marked_pages, other_nodes) {
                if(marking->vaddr == address) {
                    break;
                }
            }
            /* Bug if metadata not found */
            BUG_ON(&marking->other_nodes == &vma->marked_pages);
            marking->owner_count++;
        } else { /* Not marked yet, will mark */
            spaces = arg;
            for(i = 0; i < CONFIG_MAX_CORES; i++){
                marking = spaces[i];
                if(marking) {
                    spaces[i] = NULL; /* Marking that I have taken the provided buffer */
                    break;
                }
            }
            BUG_ON(i == CONFIG_MAX_CORES);
            marking->vaddr = address;
            marking->owner_count = 1;
            list_add(&marking->other_nodes, &vma->marked_pages);
            /* Add a 'reader' to mmap_lock for every marked page in the VMA.
             * This ensures that the VMAs will not change (split/merge)
             * until there are no markings in the address space.
             * Operations that change VMAs should be part of the setup phase
             * of programs, and not affect their main runtime */
            down_read(&vma->vm_mm->mmap_lock);

            /* Marking at the actual page tables */
            set_pte_at(vma->vm_mm, pvmw.address, ppte, pte_rmark(*ppte));
			flush_tlb_page(vma, pvmw.address);
        }
    }
    return true;
}

bool page_unmark_one(struct page *page, struct vm_area_struct *vma,
		     unsigned long address, void *arg) 
{
    pte_t *ppte;
    struct page_marking *marking;
    struct page_vma_mapped_walk pvmw = {
		.page = page,
		.vma = vma,
		.address = address,
	};
    int tmp_owner_count, n_owners_released = *(int *)arg;

    while (page_vma_mapped_walk(&pvmw)) {
        ppte = pvmw.pte;
        BUG_ON(!pte_rmarked(*ppte));

        list_for_each_entry(marking, &vma->marked_pages, other_nodes) {
            if(marking->vaddr == address) {
                break;
            }
        }
        /* Bug if metadata not found */
        BUG_ON(&marking->other_nodes == &vma->marked_pages);
        
        /* Release node from markings list when last owner */
        tmp_owner_count = marking->owner_count;
        BUG_ON(tmp_owner_count < n_owners_released);
        tmp_owner_count -= n_owners_released;
        marking->owner_count = tmp_owner_count;
        if(tmp_owner_count == 0) {
            list_del(&marking->other_nodes);
            kfree(marking);
            set_pte_at(vma->vm_mm, pvmw.address, ppte, pte_runmark(*ppte));
			flush_tlb_page(vma, pvmw.address);
            /* Release 'readers' for the VMA's address space. When there are 
            * no markings for the address space, it can be modified, allowing
            * split/merge of VMAs */
            up_read(&vma->vm_mm->mmap_lock);
        }
    }
    return true;
}
EXPORT_SYMBOL(page_unmark_one);

void tocttou_file_mark_start(struct file *file) {
    /* TODO */
}

static
unsigned long mark_and_read_subpage(uintptr_t id, unsigned long dst, unsigned long src, unsigned long size) {
    unsigned tries, i;
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *ptep, pte;
    struct page *pframe, *pframe_copy;
    void *pframe_vaddr, *new_marking_space[CONFIG_MAX_CORES];
    struct page_version *iter_version, *new_marked_version;
    struct marked_frame *new_marked_pframe;
    struct vm_area_struct *vma;
    /* Pre-setup for structure which walks reverse mappings for a frame */
	struct rmap_walk_control rwc = {
        .arg = NULL,
		.rmap_one = page_mark_one,
		.anon_lock = page_lock_anon_vma_read,
	};

    /* Reading within a single page */
    BUG_ON(((src + size - 1) & PAGE_SIZE) != (src & PAGE_SIZE));
    BUG_ON(((dst + size - 1) & PAGE_SIZE) != (dst & PAGE_SIZE));


    /* We try this only thrice */
    for(tries = 0; tries < 3; tries++) {
        spin_lock(&current->mm->page_table_lock);

        pgd = pgd_offset(current->mm, src);
        if(!pgd_present(*pgd)) {
            spin_unlock(&current->mm->page_table_lock);
            mm_populate(src & PAGE_MASK, PAGE_SIZE);
            /* Try again from scratch */
            continue;
        }

        p4d = p4d_offset(pgd, src);
        if(!p4d_present(*p4d)) {
            spin_unlock(&current->mm->page_table_lock);
            mm_populate(src & PAGE_MASK, PAGE_SIZE);
            /* Try again from scratch */
            continue;
        }

        pud = pud_offset(p4d, src);
        if(!pud_present(*pud)) {
            spin_unlock(&current->mm->page_table_lock);
            mm_populate(src & PAGE_MASK, PAGE_SIZE);
            /* Try again from scratch */
            continue;
        }

        pmd = pmd_offset(pud, src);
        if(!pmd_present(*pmd)) {
            spin_unlock(&current->mm->page_table_lock);
            mm_populate(src & PAGE_MASK, PAGE_SIZE);
            /* Try again from scratch */
            continue;
        }

        ptep = pte_offset_map(pmd, src);
        if(!pte_present(*ptep)) {
            spin_unlock(&current->mm->page_table_lock);
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

        mutex_lock(&pframe->versions_lock);
        /* Check the list of duplicates for the frame to see if there is one corresponding to 
         * this syscall */
        list_for_each_entry(iter_version, &pframe->versions, other_nodes) {
            if(iter_version->task == current) {
                break;
            }
        }
        if(&iter_version->other_nodes == &pframe->versions) {  /* Unmarked, unduplicated: Add to pframe */
            
            new_marked_version = (struct page_version *)kzalloc(sizeof(struct page_version), GFP_KERNEL);
            if(new_marked_version == NULL)
                return size;
            new_marked_version->task = current;
            new_marked_version->pframe = NULL;
            /* New version for the page frame */
            list_add(&new_marked_version->other_nodes, &pframe->versions);

            /* New marked frame for this syscall */
            new_marked_pframe = (struct marked_frame *)kzalloc(sizeof(struct marked_frame), GFP_KERNEL);
            new_marked_pframe->pframe = pframe;
            mutex_lock(&current->markings_lock);
            list_add(&new_marked_pframe->other_nodes, &current->marked_frames);
            mutex_unlock(&current->markings_lock);
            pframe_copy = pframe;

            /* Marked pages also become read-only */
		    vma = find_vma(current->mm, src);
            /* Visit all VM spaces that map this page and mark the mapings
             * rwc.arg holds the preallocated struct page_marking because we cannot
             * call kmalloc under spinlocks. Calls page_mark_one.
             * Space allocated here. If not used, freed after the rmap_walk.
             * If needed during page_mark_one, added to VMA marked_pages list. 
             * Then freed during page_unmark_one. */
            for(i = 0; i < CONFIG_MAX_CORES; i++){
                new_marking_space[i] = kzalloc(sizeof(struct page_marking), GFP_KERNEL);
                BUG_ON(new_marking_space[i] == NULL);
            }
            rwc.arg = &new_marking_space;
            rmap_walk(pframe, &rwc);
            for(i = 0; i < CONFIG_MAX_CORES; i++)
                if(new_marking_space[i]) 
                    kfree(new_marking_space[i]);

            spin_unlock(&current->mm->page_table_lock);
        } else{
            if (iter_version->pframe == NULL) /* Marked, unduplicated: Reading from original pframe */
                pframe_copy = pframe;
            else                              /* Marked, duplicated: Read from iter_version's pframe */
                pframe_copy = page_address(iter_version->pframe);

            spin_unlock(&current->mm->page_table_lock);
        }
        mutex_unlock(&pframe->versions_lock);

        pframe_vaddr = page_address(pframe_copy);
        BUG_ON(pframe_vaddr == NULL);
        src = (uintptr_t)pframe_vaddr + (src & ~PAGE_MASK);

        return __raw_copy_from_user((void *)dst, (const void *)src, size);
    }

    BUG();
    return size;
}

#define CONFIG_RAW_COPY_BUFFER_THRESHOLD (PAGE_SIZE * 2)

unsigned long __must_check
raw_copy_to_user(void __user *dst, const void *src, unsigned long size) {
    return __raw_copy_to_user(dst, src, size);
}
EXPORT_SYMBOL(raw_copy_to_user);

// #if !defined(INLINE_COPY_FROM_USER)

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
// #endif /* !defined(INLINE_COPY_FROM_USER) */

void syscall_marking_cleanup() {
	struct marked_frame *marked_frame, *next;
	struct page_version *version;
    int owners_released = 1, irq_dis;

    // printk("%d: syscall %d cleanup (%px)\n", current->pid, current->op_code, current);
    struct rmap_walk_control rwc = {
        .arg = &owners_released,
        .rmap_one = page_unmark_one,
        .anon_lock = page_lock_anon_vma_read,
    };
	/* Reset the system call information */	
    mutex_lock(&current->markings_lock);
	list_for_each_entry_safe(marked_frame, next, &current->marked_frames, other_nodes) {
        mutex_lock(&marked_frame->pframe->versions_lock);

		/* Find and delete version */
		list_for_each_entry(version, &marked_frame->pframe->versions, other_nodes) {
			if(version->task == current)
				break;
		}
		BUG_ON(version == NULL);


		/* Release frame for marked, duplicated frames. Duplication happened in 
         * the page-fault handler, which also unmarked them. 
         * For unduplicated ones, unmark */
		if(version->pframe) {
            if(version->pframe->version_refcount-- == 1)
    			tocttou_duplicate_page_free(version->pframe);
        } else {
            /* Enabling interrupts to prevent warning when flushing
             * TLBs with smp_call_function_many_cond as part of this rwalk 
             * which calls page_unmark_one. */
            irq_dis = irqs_disabled();
            local_irq_enable();
            /* Reverse walk to unmark all virtual pages */
            rmap_walk(marked_frame->pframe, &rwc);
            if(irq_dis)
                local_irq_disable();
        }
        //TODO: Optimization, delete from list first, release lock, then complete stuff
		list_del(&version->other_nodes);
		kfree(version);

		list_del(&marked_frame->other_nodes);
        mutex_unlock(&marked_frame->pframe->versions_lock);
		kfree(marked_frame);
	}
    mutex_unlock(&current->markings_lock);
}
EXPORT_SYMBOL(syscall_marking_cleanup);

#endif /* CONFIG_TOCTTOU_PROTECTION */