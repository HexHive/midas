#include <linux/mm.h>
#include <linux/rmap.h>
#include <linux/swap.h>
#include <linux/uaccess.h>
#include "../../mm/internal.h"

#define MARKER() printk("Function %s:%d\n", __func__, __LINE__);

#ifdef CONFIG_TOCTTOU_PROTECTION
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
		// 	return 0;
		
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

    /* Allowlist for testing */
    switch (current->op_code) {
        case __NR_write:
            return 1;
    }

    return 0;
}


static bool page_mark_one(struct page *page, struct vm_area_struct *vma,
		     unsigned long address, void *arg)
{
    pte_t * ppte;
    struct page_marking *marking;
    /* Set up the structure to walk the PT in the current mapping */
	struct page_vma_mapped_walk pvmw = {
		.page = page,
		.vma = vma,
		.address = address,
	};
    printk("Marking address %px\n", address);

    int count = 0;
    while (page_vma_mapped_walk(&pvmw)) {
        BUG_ON(count != 0);
        count++;
		ppte = pvmw.pte;

        if (pte_rmarked(*ppte)) {
            MARKER();
            list_for_each_entry(marking, &vma->marked_pages, other_nodes) {
                if(marking->vaddr == address) {
                    break;
                }
            }
            /* Bug if metadata not found */
            BUG_ON(&marking->other_nodes == &vma->marked_pages);
            MARKER();
            marking->owner_count++;
        } else { /* Not marked yet, will mark */
            MARKER();
            BUG_ON(*(void **)arg == NULL);
            marking = *(struct page_marking **)arg;
            *(void **)arg = NULL; /* Marking that I have taken the provided buffer */
            marking->vaddr = address;
            marking->owner_count = 1;
            MARKER();
            printk("%px %px %px\n", &vma->marked_pages, vma->marked_pages.next, vma->marked_pages.prev);
            list_add(&marking->other_nodes, &vma->marked_pages);
            // printk("marking %px other next %px prev %px\n", marking, marking->other_nodes.next, marking->other_nodes.prev);
            MARKER();
            set_pte_at(vma->vm_mm, pvmw.address, ppte, pte_rmark(*ppte));
        }
        //TODO: Handle the cases where mmap/mprotect split or merge vmas
    }
    printk("Marking done \n");
    return true;
}

static bool page_unmark_one(struct page *page, struct vm_area_struct *vma,
		     unsigned long address, void *arg) 
{
    pte_t *ppte;
    struct page_marking *marking;
    struct page_vma_mapped_walk pvmw = {
		.page = page,
		.vma = vma,
		.address = address,
	};
    printk("Trying to unmark address %px\n", address);

    while (page_vma_mapped_walk(&pvmw)) {
        ppte = pvmw.pte;
        BUG_ON(!pte_rmarked(*ppte));

        // printk("Here at %s:%d\n", __func__, __LINE__);
        list_for_each_entry(marking, &vma->marked_pages, other_nodes) {
            if(marking->vaddr == address) {
                break;
            }
        }
        /* Bug if metadata not found */
        BUG_ON(&marking->other_nodes == &vma->marked_pages);
        // printk("Here at %s:%d\n", __func__, __LINE__);
        
        /* Release node from markings list when last owner */
        if((marking->owner_count--) == 1) {
            // printk("Here at %s:%d\n", __func__, __LINE__);
            // printk("marking %px other next %px prev %px\n", marking, marking->other_nodes.next, marking->other_nodes.prev);
            list_del(&marking->other_nodes);
            kfree(marking);
            set_pte_at(vma->vm_mm, pvmw.address, ppte, pte_runmark(*ppte));
        }
    }
    printk("Unmarking done \n");
    return true;
}

void tocttou_file_mark_start(struct file *file) {
    /* TODO */
}

unsigned long mark_and_read_subpage(uintptr_t id, unsigned long dst, unsigned long src, unsigned long size) {
    unsigned tries;
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *ptep, pte;
    struct page *pframe, *pframe_copy;
    void *pframe_vaddr, *new_marking_space;
    struct page_version *iter_version, *new_marked_version;
    struct marked_frame *new_marked_pframe;
    struct vm_area_struct *vma;
    /* Pre-setup for structure which walks reverse mappings for a frame */
	struct rmap_walk_control rwc = {
        .arg = NULL,
		.rmap_one = page_mark_one,
		.anon_lock = page_lock_anon_vma_read,
	};

    MARKER();

    /* Reading within a single page */
    BUG_ON(((src + size - 1) & PAGE_SIZE) != (src & PAGE_SIZE));
    BUG_ON(((dst + size - 1) & PAGE_SIZE) != (dst & PAGE_SIZE));


    /* We try this only twice */
    for(tries = 0; tries < 2; tries++) {
        down_read(&current->mm->mmap_lock);

        pgd = pgd_offset(current->mm, src);
        if(!pgd_present(*pgd)) {
            up_read(&current->mm->mmap_lock);
            mm_populate(src & PAGE_MASK, PAGE_SIZE);
            /* Try again from scratch */
            continue;
        }

        p4d = p4d_offset(pgd, src);
        if(!p4d_present(*p4d)) {
            up_read(&current->mm->mmap_lock);
            mm_populate(src & PAGE_MASK, PAGE_SIZE);
            /* Try again from scratch */
            continue;
        }

        pud = pud_offset(p4d, src);
        if(!pud_present(*pud)) {
            up_read(&current->mm->mmap_lock);
            mm_populate(src & PAGE_MASK, PAGE_SIZE);
            /* Try again from scratch */
            continue;
        }

        pmd = pmd_offset(pud, src);
        if(!pmd_present(*pmd)) {
            up_read(&current->mm->mmap_lock);
            mm_populate(src & PAGE_MASK, PAGE_SIZE);
            /* Try again from scratch */
            continue;
        }

        ptep = pte_offset_map(pmd, src);
        if(!pte_present(*ptep)) {
            up_read(&current->mm->mmap_lock);
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
            list_add(&new_marked_pframe->other_nodes, &current->marked_frames);
            pframe_copy = pframe;

            /* Marked pages also become read-only */
		    vma = find_vma(current->mm, src);
            /* Visit all VM spaces that map this page and mark the mapings
             * rwc.arg holds the preallocated struct page_marking because we cannot
             * call kmalloc under spinlocks. Calls page_mark_one.
             * Space allocated here. If not used, freed after the rmap_walk.
             * If needed during page_mark_one, added to VMA marked_pages list. 
             * Then freed during page_unmark_one. */
            new_marking_space = kzalloc(sizeof(struct page_marking), GFP_KERNEL);
            BUG_ON(new_marking_space == NULL);
            rwc.arg = &new_marking_space;
            rmap_walk(pframe, &rwc);
            if(new_marking_space) 
                kfree(new_marking_space);

            up_read(&current->mm->mmap_lock);
        } else{
            up_read(&current->mm->mmap_lock);
            if (iter_version->pframe == NULL) /* Marked, unduplicated: Reading from original pframe */
                pframe_copy = pframe;
            else                              /* Marked, duplicated: Read from iter_version's pframe */
                pframe_copy = page_address(iter_version->pframe);
        }

        pframe_vaddr = page_address(pframe_copy);
        BUG_ON(pframe_vaddr == NULL);
        src = (uintptr_t)pframe_vaddr + (src & ~PAGE_MASK);

    MARKER();

        return __raw_copy_from_user((void *)dst, (const void *)src, size);
    }

    BUG();
    return size;
}

unsigned long __must_check
raw_copy_to_user(void __user *dst, const void *src, unsigned long size) {
    /* TODO */

    /* Placeholder */
    return __raw_copy_to_user(dst, src, size);
}
EXPORT_SYMBOL(raw_copy_to_user);

// #if !defined(INLINE_COPY_FROM_USER)

unsigned long __must_check
raw_copy_from_user(void *dst, const void __user *src, unsigned long size) {
    uintptr_t id, address, cur_dst, cur_src;
    unsigned long cur_sz, remaining_sz, unread_sz;
    struct vm_area_struct *vma;

    // MARKER();

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

    MARKER();

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
    /* Pre-setup for structure which walks reverse mappings for a frame */
	struct rmap_walk_control rwc = {
        .arg = NULL,
		.rmap_one = page_unmark_one,
		.anon_lock = page_lock_anon_vma_read,
	};

	/* Reset the system call information */	
	list_for_each_entry_safe(marked_frame, next, &current->marked_frames, other_nodes) {
        /* For each pframe, reverse walk to unmark virtual pages */
        rmap_walk(marked_frame->pframe, &rwc);

		/* Find and delete version */
		list_for_each_entry(version, &marked_frame->pframe->versions, other_nodes) {
			if(version->task == current)
				break;
		}
		BUG_ON(version == NULL);

		list_del(&version->other_nodes);
		kfree(version);

		/* Release frame for marked, duplicated pages */
		if(version->pframe)
			__free_page(version->pframe);

		list_del(&marked_frame->other_nodes);
		kfree(marked_frame);
	}
}
EXPORT_SYMBOL(syscall_marking_cleanup);

#endif /* CONFIG_TOCTTOU_PROTECTION */