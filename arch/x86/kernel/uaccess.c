#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/uaccess.h>

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
    void *pframe_vaddr;
    struct page_version *iter_version, *new_marked_version;
    struct marked_frame *new_marked_pframe;

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
        } else if (iter_version->pframe == NULL) { /* Marked, unduplicated: Reading from original pframe */
            pframe_copy = pframe;
        } else {                             /* Marked, duplicated: Read from iter_version's pframe */
            pframe_copy = page_address(iter_version->pframe);
        }

        pframe_vaddr = page_address(pframe_copy);
        BUG_ON(pframe_vaddr == NULL);
        src = (uintptr_t)pframe_vaddr + (src & ~PAGE_MASK);
        //TODO: Locking? what to do with current->mm->mmap_lock?
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

#endif /* CONFIG_TOCTTOU_PROTECTION */