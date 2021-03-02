#include <linux/mm.h>
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
		case -1:
			return 0;
	}

    return 1;
}

void tocttou_file_mark_start(struct file *file) {
    /* TODO */
}

unsigned long mark_and_read(uintptr_t id, void *dst, const void __user *src, unsigned long size) {
    /* TODO */

    /* Placeholder */
    return __raw_copy_from_user(dst, src, size);
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
    if(should_mark()) {
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

            unread_sz = mark_and_read(id, (void *)cur_dst, (void *)cur_src, cur_sz);
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