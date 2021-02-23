#include <linux/uaccess.h>


#ifdef CONFIG_TOCTTOU_PROTECTION

unsigned long __must_check
raw_copy_to_user(void __user *dst, const void *src, unsigned long size) {
    /* TODO */

    /* Placeholder */
    return __raw_copy_to_user(to, from, n);
}
EXPORT_SYMBOL(raw_copy_to_user);

unsigned long __must_check
raw_copy_from_user(void *dst, const void __user *src, unsigned long size) {
    /* TODO */

    /* Placeholder */
    return __raw_copy_from_user(dst, src, size);
}

#endif /* CONFIG_TOCTTOU_PROTECTION */