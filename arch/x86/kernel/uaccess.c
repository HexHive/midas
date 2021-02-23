#include <linux/uaccess.h>


#ifdef CONFIG_TOCTTOU_PROTECTION

unsigned long __must_check
raw_copy_to_user(void __user *dst, const void *src, unsigned long size) {
    /* TODO */

    /* Placeholder */
    return __raw_copy_to_user(to, from, n);
}
EXPORT_SYMBOL(raw_copy_to_user);
#endif /* CONFIG_TOCTTOU_PROTECTION */