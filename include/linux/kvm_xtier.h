#ifndef __KVM_XTIER_H
#define __KVM_XTIER_H

#include <linux/xtier.h>

/*
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Internal xtier structures and functions.
 */


// page offsets
// replace by __PAGE_OFFSET in asm/page_{64,32}_types.h ?
#define XTIER_LINUX_PAGE_OFFSET_32   0xc0000000
#define XTIER_LINUX_PAGE_OFFSET_64   0xffff880000000000
#define XTIER_WINDOWS_PAGE_OFFSET_32 0x80000000


struct xtier_list_element {
	struct xtier_list_element *next;
	struct xtier_list_element *prev;
};

struct xtier_list {
	struct xtier_list_element *first;
	struct xtier_list_element *last;
	int length;
};

struct xtier_queued_interrupt {
	u32 interrupt_info;
	struct xtier_list_element list;
};


/**
 * call to initialize and clear the xtier vm state.
 */
void xtier_init(struct xtier_vm *xtier);


#endif
