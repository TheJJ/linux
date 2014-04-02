#include "list.h"

#include <linux/kvm_xtier.h>
#include <linux/slab.h>

struct xtier_list *xtier_list_create(void)
{
	struct xtier_list *result = kzalloc(sizeof(struct xtier_list), GFP_KERNEL);

	if (!result) {
		// Error
		return NULL;
	}

	result->first = NULL;
	result->last = NULL;
	result->length = 0;

	return result;
}

void xtier_list_delete(struct xtier_list *list)
{
	struct xtier_list_element *e = list->first;
	struct xtier_list_element *next = NULL;

	while (e) {
		next = e->next;
		kfree(e);
		e = next;
	}

	kfree(list);
}

void xtier_list_add(struct xtier_list *list, struct xtier_list_element *element)
{
	if (!list->first) {
		list->first = element;
		element->prev = NULL;
	}
	else {
		element->prev = list->last;
		list->last->next = element;
	}

	element->next = NULL;
	list->last = element;

	list->length++;
}

void xtier_list_remove(struct xtier_list *list, struct xtier_list_element *element)
{
	if (list->first == element)
		list->first = element->next;

	if (list->last == element)
		list->last = element->prev;

	if (element->next)
		element->next->prev = element->prev;

	if (element->prev)
		element->prev->next = element->next;

	list->length--;
}
