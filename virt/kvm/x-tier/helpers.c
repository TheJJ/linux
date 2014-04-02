#include <linux/string.h>
#include <linux/slab.h>
#include <linux/xtier.h>

#include "debug.h"


static struct injection_arg *get_first_injection_arg(struct injection *injection)
{
	if (injection->argc == 0) {
		PRINT_ERROR("queried first injection argument where argc == 0!\n");
		return NULL;
	}

	if ((injection->type & (CONSOLIDATED))) {
		return (struct injection_arg *)((char *)injection + injection_size(injection) - injection->args_size);
	}
	else {
		return injection->argv;
	}
}


static struct injection_arg *get_last_injection_arg(struct injection *injection)
{
	if (injection->argc == 0) {
		PRINT_ERROR("queried last injection argument where argc == 0!\n");
		return NULL;
	}

	if ((injection->type & (CONSOLIDATED))) {
		return (struct injection_arg *)((char *)injection + injection_size(injection) - injection->size_last_arg);
	}
	else {
		if (injection->argv) {
			if (injection->type & (CONSOLIDATED_ARGS)) {
				return (struct injection_arg *)((char *)injection->argv + injection->args_size - injection->size_last_arg);
			}
			else {
				return injection->argv->prev;
			}
		}
		else {
			PRINT_ERROR("injection argv is NULL even though argc != 0!\n");
			return NULL;
		}
	}
}


struct injection_arg *get_next_arg(struct injection *injection,
                                   struct injection_arg *arg)
{
	struct injection_arg *ret = NULL;

	// If no previous arg was queried, return the first arg
	if (arg == NULL) {
		ret = get_first_injection_arg(injection);
	}
	else if (injection->argc == 1) {
		ret = arg;
	}
	else if ((injection->type & (CONSOLIDATED | CONSOLIDATED_ARGS))) {
		//next argument is located after the size of this argument + its data
		ret = (struct injection_arg *)(((char *)arg) + sizeof(struct injection_arg) + arg->size);
	}
	else {
		ret = arg->next;
	}

	return ret;
}


struct injection_arg *get_prev_arg(struct injection *injection,
                                   struct injection_arg *arg)
{
	struct injection_arg *ret = NULL;

	// If arg is NULL we return the last arg
	if (arg == NULL) {
		ret = get_last_injection_arg(injection);
	}
	else if (injection->argc == 1) {
		ret = arg;
	}
	else if ((injection->type & (CONSOLIDATED | CONSOLIDATED_ARGS))) {
		ret = (struct injection_arg *)(((char *)arg) - (sizeof(struct injection_arg) + arg->size_prev));
	}
	else {
		ret = arg->prev;
	}

	return ret;
}


/**
 * return pointer to the argument data.
 */
char *get_arg_data(struct injection *injection, struct injection_arg *arg)
{
	//when serialized, the arg data is stored right behind the injection_arg structure.
	if ((injection->type & (CONSOLIDATED | CONSOLIDATED_ARGS))) {
		return (char *)(((char *)arg) + sizeof(struct injection_arg));
	}
	else {
		return arg->data;
	}
}


static void free_injection_args(struct injection *injection)
{
	struct injection_arg *next = NULL;
	struct injection_arg *cur = NULL;
	unsigned int i = 0;

	// injection arguments
	if (injection->argc > 0) {
		//only free argument components if they were not consolidated
		if (!(injection->type & CONSOLIDATED_ARGS)) {
			cur = get_first_injection_arg(injection);

			for (i = 0; i < injection->argc; ++i) {
				next = cur->next; //remember the next

				kfree(cur->data);
				kfree(cur);

				cur = next; //go to the next
			}
		}
	}
}


void free_injection(struct injection *injection)
{
	if (!(injection->type & (CONSOLIDATED))) {
		//free components if injection is not consolidated
		free_injection_args(injection);
		kfree(injection->name);
		kfree(injection->code);
	}

	kfree(injection);
}


void free_injection_without_code(struct injection *injection)
{
	if (!(injection->type & CONSOLIDATED))
	{
		free_injection_args(injection);
		kfree(injection->name);
	}

	kfree(injection);
}


/*
 * +=========================================================
 * |                   CONSOLIDATION
 * +=========================================================
 */

unsigned int injection_size(struct injection *injection)
{
	unsigned int total_size = 0;

	total_size += sizeof(struct injection);

	// Module name
	total_size += injection->name_len;

	// Code len
	total_size += injection->code_len;

	// Args
	total_size += injection->args_size;

	return total_size;
}

// Fixes the argument pointers in a consolidated injection structure
void consolidated_update_arg_pointers(struct injection *injection)
{
	/*
	  consolidated_args:
	  ######### <- injection blob
	          | <- argv ptr
	          v
	          #%%#%%%#%%
	          ^ \_ injection_arg data
	          injection_arg

	  consolidated:

	  ##########%%#%%%#%%

	 */
	struct injection_arg *cur, *prev, *last;

	if (injection->argc > 0) {
		//when CONSOLIDATED, cur is the offset within the injection blob
		//else cur is the current (new) arg start pointer
		cur = get_first_injection_arg(injection);

		//set the new arg start ptr to that point
		injection->argv = cur;

		//get new last injection arg ptr
		last = get_last_injection_arg(injection);

		//current arg is the first.
		//the previous to the first arg is the last
		prev = last;

		if (!cur) {
			//no arguments stored.
			return;
		}

		do {
			// Set previous arg ptr for the current arg
			cur->prev = prev;

			// The next of the previous arg is the current arg
			prev->next = cur;

			// The arg data may lie behind the arg metadata structure
			cur->data = get_arg_data(injection, cur);

			// Move onto the next arg
			prev = cur;
			cur = get_next_arg(injection, cur);
		}
		while (prev != last);
	}
	else {
		injection->argv = NULL;
	}
}

// Fixes the pointers in a consolidated injection structure
static void consolidated_update_pointers(struct injection *injection)
{
	// Structure consolidated? pointer update only makes sense for blob
	if (injection->type != CONSOLIDATED) {
		PRINT_WARNING("This is not a consolidated injection structure!\n");
		return;
	}

	// the module name is stored right behind the injection structure
	if (injection->name_len) {
		injection->name = ((char *)injection) + sizeof(struct injection);
	}
	else {
		injection->name = NULL;
	}

	// the code is stored right after the module name
	if (injection->code_len) {
		injection->code = ((char *)injection->name) + injection->name_len;
	}
	else {
		injection->code = NULL;
	}

	// the argument data, should be right after the code
	if (injection->argc > 0) {
		injection->argv = get_first_injection_arg(injection);
	}

	consolidated_update_arg_pointers(injection);
}

/**
 * Helper that consolidates the arguments only. Notice that this function does _NOT_
 * update the argument pointers. To achieve this the consolidated_update_arg_pointers
 * funciton can be used. Further the function does _NOT_ update the type of the injection
 * structure nor the original unconsolidated arguments.
 */
struct injection_arg *get_consolidated_args(struct injection *injection, char *consolidated_data_dest_ptr)
{
	struct injection_arg *result = NULL;
	struct injection_arg *arg = NULL;
	unsigned int i = 0;

	if (injection->argc > 0) {
		//return the descination position as result.
		result = (struct injection_arg *)consolidated_data_dest_ptr;

		// copy each argument
		arg = get_first_injection_arg(injection);

		for (i = 0; i < injection->argc; arg = get_next_arg(injection, arg), ++i) {
			memcpy(consolidated_data_dest_ptr, arg, sizeof(struct injection_arg));

			//set linked list pointers to NULL
			((struct injection_arg *)consolidated_data_dest_ptr)->next = NULL;
			((struct injection_arg *)consolidated_data_dest_ptr)->prev = NULL;
			((struct injection_arg *)consolidated_data_dest_ptr)->data = NULL;

			//move storage pointer behind current copied argument structure
			consolidated_data_dest_ptr += sizeof(struct injection_arg);

			//store the argument data right behinnd the injection_arg structure
			//belonging to it.
			memcpy(consolidated_data_dest_ptr, arg->data, arg->size);
			consolidated_data_dest_ptr += arg->size;
		}
	}

	return result;
}

/**
 * create a blob for all the injection argument data
 */
struct injection *consolidate_args(struct injection *injection)
{
	char *consolidated_data = NULL;
	struct injection_arg *consolidated_args = NULL;

	// Is this structure already a blob including the arguments
	if (injection->type & CONSOLIDATED) {
		PRINT_WARNING("Injection structure already consolidated! Aborting!\n");
		return injection;
	}

	// Allocate memory for arg blob
	consolidated_data = (char *)kmalloc(injection->args_size, GFP_KERNEL);

	if (!consolidated_data) {
		PRINT_ERROR("Could not allocated memory for argument data!\n");
		return injection;
	}

	// Get consolidated arguments
	consolidated_args = get_consolidated_args(injection, consolidated_data);

	// Free original args
	free_injection_args(injection);

	// Update args and pointers
	injection->type = CONSOLIDATED_ARGS;
	injection->argv = consolidated_args;
	consolidated_update_arg_pointers(injection);

	return injection;
}

struct injection *consolidate(struct injection *injection)
{
	char *consolidated_data = NULL;
	struct injection *result = NULL;

	size_t blob_size = injection_size(injection);

	// Is this structure already consolidated?
	if (injection->type & (CONSOLIDATED)) {
		PRINT_WARNING("Injection structure already consolidated! Aborting!\n");
		return injection;
	}

	if (injection->code_len <= 0) {
		PRINT_WARNING("Injection code length is <= 0\n");
	}

	// Allocate memory for the whole injection blob
	// this includes metadata, module name, code and arguments
	consolidated_data = (char *)kmalloc(blob_size, GFP_KERNEL);

	if (!consolidated_data) {
		PRINT_ERROR("Could not allocated memory!\n");
		return injection;
	}

	result = (struct injection *)consolidated_data;

	// Set & Copy Injection
	memcpy(consolidated_data, injection, sizeof(struct injection));
	consolidated_data += sizeof(struct injection);

	// Copy Module Name
	memcpy(consolidated_data, injection->name, result->name_len);
	result->name = NULL;
	consolidated_data += result->name_len;

	// Copy code
	memcpy(consolidated_data, injection->code, result->code_len);
	result->code = NULL;
	consolidated_data += result->code_len;

	// Consolidate arguments, store them behind the code
	result->argv = get_consolidated_args(injection, consolidated_data);

	// Free old injection structure
	free_injection(injection);

	result->type = CONSOLIDATED;

	// Fix pointers
	consolidated_update_pointers(result);

	return result;
}


/*
 * +=========================================================
 * |                    UTILITY FUNCTIONS
 * +=========================================================
 *
 */
char is_immediate(struct injection_arg *arg)
{
	if (arg == NULL) {
		return -1;
	}

	switch (arg->type) {
	case NUMERIC:
		return 1;
	case STRING:
	case STRUCTURE:
		return 0;
	default:
		return 0;
	}
}

const char *argument_type_to_string(enum arg_type type)
{
	switch (type) {
	case NUMERIC:
		return "NUMERIC";
	case STRING:
		return "STRING";
	case STRUCTURE:
		return "STRUCTURE";
	default:
		return "UNDEFINED";
	}
}

void print_argument_data(struct injection *injection, struct injection_arg *arg)
{
	char *arg_data = get_arg_data(injection, arg);

	switch (arg->type) {
	case NUMERIC:
		switch (arg->size) {
		case sizeof(char):
			PRINT_DEBUG("\t\t DATA: %c\n", *arg_data);
			return;
		case sizeof(short):
			PRINT_DEBUG("\t\t DATA: %hd\n", *((short *)arg_data));
			return;
		case sizeof(int):
			PRINT_DEBUG("\t\t DATA: %d\n", *((int *)arg_data));
			return;
		case sizeof(long):
			PRINT_DEBUG("\t\t DATA: %ld\n", *((long *)arg_data));
			return;
		default:
			PRINT_DEBUG("\t\t DATA: UNKNOWN NUMERIC SIZE!\n");
			return;
		}
	case STRING:
		PRINT_DEBUG("\t\t DATA: %s\n", arg_data);
		return;
	case STRUCTURE:
		PRINT_DEBUG("\t\t DATA: 0x%llx\n", *((long long *)arg_data));
		return;
	default:
		PRINT_DEBUG("\t\t DATA: UNDEFINED!\n");
		return;
	}
}

void print_argument(struct injection *injection, struct injection_arg *arg)
{
	PRINT_DEBUG("\t ARGUMENT %d @ %p\n", arg->number, arg);
	PRINT_DEBUG("\t\t TYPE: %s\n", argument_type_to_string(arg->type));
	PRINT_DEBUG("\t\t SIZE: %d\n", arg->size);
	PRINT_DEBUG("\t\t NEXT: %p\n", arg->next);
	PRINT_DEBUG("\t\t PREV: %p\n", arg->prev);
	PRINT_DEBUG("\t\t DATA @%p\n", arg->data);
	print_argument_data(injection, arg);
}

void print_arguments(struct injection *injection)
{
	struct injection_arg *arg = NULL;
	unsigned int i = 0;

	PRINT_DEBUG("arguments:\n");
	PRINT_DEBUG("\tlen(arguments): %d (argv @ %p)\n", injection->argc, get_first_injection_arg(injection));

	for (i = 0; i < injection->argc; ++i) {
		arg = get_next_arg(injection, arg);

		if (arg == NULL) {
			PRINT_ERROR("Error: injection argument %d is nullptr!\n", i);
			return;
		}

		print_argument(injection, arg);
	}
}

void print_arguments_reverse(struct injection *injection)
{
	struct injection_arg *arg = NULL;
	unsigned int i = 0;

	PRINT_DEBUG("arguments: reverse order\n");
	PRINT_DEBUG("\tlen(arguments): %d (argv @ %p)\n", injection->argc, get_first_injection_arg(injection));

	for (i = 0; i < injection->argc; ++i)
	{
		arg = get_prev_arg(injection, arg);
		if (arg == NULL) {
			PRINT_ERROR("Error: injection argument %d is nullptr!\n", i);
			return;
		}

		print_argument(injection, arg);
	}
}


static void _print_injection(struct injection *injection, int order)
{
	PRINT_DEBUG("INJECTION STRUCTURE\n");
	PRINT_DEBUG("===================\n");
	PRINT_DEBUG("\t MODULE: %s\n", injection->name);

	if (injection->type == VARIABLE)
		PRINT_DEBUG("\t TYPE: VARIABLE\n");
	else if (injection->type == CONSOLIDATED_ARGS)
		PRINT_DEBUG("\t TYPE: CONSOLIDATED ARGS\n");
	else if (injection->type == CONSOLIDATED)
		PRINT_DEBUG("\t TYPE: CONSOLIDATED\n");
	else
		PRINT_DEBUG("\t TYPE: UNDEFINED\n");

	PRINT_DEBUG("\t TOTAL SIZE: %d\n", injection_size(injection));

	PRINT_DEBUG("\t CODE:        @ 0x%p\n", injection->code);
	PRINT_DEBUG("\t CODE LEN:      %d\n", injection->code_len);
	PRINT_DEBUG("\t ARGUMENTS:   @ 0x%p\n", injection->argv);
	PRINT_DEBUG("\t ARGS SIZE:     %d\n", injection->args_size);
	//PRINT_DEBUG("\t EVENT BASED:   %d\n", injection->event_based);
	//PRINT_DEBUG("\t EVENT ADDRESS: 0x%p\n", injection->event_address);
	//PRINT_DEBUG("\t TIME BASED:    %d\n", injection->time_inject);
	//PRINT_DEBUG("\t AUTO INJECT:   %d\n", injection->auto_inject);
	PRINT_DEBUG("\t EXIT AFTER INJECTION: %d\n", injection->exit_after_injection);

	if (order > 0)
		print_arguments(injection);
	else
		print_arguments_reverse(injection);
}

void print_injection(struct injection *injection)
{
	_print_injection(injection, 1);
}

void print_injection_reverse(struct injection *injection)
{
	_print_injection(injection, -1);
}
