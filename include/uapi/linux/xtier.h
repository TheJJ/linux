#ifndef __LINUX_XTIER_H
#define __LINUX_XTIER_H

#include <linux/kvm.h>
#include <linux/types.h>

#ifdef __KERNEL__
#include <linux/time.h>
#endif

/*
 * userspace x-tier interface for /dev/kvm
 */

/* The interrupt number that signals a hypercall */
#define XTIER_HYPERCALL_INTERRUPT 42

// CONVENTION:
// -> COMMAND: RAX
// -> FIRST PARAM: RBX
// -> SECOND PARAM: RCX
// -> RETURN VALUE: RAX

/* The individual hypercall commands. The command register is RAX. */
#define XTIER_HYPERCALL_RESERVE_MEMORY 12345
#define XTIER_HYPERCALL_PRINT 2
#define XTIER_HYPERCALL_DATA_TRANSFER 3
#define XTIER_HYPERCALL_EXTERNAL_FUNCTION_CALL 42


/* OUTPUT Delimiters for external data transfers. */
#define XTIER_EXTERNAL_OUTPUT_BEGIN "####### X-TIER OUTPUT BEGIN #######"
#define XTIER_EXTERNAL_OUTPUT_END   "####### X-TIER OUTPUT END #######"

#define XTIER_EXTERNAL_COMMAND_RETURN_VALUE_FORMAT "0x%016lx"
#define XTIER_EXTERNAL_COMMAND_RETURN_VALUE_SIZE 18

/* Tracing Modes */
#define XTIER_HLT_EXIT 1ULL << 35
#define XTIER_EXCEPTION_EXIT 1ULL << 36
#define XTIER_CR3_EXIT 1ULL << 37
#define XTIER_CAPTURE_IDLE 1ULL << 60  // store the cr3 for the idle task
#define XTIER_AVOID_IDLE 1ULL << 61    // postpone injections for idletask cr3
#define XTIER_CODE_INJECTION 1ULL << 62
#define XTIER_STOP_VM_AFTER_EVENT 1ULL << 63

/* Different OSs */
#define XTIER_OS_UNKNOWN 0
#define XTIER_OS_LINUX_64 1
#define XTIER_OS_LINUX_32 2
#define XTIER_OS_WINDOWS_7_32 3

/* Default OS */
#define XTIER_OS_DEFAULT XTIER_OS_LINUX_64

/* Exit Reasons */
#define XTIER_EXIT_REASON                    (0x1337ULL << (2*8))
#define XTIER_EXIT_REASON_DEBUG              0x1111ULL | XTIER_EXIT_REASON
#define XTIER_EXIT_REASON_INJECT_FINISHED    0x1341ULL | XTIER_EXIT_REASON
#define XTIER_EXIT_REASON_INJECT_COMMAND     0x1342ULL | XTIER_EXIT_REASON
#define XTIER_EXIT_REASON_INJECT_FAULT       0x1343ULL | XTIER_EXIT_REASON

/* IOCTLS */
#define XTIER_IOCTL_SET_XTIER_STATE 1337
#define XTIER_IOCTL_INJECT 1350
#define XTIER_IOCTL_INJECT_RESERVE_MEMORY 1351
#define XTIER_IOCTL_INJECT_GET_PERFORMANCE 1352
#define XTIER_IOCTL_INJECT_SET_AUTO_INJECT 1353
#define XTIER_IOCTL_INJECT_SET_TIME_INJECT 1354
#define XTIER_IOCTL_INJECT_CAPTURE_IDLE_CR3 1355
#define XTIER_IOCTL_INJECT_AVOID_IDLE_CR3 1356
#define XTIER_IOCTL_INJECT_GET_STATE 1357

/* X-TIER MEMORY AREA */
// Make sure this stays under 32 bits, since 32-bit paging only supports 32 bit physical addresses.
#define XTIER_MEMORY_AREA_ADDRESS (1ULL << 30)
#define XTIER_MEMORY_AREA_PAGES 1024
#define XTIER_MEMORY_AREA_PAGE_SIZE 4096
#define XTIER_MEMORY_AREA_SIZE (XTIER_MEMORY_AREA_PAGES * XTIER_MEMORY_AREA_PAGE_SIZE)

/* EVENT-BASE INJECTION */
// The debug register that will be used to contain the code hook.
#define XTIER_INJECT_HOOK_DR 0

// The different types of an argument
enum arg_type {
    UNDEFINED = 0,
    NUMERIC = 1,
    STRING = 2,
    STRUCTURE = 4
};

/**
 * An injection can either be variable or consolidated.
 * A variable injection makes use of the pointers to iterate over the individual
 * arguments. In contrast to that a consolidated injection structure is allocated
 * in one consecutive memory block. In this case the pointers within the structures
 * may be invalid i.e. if the structure is transferred from userspace to kernelspace.
 * However, it is still possible to iterate over the structure using the size arguments.
 */
enum injection_type {
    VARIABLE          = 0x0,
    CONSOLIDATED_ARGS = 0x1,  // last bit: the arguments are one blob (stored at injection->argv).
    CONSOLIDATED      = 0x2,  // fist bit: the whole injection is one blob then.
};

/**
 * Structure that wraps a single argument for an injected module.
 */
struct injection_arg {
    unsigned int number;         // The number of the argument, e.g, the first argument
    enum arg_type type;          // The type of the argument
    unsigned int size;           // The size of the arguments data in bytes
    unsigned int size_prev;      // The size of the previous argument in bytes
                                 // Needed for backwards iteration in consolidated state.
    struct injection_arg *next;  // Pointer to the next argument
    struct injection_arg *prev;  // Pointer to the previous argument
    char *data;                  // The data of the argument which is dynamic and will be
                                 // exactly of size bytes.
    void *data_on_stack;         // Helper variable that is used by the kvm kernel module
                                 // and specifies where the data was written to the stack
};


/**
 * Structure to measure the performance of a code injection.
 * Notice that all time values that are stored within this
 * struct are the accumulated sums of the events. Thus
 * to get the average time of a single execution, for instance,
 * the total time stored in total_module_exec_time has to be divided
 * by the number of injections
 *
 * time unit: nanoseconds
 */
struct xtier_stats {
	struct timespec hypercall_time;
	struct timespec run_time;

	long total_module_load_time;            // the time it took to inject the module in ns
	long total_module_exec_time;            // the time that it took the module to execute in ns,
	                                        // includes external function calls and vmexits.
	long total_module_unload_time;          // the time it took to remove the module in ns
	long total_module_temp_removal_time;    // the time it took to temporarily remove the module in ns
	long total_module_temp_resume_time;     // the time it took to resume a temporarily removed module in ns
	long total_module_hypercall_time;       // time spent during external (userspace handled) hypercalls
	int injections;                         // the number of times the module was injected
	int temp_removals;
	int hypercalls;
};


/**
 * The main structure for code injection. Notice that this structure is also used
 * by the kvm modules and the qemu userspace.
 */
struct injection {
	enum injection_type type;    // The type of the injection structure

	char *name;                  // module name
	size_t name_len;             // module name length

	char *code;                  // points to the code to be injected.
	unsigned int code_len;       // The length of the injected code.

	unsigned char event_based;   // Is this an even based injection?
	void *event_address;         // The address of the event that should be intercepted
	unsigned int auto_inject;    // Should the same module be automatically injected multiple times
	unsigned int time_inject;    // Should the same module be injected after a certain period of time
	char exit_after_injection;   // Exit after the injection is done?

	size_t faults;               // How often did this injection fail?

	unsigned int args_size;      // The total size of all arguments in bytes
	unsigned int size_last_arg;  // The size of the last argument including its data
	                             // structure in bytes. This is required for backwards
	                             // iteration in consolidated state.
	unsigned int argc;           // The number of arguments in this injection.
	struct injection_arg *argv;  // Pointer to the first argument
};


/**
 * xtier configuration variables.
 */
struct xtier_config {
	int64_t mode;
	int32_t os;
};


/**
 * state of the xtier instance.
 */
struct xtier_state {
	char event_based;             // Is this an event based injection?
	char exit_after_injection;    // Exit after the injection is done?
	char new_module;              // Was the injected module changed?
	char qemu_hypercall;          // Does qemu currently handle a hypercall
	char injection_fault;         // Was there a fault during last injection?
	char reinject;                // Should the module be reinjected?
	char exception_exit;          // Was the last exit due to an exception?

	struct kvm_regs regs;         // virtual registers for restoring vm state
	struct kvm_sregs sregs;       // virtual sregisters

	size_t cr3;                   // cr3 value when a injection was started
	size_t idle_cr3;              // cr3 determined for the idle thread
	size_t external_function_return_rip; // return to this rip after the external function
	ssize_t return_value;         // injection return value
};


/**
 * per-vcpu xtier state.
 * this is the central data entry point.
 */
struct xtier_vm {
	// xtier configuration
	struct xtier_config cfg;

	// status variables
	struct xtier_state state;

	// injection statistics and time measurement
	struct xtier_stats stats;

	// injection state
	struct injection injection;
};

/**
 * Creates a new injection structure from the given file descriptor.
 * This function assumes that the injection structure which is available
 * via the fd is CONSOLIDATED. It can be used in conjunction with
 * injection_to_fd.
 *
 * @param fd The file pointer to read from.
 * @returns A pointer to the injection structure or NULL.
 */
struct injection *injection_from_fd(int fd);

/**
 * Write the given injection structure to a file descriptor.
 * This function requires that the injection structure which is available
 * via the fd is CONSOLIDATED. It can be used in conjunction with
 * injection_to_fd.
 *
 * @param injection The injection structure that should be written.
 * @param fd The fd to write to.
 */
void injection_to_fd(struct injection *injection, int fd);

/**
 * Free an injection structure and its arguments.
 *
 * @param injection The injection structure to free.
 */
void free_injection(struct injection *injection);

/**
 * Free an injection structure and its arguments, but do not free its code.
 *
 * @param injection The injection structure to free.
 */
void free_injection_without_code(struct injection *injection);


/**
 * Get the size of the given injection struct.
 *
 * @param injection The injection structure whose size should be calculated
 * @returns The size of the injection structure.
 */
unsigned int injection_size(struct injection *injection);

/**
 * The given injection structure is freed and a new injection structure
 * is created that is contained in a single block of memory.
 *
 * Layout of the consolidated structure:
 *
 *  --------------------------
 * |    struct injection      |
 *  --------------------------
 * |      module name         |
 *  --------------------------
 * |      module code         |
 *  --------------------------
 * |   struct injection_args  |
 *  --------------------------
 * |  struct injection_arg_0  |
 *  --------------------------
 * |      data of arg_0       |
 *  --------------------------
 *            ...
 *  --------------------------
 * |  struct injection_arg_N  |
 *  --------------------------
 * |      data of arg_N       |
 *  --------------------------
 *
 * @param injection The injection structure to consolidate.
 * @returns A pointer to a consolidated injection structure.
 */
struct injection *consolidate(struct injection *injection);

/**
 * The arguments of the given injection structure are freed and a new
 * argument structure is created that is contained in a single block of
 * memory.
 *
 * @param injection The injection structure to consolidate.
 * @returns A pointer to an injection structure with consolidated
 *          arguments.
 */
struct injection *consolidate_args(struct injection *injection);

/**
 * Get the injection arguments of an injection structure. Notice that this
 * function handles consolidated injection structures as well as variable
 * injection structures.
 *
 * @param injection The injection structure whose arguments should be
 *                  obtained.
 * @returns A pointer to the injection_args structure or NULL.
 */
struct injection_args *get_injection_args(struct injection *injection);

/**
 * Get the next injection argument of an injection structure. Notice that
 * this function handles consolidated injection structures as well as variable
 * injection structures.
 *
 * @param injection The injection structure whose arguments should be
 *                  obtained.
 * @param arg The current injection argument. If this is set to NULL the
 *            first argument of the injection structure will be returned.
 * @returns A pointer to the injection_arg structure or NULL.
 */
struct injection_arg *get_next_arg(struct injection *injection,
                                    struct injection_arg *arg);

/**
 * Get the previous injection argument of an injection structure. Notice that
 * this function handles consolidated injection structures as well as variable
 * injection structures.
 *
 * @param injection The injection structure whose argument should be
 *                  obtained.
 * @param arg The current injection argument. If this is set to NULL the
 *            last argument of the injection structure will be returned.
 * @returns A pointer to the injection_arg structure or NULL.
 */
struct injection_arg *get_prev_arg(struct injection *injection,
                                    struct injection_arg *arg);

/**
 * Get the data of an injection argument. Notice that function handles
 * consolidated injection structures as well as variable injection structures.
 *
 * @param injection The injection structure the argument belongs to.
 * @param arg The injection_arg structure that contains the argument.
 * @returns A pointer to the data of the argument.
 */
char *get_arg_data(struct injection *injection, struct injection_arg *arg);

/**
 * Add a char argument to an injection structure. The new argument
 * will automatically reveive the next free argument number.
 *
 * @param injection A pointer to the injection structure that will hold
 *                  the argument.
 * @param data The char value of the argument.
 */
void add_char_argument(struct injection *injection, char data);

/**
 * Add a short argument to an injection structure. The new argument
 * will automatically reveive the next free argument number.
 *
 * @param injection A pointer to the injection structure that will hold
 *                  the argument.
 * @param data The short value of the argument.
 */
void add_short_argument(struct injection *injection, short data);

/**
 * Add an int argument to an injection structure. The new argument
 * will automatically reveive the next free argument number.
 *
 * @param injection A pointer to the injection structure that will hold
 *                  the argument.
 * @param data The int value of the argument.
 */
void add_int_argument(struct injection *injection, int data);

/**
 * Add a long argument to an injection structure. The new argument
 * will automatically reveive the next free argument number.
 *
 * @param injection A pointer to the injection structure that will hold
 *                  the argument.
 * @param data The long value of the argument.
 */
void add_long_argument(struct injection *injection, long data);

/**
 * Add a string argument to an injection structure. The new argument
 * will automatically reveive the next free argument number.
 *
 * @param injection A pointer to the injection structure that will hold
 *                  the argument.
 * @param data A pointer that points to the string of the argument.
 */
void add_string_argument(struct injection *injection, const char *data);

/**
 * Add a struct or array argument to an injection structure. The new argument
 * will automatically reveive the next free argument number.
 *
 * @param injection A pointer to the injection structure that will hold
 *                  the argument.
 * @param data A pointer that points to the data of the argument.
 * @param size The complete size of the data i.e. including 0 bytes.
 */
void add_struct_argument(struct injection *injection, void *data, unsigned int size);

/**
 * Determines whether the given argument is an immediate i.e. it can be directly
 * passed on the stack or within a register such as a number or not. Latter means
 * that the argument must first be written into memory and then a pointer must be
 * passed to the receiving module.
 *
 * @param arg A pointer to the argument that should be tested.
 * @returns 1 if it is an immediate, 0 otherwise.
 */
char is_immediate(struct injection_arg *arg);

/**
 * Print an injection structure and its arguments.
 *
 * @param injection A pointer to the injection structure that should be
 *                  printed.
 */
void print_injection(struct injection *injection);

/**
 * Print an injection structure and its arguments in reverse order
 * i.e. last argument first.
 *
 * @param injection A pointer to the injection structure that should be
 *                  printed.
 */
void print_injection_reverse(struct injection *injection);

void print_argument_data(struct injection *injection, struct injection_arg *arg);
void print_argument(struct injection *injection, struct injection_arg *arg);
void print_arguments(struct injection *injection);
void print_arguments_reverse(struct injection *injection);
const char *argument_type_to_string(enum arg_type type);
struct injection_arg *get_consolidated_args(struct injection *injection, char *consolidated_data_dest_ptr);
void consolidated_update_arg_pointers(struct injection *injection);

#endif /* __LINUX_XTIER_H */
